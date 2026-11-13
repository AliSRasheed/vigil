"""Email authentication posture: SPF, DMARC and DKIM for the target's domain."""

from __future__ import annotations

import re

from aegisscan.checks.base import Check, CheckSkipped
from aegisscan.checks.recon.dns import require_dns_name
from aegisscan.engine import ScanContext
from aegisscan.models import Evidence, Finding, Severity, Target
from aegisscan.resolver import zone_apex

SPOOFABLE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 4.3
SPF_ALLOWS_ALL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"  # 5.3
WEAK = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 3.1

# DKIM selectors cannot be enumerated; these are the ones the large providers use by default.
DKIM_SELECTORS = (
    "default", "selector1", "selector2", "google", "k1", "k2", "s1", "s2",
    "dkim", "mail", "smtp", "mandrill", "amazonses", "protonmail", "fm1",
)  # fmt: skip
_ALL = re.compile(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", re.I)

_DESCRIPTION = (
    "SPF, DKIM and DMARC let receiving mail servers verify that a message really comes from "
    "this domain. Where they are missing or permissive, anyone can send email that appears to "
    "come from it, which is the basis of phishing and invoice fraud."
)


def spf_all_qualifier(record: str) -> str | None:
    """Qualifier of the 'all' mechanism ('+', '-', '~', '?'), or None when there is none."""
    match = _ALL.search(record)
    if match is None:
        return None
    return match.group(1) or "+"


def dmarc_policy(record: str) -> str | None:
    match = re.search(r"(?:^|;)\s*p\s*=\s*(\w+)", record, re.I)
    return match.group(1).lower() if match else None


class EmailAuthentication(Check):
    id = "recon.email_auth"
    title = "Email authentication (SPF, DMARC, DKIM)"
    severity = Severity.MEDIUM
    cwe = "CWE-290"
    owasp = "A07:2025 Authentication Failures"
    category = "recon"
    description = (
        "SPF and DMARC presence and strictness for the target's zone, and DKIM keys at "
        "common selectors."
    )

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        require_dns_name(target)
        domain = await zone_apex(ctx.dns, target.host)
        if not (await ctx.dns.query(domain, "SOA")).found:
            raise CheckSkipped(f"no DNS zone found for {target.host}")
        findings: list[Finding] = []

        def add(
            title: str, why: str, evidence: list[Evidence], remediation: str, vector: str | None
        ) -> None:
            findings.append(
                self.finding(
                    title=title,
                    url=f"dns:{domain}",
                    description=_DESCRIPTION,
                    why=why,
                    evidence=evidence,
                    remediation=remediation,
                    cvss_vector=vector,
                )
            )

        # --- SPF -----------------------------------------------------------
        txt = await ctx.dns.query(domain, "TXT")
        spf_records = [r for r in txt.records if re.match(r"v=spf1(\s|$)", r, re.I)]
        spf_fix = f'Publish one TXT record at {domain}: "v=spf1 <your mail sources> -all"'
        if txt.failed:
            pass  # cannot tell; do not guess
        elif not spf_records:
            why = f"{domain} has no SPF record (no TXT record starting with v=spf1)."
            add("No SPF record", why, [txt.evidence(why)], spf_fix, SPOOFABLE)
        elif len(spf_records) > 1:
            why = (
                f"{domain} publishes {len(spf_records)} SPF records. Receivers treat that as a "
                "permanent error and ignore SPF entirely."
            )
            add("Multiple SPF records", why, [txt.evidence(why)], spf_fix, SPOOFABLE)
        else:
            record = spf_records[0]
            qualifier = spf_all_qualifier(record)
            if qualifier == "+":
                why = (
                    f"The SPF record ends in +all ('{record}'), which authorizes every server "
                    "on the internet to send mail for the domain."
                )
                add("SPF record allows any sender (+all)", why, [txt.evidence(why)],
                    "Replace +all with -all after listing the legitimate mail sources.",
                    SPF_ALLOWS_ALL)  # fmt: skip
            elif qualifier == "?" or (qualifier is None and "redirect=" not in record.lower()):
                state = "?all (neutral)" if qualifier == "?" else "no 'all' mechanism"
                why = (
                    f"The SPF record has {state} ('{record}'), so mail from unlisted servers is "
                    "not marked as failing."
                )
                add("SPF record does not reject unlisted senders", why, [txt.evidence(why)],
                    "End the record with -all (or ~all while rolling out).", WEAK)  # fmt: skip

        # --- DMARC ---------------------------------------------------------
        dmarc = await ctx.dns.query(f"_dmarc.{domain}", "TXT")
        dmarc_records = [r for r in dmarc.records if re.match(r"v=DMARC1(\s|;|$)", r, re.I)]
        dmarc_fix = (
            f'Publish a TXT record at _dmarc.{domain}: "v=DMARC1; p=quarantine; '
            f'rua=mailto:dmarc@{domain}", then move to p=reject once reports are clean.'
        )
        policy = dmarc_policy(dmarc_records[0]) if len(dmarc_records) == 1 else None
        if dmarc.failed:
            pass
        elif len(dmarc_records) != 1:
            why = (
                f"_dmarc.{domain} has no DMARC record."
                if not dmarc_records
                else f"_dmarc.{domain} has {len(dmarc_records)} DMARC records; receivers ignore "
                "all of them."
            )
            add("No DMARC policy", why, [dmarc.evidence(why)], dmarc_fix, SPOOFABLE)
        elif policy not in ("quarantine", "reject"):
            why = (
                f"The DMARC policy is p={policy or '(missing)'} ('{dmarc_records[0]}'): "
                "receivers are asked to report failures but still deliver spoofed mail."
            )
            add("DMARC policy is not enforced", why, [dmarc.evidence(why)],
                "Move to p=quarantine and then p=reject.", WEAK)  # fmt: skip

        # --- DKIM ----------------------------------------------------------
        selectors: list[str] = []
        lookups = []
        for selector in DKIM_SELECTORS:
            answer = await ctx.dns.query(f"{selector}._domainkey.{domain}", "TXT")
            lookups.append(answer)
            if any("p=" in record for record in answer.records):
                selectors.append(selector)
        if not selectors and not all(answer.failed for answer in lookups):
            why = (
                f"No DKIM public key was found for {domain} at {len(DKIM_SELECTORS)} commonly "
                "used selectors. Selectors cannot be listed from outside, so a key may exist "
                "under another name; confirm against a real message header."
            )
            evidence = Evidence(
                kind="dns",
                request="DNS queries: <selector>._domainkey."
                + domain
                + " IN TXT for selectors "
                + ", ".join(DKIM_SELECTORS),
                response="no DKIM key (p=) record at any of these names",
                note=why,
            )
            add("No DKIM key found at common selectors", why, [evidence],
                "Enable DKIM signing at the mail provider and publish the selector record it "
                "gives you.", None)  # fmt: skip

        mx = await ctx.dns.query(domain, "MX")
        ctx.observe(
            "email_authentication",
            {
                "domain": domain,
                "mail servers (MX)": mx.records or ["none"],
                "SPF": spf_records or ["none"],
                "DMARC": dmarc_records or ["none"],
                "DKIM selectors found": selectors or ["none"],
            },
        )
        return findings
