"""Passive subdomain enumeration.

Sources are limited to what the scan already has in hand: DNS records for the
zone (asked of the operator's resolver), host names in the target page and its
security headers, and the names on the target's TLS certificate. No third-party
lookup service is contacted and no name is guessed.

Discovered subdomains are recorded for the report. They are never requested:
they are out of scope unless the operator names them.
"""

from __future__ import annotations

import re

from vigil import tlsutil
from vigil.checks.base import Check
from vigil.checks.recon.dns import require_dns_name
from vigil.engine import ScanContext
from vigil.htmlutil import extract_links
from vigil.http import RequestFailed, http_evidence
from vigil.models import Evidence, Finding, Severity, Target, host_of, normalize_host
from vigil.resolver import zone_apex
from vigil.scope import OutOfScopeError

_HOSTNAME = re.compile(r"(?<![\w.-])((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,})", re.I)


def hostnames_in(text: str) -> list[str]:
    return [normalize_host(match) for match in _HOSTNAME.findall(text)]


class SubdomainEnumeration(Check):
    id = "recon.subdomains"
    title = "Passive subdomain enumeration"
    severity = Severity.INFO
    cwe = "CWE-200"
    owasp = "A01:2025 Broken Access Control"
    category = "recon"
    description = (
        "Subdomains revealed by DNS records, page links, security headers and certificate "
        "names. Recorded, never contacted."
    )

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        require_dns_name(target)
        apex = await zone_apex(ctx.dns, target.host)
        found: dict[str, str] = {}  # subdomain -> where it was seen
        evidence: list[Evidence] = []

        def consider(name: str, source: str) -> bool:
            name = normalize_host(name).removeprefix("*.")
            if name.endswith("." + apex) and name != target.host and name not in found:
                found[name] = source
                return True
            return False

        # 1. DNS records of the zone and the host
        for name, rdtype in ((apex, "NS"), (apex, "MX"), (apex, "TXT"), (target.host, "CNAME")):
            answer = await ctx.dns.query(name, rdtype)
            new = [
                candidate
                for record in answer.records
                for candidate in hostnames_in(record)
                if consider(candidate, f"{rdtype} record of {name}")
            ]
            if new:
                evidence.append(answer.evidence(f"{rdtype} record names {', '.join(new)}"))

        # 2. the target page: links and the hosts named in its security headers
        try:
            home = await ctx.baseline()
        except (RequestFailed, OutOfScopeError):
            home = None
        if home is not None:
            new = []
            if home.is_html:
                for link in extract_links(home.text, home.url):
                    if consider(host_of(link), "link on the target page"):
                        new.append(host_of(link))
            for header in ("content-security-policy", "access-control-allow-origin"):
                for candidate in hostnames_in(home.headers.get(header, "")):
                    if consider(candidate, f"{header} header"):
                        new.append(candidate)
            if new:
                lines = [
                    line.strip()
                    for line in home.text.splitlines()
                    if any(name in line for name in new)
                ]
                evidence.append(
                    http_evidence(
                        home,
                        f"The page references {', '.join(new)}",
                        excerpt="\n".join(lines[:8]),
                    )
                )

        # 3. names on the TLS certificate
        if target.scheme == "https":
            try:
                handshake = await ctx.tls_probe()
            except tlsutil.TlsProbeError:
                handshake = None
            if handshake is not None and handshake.cert is not None:
                new = [n for n in handshake.cert.sans if consider(n, "TLS certificate name")]
                if new:
                    evidence.append(
                        Evidence(
                            kind="tls",
                            request=f"TLS handshake with {target.host}:{target.port}",
                            response="certificate names: " + ", ".join(handshake.cert.sans),
                            note=f"The certificate also covers {', '.join(new)}",
                        )
                    )

        subdomains = sorted(found)
        for name in subdomains:
            if not ctx.scope.host_in_scope(name):
                ctx.out_of_scope.record("", "subdomain", source=found[name], host=name)
        ctx.observe(
            "subdomains",
            [{"subdomain": name, "seen in": found[name]} for name in subdomains],
        )
        if not subdomains:
            return []
        why = (
            f"{len(subdomains)} subdomain(s) of {apex} are revealed by public records and the "
            f"target's own responses: {', '.join(subdomains)}."
        )
        return [
            self.finding(
                title=f"{len(subdomains)} subdomain(s) discovered passively",
                url=target.url,
                description=(
                    "Recon result. Each subdomain is additional attack surface, and names such "
                    "as staging, dev or legacy often point at less protected systems. These "
                    "hosts were not contacted: they are outside the scope of this scan unless "
                    "named explicitly."
                ),
                why=why,
                evidence=evidence,
                remediation=(
                    "Confirm every listed host is still needed and maintained. Remove DNS "
                    "records for decommissioned services, and add the hosts you are authorized "
                    "to test to the scope file to scan them."
                ),
                severity=Severity.INFO,
            )
        ]
