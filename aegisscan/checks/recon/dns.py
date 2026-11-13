"""DNS records for the target host and its zone, plus CAA and DNSSEC posture."""

from __future__ import annotations

from aegisscan.checks.base import Check, CheckSkipped
from aegisscan.engine import ScanContext
from aegisscan.models import Finding, Severity, Target
from aegisscan.resolver import is_ip_literal, zone_apex
from aegisscan.scope import is_loopback

NO_CAA = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 3.1
HOST_TYPES = ("A", "AAAA", "CNAME")
ZONE_TYPES = ("NS", "MX", "TXT", "SOA", "CAA", "DNSKEY")


def require_dns_name(target: Target) -> None:
    """DNS-based checks make no sense for an IP address or localhost."""
    if is_ip_literal(target.host) or is_loopback(target.host) or "." not in target.host:
        raise CheckSkipped("target is an IP address or local name; there is no DNS zone to inspect")


class DnsRecords(Check):
    id = "recon.dns"
    title = "DNS records and zone posture"
    severity = Severity.LOW
    cwe = "CWE-693"
    owasp = "A06:2025 Insecure Design"
    category = "recon"
    description = (
        "A, AAAA, CNAME, NS, MX, TXT, SOA records via the operator's resolver; flags missing "
        "CAA and unsigned (no DNSSEC) zones."
    )

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        require_dns_name(target)
        host = target.host
        host_answers = {rdtype: await ctx.dns.query(host, rdtype) for rdtype in HOST_TYPES}
        if all(answer.failed for answer in host_answers.values()):
            raise CheckSkipped(f"DNS lookups failed: {host_answers['A'].error}")
        if not any(answer.found for answer in host_answers.values()):
            raise CheckSkipped(f"{host} has no address records in DNS")

        apex = await zone_apex(ctx.dns, host)
        zone_answers = {rdtype: await ctx.dns.query(apex, rdtype) for rdtype in ZONE_TYPES}

        records: dict[str, list[str]] = {}
        for rdtype, answer in host_answers.items():
            if answer.found:
                records[f"{host} {rdtype}"] = answer.records
        for rdtype, answer in zone_answers.items():
            if answer.found and rdtype != "DNSKEY":
                records[f"{apex} {rdtype}"] = answer.records
        ctx.observe("dns", {"zone": apex, "records": records})

        findings: list[Finding] = []

        # CAA is looked up from the host towards the zone apex (RFC 8659).
        caa_names = [host] if host == apex else [host, apex]
        caa_answers = [await ctx.dns.query(name, "CAA") for name in caa_names]
        if not any(answer.found or answer.failed for answer in caa_answers):
            why = (
                f"No CAA record exists for {' or '.join(caa_names)}, so any certificate "
                "authority may issue certificates for this domain."
            )
            findings.append(
                self.finding(
                    title="No CAA record restricts certificate issuance",
                    url=target.url,
                    description=(
                        "A CAA record names the certificate authorities allowed to issue for a "
                        "domain. Without one, a mistake or compromise at any CA can produce a "
                        "valid certificate for the site."
                    ),
                    why=why,
                    evidence=[answer.evidence(why) for answer in caa_answers],
                    remediation=(
                        f"Publish a CAA record at {apex} naming your CA, for example: "
                        f'{apex}. CAA 0 issue "letsencrypt.org"'
                    ),
                    cvss_vector=NO_CAA,
                )
            )

        dnskey = zone_answers["DNSKEY"]
        if not dnskey.found and not dnskey.failed:
            why = f"The zone {apex} publishes no DNSKEY record, so it is not signed with DNSSEC."
            findings.append(
                self.finding(
                    title="Zone is not signed with DNSSEC",
                    url=target.url,
                    description=(
                        "DNSSEC lets resolvers verify that DNS answers are authentic. Without "
                        "it, answers for this domain can be forged by an attacker positioned "
                        "to tamper with DNS. Informational: many zones are unsigned."
                    ),
                    why=why,
                    evidence=[dnskey.evidence(why)],
                    remediation="Enable DNSSEC signing at the DNS provider and publish the DS "
                    "record at the registrar.",
                    severity=Severity.INFO,
                    cwe="CWE-350",
                )
            )
        return findings
