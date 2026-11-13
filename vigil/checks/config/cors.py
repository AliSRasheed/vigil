"""CORS misconfiguration: which origins the target lets read its responses.

Sends the target URL a few GET requests with different Origin headers and reads
the Access-Control-Allow-* response headers. Nothing else changes.
"""

from __future__ import annotations

from vigil.checks.base import Check
from vigil.engine import ScanContext
from vigil.http import Response, http_evidence
from vigil.models import Finding, Severity, Target

WITH_CREDENTIALS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"  # 7.1
WITHOUT_CREDENTIALS = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1
PROBE_DOMAIN = "vigil-cors-probe.example"  # .example is reserved: it can never be a real site


def allows(response: Response, origin: str) -> bool:
    return response.headers.get("access-control-allow-origin", "").strip() == origin


def with_credentials(response: Response) -> bool:
    return response.headers.get("access-control-allow-credentials", "").strip().lower() == "true"


class CorsMisconfiguration(Check):
    id = "config.cors"
    title = "CORS misconfiguration"
    severity = Severity.HIGH
    cwe = "CWE-942"
    owasp = "A02:2025 Security Misconfiguration"
    category = "config"
    description = (
        "Arbitrary-origin reflection, the null origin and weak origin validation, with or "
        "without credentials."
    )

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        host = target.host
        probes = [
            (
                f"https://{PROBE_DOMAIN}",
                "reflects any Origin",
                "The server copied an arbitrary, unrelated Origin into Access-Control-Allow-Origin",
            ),
            (
                "null",
                "trusts the null origin",
                "The server allows the 'null' origin, which any site can produce from a "
                "sandboxed iframe",
            ),
            (
                f"https://{host}.{PROBE_DOMAIN}",
                "validates Origin by prefix",
                f"The server accepted an attacker-registrable origin that merely starts with "
                f"'{host}'",
            ),
            (
                f"https://{PROBE_DOMAIN.split('.')[0]}-{host}",
                "validates Origin by suffix",
                f"The server accepted an attacker-registrable origin that merely ends with "
                f"'{host}'",
            ),
        ]
        for origin, label, reason in probes:
            response = await ctx.http.get(target.url, headers={"Origin": origin})
            if not allows(response, origin):
                continue
            credentials = with_credentials(response)
            if credentials:
                why = (
                    f"{reason}, and also sent Access-Control-Allow-Credentials: true. A "
                    "malicious site can therefore make requests as a logged-in visitor and "
                    "read the responses."
                )
            else:
                why = (
                    f"{reason}. Credentials are not allowed, so only content available "
                    "without a session can be read cross-origin; this still matters for "
                    "anything reachable only from an internal network."
                )
            return [
                self.finding(
                    title=f"CORS policy {label}"
                    + (" with credentials" if credentials else " (no credentials)"),
                    url=response.url,
                    description=(
                        "Cross-Origin Resource Sharing headers decide which other websites may "
                        "read this site's responses from a visitor's browser."
                    ),
                    why=why,
                    evidence=[http_evidence(response, why, excerpt="")],
                    remediation=(
                        "Compare the Origin header against an exact allow-list of trusted "
                        "origins and return Access-Control-Allow-Origin only for those. Never "
                        "reflect the request Origin, never allow 'null', and send "
                        "Access-Control-Allow-Credentials only where it is needed. Add "
                        "Vary: Origin."
                    ),
                    cvss_vector=WITH_CREDENTIALS if credentials else WITHOUT_CREDENTIALS,
                )
            ]
        return []
