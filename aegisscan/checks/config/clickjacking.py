"""Clickjacking exposure: can another site put this page in a frame?"""

from __future__ import annotations

from aegisscan.checks.base import Check
from aegisscan.engine import ScanContext
from aegisscan.http import Response, http_evidence, parse_csp
from aegisscan.models import Finding, Severity, Target

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 4.3
_PERMISSIVE_ANCESTORS = {"*", "http:", "https:"}


def framing_weakness(response: Response) -> str | None:
    """Why the response can be framed by another site, or None when it is protected."""
    for policy in response.headers.get_list("content-security-policy"):
        ancestors = parse_csp(policy).get("frame-ancestors")
        if ancestors is None:
            continue
        loose = sorted(_PERMISSIVE_ANCESTORS.intersection(ancestors))
        if not loose:
            return None  # frame-ancestors takes precedence over X-Frame-Options
        return (
            f"Content-Security-Policy frame-ancestors allows any site ({', '.join(loose)}) to "
            "frame the page."
        )
    xfo = response.headers.get("x-frame-options")
    if xfo is None:
        return (
            "The page sends neither X-Frame-Options nor a Content-Security-Policy "
            "frame-ancestors directive, so any website can display it inside a frame."
        )
    if xfo.strip().lower() in ("deny", "sameorigin"):
        return None
    return (
        f"X-Frame-Options is '{xfo}', which browsers do not recognise (only DENY and SAMEORIGIN "
        "are honoured), and there is no frame-ancestors directive."
    )


class Clickjacking(Check):
    id = "config.clickjacking"
    title = "Clickjacking exposure"
    severity = Severity.MEDIUM
    cwe = "CWE-1021"
    owasp = "A06:2025 Insecure Design"
    category = "config"
    description = "Missing or ineffective X-Frame-Options / CSP frame-ancestors on HTML pages."

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        response = await ctx.baseline()
        if not response.is_html or response.status >= 400:
            return []  # only a rendered HTML page can be used for clickjacking
        why = framing_weakness(response)
        if why is None:
            return []
        return [
            self.finding(
                title="Page can be framed by other sites (clickjacking)",
                url=response.url,
                description=(
                    "A page that can be framed can be overlaid invisibly on an attacker's site, "
                    "tricking a logged-in visitor into clicking buttons they cannot see."
                ),
                why=why,
                evidence=[http_evidence(response, why, excerpt="")],
                remediation=(
                    "Send Content-Security-Policy: frame-ancestors 'none' (or 'self'), and "
                    "X-Frame-Options: DENY (or SAMEORIGIN) for older browsers."
                ),
                cvss_vector=VECTOR,
            )
        ]
