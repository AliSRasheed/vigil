"""Cookie flags: HttpOnly, Secure, SameSite."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegisscan import cvss
from aegisscan.checks.base import Check
from aegisscan.engine import ScanContext
from aegisscan.http import http_evidence
from aegisscan.models import Finding, Severity, Target

SESSION_NO_HTTPONLY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 4.3
SESSION_NO_SECURE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 5.9
LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1

_SESSION_NAME = re.compile(r"sess|sid\b|sid$|auth|token|jwt|login|remember|identity", re.I)
_SCRIPT_READABLE = re.compile(r"csrf|xsrf", re.I)  # read by page script on purpose


@dataclass
class Cookie:
    name: str
    attributes: dict[str, str] = field(default_factory=dict)

    @property
    def is_session(self) -> bool:
        return bool(_SESSION_NAME.search(self.name)) and not _SCRIPT_READABLE.search(self.name)


@dataclass
class CookieIssue:
    flag: str
    why: str
    vector: str
    cwe: str


def parse_set_cookie(value: str) -> Cookie | None:
    pair, _, rest = value.partition(";")
    name, eq, _ = pair.partition("=")
    if not eq or not name.strip():
        return None
    attributes: dict[str, str] = {}
    for part in rest.split(";"):
        key, _, val = part.strip().partition("=")
        if key:
            attributes[key.lower()] = val.strip()
    return Cookie(name=name.strip(), attributes=attributes)


def cookie_issues(cookie: Cookie, *, https: bool) -> list[CookieIssue]:
    issues: list[CookieIssue] = []
    attributes = cookie.attributes
    kind = "session cookie" if cookie.is_session else "cookie"

    if cookie.is_session and "httponly" not in attributes:
        issues.append(
            CookieIssue(
                "HttpOnly",
                f"The {kind} can be read by JavaScript, so any cross-site scripting flaw can "
                "steal it.",
                SESSION_NO_HTTPONLY,
                "CWE-1004",
            )
        )
    # Browsers refuse Secure cookies from plain-HTTP origins, so only judged over HTTPS.
    if https and "secure" not in attributes:
        issues.append(
            CookieIssue(
                "Secure",
                f"The {kind} will also be sent over unencrypted HTTP, where it can be intercepted.",
                SESSION_NO_SECURE if cookie.is_session else LOW,
                "CWE-614",
            )
        )
    samesite = attributes.get("samesite")
    if samesite is None:
        if cookie.is_session:
            issues.append(
                CookieIssue(
                    "SameSite",
                    "No SameSite attribute is set; protection against cross-site request "
                    "forgery then depends on each browser's default.",
                    LOW,
                    "CWE-1275",
                )
            )
    elif samesite.lower() == "none":
        if "secure" not in attributes:
            issues.append(
                CookieIssue(
                    "SameSite",
                    "SameSite=None is set without Secure; browsers reject this combination and "
                    "the intent (cross-site use) is unprotected.",
                    LOW,
                    "CWE-1275",
                )
            )
        elif cookie.is_session:
            issues.append(
                CookieIssue(
                    "SameSite",
                    "SameSite=None sends the session cookie on every cross-site request, "
                    "removing the browser's cross-site request forgery protection.",
                    LOW,
                    "CWE-1275",
                )
            )
    return issues


class CookieFlags(Check):
    id = "config.cookies"
    title = "Cookie flags"
    severity = Severity.MEDIUM
    cwe = "CWE-1004"
    owasp = "A05:2021 Security Misconfiguration"
    category = "config"
    description = "HttpOnly, Secure and SameSite on the cookies the target sets."

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        response = await ctx.baseline()
        https = response.url.startswith("https://")
        findings: list[Finding] = []
        for header in response.headers.get_list("set-cookie"):
            cookie = parse_set_cookie(header)
            if cookie is None:
                continue
            issues = cookie_issues(cookie, https=https)
            if not issues:
                continue
            worst = max(issues, key=lambda issue: cvss.base_score(issue.vector))
            flags = ", ".join(dict.fromkeys(issue.flag for issue in issues))
            why = " ".join(issue.why for issue in issues)
            kind = "Session cookie" if cookie.is_session else "Cookie"
            findings.append(
                self.finding(
                    title=f"{kind} '{cookie.name}' has weak flags: {flags}",
                    url=response.url,
                    description=(
                        "Cookie attributes tell the browser when a cookie may be sent and "
                        "whether page scripts may read it. The cookie value is redacted in the "
                        "evidence below."
                    ),
                    why=why,
                    evidence=[http_evidence(response, why, excerpt="")],
                    remediation=(
                        f"Set the cookie as: {cookie.name}=...; Path=/; Secure; HttpOnly; "
                        "SameSite=Lax (use SameSite=Strict where cross-site navigation with the "
                        "cookie is not needed)."
                    ),
                    cvss_vector=worst.vector,
                    cwe=worst.cwe,
                )
            )
        return findings
