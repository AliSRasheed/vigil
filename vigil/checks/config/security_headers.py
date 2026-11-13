"""Security response headers: presence and quality, with an overall grade.

X-Frame-Options / frame-ancestors is left to the clickjacking check so the same
gap is not reported twice.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from vigil.checks.base import Check
from vigil.engine import ScanContext
from vigil.http import http_evidence, parse_csp
from vigil.models import Finding, Severity, Target

LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1
HSTS_MISSING = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"  # 4.2
SIX_MONTHS = 15552000
_LOOSE_SOURCES = {"*", "http:", "https:", "data:"}


@dataclass
class HeaderIssue:
    title: str
    description: str
    why: str
    remediation: str
    penalty: int
    vector: str | None = LOW  # None means informational
    cwe: str = "CWE-693"


def csp_weaknesses(policy: dict[str, list[str]]) -> list[str]:
    """Reasons a Content-Security-Policy gives little protection against script injection."""
    problems: list[str] = []
    scripts = policy.get("script-src", policy.get("default-src"))
    if scripts is None:
        problems.append("no script-src or default-src directive, so scripts are unrestricted")
    else:
        has_nonce_or_hash = any(
            source.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for source in scripts
        )
        if "'unsafe-inline'" in scripts and not has_nonce_or_hash:
            problems.append("script sources allow 'unsafe-inline', which permits injected scripts")
        if "'unsafe-eval'" in scripts:
            problems.append("script sources allow 'unsafe-eval'")
        loose = sorted(_LOOSE_SOURCES.intersection(scripts))
        if loose:
            problems.append(f"script sources allow any origin via {', '.join(loose)}")
    if "object-src" not in policy and "default-src" not in policy:
        problems.append("no object-src (or default-src) directive to block plugin content")
    if "base-uri" not in policy:
        problems.append(
            "no base-uri directive, so an injected <base> tag can redirect script loads"
        )
    return problems


def analyse(headers: httpx.Headers, *, https: bool) -> list[HeaderIssue]:
    issues: list[HeaderIssue] = []

    # Content-Security-Policy
    policies = headers.get_list("content-security-policy")
    csp_description = (
        "Content-Security-Policy restricts where scripts, styles and other resources may load "
        "from. It is the main browser-side mitigation for cross-site scripting."
    )
    if not policies:
        report_only = "content-security-policy-report-only" in headers
        issues.append(
            HeaderIssue(
                title="Content-Security-Policy header is missing",
                description=csp_description,
                why=(
                    "Only Content-Security-Policy-Report-Only is sent, which reports violations "
                    "but does not block anything."
                    if report_only
                    else "The response has no Content-Security-Policy header."
                ),
                remediation=(
                    "Send a policy that restricts script sources, for example: "
                    "Content-Security-Policy: default-src 'self'; object-src 'none'; "
                    "base-uri 'self'; frame-ancestors 'none'"
                ),
                penalty=30,
            )
        )
    else:
        problems = csp_weaknesses(parse_csp(policies[0]))
        if problems:
            issues.append(
                HeaderIssue(
                    title="Content-Security-Policy is weak",
                    description=csp_description,
                    why="The policy is present but: " + "; ".join(problems) + ".",
                    remediation=(
                        "Remove 'unsafe-inline' and 'unsafe-eval' (use nonces or hashes), avoid "
                        "wildcard and scheme-only sources, and add object-src 'none' and "
                        "base-uri 'self'."
                    ),
                    penalty=15,
                )
            )

    # Strict-Transport-Security: browsers ignore it over plain HTTP, so only judged on HTTPS
    if https:
        hsts = headers.get("strict-transport-security")
        hsts_description = (
            "Strict-Transport-Security tells browsers to use HTTPS only, which defeats "
            "SSL-stripping attacks on later visits."
        )
        match = re.search(r"max-age\s*=\s*\"?(\d+)", hsts or "", re.I)
        max_age = int(match.group(1)) if match else None
        if hsts is None or not max_age:
            issues.append(
                HeaderIssue(
                    title="Strict-Transport-Security header is missing",
                    description=hsts_description,
                    why=(
                        "The HTTPS response has no Strict-Transport-Security header."
                        if hsts is None
                        else f"Strict-Transport-Security is '{hsts}', which disables the policy."
                    ),
                    remediation="Send Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains",
                    penalty=25,
                    vector=HSTS_MISSING,
                    cwe="CWE-319",
                )
            )
        elif max_age < SIX_MONTHS:
            issues.append(
                HeaderIssue(
                    title="Strict-Transport-Security max-age is too short",
                    description=hsts_description,
                    why=f"max-age is {max_age} seconds; at least {SIX_MONTHS} (six months) is "
                    "recommended.",
                    remediation="Raise max-age to 31536000 (one year).",
                    penalty=10,
                    cwe="CWE-319",
                )
            )

    # X-Content-Type-Options
    nosniff = headers.get("x-content-type-options")
    if (nosniff or "").strip().lower() != "nosniff":
        issues.append(
            HeaderIssue(
                title="X-Content-Type-Options: nosniff is missing",
                description="Without nosniff, browsers may guess a response's type and run "
                "uploaded or user-controlled content as script.",
                why=(
                    "The response has no X-Content-Type-Options header."
                    if nosniff is None
                    else f"X-Content-Type-Options is '{nosniff}', not 'nosniff'."
                ),
                remediation="Send X-Content-Type-Options: nosniff on every response.",
                penalty=15,
            )
        )

    # Referrer-Policy
    referrer = headers.get("referrer-policy")
    referrer_description = (
        "Referrer-Policy controls how much of the page URL is sent to other sites in the "
        "Referer header."
    )
    if referrer is None:
        issues.append(
            HeaderIssue(
                title="Referrer-Policy header is missing",
                description=referrer_description,
                why="The response has no Referrer-Policy header, so the browser default applies.",
                remediation="Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
                penalty=5,
                vector=None,
            )
        )
    else:
        effective = [value.strip().lower() for value in referrer.split(",") if value.strip()]
        if effective and effective[-1] in ("unsafe-url", "no-referrer-when-downgrade"):
            issues.append(
                HeaderIssue(
                    title="Referrer-Policy leaks full URLs to other sites",
                    description=referrer_description,
                    why=f"Referrer-Policy is '{effective[-1]}', which sends the full URL, "
                    "including path and query string, to other origins.",
                    remediation="Use strict-origin-when-cross-origin or no-referrer.",
                    penalty=10,
                    cwe="CWE-200",
                )
            )

    # Permissions-Policy
    if "permissions-policy" not in headers and "feature-policy" not in headers:
        issues.append(
            HeaderIssue(
                title="Permissions-Policy header is missing",
                description="Permissions-Policy switches off browser features (camera, "
                "microphone, geolocation) the site does not use, limiting what injected or "
                "embedded content can do.",
                why="The response has no Permissions-Policy header.",
                remediation="Send Permissions-Policy: geolocation=(), camera=(), microphone=()",
                penalty=5,
                vector=None,
            )
        )
    return issues


def grade(issues: list[HeaderIssue]) -> tuple[str, int]:
    score = max(0, 100 - sum(issue.penalty for issue in issues))
    for letter, floor in (("A", 90), ("B", 75), ("C", 60), ("D", 40)):
        if score >= floor:
            return letter, score
    return "F", score


class SecurityHeaders(Check):
    id = "config.security_headers"
    title = "Security headers"
    severity = Severity.MEDIUM
    cwe = "CWE-693"
    owasp = "A06:2025 Insecure Design"
    category = "config"
    description = (
        "Presence and quality of CSP, HSTS, X-Content-Type-Options, Referrer-Policy and "
        "Permissions-Policy, with an overall grade."
    )

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        response = await ctx.baseline()
        issues = analyse(response.headers, https=response.url.startswith("https://"))
        letter, score = grade(issues)
        ctx.observe("security_headers", {"grade": letter, "score": f"{score}/100"})
        return [
            self.finding(
                title=issue.title,
                url=response.url,
                description=f"{issue.description} Header grade for this response: {letter} "
                f"({score}/100).",
                why=issue.why,
                evidence=[http_evidence(response, issue.why, excerpt="")],
                remediation=issue.remediation,
                cvss_vector=issue.vector,
                cwe=issue.cwe,
            )
            for issue in issues
        ]
