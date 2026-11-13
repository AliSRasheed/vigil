"""Server, version and banner information disclosure.

Reads the headers of the target page, then requests one path that cannot exist
to see what the error page gives away.
"""

from __future__ import annotations

import contextlib
import re
import secrets

from vigil.checks.base import Check
from vigil.engine import ScanContext
from vigil.http import RequestFailed, Response, http_evidence
from vigil.models import Evidence, Finding, Severity, Target
from vigil.scope import OutOfScopeError

VERSIONS = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 3.7
STACK_TRACE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3

_VERSION = re.compile(r"\d+\.\d+")
# Headers whose only purpose is to announce the software in use.
_ANNOUNCING_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
_SERVER_SIGNATURE = re.compile(
    r"<address>\s*([^<]*\d+\.\d+[^<]*)</address>|"
    r"(Apache Tomcat/\d[\d.]+|nginx/\d[\d.]+|Microsoft-IIS/\d[\d.]+|Jetty\(?[\d.]+)",
    re.I,
)
_ERROR_DETAILS = [
    (re.compile(r"Traceback \(most recent call last\)"), "a Python traceback"),
    (re.compile(r"^\s*at [\w.$<>]+\([\w$]+\.java:\d+\)", re.M), "a Java stack trace"),
    (re.compile(r"(Fatal error|Warning|Notice)</b>:.{0,200} on line <b>\d+", re.S), "a PHP error"),
    (re.compile(r"(Fatal error|Parse error): .{0,200} in /[\w/.\-]+\.php", re.S), "a PHP error"),
    (re.compile(r"System\.\w+(\.\w+)*Exception: "), "a .NET exception"),
    (re.compile(r"Server Error in '.*' Application"), "an ASP.NET error page"),
    (re.compile(r"You're seeing this error because you have <code>DEBUG = True"), "Django debug"),
    (re.compile(r"Werkzeug Debugger|werkzeug\.debug"), "the Werkzeug debugger"),
    (re.compile(r"SQLSTATE\[\w+\]|ORA-\d{5}|You have an error in your SQL syntax"), "a SQL error"),
    (
        re.compile(r"Whoops, looks like something went wrong.*Stack trace", re.S),
        "a framework trace",
    ),
]


def disclosing_headers(response: Response) -> list[str]:
    """Header lines that reveal product names and versions."""
    found = []
    server = response.headers.get("server")
    if server and _VERSION.search(server):
        found.append(f"Server: {server}")
    for name in _ANNOUNCING_HEADERS:
        value = response.headers.get(name)
        if value:
            found.append(f"{name.title()}: {value}")
    return found


def error_detail(text: str) -> tuple[str, str] | None:
    """(what was found, the lines that show it) for a verbose error page, or None."""
    for pattern, label in _ERROR_DETAILS:
        match = pattern.search(text)
        if match:
            start = text.rfind("\n", 0, match.start()) + 1
            excerpt = "\n".join(text[start:].splitlines()[:5])
            return label, excerpt
    return None


class InfoDisclosure(Check):
    id = "config.info_disclosure"
    title = "Server and version disclosure"
    severity = Severity.MEDIUM
    cwe = "CWE-200"
    owasp = "A01:2025 Broken Access Control"
    category = "config"
    description = (
        "Software versions in response headers and error pages; stack traces and debug "
        "output on errors."
    )

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        home = await ctx.baseline()

        error_page: Response | None = None
        with contextlib.suppress(RequestFailed, OutOfScopeError):
            error_page = await ctx.http.get(target.join(f"vigil-{secrets.token_hex(6)}"))

        # 1. product names and versions
        evidence: list[Evidence] = []
        disclosed = disclosing_headers(home)
        if disclosed:
            evidence.append(
                http_evidence(
                    home, "Response headers name the software and version in use", excerpt=""
                )
            )
        signature = _SERVER_SIGNATURE.search(error_page.text) if error_page else None
        if signature and error_page:
            banner = (signature.group(1) or signature.group(2)).strip()
            disclosed.append(f"error page footer: {banner}")
            evidence.append(
                http_evidence(
                    error_page,
                    "The error page for a non-existent path prints the server version",
                    excerpt=signature.group(0),
                )
            )
        if disclosed:
            why = "The server discloses: " + "; ".join(disclosed) + "."
            findings.append(
                self.finding(
                    title="Software versions disclosed by the server",
                    url=home.url,
                    description=(
                        "Exact product and version numbers let an attacker look up known "
                        "vulnerabilities for this stack without any further probing."
                    ),
                    why=why,
                    evidence=evidence,
                    remediation=(
                        "Remove or genericise these banners (Apache: ServerTokens Prod and "
                        "ServerSignature Off; nginx: server_tokens off; PHP: expose_php = Off; "
                        'ASP.NET: enableVersionHeader="false"; Express: app.disable'
                        "('x-powered-by'))."
                    ),
                    cvss_vector=VERSIONS,
                )
            )

        # 2. stack traces and debug output
        detail = error_detail(error_page.text) if error_page else None
        if detail and error_page:
            label, excerpt = detail
            why = (
                f"Requesting a path that does not exist returned {label}, exposing internal "
                "file paths and code structure."
            )
            findings.append(
                self.finding(
                    title="Verbose error page exposes internal details",
                    url=error_page.url,
                    description=(
                        "Detailed error output is meant for developers. Shown to visitors it "
                        "reveals file paths, library names and logic that help target an attack."
                    ),
                    why=why,
                    evidence=[http_evidence(error_page, why, excerpt=excerpt)],
                    remediation=(
                        "Disable debug mode in production and return a generic error page; log "
                        "the details server-side instead."
                    ),
                    cvss_vector=STACK_TRACE,
                    cwe="CWE-209",
                )
            )
        return findings
