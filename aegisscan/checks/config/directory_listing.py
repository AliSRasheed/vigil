"""Directory listing enabled.

Requests a short list of directories (the target's own, those referenced by the
target page, and a few common names) and looks for an auto-generated index.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from aegisscan.checks.base import Check
from aegisscan.engine import ScanContext
from aegisscan.htmlutil import extract_links
from aegisscan.http import RequestFailed, Response, http_evidence
from aegisscan.models import Finding, Severity, Target, host_of
from aegisscan.scope import OutOfScopeError

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3
COMMON_DIRECTORIES = (
    "static/", "assets/", "images/", "img/", "uploads/", "files/",
    "backup/", "backups/", "css/", "js/", "media/", "includes/",
)  # fmt: skip
MAX_DIRECTORIES = 20
MAX_EVIDENCE = 5

# Markers of a server-generated index page (Apache, nginx, Python, Tomcat, IIS, lighttpd).
_SIGNATURES = [
    re.compile(r"<title>\s*Index of /", re.I),
    re.compile(r"<h1>\s*Index of /", re.I),
    re.compile(r"<title>\s*Directory listing for /", re.I),
    re.compile(r"<h1>\s*Directory Listing For", re.I),
    re.compile(r"\[To Parent Directory\]", re.I),
]


def listing_marker(response: Response) -> str | None:
    """The line that identifies the response as a directory index, or None."""
    if response.status != 200 or not response.is_html:
        return None
    text = response.text
    for signature in _SIGNATURES:
        match = signature.search(text)
        if match:
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            return text[start : end if end != -1 else len(text)].strip()
    return None


def candidate_directories(target: Target, links: list[str], in_scope_host: str) -> list[str]:
    candidates: dict[str, None] = {target.base_url: None}
    for link in links:
        if host_of(link) != in_scope_host:
            continue
        parts = urlsplit(link)
        directory = parts.path.rsplit("/", 1)[0] + "/"
        # every ancestor directory of a referenced resource
        while directory not in ("/", ""):
            candidates.setdefault(f"{parts.scheme}://{parts.netloc}{directory}", None)
            directory = directory.rstrip("/").rsplit("/", 1)[0] + "/"
    for name in COMMON_DIRECTORIES:
        candidates.setdefault(target.join(name), None)
    return list(candidates)[:MAX_DIRECTORIES]


class DirectoryListing(Check):
    id = "config.directory_listing"
    title = "Directory listing enabled"
    severity = Severity.MEDIUM
    cwe = "CWE-548"
    owasp = "A05:2021 Security Misconfiguration"
    category = "config"
    description = "Auto-generated directory indexes on common and page-referenced directories."

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        links: list[str] = []
        try:
            home = await ctx.baseline()
            if home.is_html:
                links = extract_links(home.text, home.url)
        except RequestFailed:
            pass

        listed: list[tuple[Response, str]] = []
        for url in candidate_directories(target, links, target.host):
            try:
                response = await ctx.http.get(url)
            except (RequestFailed, OutOfScopeError):
                continue  # unreachable, or excluded by the scope file
            marker = listing_marker(response)
            if marker:
                listed.append((response, marker))
        if not listed:
            return []

        paths = [urlsplit(response.url).path for response, _ in listed]
        why = (
            "The server returned an auto-generated index of the directory contents for: "
            + ", ".join(paths)
            + "."
        )
        evidence = [
            http_evidence(
                response,
                f"Response is a generated directory index (marker: {marker})",
                excerpt=_listing_excerpt(response),
            )
            for response, marker in listed[:MAX_EVIDENCE]
        ]
        count = len(listed)
        return [
            self.finding(
                title=f"Directory listing enabled ({count} director{'y' if count == 1 else 'ies'})",
                url=listed[0][0].url,
                description=(
                    "With directory listing on, anyone can browse the files in a directory, "
                    "including ones that are not linked from the site: old versions, backups, "
                    "uploads and configuration."
                ),
                why=why,
                evidence=evidence,
                remediation=(
                    "Turn off automatic indexes (Apache: Options -Indexes; nginx: autoindex off; "
                    "IIS: disable Directory Browsing) and remove files that should not be public."
                ),
                cvss_vector=VECTOR,
            )
        ]


def _listing_excerpt(response: Response) -> str:
    """Title plus the first few entry names: enough to prove the listing, not a full copy."""
    text = response.text
    title = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
    entries = re.findall(r'<a href="([^"?][^"]*)"', text, re.I)[:6]
    lines = [f"<title>{title.group(1).strip()}</title>"] if title else []
    lines += [f"  entry: {entry}" for entry in entries]
    return "\n".join(lines)
