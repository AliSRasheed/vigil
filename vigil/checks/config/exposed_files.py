"""Exposed sensitive files: version control data, environment files, backups, config.

Each probe is a single GET for a well-known path. A hit is only reported when the
*content* matches what that file type looks like, so a site that answers every
path with HTTP 200 (a "soft 404") does not produce false positives.

Non-destructive by design: response bodies are capped by the HTTP client, so
backups are identified from their first bytes and never downloaded, and secret
values are masked before anything is written to the report.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from vigil.checks.base import Check
from vigil.engine import ScanContext
from vigil.http import RequestFailed, Response, http_evidence, redact_values
from vigil.models import Evidence, Finding, Severity, Target
from vigil.scope import OutOfScopeError

SECRETS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
INTERNALS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3


def _is_html(response: Response) -> bool:
    head = response.body[:512].lower()
    return response.is_html or b"<html" in head or b"<!doctype html" in head


def _plain(pattern: str, flags: int = 0) -> Callable[[Response], bool]:
    """Non-HTML text that matches ``pattern``."""
    compiled = re.compile(pattern, flags | re.M)

    def validate(response: Response) -> bool:
        return not _is_html(response) and bool(compiled.search(response.text))

    return validate


def _html(pattern: str) -> Callable[[Response], bool]:
    compiled = re.compile(pattern, re.I | re.S)
    return lambda response: bool(compiled.search(response.text))


def _magic(*prefixes: bytes) -> Callable[[Response], bool]:
    return lambda response: response.body.startswith(prefixes)


# --- how much of a hit goes into the report --------------------------------


def _masked(response: Response) -> str:
    lines = response.text.strip().splitlines()[:6]
    return redact_values("\n".join(lines)) + "\n[values masked by Vigil]"


def _git(response: Response) -> str:
    text = response.text.strip()
    if re.match(r"(ref: refs/|[0-9a-f]{40}$)", text):
        return text.splitlines()[0]  # a branch name or commit id, not a secret
    return _masked(response)  # .git/config may embed credentials in a remote URL


def _first_line(response: Response) -> str:
    lines = response.text.strip().splitlines()
    return f"{lines[0][:120]}\n[{max(len(lines) - 1, 0)} more line(s) withheld by Vigil]"


def _binary(response: Response) -> str:
    size = response.headers.get("content-length", "unknown")
    return (
        f"<binary file, first bytes {response.body[:8]!r}, Content-Length: {size}; not downloaded>"
    )


def _title_only(response: Response) -> str:
    match = re.search(r"<title>(.*?)</title>", response.text, re.I | re.S)
    heading = re.search(r"<h1[^>]*>(.*?)</h1>", response.text, re.I | re.S)
    parts = [m.group(0).strip() for m in (match, heading) if m]
    return "\n".join(parts) or response.text[:120]


@dataclass(frozen=True)
class Kind:
    title: str
    vector: str
    description: str
    remediation: str
    excerpt: Callable[[Response], str]
    cwe: str = "CWE-538"


@dataclass(frozen=True)
class Probe:
    path: str
    kind: str
    matches: Callable[[Response], bool]


_BLOCK = "Block access to it in the web server configuration and remove it from the web root."

KINDS: dict[str, Kind] = {
    "git": Kind(
        "Git repository exposed",
        SECRETS,
        "The .git directory is served. The full source code and its history, often including "
        "credentials, can be reconstructed from it.",
        "Remove .git from the web root or deny access to it (for example, a rule returning 404 "
        "for /.git). Rotate any secret that was ever committed.",
        _git,
        "CWE-527",
    ),
    "svn": Kind(
        "Subversion metadata exposed",
        SECRETS,
        "The .svn directory is served, which allows the source code to be recovered.",
        f"{_BLOCK} Deploy from an export, not a working copy.",
        _binary,
        "CWE-527",
    ),
    "env": Kind(
        "Environment file exposed",
        SECRETS,
        "An environment file is served. These hold database passwords, API keys and signing "
        "secrets.",
        f"{_BLOCK} Rotate every secret in the file: it must be assumed compromised.",
        _masked,
    ),
    "credentials": Kind(
        "Credential file exposed",
        SECRETS,
        "A file holding credentials or private keys is served.",
        f"{_BLOCK} Rotate the credentials: they must be assumed compromised.",
        _masked,
    ),
    "archive": Kind(
        "Backup archive exposed",
        SECRETS,
        "A backup archive is downloadable. Site backups normally contain source code, "
        "configuration and data.",
        "Remove backups from the web root and store them outside any served directory.",
        _binary,
        "CWE-530",
    ),
    "sql": Kind(
        "Database dump exposed",
        SECRETS,
        "A SQL dump is downloadable, exposing the database contents.",
        "Remove the dump from the web root. Treat the data and any stored credentials as exposed.",
        _first_line,
        "CWE-530",
    ),
    "source-backup": Kind(
        "Backup copy of a source file exposed",
        SECRETS,
        "A backup or editor copy of a server-side script is served as plain text instead of "
        "being executed, revealing its source and any embedded credentials.",
        "Delete backup and editor files (.bak, ~, .swp, .old) from the web root and deny those "
        "extensions in the web server.",
        _first_line,
        "CWE-530",
    ),
    "phpinfo": Kind(
        "phpinfo() page exposed",
        INTERNALS,
        "A phpinfo() page is public. It lists the PHP version, loaded modules, file paths and "
        "environment variables.",
        "Delete the page.",
        _title_only,
        "CWE-200",
    ),
    "server-status": Kind(
        "Apache server-status exposed",
        INTERNALS,
        "The Apache mod_status page is public. It shows current requests, client addresses and "
        "internal URLs.",
        "Restrict /server-status to localhost (Require local) or disable mod_status.",
        _title_only,
        "CWE-200",
    ),
    "config": Kind(
        "Configuration file exposed",
        INTERNALS,
        "A deployment or server configuration file is served, revealing internal structure and "
        "sometimes credentials.",
        _BLOCK,
        _masked,
    ),
    "ds-store": Kind(
        "macOS .DS_Store file exposed",
        INTERNALS,
        "A .DS_Store file is served. It lists the names of the files and folders in the "
        "directory, including ones that are not linked.",
        _BLOCK,
        _binary,
    ),
}

_ARCHIVE = _magic(b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!")
_SQL = _plain(r"^(-- (MySQL|PostgreSQL|MariaDB) (database )?dump|CREATE TABLE|INSERT INTO)", re.I)
_PHP = _plain(r"<\?php")

PROBES: tuple[Probe, ...] = (
    Probe(".git/HEAD", "git", _plain(r"\A(ref: refs/|[0-9a-f]{40}\s*\Z)")),
    Probe(".git/config", "git", _plain(r"^\[core\]")),
    Probe(".svn/wc.db", "svn", _magic(b"SQLite format 3")),
    Probe(".env", "env", _plain(r"^[A-Z][A-Z0-9_]{2,}=")),
    Probe(".env.local", "env", _plain(r"^[A-Z][A-Z0-9_]{2,}=")),
    Probe(".env.production", "env", _plain(r"^[A-Z][A-Z0-9_]{2,}=")),
    Probe(".htpasswd", "credentials", _plain(r"^[^:\s<>]+:(\$|\{SHA\})?[A-Za-z0-9./$+=]{10,}$")),
    Probe(".aws/credentials", "credentials", _plain(r"^aws_access_key_id\s*=", re.I)),
    Probe("id_rsa", "credentials", _plain(r"\A-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    Probe("backup.zip", "archive", _ARCHIVE),
    Probe("backup.tar.gz", "archive", _ARCHIVE),
    Probe("site.zip", "archive", _ARCHIVE),
    Probe("www.zip", "archive", _ARCHIVE),
    Probe("backup.sql", "sql", _SQL),
    Probe("dump.sql", "sql", _SQL),
    Probe("database.sql", "sql", _SQL),
    Probe("db.sql", "sql", _SQL),
    Probe("config.php.bak", "source-backup", _PHP),
    Probe("config.php~", "source-backup", _PHP),
    Probe("wp-config.php.bak", "source-backup", _PHP),
    Probe("wp-config.php~", "source-backup", _PHP),
    Probe("index.php.bak", "source-backup", _PHP),
    Probe("phpinfo.php", "phpinfo", _html(r"phpinfo\(\).*PHP Version")),
    Probe("info.php", "phpinfo", _html(r"phpinfo\(\).*PHP Version")),
    Probe("server-status", "server-status", _html(r"Apache Server Status for")),
    Probe("web.config", "config", _plain(r"<configuration[\s>]")),
    Probe("docker-compose.yml", "config", _plain(r"^services:")),
    Probe(".DS_Store", "ds-store", _magic(b"\x00\x00\x00\x01Bud1")),
)


class ExposedFiles(Check):
    id = "config.exposed_files"
    title = "Exposed sensitive files"
    severity = Severity.HIGH
    cwe = "CWE-538"
    owasp = "A01:2025 Broken Access Control"
    category = "config"
    description = (
        "Version control data, .env, credential files, backups, database dumps and config "
        "files, each confirmed by content."
    )

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        hits: dict[str, list[tuple[Probe, Response]]] = {}
        for probe in PROBES:
            try:
                response = await ctx.http.get(target.join(probe.path))
            except (RequestFailed, OutOfScopeError):
                continue  # unreachable, or excluded by the scope file
            if response.status in (200, 206) and response.body and probe.matches(response):
                hits.setdefault(probe.kind, []).append((probe, response))

        findings: list[Finding] = []
        for kind_key, matched in hits.items():
            kind = KINDS[kind_key]
            paths = ", ".join("/" + probe.path for probe, _ in matched)
            why = (
                f"{paths} returned HTTP {matched[0][1].status} and the content has the "
                f"signature of this file type, so it is the real file and not an error page."
            )
            evidence: list[Evidence] = [
                http_evidence(
                    response,
                    f"/{probe.path} is served and its content matches the expected format",
                    excerpt=kind.excerpt(response),
                )
                for probe, response in matched
            ]
            findings.append(
                self.finding(
                    title=f"{kind.title}: {paths}",
                    url=matched[0][1].url,
                    description=kind.description,
                    why=why,
                    evidence=evidence,
                    remediation=kind.remediation,
                    cvss_vector=kind.vector,
                    cwe=kind.cwe,
                )
            )
        return findings
