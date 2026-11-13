"""Data models shared by the engine, the checks and the reports."""

from __future__ import annotations

import datetime as dt
import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, Field

from vigil import __version__

_DEFAULT_PORTS = {"http": 80, "https": 443}


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


def normalize_host(host: str) -> str:
    """Canonical form of a hostname or IP literal: lower case, no brackets, no root dot."""
    host = host.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.rstrip(".")


def host_of(url: str) -> str:
    """Normalized host of an absolute URL ('' when it has none)."""
    try:
        return normalize_host(urlsplit(url).hostname or "")
    except ValueError:
        return ""


class Target(BaseModel):
    """The single URL the operator named on the command line."""

    url: str
    scheme: Literal["http", "https"]
    host: str
    port: int
    path: str

    @classmethod
    def parse(cls, raw: str) -> Target:
        raw = raw.strip()
        try:
            parts = urlsplit(raw)
            port = parts.port
        except ValueError as exc:
            raise ValueError(f"invalid target URL {raw!r}: {exc}") from exc
        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            raise ValueError(
                f"invalid target URL {raw!r}: give a full http:// or https:// URL, "
                "for example https://app.example.com"
            )
        host = normalize_host(parts.hostname or "")
        if not host:
            raise ValueError(f"invalid target URL {raw!r}: no host")
        port = port or _DEFAULT_PORTS[scheme]
        path = parts.path or "/"
        netloc = f"[{host}]" if ":" in host else host
        if port != _DEFAULT_PORTS[scheme]:
            netloc = f"{netloc}:{port}"
        url = f"{scheme}://{netloc}{path}"
        if parts.query:
            url = f"{url}?{parts.query}"
        return cls(url=url, scheme=scheme, host=host, port=port, path=path)

    @property
    def origin(self) -> str:
        netloc = f"[{self.host}]" if ":" in self.host else self.host
        if self.port != _DEFAULT_PORTS[self.scheme]:
            netloc = f"{netloc}:{self.port}"
        return f"{self.scheme}://{netloc}"

    @property
    def base_url(self) -> str:
        """Directory of the target URL, always ending in '/'. Probes are relative to it."""
        directory = self.path.rsplit("/", 1)[0] + "/"
        return f"{self.origin}{directory}"

    def join(self, relative: str) -> str:
        return urljoin(self.base_url, relative)


class Evidence(BaseModel):
    """Proof for a finding: what was sent, what came back, and what it shows."""

    kind: Literal["http", "dns", "tls"] = "http"
    request: str
    response: str
    note: str = ""


class Finding(BaseModel):
    id: str
    check_id: str
    title: str
    severity: Severity
    category: str
    url: str
    description: str
    why: str
    evidence: list[Evidence] = Field(min_length=1)
    remediation: str
    cwe: str | None = None
    owasp: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    references: list[str] = Field(default_factory=list)

    @staticmethod
    def make_id(check_id: str, url: str, title: str) -> str:
        digest = hashlib.sha256(f"{check_id}|{url}|{title}".encode()).hexdigest()[:10]
        return f"{check_id}-{digest}"


class AuthorizationRecord(BaseModel):
    """Which authorization assertion allowed the scan, and when it was made."""

    method: Literal["flag", "env", "scope-file", "loopback"]
    detail: str
    timestamp: datetime
    asserted_by: str | None = None
    basis: str | None = None
    date: dt.date | None = None

    def summary(self) -> str:
        text = self.detail
        if self.method == "scope-file":
            text += f" (asserted by {self.asserted_by} on {self.date}, basis: {self.basis})"
        return text


class OutOfScopeRecord(BaseModel):
    """A host or URL the scan came across but did not contact."""

    host: str
    url: str
    reason: Literal["link", "redirect", "subdomain", "blocked", "excluded-path"]
    source: str = ""


class CheckInfo(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    cwe: str
    owasp: str
    safe: bool
    description: str = ""


class CheckRun(BaseModel):
    check: CheckInfo
    status: Literal["ran", "skipped", "error"]
    detail: str = ""
    findings: int = 0
    duration_ms: int = 0


class ScanResult(BaseModel):
    tool: str = "Vigil"
    version: str = __version__
    target: Target
    scope_hosts: list[str]
    include_subdomains: bool = False
    exclude_paths: list[str] = Field(default_factory=list)
    authorization: AuthorizationRecord
    started_at: datetime
    finished_at: datetime
    checks: list[CheckRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    observations: dict[str, Any] = Field(default_factory=dict)
    out_of_scope: list[OutOfScopeRecord] = Field(default_factory=list)
    requests_sent: int = 0
    dns_queries: int = 0

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in reversed(Severity)}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def duration_seconds(self) -> float:
        return round((self.finished_at - self.started_at).total_seconds(), 2)
