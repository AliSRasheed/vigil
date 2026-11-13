"""Scope and the authorization gate.

Two conditions must both hold before any request leaves the tool:

* the destination is **in scope**: a host the operator explicitly named (the
  command-line target, plus anything added by an optional scope file);
* **authorization is asserted** by flag, environment variable or scope file
  (loopback-only scopes are exempt).

`authorize()` is the only way to obtain a `Permit`, and the network layer
refuses to exist without one. There is deliberately no option that turns the
in-scope check off.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegisscan.models import (
    AuthorizationRecord,
    OutOfScopeRecord,
    Target,
    host_of,
    normalize_host,
)

audit_log = logging.getLogger("aegisscan.audit")

ENV_VAR = "AEGISSCAN_AUTHORIZED"
FLAG = "--i-have-authorization"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class ScopeError(Exception):
    """The scan may not proceed. The message says exactly what is missing."""


class AuthorizationError(ScopeError):
    """No authorization assertion was made for a non-loopback scope."""


class OutOfScopeError(ScopeError):
    """A request was about to leave for somewhere the operator did not name."""

    def __init__(self, url: str, host: str, reason: str) -> None:
        super().__init__(f"refusing to contact {url or host}: {reason}")
        self.url = url
        self.host = host
        self.reason = reason


def is_loopback(host: str) -> bool:
    return normalize_host(host) in LOOPBACK_HOSTS


# --- scope file ------------------------------------------------------------


class ScopeFileAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asserted_by: str = Field(min_length=1)
    date: dt.date
    basis: Literal["owned", "written-permission"]


class ScopeFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hosts: list[str] = Field(default_factory=list)
    include_subdomains: bool = False
    exclude_paths: list[str] = Field(default_factory=list)
    authorization: ScopeFileAuthorization | None = None


def load_scope_file(path: Path) -> ScopeFile:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScopeError(f"cannot read scope file {path}: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise ScopeError(f"scope file {path} is not valid YAML: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ScopeError(f"scope file {path} must be a YAML mapping")
    try:
        scope_file = ScopeFile.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in err['loc']) or 'file'}: {err['msg']}"
            for err in exc.errors()
        )
        raise ScopeError(f"scope file {path} is invalid: {problems}") from exc
    for host in scope_file.hosts:
        if not host.strip() or any(ch in host for ch in "/*@ ") or "://" in host:
            raise ScopeError(
                f"scope file {path}: {host!r} is not a hostname. List bare hosts such as "
                "api.example.com; use include_subdomains for subdomains."
            )
    for pattern in scope_file.exclude_paths:
        if not pattern.startswith("/"):
            raise ScopeError(
                f"scope file {path}: exclude_paths entry {pattern!r} must start with /"
            )
    return scope_file


# --- scope -----------------------------------------------------------------


@dataclass(frozen=True)
class Scope:
    """The set of hosts the operator explicitly named."""

    hosts: frozenset[str]
    include_subdomains: bool = False
    exclude_paths: tuple[str, ...] = ()

    def host_in_scope(self, host: str) -> bool:
        host = normalize_host(host)
        if not host:
            return False
        if host in self.hosts:
            return True
        if self.include_subdomains:
            return any(host.endswith("." + named) for named in self.hosts)
        return False

    def path_excluded(self, path: str) -> bool:
        path = path or "/"
        for pattern in self.exclude_paths:
            if "*" in pattern or "?" in pattern:
                if fnmatch.fnmatchcase(path, pattern):
                    return True
            elif path == pattern or path.startswith(pattern.rstrip("/") + "/"):
                return True
        return False

    def violation(self, url: str) -> str | None:
        """Why ``url`` may not be requested, or None when it is in scope."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return "not a valid URL"
        if parts.scheme.lower() not in ("http", "https"):
            return f"scheme {parts.scheme or '(none)'!r} is not http or https"
        host = normalize_host(parts.hostname or "")
        if not self.host_in_scope(host):
            return f"host {host or '(none)'!r} is not in scope (in scope: {self.describe()})"
        if self.path_excluded(parts.path):
            return f"path {parts.path!r} is excluded by the scope file"
        return None

    def url_in_scope(self, url: str) -> bool:
        return self.violation(url) is None

    def check_url(self, url: str) -> None:
        reason = self.violation(url)
        if reason is not None:
            raise OutOfScopeError(url, host_of(url), reason)

    def check_host(self, host: str) -> None:
        if not self.host_in_scope(host):
            raise OutOfScopeError(
                "", normalize_host(host), f"host is not in scope (in scope: {self.describe()})"
            )

    @property
    def loopback_only(self) -> bool:
        return not self.include_subdomains and all(is_loopback(host) for host in self.hosts)

    def describe(self) -> str:
        text = ", ".join(sorted(self.hosts))
        return f"{text} and subdomains" if self.include_subdomains else text


@dataclass
class OutOfScopeLog:
    """Hosts and URLs seen during the scan that were recorded instead of contacted."""

    records: list[OutOfScopeRecord] = field(default_factory=list)
    _seen: set[tuple[str, str, str]] = field(default_factory=set)

    def record(self, url: str, reason: str, source: str = "", host: str | None = None) -> None:
        host = normalize_host(host) if host else host_of(url)
        key = (host, url, reason)
        if key in self._seen:
            return
        self._seen.add(key)
        self.records.append(OutOfScopeRecord(host=host, url=url, reason=reason, source=source))


@dataclass(frozen=True)
class Permit:
    """Proof that the gate was passed. The network layer requires one."""

    target: Target
    scope: Scope
    authorization: AuthorizationRecord


# --- the gate --------------------------------------------------------------


def authorize(
    target_url: str,
    *,
    scope_file: Path | None = None,
    flag: bool = False,
    environ: Mapping[str, str] | None = None,
) -> Permit:
    """Build the scope and check the authorization assertion.

    Raises `ScopeError` (or its subclass `AuthorizationError`) with a message
    that says exactly what is missing. Nothing may be requested without the
    `Permit` this returns.
    """
    environ = os.environ if environ is None else environ
    try:
        target = Target.parse(target_url)
    except ValueError as exc:
        raise ScopeError(str(exc)) from exc

    loaded = load_scope_file(scope_file) if scope_file is not None else None
    hosts = {target.host}
    if loaded is not None:
        hosts.update(normalize_host(host) for host in loaded.hosts)
    scope = Scope(
        hosts=frozenset(hosts),
        include_subdomains=loaded.include_subdomains if loaded else False,
        exclude_paths=tuple(loaded.exclude_paths) if loaded else (),
    )
    if scope.path_excluded(target.path):
        raise ScopeError(
            f"target path {target.path!r} is excluded by the scope file {scope_file}; "
            "nothing to scan."
        )

    now = dt.datetime.now(dt.UTC)
    if flag:
        record = AuthorizationRecord(
            method="flag", detail=f"{FLAG} on the command line", timestamp=now
        )
    elif environ.get(ENV_VAR) == "1":
        record = AuthorizationRecord(
            method="env", detail=f"{ENV_VAR}=1 in the environment", timestamp=now
        )
    elif loaded is not None and loaded.authorization is not None:
        block = loaded.authorization
        record = AuthorizationRecord(
            method="scope-file",
            detail=f"authorization block in scope file {scope_file}",
            timestamp=now,
            asserted_by=block.asserted_by,
            basis=block.basis,
            date=block.date,
        )
    elif scope.loopback_only:
        record = AuthorizationRecord(
            method="loopback",
            detail="loopback target, no assertion required",
            timestamp=now,
        )
    else:
        raise AuthorizationError(
            f"authorization has not been asserted for {scope.describe()}.\n"
            "AegisScan only scans systems you own or have written permission to test. "
            "Assert that by any one of:\n"
            f"  * {FLAG} on the command line\n"
            f"  * {ENV_VAR}=1 in the environment\n"
            "  * an authorization: block (asserted_by, date, basis) in a scope file "
            "passed with --scope"
        )

    audit_log.info(
        "scan authorized: target=%s scope=[%s] method=%s (%s) at %s",
        target.url,
        scope.describe(),
        record.method,
        record.summary(),
        record.timestamp.isoformat(timespec="seconds"),
    )
    return Permit(target=target, scope=scope, authorization=record)
