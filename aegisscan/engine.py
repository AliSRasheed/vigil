"""Scan orchestration: runs the selected checks against one target.

The engine knows nothing about individual checks. It builds the shared context
(scope-gated HTTP client, DNS client, TLS probe), runs checks concurrently,
isolates their failures, and assembles the result.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from aegisscan import tlsutil
from aegisscan.checks.base import Check, CheckSkipped, discover_checks
from aegisscan.htmlutil import extract_links
from aegisscan.http import HttpClient, RequestFailed, Response
from aegisscan.models import CheckRun, Finding, ScanResult, Target, host_of
from aegisscan.resolver import DnsClient
from aegisscan.scope import OutOfScopeError, OutOfScopeLog, Permit

log = logging.getLogger("aegisscan.engine")


@dataclass
class ScanOptions:
    rate: float | None = 5.0  # requests per second, per host
    concurrency: int = 5  # simultaneous requests
    check_concurrency: int = 4  # simultaneous checks
    timeout: float = 10.0
    retries: int = 2
    ca_file: Path | None = None  # extra trust anchors for the TLS check
    include_unsafe: bool = False


class ScanContext:
    """What a check gets to work with. All network access here is scope-gated."""

    def __init__(
        self,
        permit: Permit,
        http: HttpClient,
        dns: DnsClient,
        options: ScanOptions,
    ) -> None:
        self.permit = permit
        self.target = permit.target
        self.scope = permit.scope
        self.http = http
        self.dns = dns
        self.options = options
        self.out_of_scope: OutOfScopeLog = http.out_of_scope
        self.observations: dict[str, Any] = {}
        self._baseline: Response | None = None
        self._baseline_error: Exception | None = None
        self._baseline_lock = asyncio.Lock()

    async def baseline(self) -> Response:
        """The target page, fetched once and shared by every check."""
        async with self._baseline_lock:
            if self._baseline_error is not None:
                raise self._baseline_error
            if self._baseline is None:
                try:
                    self._baseline = await self.http.get(self.target.url, follow_redirects=True)
                except (RequestFailed, OutOfScopeError) as exc:
                    self._baseline_error = exc
                    raise
                self._record_foreign_links(self._baseline)
            return self._baseline

    def _record_foreign_links(self, response: Response) -> None:
        """Links that lead to other hosts are recorded for the report, never followed."""
        if not response.is_html:
            return
        for link in extract_links(response.text, response.url):
            if not self.scope.host_in_scope(host_of(link)):
                self.out_of_scope.record(link, "link", source=response.url)

    def observe(self, key: str, value: Any) -> None:
        """Record recon data for the report that is not itself a finding."""
        self.observations[key] = value

    async def tls_probe(self, **kwargs: Any) -> tlsutil.Handshake:
        """One TLS handshake with the target host, rate limited and scope-gated."""
        await self.http.limiter.wait(self.target.host)
        kwargs.setdefault("timeout", self.options.timeout)
        return await tlsutil.probe(self.scope, self.target.host, self.target.port, **kwargs)


def select_checks(
    only: list[str] | None = None,
    skip: list[str] | None = None,
    available: list[type[Check]] | None = None,
) -> list[Check]:
    """Instantiate the registered checks, filtered by id or category name."""
    available = discover_checks() if available is None else available
    known = {check.id for check in available} | {check.category for check in available}
    unknown = [name for name in (only or []) + (skip or []) if name not in known]
    if unknown:
        raise ValueError(
            f"unknown check or category: {', '.join(unknown)} (see `aegisscan list-checks`)"
        )

    def matches(check: type[Check], names: list[str]) -> bool:
        return check.id in names or check.category in names

    selected = [check for check in available if only is None or matches(check, only)]
    return [check() for check in selected if not matches(check, skip or [])]


class Engine:
    def __init__(
        self,
        permit: Permit,
        *,
        checks: list[Check] | None = None,
        options: ScanOptions | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        dns: DnsClient | None = None,
    ) -> None:
        if not isinstance(permit, Permit):
            raise TypeError("Engine requires a Permit from aegisscan.scope.authorize()")
        self.permit = permit
        self.options = options or ScanOptions()
        self.checks = select_checks() if checks is None else checks
        self._transport = transport
        self._dns = dns

    async def run(self) -> ScanResult:
        permit, options = self.permit, self.options
        started = dt.datetime.now(dt.UTC)
        log.info(
            "scanning %s (in scope: %s; authorization: %s)",
            permit.target.url,
            permit.scope.describe(),
            permit.authorization.summary(),
        )
        http = HttpClient(
            permit,
            rate=options.rate,
            concurrency=options.concurrency,
            timeout=options.timeout,
            retries=options.retries,
            transport=self._transport,
        )
        dns = self._dns or DnsClient(timeout=min(options.timeout, 5.0))
        ctx = ScanContext(permit, http, dns, options)
        semaphore = asyncio.Semaphore(options.check_concurrency)

        async def run_one(check: Check) -> tuple[CheckRun, list[Finding]]:
            async with semaphore:
                return await self._run_check(check, permit.target, ctx)

        try:
            outcomes = await asyncio.gather(*(run_one(check) for check in self.checks))
        finally:
            await http.aclose()

        findings = [finding for _, found in outcomes for finding in found]
        findings.sort(key=lambda f: (-f.severity.rank, f.check_id, f.title, f.url))
        return ScanResult(
            target=permit.target,
            scope_hosts=sorted(permit.scope.hosts),
            include_subdomains=permit.scope.include_subdomains,
            exclude_paths=list(permit.scope.exclude_paths),
            authorization=permit.authorization,
            started_at=started,
            finished_at=dt.datetime.now(dt.UTC),
            checks=[run for run, _ in outcomes],
            findings=findings,
            observations=ctx.observations,
            out_of_scope=ctx.out_of_scope.records,
            requests_sent=http.requests_sent,
            dns_queries=dns.queries_sent,
        )

    async def _run_check(
        self, check: Check, target: Target, ctx: ScanContext
    ) -> tuple[CheckRun, list[Finding]]:
        info = check.info()
        if not check.safe and not self.options.include_unsafe:
            return CheckRun(check=info, status="skipped", detail="not a safe check"), []
        began = time.monotonic()
        findings: list[Finding] = []
        status, detail = "ran", ""
        try:
            findings = list(await check.run(target, ctx))
        except CheckSkipped as exc:
            status, detail = "skipped", str(exc)
        except OutOfScopeError as exc:
            status, detail = "skipped", f"blocked by the scope gate: {exc}"
        except (RequestFailed, tlsutil.TlsProbeError) as exc:
            status, detail = "error", str(exc)
        except Exception as exc:  # noqa: BLE001 - one broken check must not end the scan
            log.exception("check %s crashed", check.id)
            status, detail = "error", f"{type(exc).__name__}: {exc}"
        elapsed = int((time.monotonic() - began) * 1000)
        log.info("check %s: %s, %d finding(s)", check.id, status, len(findings))
        run = CheckRun(
            check=info, status=status, detail=detail, findings=len(findings), duration_ms=elapsed
        )
        return run, findings


async def run_scan(
    permit: Permit,
    *,
    checks: list[Check] | None = None,
    options: ScanOptions | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    dns: DnsClient | None = None,
) -> ScanResult:
    engine = Engine(permit, checks=checks, options=options, transport=transport, dns=dns)
    return await engine.run()
