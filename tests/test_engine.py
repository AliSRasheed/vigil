"""Check registry and scan orchestration."""

from __future__ import annotations

import pytest

from aegisscan.checks import base
from aegisscan.checks.base import Check, CheckSkipped, discover_checks
from aegisscan.engine import ScanContext, ScanOptions, run_scan, select_checks
from aegisscan.http import http_evidence
from aegisscan.models import Finding, Severity, Target
from aegisscan.scope import authorize
from tests.conftest import FAST
from tests.fixtures.app import FixtureApp

MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


class _Base(Check, register=False):
    severity = Severity.HIGH
    cwe = "CWE-200"
    owasp = "A05:2021 Security Misconfiguration"
    category = "config"


class Reporter(_Base, register=False):
    id = "test.reporter"
    title = "Reports two findings"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        response = await ctx.baseline()
        common = {
            "url": response.url,
            "description": "d",
            "why": "because",
            "evidence": [http_evidence(response, "because")],
            "remediation": "fix it",
        }
        return [
            self.finding(title="medium one", cvss_vector=MEDIUM, **common),
            self.finding(title="high one", cvss_vector=HIGH, **common),
            self.finding(title="info one", **common),
        ]


class Crasher(_Base, register=False):
    id = "test.crasher"
    title = "Raises"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        raise RuntimeError("boom")


class NotApplicable(_Base, register=False):
    id = "test.not_applicable"
    title = "Skips itself"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        raise CheckSkipped("target is not HTTPS")


class Intrusive(_Base, register=False):
    id = "test.intrusive"
    title = "Not safe"
    safe = False

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        raise AssertionError("an unsafe check must not run by default")


@pytest.fixture
def empty_registry(monkeypatch: pytest.MonkeyPatch) -> dict:
    registry: dict = {}
    monkeypatch.setattr(base, "_REGISTRY", registry)
    return registry


def test_subclassing_registers_a_check(empty_registry: dict) -> None:
    class Sample(_Base):
        id = "config.sample"
        title = "Sample"

        async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
            return []

    assert empty_registry == {"config.sample": Sample}
    assert Sample.info().owasp == "A05:2021 Security Misconfiguration"


def test_incomplete_or_duplicate_checks_are_rejected(empty_registry: dict) -> None:
    with pytest.raises(TypeError, match="missing metadata: id, title"):

        class NoMetadata(_Base):
            async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
                return []

    class First(_Base):
        id = "config.dup"
        title = "First"

        async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
            return []

    with pytest.raises(TypeError, match="duplicate check id"):

        class Second(_Base):
            id = "config.dup"
            title = "Second"

            async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
                return []

    with pytest.raises(TypeError, match="unknown category"):

        class BadCategory(_Base):
            id = "x.bad"
            title = "Bad"
            category = "exploit"

            async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
                return []


def test_discovery_imports_every_check_module() -> None:
    checks = discover_checks()
    ids = [check.id for check in checks]
    assert len(ids) == len(set(ids))
    for check in checks:
        assert check.__module__.startswith("aegisscan.checks.")
        assert check.id.split(".")[0] == check.category
        assert check.safe, "every v1 check is a safe check"


def test_select_checks_filters_by_id_and_category() -> None:
    available = [Reporter, Crasher, NotApplicable]
    assert [type(c) for c in select_checks(available=available)] == available
    assert [type(c) for c in select_checks(only=["test.crasher"], available=available)] == [Crasher]
    assert select_checks(only=["config"], skip=["test.crasher"], available=available)[0].id == (
        "test.reporter"
    )
    with pytest.raises(ValueError, match="unknown check or category: nope"):
        select_checks(only=["nope"], available=available)


async def test_engine_runs_checks_and_isolates_failures(vulnerable_app: FixtureApp) -> None:
    permit = authorize(vulnerable_app.url)
    checks = [Crasher(), Reporter(), NotApplicable(), Intrusive()]

    result = await run_scan(permit, checks=checks, options=FAST)

    status = {run.check.id: (run.status, run.detail) for run in result.checks}
    assert status["test.reporter"] == ("ran", "")
    assert status["test.crasher"] == ("error", "RuntimeError: boom")
    assert status["test.not_applicable"] == ("skipped", "target is not HTTPS")
    assert status["test.intrusive"] == ("skipped", "not a safe check")
    assert [finding.title for finding in result.findings] == ["high one", "medium one", "info one"]
    assert result.severity_counts() == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 1}
    assert result.requests_sent == 1, "the baseline page is fetched once and shared"
    assert result.finished_at >= result.started_at


async def test_unreachable_target_is_reported_per_check_not_raised() -> None:
    permit = authorize("http://127.0.0.1:1/")
    options = ScanOptions(rate=None, timeout=2.0, retries=0)
    result = await run_scan(permit, checks=[Reporter()], options=options)
    assert result.checks[0].status == "error"
    assert "failed" in result.checks[0].detail
    assert result.findings == []


def test_findings_derive_score_and_severity_from_the_vector() -> None:
    check = Reporter()
    common = {
        "url": "http://x/",
        "description": "d",
        "why": "w",
        "evidence": [{"request": "GET /", "response": "200"}],
        "remediation": "r",
    }
    finding = check.finding(title="t", cvss_vector=HIGH, **common)
    assert (finding.severity, finding.cvss_score) == (Severity.HIGH, 7.5)
    assert finding.cwe == "CWE-200" and finding.owasp.startswith("A05")
    assert finding.id == check.finding(title="t", cvss_vector=HIGH, **common).id
    info = check.finding(title="t2", **common)
    assert (info.severity, info.cvss_score) == (Severity.INFO, None)


def test_a_finding_without_evidence_is_invalid() -> None:
    with pytest.raises(ValueError, match="evidence"):
        Reporter().finding(
            title="t", url="http://x/", description="d", why="w", evidence=[], remediation="r"
        )
