"""HTML and JSON reports, generated from full scans of the fixture apps."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.fixtures.app import FAKE_SECRET, FixtureApp
from tests.fixtures.certs import TlsMaterial
from vigil import cvss, owasp, report
from vigil.checks.base import discover_checks
from vigil.cli import app as cli_app
from vigil.cli import checks_markdown
from vigil.engine import ScanOptions, run_scan
from vigil.models import ScanResult
from vigil.scope import authorize

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
async def vulnerable_scan(vulnerable_tls_app: FixtureApp, tls_material: TlsMaterial) -> ScanResult:
    options = ScanOptions(rate=None, timeout=5.0, ca_file=tls_material.ca_file)
    return await run_scan(authorize(vulnerable_tls_app.url), options=options)


@pytest.fixture
async def clean_scan(clean_tls_app: FixtureApp, tls_material: TlsMaterial) -> ScanResult:
    options = ScanOptions(rate=None, timeout=5.0, ca_file=tls_material.ca_file)
    return await run_scan(authorize(clean_tls_app.url), options=options)


def test_full_scan_of_the_vulnerable_fixture(vulnerable_scan: ScanResult) -> None:
    result = vulnerable_scan
    status = {run.check.id: run.status for run in result.checks}
    assert len(status) == 12
    # localhost has no DNS zone, so the three DNS-based checks report themselves not applicable
    assert {name for name, state in status.items() if state == "skipped"} == {
        "recon.dns",
        "recon.email_auth",
        "recon.subdomains",
    }
    assert "error" not in status.values(), [r.detail for r in result.checks if r.status == "error"]
    fired = {finding.check_id for finding in result.findings}
    assert fired == {name for name, state in status.items() if state == "ran"}
    counts = result.severity_counts()
    assert counts["high"] >= 5 and counts["medium"] >= 8 and counts["critical"] == 0
    assert [f.severity.rank for f in result.findings] == sorted(
        (f.severity.rank for f in result.findings), reverse=True
    )


def test_full_scan_of_the_clean_fixture_reports_nothing(clean_scan: ScanResult) -> None:
    assert [run.status for run in clean_scan.checks].count("error") == 0
    assert clean_scan.findings == [], [finding.title for finding in clean_scan.findings]


def test_every_finding_is_consistent_and_carries_evidence(vulnerable_scan: ScanResult) -> None:
    ceilings = {check.id: check.severity for check in discover_checks()}
    ids = [finding.id for finding in vulnerable_scan.findings]
    assert len(ids) == len(set(ids))
    for finding in vulnerable_scan.findings:
        assert finding.evidence and finding.why and finding.remediation
        assert finding.severity.rank <= ceilings[finding.check_id].rank, finding.title
        if finding.cvss_vector:
            assert finding.cvss_score == cvss.base_score(finding.cvss_vector)
            assert finding.severity.value == cvss.rating(finding.cvss_score)
        else:
            assert finding.severity.value == "info"


def test_every_finding_and_check_maps_to_the_owasp_top_10_2025(
    vulnerable_scan: ScanResult,
) -> None:
    for check in discover_checks():
        assert check.owasp == owasp.category_for(check.cwe), check.id
    seen = set()
    for finding in vulnerable_scan.findings:
        assert finding.owasp == owasp.category_for(finding.cwe), finding.title
        assert re.fullmatch(r"A(0[1-9]|10):2025 .+", finding.owasp)
        seen.add(finding.owasp[:3])
    assert seen == {"A01", "A02", "A04", "A06", "A07", "A10"}
    html = report.render_html(vulnerable_scan)
    assert ":2021" not in html and "A10:2025 Mishandling of Exceptional Conditions" in html


def test_out_of_scope_references_are_recorded(vulnerable_scan: ScanResult) -> None:
    hosts = {record.host for record in vulnerable_scan.out_of_scope}
    assert {"partner.thirdparty.example", "cdn.thirdparty.example", "staging.localhost"} <= hosts
    assert vulnerable_scan.scope_hosts == ["localhost"]


def test_json_report_round_trips(vulnerable_scan: ScanResult) -> None:
    text = report.render_json(vulnerable_scan)
    data = json.loads(text)
    assert list(data)[:3] == ["tool", "version", "summary"]
    assert data["summary"]["total"] == len(vulnerable_scan.findings)
    assert data["summary"]["highest_severity"] == "high"
    assert data["authorization"]["method"] == "loopback"
    first = data["findings"][0]
    for key in (
        "id", "title", "severity", "cvss_vector", "cvss_score", "cwe", "owasp", "url",
        "why", "evidence", "remediation",
    ):  # fmt: skip
        assert key in first
    assert ScanResult.model_validate_json(text) == vulnerable_scan


def test_html_report_contents(vulnerable_scan: ScanResult) -> None:
    html = report.render_html(vulnerable_scan)
    assert html.startswith("<!doctype html>")
    for section in ("Executive summary", "Scope and authorization", "Findings",
                    "Reconnaissance", "Checks performed", "Method and limits"):  # fmt: skip
        assert section in html
    # the assertion used is printed, with its timestamp
    assert "loopback target, no assertion required" in html
    assert vulnerable_scan.authorization.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") in html
    for finding in vulnerable_scan.findings:
        assert f'id="{finding.id}"' in html
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N" in html
    assert "https://cwe.mitre.org/data/definitions/942.html" in html
    assert "partner.thirdparty.example" in html  # out of scope, recorded
    assert "not applicable" in html
    assert FAKE_SECRET not in html


def test_html_report_is_self_contained_and_escapes_target_content(
    vulnerable_scan: ScanResult,
) -> None:
    html = report.render_html(vulnerable_scan)
    # Evidence contains markup served by the target; it must arrive as text, not as HTML.
    assert "&lt;title&gt;Index of /static/&lt;/title&gt;" in html
    assert "<title>Index of" not in html
    assert "<script" not in html.lower()
    # no external resources are loaded: the only URLs are plain links
    assert not re.search(r'(?:src|href)="(?!#|https://cwe\.mitre\.org/)', html)


def test_html_report_for_a_clean_scan(clean_scan: ScanResult) -> None:
    html = report.render_html(clean_scan)
    assert "No findings" in html
    assert "No weaknesses were identified" in html or "No findings were identified" in html


def test_cli_writes_both_reports_and_can_re_render(
    tmp_path: Path, vulnerable_app: FixtureApp
) -> None:
    out = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(cli_app, ["scan", vulnerable_app.url, "-o", str(out), "--rate", "50"])
    assert result.exit_code == 0, result.output
    assert "HIGH" in result.output and "Findings" in result.output
    assert (out / "vigil-report.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert json.loads((out / "vigil-report.json").read_text(encoding="utf-8"))["findings"]

    copy = tmp_path / "again.html"
    again = runner.invoke(cli_app, ["report", str(out / "vigil-report.json"), "-o", str(copy)])
    assert again.exit_code == 0, again.output
    assert "Executive summary" in copy.read_text(encoding="utf-8")

    missing = runner.invoke(cli_app, ["report", str(tmp_path / "nope.json")])
    assert missing.exit_code == 2


def test_cli_can_limit_the_checks_that_run(tmp_path: Path, vulnerable_app: FixtureApp) -> None:
    out = tmp_path / "out"
    result = CliRunner().invoke(
        cli_app,
        ["scan", vulnerable_app.url, "-o", str(out), "--checks", "config", "--skip",
         "config.exposed_files", "--format", "json"],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    data = json.loads((out / "vigil-report.json").read_text(encoding="utf-8"))
    ran = {run["check"]["id"] for run in data["checks"]}
    assert len(ran) == 6 and all(name.startswith("config.") for name in ran)
    assert not (out / "vigil-report.html").exists()


def test_readme_check_table_matches_the_registry() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"<!-- checks:start -->\n(.*?)\n<!-- checks:end -->", readme, re.S)
    assert match, "README.md must contain the generated check table between the markers"
    assert match.group(1).strip() == checks_markdown().strip(), (
        "README check table is stale: regenerate with `vigil list-checks --markdown`"
    )
