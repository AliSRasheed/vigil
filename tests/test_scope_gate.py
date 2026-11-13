"""The scope gate, exactly as specified in CLAUDE.md.

* a target given on the command line is in scope with no scope file;
* a host other than the named one (via link, redirect or discovered subdomain) is never
  requested, under any assertion method;
* a named host without an assertion is blocked;
* each of the three assertion methods allows the scan;
* a loopback target runs with no assertion;
* a scope file can add hosts and exclusions;
* the assertion used is logged.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegisscan.checks.base import Check
from aegisscan.cli import app as cli_app
from aegisscan.engine import ScanContext, run_scan
from aegisscan.htmlutil import extract_links
from aegisscan.http import HttpClient
from aegisscan.models import Finding, Severity, Target
from aegisscan.scope import (
    ENV_VAR,
    AuthorizationError,
    OutOfScopeError,
    Permit,
    ScopeError,
    authorize,
)
from tests.conftest import FAST
from tests.fixtures.app import FixtureApp
from tests.fixtures.transport import RewriteTransport

NAMED = "app.fixture.test"
OTHER = "other.fixture.test"
TARGET = f"http://{NAMED}/"

SCOPE_FILE_WITH_AUTHORIZATION = """\
authorization:
  asserted_by: Test Operator
  date: 2026-11-13
  basis: written-permission
"""


def write_scope(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def permit_for(method: str, tmp_path: Path, url: str = TARGET) -> Permit:
    """Pass the gate using exactly one assertion method."""
    if method == "flag":
        return authorize(url, flag=True, environ={})
    if method == "env":
        return authorize(url, environ={ENV_VAR: "1"})
    if method == "scope-file":
        scope_file = write_scope(tmp_path, SCOPE_FILE_WITH_AUTHORIZATION)
        return authorize(url, scope_file=scope_file, environ={})
    if method == "loopback":
        return authorize(url, environ={})
    raise AssertionError(method)


class Wanderer(Check, register=False):
    """A check that tries its best to leave the named host."""

    id = "test.wanderer"
    title = "Tries to leave scope"
    severity = Severity.INFO
    cwe = "CWE-000"
    owasp = "n/a"
    category = "recon"

    def __init__(self, extra_urls: list[str]) -> None:
        self.extra_urls = extra_urls
        self.refused: list[str] = []
        self.fetched: list[str] = []

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        home = await ctx.baseline()
        # 1. every link on the page, wherever it points
        candidates = extract_links(home.text, home.url)
        # 2. a redirect that leads to another host
        redirect = await ctx.http.get(target.join("redirect-out"), follow_redirects=True)
        assert redirect.status == 302, "an out-of-scope redirect must be returned, not followed"
        candidates.append(redirect.headers["location"])
        # 3. discovered subdomains and anything else the test supplies
        candidates += self.extra_urls
        for url in candidates:
            try:
                await ctx.http.get(url, follow_redirects=True)
                self.fetched.append(url)
            except OutOfScopeError:
                self.refused.append(url)
        return []


# --- in scope by default ---------------------------------------------------


def test_command_line_target_is_in_scope_without_a_scope_file() -> None:
    permit = authorize("https://app.example.com/shop?x=1", flag=True, environ={})
    assert permit.scope.hosts == frozenset({"app.example.com"})
    assert permit.scope.url_in_scope("https://app.example.com/")
    assert permit.scope.url_in_scope("http://APP.example.com:8080/any/path")


@pytest.mark.parametrize(
    "url",
    [
        "https://www.app.example.com/",  # subdomain
        "https://example.com/",  # parent domain
        "https://app.example.com.attacker.test/",  # look-alike suffix
        "https://notapp.example.com/",
        "https://app.example.org/",
        "ftp://app.example.com/",  # not http(s)
        "https://203.0.113.5/",
        "//app.example.com/",
        "not a url",
    ],
)
def test_only_the_named_host_is_in_scope(url: str) -> None:
    permit = authorize("https://app.example.com", flag=True, environ={})
    assert not permit.scope.url_in_scope(url)
    with pytest.raises(OutOfScopeError):
        permit.scope.check_url(url)


# --- other hosts are never requested ---------------------------------------


@pytest.mark.parametrize("method", ["flag", "env", "scope-file"])
async def test_other_hosts_are_never_requested(
    method: str, tmp_path: Path, vulnerable_app: FixtureApp, foreign_app: FixtureApp
) -> None:
    vulnerable_app.foreign = f"http://{OTHER}"
    # Both names are routable, so only the scope gate stands between the scanner and OTHER.
    transport = RewriteTransport({NAMED: vulnerable_app.url, OTHER: foreign_app.url})
    wanderer = Wanderer(
        [f"http://staging.{NAMED}/", f"http://{OTHER}/", f"https://{OTHER}/landing"]
    )
    permit = permit_for(method, tmp_path)
    assert permit.authorization.method == method

    result = await run_scan(permit, checks=[wanderer], options=FAST, transport=transport)

    assert result.checks[0].status == "ran", result.checks[0].detail
    assert set(transport.seen) == {NAMED}, "a request was addressed to an out-of-scope host"
    assert foreign_app.requests == [], "the out-of-scope host received a request"
    assert vulnerable_app.requests, "the named host should have been scanned"
    # the link, the redirect target and the subdomain were all refused...
    assert f"http://{OTHER}/landing" in wanderer.refused
    assert f"http://staging.{NAMED}/" in wanderer.refused
    assert f"http://{OTHER}/" in wanderer.refused
    assert all(NAMED in url and "staging" not in url for url in wanderer.fetched)
    # ...and recorded for the report instead
    reasons = {(record.host, record.reason) for record in result.out_of_scope}
    assert (OTHER, "link") in reasons
    assert (OTHER, "redirect") in reasons
    assert (f"staging.{NAMED}", "link") in reasons
    assert (OTHER, "blocked") in reasons


async def test_other_hosts_are_never_requested_from_a_loopback_target(
    tmp_path: Path, vulnerable_app: FixtureApp, foreign_app: FixtureApp
) -> None:
    # Target is 127.0.0.1; "localhost" is a different host name, so it is out of scope
    # even though it is the same machine.
    foreign = f"http://localhost:{foreign_app.port}"
    vulnerable_app.foreign = foreign
    wanderer = Wanderer([f"{foreign}/", f"http://localhost:{vulnerable_app.port}/"])
    permit = permit_for("loopback", tmp_path, vulnerable_app.url)
    assert permit.authorization.method == "loopback"

    result = await run_scan(permit, checks=[wanderer], options=FAST)

    assert result.checks[0].status == "ran", result.checks[0].detail
    assert foreign_app.requests == []
    assert all(request.host.startswith("127.0.0.1") for request in vulnerable_app.requests)
    assert f"{foreign}/landing" in wanderer.refused
    assert ("localhost", "redirect") in {(r.host, r.reason) for r in result.out_of_scope}


async def test_the_http_client_cannot_be_built_without_a_permit() -> None:
    with pytest.raises(TypeError, match="Permit"):
        HttpClient(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="Permit"):
        await run_scan(None)  # type: ignore[arg-type]


def test_the_scan_command_has_no_option_that_relaxes_scope() -> None:
    help_text = CliRunner().invoke(cli_app, ["scan", "--help"]).output.lower()
    for word in ("--force", "--no-scope", "--skip-scope", "--ignore-scope", "--follow"):
        assert word not in help_text
    result = CliRunner().invoke(cli_app, ["scan", "https://app.example.com", "--no-scope-check"])
    assert result.exit_code != 0


# --- no assertion, no scan -------------------------------------------------


def test_named_host_without_assertion_is_blocked() -> None:
    with pytest.raises(AuthorizationError) as excinfo:
        authorize("https://app.example.com", environ={})
    message = str(excinfo.value)
    assert "app.example.com" in message
    assert "--i-have-authorization" in message
    assert "AEGISSCAN_AUTHORIZED=1" in message
    assert "authorization:" in message


@pytest.mark.parametrize("value", ["0", "", "true", "yes", "01"])
def test_only_the_exact_environment_value_counts(value: str) -> None:
    with pytest.raises(AuthorizationError):
        authorize("https://app.example.com", environ={ENV_VAR: value})


def test_scope_file_without_authorization_block_does_not_authorize(tmp_path: Path) -> None:
    scope_file = write_scope(tmp_path, "hosts: [api.example.com]\n")
    with pytest.raises(AuthorizationError):
        authorize("https://app.example.com", scope_file=scope_file, environ={})


def test_cli_blocks_unasserted_scan_with_nonzero_exit(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = CliRunner().invoke(cli_app, ["scan", "https://app.example.com", "-o", str(out)])
    assert result.exit_code == 2
    assert "Scan blocked" in result.output
    assert "--i-have-authorization" in result.output
    assert not out.exists(), "nothing may be written or sent for a blocked scan"


def test_cli_rejects_a_target_without_a_scheme() -> None:
    result = CliRunner().invoke(cli_app, ["scan", "app.example.com", "--i-have-authorization"])
    assert result.exit_code == 2
    assert "http://" in result.output


# --- each assertion method allows the scan ---------------------------------


@pytest.mark.parametrize("method", ["flag", "env", "scope-file"])
async def test_each_assertion_method_allows_the_scan(
    method: str, tmp_path: Path, clean_app: FixtureApp
) -> None:
    transport = RewriteTransport({NAMED: clean_app.url})
    permit = permit_for(method, tmp_path)

    result = await run_scan(permit, checks=[Wanderer([])], options=FAST, transport=transport)

    assert result.authorization.method == method
    assert result.checks[0].status == "ran"
    assert clean_app.requests, "the scan should have reached the named host"
    assert {request.host for request in clean_app.requests} == {NAMED}


def test_cli_environment_variable_allows_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No checks registered against this name can reach the network (see conftest), so this
    # exercises the gate through the real CLI: with the variable set the scan proceeds.
    monkeypatch.setenv(ENV_VAR, "1")
    out = tmp_path / "out"
    result = CliRunner().invoke(
        cli_app, ["scan", "http://app.fixture.test", "-o", str(out), "--timeout", "1"]
    )
    assert result.exit_code == 0, result.output
    assert f"{ENV_VAR}=1" in result.output


def test_scope_file_authorization_is_recorded(tmp_path: Path) -> None:
    scope_file = write_scope(tmp_path, SCOPE_FILE_WITH_AUTHORIZATION)
    record = authorize(TARGET, scope_file=scope_file, environ={}).authorization
    assert record.method == "scope-file"
    assert record.asserted_by == "Test Operator"
    assert record.basis == "written-permission"
    assert str(record.date) == "2026-11-13"


# --- loopback --------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["http://localhost:8080/", "http://127.0.0.1/", "https://[::1]:8443/", "http://LOCALHOST"],
)
def test_loopback_target_needs_no_assertion(url: str) -> None:
    permit = authorize(url, environ={})
    assert permit.authorization.method == "loopback"


@pytest.mark.parametrize(
    "url",
    ["http://localhost.example.com/", "http://127.0.0.1.example.com/", "http://10.0.0.5/"],
)
def test_non_loopback_lookalikes_still_need_an_assertion(url: str) -> None:
    with pytest.raises(AuthorizationError):
        authorize(url, environ={})


def test_cli_scans_a_loopback_target_with_no_assertion(
    tmp_path: Path, clean_app: FixtureApp
) -> None:
    out = tmp_path / "out"
    result = CliRunner().invoke(cli_app, ["scan", clean_app.url, "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "loopback target, no assertion required" in result.output


def test_loopback_target_with_external_scope_host_needs_an_assertion(tmp_path: Path) -> None:
    scope_file = write_scope(tmp_path, "hosts: [api.example.com]\n")
    with pytest.raises(AuthorizationError):
        authorize("http://localhost:8080", scope_file=scope_file, environ={})


# --- scope file ------------------------------------------------------------


def test_scope_file_adds_hosts_and_exclusions(tmp_path: Path) -> None:
    scope_file = write_scope(
        tmp_path,
        "hosts:\n  - api.example.com\n  - Static.Example.com\n"
        "exclude_paths:\n  - /logout\n  - /admin/*\n",
    )
    scope = authorize("https://app.example.com", scope_file=scope_file, flag=True).scope
    assert scope.hosts == frozenset({"app.example.com", "api.example.com", "static.example.com"})
    assert scope.url_in_scope("https://api.example.com/v1/users")
    assert not scope.url_in_scope("https://other.example.com/")
    assert not scope.url_in_scope("https://app.example.com/logout")
    assert not scope.url_in_scope("https://app.example.com/logout/confirm")
    assert not scope.url_in_scope("https://api.example.com/admin/users")
    assert scope.url_in_scope("https://app.example.com/logout-help")
    assert scope.url_in_scope("https://app.example.com/administrator")


def test_scope_file_can_include_subdomains(tmp_path: Path) -> None:
    scope_file = write_scope(tmp_path, "include_subdomains: true\n")
    scope = authorize("https://example.com", scope_file=scope_file, flag=True).scope
    assert scope.url_in_scope("https://staging.example.com/")
    assert scope.url_in_scope("https://a.b.example.com/")
    assert not scope.url_in_scope("https://badexample.com/")
    assert not scope.url_in_scope("https://example.com.attacker.test/")


async def test_excluded_paths_are_never_requested(
    tmp_path: Path, vulnerable_app: FixtureApp
) -> None:
    scope_file = write_scope(tmp_path, "exclude_paths: [/admin]\n")
    permit = authorize(vulnerable_app.url, scope_file=scope_file)
    async with HttpClient(permit, rate=None) as http:
        assert (await http.get(f"{vulnerable_app.url}/page2")).status == 200
        with pytest.raises(OutOfScopeError, match="excluded"):
            await http.get(f"{vulnerable_app.url}/admin/panel")
    assert vulnerable_app.paths() == ["/page2"]
    assert http.out_of_scope.records[0].reason == "excluded-path"


async def test_redirect_to_a_host_added_by_the_scope_file_is_followed(
    tmp_path: Path, vulnerable_app: FixtureApp, foreign_app: FixtureApp
) -> None:
    vulnerable_app.foreign = f"http://{OTHER}"
    transport = RewriteTransport({NAMED: vulnerable_app.url, OTHER: foreign_app.url})
    scope_file = write_scope(tmp_path, f"hosts: [{OTHER}]\n")
    permit = authorize(TARGET, scope_file=scope_file, flag=True)
    async with HttpClient(permit, rate=None, transport=transport) as http:
        response = await http.get(f"http://{NAMED}/redirect-out", follow_redirects=True)
    assert response.status == 200
    assert response.url == f"http://{OTHER}/landing"
    assert foreign_app.paths() == ["/landing"]


def test_target_inside_an_excluded_path_is_refused(tmp_path: Path) -> None:
    scope_file = write_scope(tmp_path, "exclude_paths: [/admin]\n")
    with pytest.raises(ScopeError, match="excluded"):
        authorize("https://app.example.com/admin/users", scope_file=scope_file, flag=True)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("hosts: [https://api.example.com]\n", "not a hostname"),
        ("hosts: ['*.example.com']\n", "not a hostname"),
        ("exclude_paths: [admin]\n", "must start with /"),
        ("skip_scope_check: true\n", "skip_scope_check"),
        ("authorization:\n  asserted_by: A\n  date: 2026-01-01\n  basis: because\n", "basis"),
        ("authorization:\n  asserted_by: A\n  basis: owned\n", "date"),
        ("- just\n- a list\n", "mapping"),
        ("hosts: [unclosed\n", "not valid YAML"),
    ],
)
def test_invalid_scope_files_are_rejected(tmp_path: Path, text: str, expected: str) -> None:
    with pytest.raises(ScopeError, match=expected):
        authorize("https://app.example.com", scope_file=write_scope(tmp_path, text), flag=True)


def test_missing_scope_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(ScopeError, match="cannot read scope file"):
        authorize("https://app.example.com", scope_file=tmp_path / "nope.yaml", flag=True)


# --- the assertion is logged -----------------------------------------------


@pytest.mark.parametrize("method", ["flag", "env", "scope-file", "loopback"])
def test_the_assertion_used_is_logged_with_a_timestamp(
    method: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    url = "http://127.0.0.1:9/" if method == "loopback" else TARGET
    with caplog.at_level(logging.INFO, logger="aegisscan.audit"):
        permit = permit_for(method, tmp_path, url)
    records = [record for record in caplog.records if record.name == "aegisscan.audit"]
    assert len(records) == 1
    message = records[0].getMessage()
    assert f"method={method}" in message
    assert permit.authorization.timestamp.isoformat(timespec="seconds") in message
    assert permit.authorization.timestamp.tzinfo is not None


def test_cli_writes_the_assertion_to_the_audit_log_and_report(
    tmp_path: Path, clean_app: FixtureApp
) -> None:
    out = tmp_path / "out"
    result = CliRunner().invoke(
        cli_app, ["scan", clean_app.url, "--i-have-authorization", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert "scan authorized" in result.output and "method=flag" in result.output

    entry = json.loads((out / "audit.log").read_text(encoding="utf-8").splitlines()[-1])
    assert entry["authorization_method"] == "flag"
    assert entry["target"] == clean_app.url + "/"
    assert entry["timestamp"]

    report = json.loads((out / "aegisscan-report.json").read_text(encoding="utf-8"))
    assert report["authorization"]["method"] == "flag"
    assert report["authorization"]["timestamp"]
    assert report["scope_hosts"] == ["127.0.0.1"]
