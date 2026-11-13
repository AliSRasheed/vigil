"""Config and exposure checks: each fires on the vulnerable fixture, silent on the clean one."""

from __future__ import annotations

import httpx
import pytest

from aegisscan.checks.config.clickjacking import Clickjacking, framing_weakness
from aegisscan.checks.config.cookies import CookieFlags, cookie_issues, parse_set_cookie
from aegisscan.checks.config.cors import CorsMisconfiguration
from aegisscan.checks.config.directory_listing import DirectoryListing
from aegisscan.checks.config.exposed_files import PROBES, ExposedFiles
from aegisscan.checks.config.info_disclosure import InfoDisclosure, error_detail
from aegisscan.checks.config.security_headers import (
    SecurityHeaders,
    analyse,
    csp_weaknesses,
    grade,
)
from aegisscan.http import Response, parse_csp
from aegisscan.models import Finding, Severity
from aegisscan.scope import authorize
from tests.fixtures.app import FAKE_SECRET, FixtureApp


async def run(check, make_ctx, url: str, **kwargs) -> list[Finding]:
    ctx = make_ctx(url, **kwargs)
    try:
        return await check.run(ctx.target, ctx)
    finally:
        await ctx.http.aclose()


def titles(findings: list[Finding]) -> list[str]:
    return [finding.title for finding in findings]


def assert_well_formed(findings: list[Finding]) -> None:
    """Rule 3: every finding stores the request, the response excerpt and why it was flagged."""
    for finding in findings:
        assert finding.why and finding.remediation and finding.description
        assert finding.evidence
        for evidence in finding.evidence:
            assert evidence.request and evidence.response
        assert finding.cwe.startswith("CWE-") and finding.owasp


def fake_response(headers: dict[str, str] | list[tuple[str, str]], body: str = "<html></html>"):
    return Response(
        method="GET",
        url="https://site.example/",
        status=200,
        headers=httpx.Headers(headers),
        body=body.encode(),
        truncated=False,
        request_headers={},
    )


# --- security headers ------------------------------------------------------


async def test_security_headers_fires_on_vulnerable(make_ctx, vulnerable_app: FixtureApp) -> None:
    findings = await run(SecurityHeaders(), make_ctx, vulnerable_app.url)
    assert_well_formed(findings)
    assert titles(findings) == [
        "Content-Security-Policy header is missing",
        "X-Content-Type-Options: nosniff is missing",
        "Referrer-Policy header is missing",
        "Permissions-Policy header is missing",
    ]
    assert [f.severity for f in findings] == [
        Severity.LOW,
        Severity.LOW,
        Severity.INFO,
        Severity.INFO,
    ]
    assert "Header grade for this response: D (45/100)" in findings[0].description


async def test_security_headers_silent_on_clean(make_ctx, clean_app: FixtureApp) -> None:
    ctx = make_ctx(clean_app.url)
    assert await SecurityHeaders().run(ctx.target, ctx) == []
    assert ctx.observations["security_headers"] == {"grade": "A", "score": "100/100"}


async def test_hsts_is_judged_over_https_only(
    make_ctx, vulnerable_tls_app: FixtureApp, clean_tls_app: FixtureApp
) -> None:
    findings = await run(SecurityHeaders(), make_ctx, vulnerable_tls_app.url)
    hsts = [f for f in findings if "Strict-Transport-Security" in f.title]
    assert len(hsts) == 1 and hsts[0].severity is Severity.MEDIUM and hsts[0].cwe == "CWE-319"
    assert await run(SecurityHeaders(), make_ctx, clean_tls_app.url) == []


def test_header_quality_grading() -> None:
    weak = httpx.Headers(
        {
            "content-security-policy": "default-src * 'unsafe-inline' 'unsafe-eval'",
            "strict-transport-security": "max-age=3600",
            "x-content-type-options": "nosniff",
            "referrer-policy": "unsafe-url",
            "permissions-policy": "camera=()",
        }
    )
    issues = analyse(weak, https=True)
    assert [issue.title for issue in issues] == [
        "Content-Security-Policy is weak",
        "Strict-Transport-Security max-age is too short",
        "Referrer-Policy leaks full URLs to other sites",
    ]
    assert "'unsafe-inline'" in issues[0].why and "'unsafe-eval'" in issues[0].why
    assert grade(issues) == ("C", 65)

    report_only = analyse(
        httpx.Headers({"content-security-policy-report-only": "default-src 'self'"}), https=False
    )
    assert "does not block anything" in report_only[0].why
    disabled = analyse(httpx.Headers({"strict-transport-security": "max-age=0"}), https=True)
    assert any("disables the policy" in issue.why for issue in disabled)


def test_csp_with_nonces_is_not_called_weak() -> None:
    strict = parse_csp(
        "script-src 'nonce-r4nd0m' 'strict-dynamic' 'unsafe-inline'; object-src 'none'; "
        "base-uri 'none'"
    )
    assert csp_weaknesses(strict) == []
    assert csp_weaknesses(parse_csp("img-src 'self'"))[0].startswith("no script-src")


# --- cookies ---------------------------------------------------------------


async def test_cookie_flags_fires_on_vulnerable(make_ctx, vulnerable_app: FixtureApp) -> None:
    findings = await run(CookieFlags(), make_ctx, vulnerable_app.url)
    assert_well_formed(findings)
    assert titles(findings) == [
        "Session cookie 'PHPSESSID' has weak flags: HttpOnly, SameSite",
        "Cookie 'prefs' has weak flags: SameSite",
    ]
    assert findings[0].severity is Severity.MEDIUM and findings[0].cwe == "CWE-1004"
    assert findings[1].severity is Severity.LOW
    assert "7f3a9c2e5b1d4f60a8c1" not in findings[0].model_dump_json()


async def test_cookie_flags_silent_on_clean(make_ctx, clean_app: FixtureApp) -> None:
    assert await run(CookieFlags(), make_ctx, clean_app.url) == []


async def test_missing_secure_flag_is_reported_over_https(
    make_ctx, vulnerable_tls_app: FixtureApp, clean_tls_app: FixtureApp
) -> None:
    findings = await run(CookieFlags(), make_ctx, vulnerable_tls_app.url)
    assert "Secure" in findings[0].title and findings[0].cwe == "CWE-614"
    assert await run(CookieFlags(), make_ctx, clean_tls_app.url) == []


def test_cookie_rules() -> None:
    def flags(header: str, https: bool = True) -> list[str]:
        return [issue.flag for issue in cookie_issues(parse_set_cookie(header), https=https)]

    assert flags("theme=dark; Path=/; Secure") == []  # not a session cookie: script may read it
    assert flags("XSRF-TOKEN=abc; Secure; SameSite=Strict") == []  # read by script on purpose
    assert flags("auth_token=abc; Secure; HttpOnly; SameSite=None") == ["SameSite"]
    assert flags("sessionid=abc; HttpOnly; SameSite=Lax", https=False) == []
    assert flags("sessionid=abc; HttpOnly; SameSite=Lax", https=True) == ["Secure"]
    assert parse_set_cookie("garbage") is None


# --- CORS ------------------------------------------------------------------


async def test_cors_fires_on_vulnerable(make_ctx, vulnerable_app: FixtureApp) -> None:
    findings = await run(CorsMisconfiguration(), make_ctx, vulnerable_app.url)
    assert_well_formed(findings)
    assert titles(findings) == ["CORS policy reflects any Origin with credentials"]
    assert findings[0].severity is Severity.HIGH
    assert "Origin: https://aegisscan-cors-probe.example" in findings[0].evidence[0].request
    assert "Access-Control-Allow-Credentials: true" in findings[0].evidence[0].response


async def test_cors_silent_on_clean(make_ctx, clean_app: FixtureApp) -> None:
    # The clean app does send CORS headers, but only to its one allow-listed origin.
    assert await run(CorsMisconfiguration(), make_ctx, clean_app.url) == []
    assert len(clean_app.requests) == 4, "all four origin probes were tried and refused"


@pytest.mark.parametrize(
    ("path", "title", "severity"),
    [
        ("/cors/null", "CORS policy trusts the null origin with credentials", Severity.HIGH),
        ("/cors/prefix", "CORS policy validates Origin by prefix with credentials", Severity.HIGH),
        (
            "/cors/reflect-no-credentials",
            "CORS policy reflects any Origin (no credentials)",
            Severity.LOW,
        ),
    ],
)
async def test_cors_variants(
    make_ctx, vulnerable_app: FixtureApp, path: str, title: str, severity: Severity
) -> None:
    findings = await run(CorsMisconfiguration(), make_ctx, vulnerable_app.url + path)
    assert titles(findings) == [title]
    assert findings[0].severity is severity


# --- clickjacking ----------------------------------------------------------


async def test_clickjacking_fires_on_vulnerable(make_ctx, vulnerable_app: FixtureApp) -> None:
    findings = await run(Clickjacking(), make_ctx, vulnerable_app.url)
    assert_well_formed(findings)
    assert titles(findings) == ["Page can be framed by other sites (clickjacking)"]
    assert findings[0].severity is Severity.MEDIUM and findings[0].cwe == "CWE-1021"


async def test_clickjacking_silent_on_clean(make_ctx, clean_app: FixtureApp) -> None:
    assert await run(Clickjacking(), make_ctx, clean_app.url) == []


async def test_clickjacking_ignores_non_html(make_ctx, vulnerable_app: FixtureApp) -> None:
    assert await run(Clickjacking(), make_ctx, vulnerable_app.url + "/echo-headers") == []


def test_framing_rules() -> None:
    assert framing_weakness(fake_response({"x-frame-options": "SAMEORIGIN"})) is None
    assert "not recognise" in framing_weakness(
        fake_response({"x-frame-options": "ALLOW-FROM https://a.example"})
    )
    permissive = fake_response(
        {"content-security-policy": "frame-ancestors *", "x-frame-options": "DENY"}
    )
    assert "allows any site" in framing_weakness(permissive)


def test_framing_rules_accept_frame_ancestors_self() -> None:
    protected = fake_response(
        {"content-security-policy": "default-src 'self'; frame-ancestors 'self'"}
    )
    assert framing_weakness(protected) is None


# --- directory listing -----------------------------------------------------


async def test_directory_listing_fires_on_vulnerable(make_ctx, vulnerable_app: FixtureApp) -> None:
    findings = await run(DirectoryListing(), make_ctx, vulnerable_app.url)
    assert_well_formed(findings)
    assert titles(findings) == ["Directory listing enabled (3 directories)"]
    assert findings[0].severity is Severity.MEDIUM
    for path in ("/static/", "/uploads/", "/backup/"):
        assert path in findings[0].why
    assert "<title>Index of /static/</title>" in findings[0].evidence[0].response


async def test_directory_listing_silent_on_clean(make_ctx, clean_app: FixtureApp) -> None:
    # The clean app answers /uploads/, /backup/ and the rest with HTTP 200 soft-404 pages.
    assert await run(DirectoryListing(), make_ctx, clean_app.url) == []
    assert "/static/" in clean_app.paths()


# --- exposed files ---------------------------------------------------------


async def test_exposed_files_fires_on_vulnerable(make_ctx, vulnerable_app: FixtureApp) -> None:
    findings = await run(ExposedFiles(), make_ctx, vulnerable_app.url)
    assert_well_formed(findings)
    assert sorted(titles(findings)) == [
        "Apache server-status exposed: /server-status",
        "Backup archive exposed: /backup.zip",
        "Backup copy of a source file exposed: /config.php.bak",
        "Database dump exposed: /database.sql",
        "Environment file exposed: /.env",
        "Git repository exposed: /.git/HEAD, /.git/config",
        "macOS .DS_Store file exposed: /.DS_Store",
        "phpinfo() page exposed: /phpinfo.php",
    ]
    by_title = {finding.title.split(":")[0]: finding for finding in findings}
    assert by_title["Environment file exposed"].severity is Severity.HIGH
    assert by_title["phpinfo() page exposed"].severity is Severity.MEDIUM
    assert len(by_title["Git repository exposed"].evidence) == 2
    assert "ref: refs/heads/main" in by_title["Git repository exposed"].evidence[0].response


async def test_exposed_files_never_copies_secrets_into_the_report(
    make_ctx, vulnerable_app: FixtureApp
) -> None:
    findings = await run(ExposedFiles(), make_ctx, vulnerable_app.url)
    dumped = "".join(finding.model_dump_json() for finding in findings)
    assert FAKE_SECRET not in dumped, "secret values must be masked in evidence"
    assert "fixture@example.invalid" not in dumped, "database rows must not be extracted"
    assert "DB_PASSWORD=<redacted>" in dumped


async def test_exposed_files_silent_on_clean(make_ctx, clean_app: FixtureApp) -> None:
    # Every probe gets HTTP 200 from the clean app's soft-404 page; none may be reported.
    assert await run(ExposedFiles(), make_ctx, clean_app.url) == []
    assert len(clean_app.requests) == len(PROBES)
    assert {request.method for request in clean_app.requests} == {"GET"}


async def test_exposed_files_respects_excluded_paths(
    make_ctx, tmp_path, vulnerable_app: FixtureApp
) -> None:
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("exclude_paths: [/.git, /.env]\n", encoding="utf-8")
    permit = authorize(vulnerable_app.url, scope_file=scope_file)
    findings = await run(ExposedFiles(), make_ctx, vulnerable_app.url, permit=permit)
    assert not any("Git" in title or "Environment" in title for title in titles(findings))
    requested = vulnerable_app.paths()
    assert "/.env" not in requested and not any(p.startswith("/.git/") for p in requested)
    assert "/.env.local" in requested, "only the excluded paths are skipped"
    assert len(findings) == 6


# --- information disclosure ------------------------------------------------


async def test_info_disclosure_fires_on_vulnerable(make_ctx, vulnerable_app: FixtureApp) -> None:
    findings = await run(InfoDisclosure(), make_ctx, vulnerable_app.url)
    assert_well_formed(findings)
    assert titles(findings) == [
        "Software versions disclosed by the server",
        "Verbose error page exposes internal details",
    ]
    versions, errors = findings
    assert versions.severity is Severity.LOW
    assert "Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3" in versions.why
    assert "X-Powered-By: PHP/7.4.3" in versions.why
    assert "error page footer: Apache/2.4.49 (Unix) Server at" in versions.why
    assert errors.severity is Severity.MEDIUM and errors.cwe == "CWE-209"
    assert "Traceback (most recent call last)" in errors.evidence[0].response


async def test_info_disclosure_silent_on_clean(make_ctx, clean_app: FixtureApp) -> None:
    assert await run(InfoDisclosure(), make_ctx, clean_app.url) == []


def test_error_page_patterns() -> None:
    assert error_detail("<p>Sorry, page not found</p>") is None
    assert error_detail("java.lang.NullPointerException\n\tat com.shop.Cart.add(Cart.java:42)\n")[
        0
    ] == ("a Java stack trace")
    assert error_detail("<b>Fatal error</b>: Uncaught Error in /var/www/a.php on line <b>3</b>")
    assert error_detail("SQLSTATE[42000]: Syntax error")[0] == "a SQL error"
