"""Recon checks: each fires on the vulnerable fixture and is silent on the clean one.

DNS-based checks run against the fixture DNS server (zones vulnerable-fixture.test and
clean-fixture.test); HTTP for those names is routed to the local fixture app.
"""

from __future__ import annotations

import datetime as dt

import pytest

from tests.fixtures.app import FixtureApp
from tests.fixtures.dns_server import FixtureDns
from tests.test_checks_config import assert_well_formed, run, titles
from vigil import tlsutil
from vigil.checks.base import CheckSkipped
from vigil.checks.recon.dns import DnsRecords
from vigil.checks.recon.email_auth import EmailAuthentication, dmarc_policy, spf_all_qualifier
from vigil.checks.recon.fingerprint import TechnologyFingerprint
from vigil.checks.recon.subdomains import SubdomainEnumeration, hostnames_in
from vigil.checks.recon.tls import TlsAnalysis, certificate_problems
from vigil.models import Finding, Severity

VULNERABLE = "vulnerable-fixture.test"
CLEAN = "clean-fixture.test"


# --- technology fingerprinting ---------------------------------------------


async def test_fingerprint_fires_on_vulnerable(make_ctx, vulnerable_app: FixtureApp) -> None:
    ctx = make_ctx(vulnerable_app.url)
    findings = await TechnologyFingerprint().run(ctx.target, ctx)
    assert_well_formed(findings)
    assert titles(findings) == ["Technology stack identified (5 components)"]
    assert findings[0].severity is Severity.INFO and findings[0].cvss_vector is None
    detected = {row["technology"]: row["version"] for row in ctx.observations["technologies"]}
    assert detected == {
        "Apache HTTP Server": "2.4.49",
        "OpenSSL": "1.1.1k",
        "PHP": "7.4.3",
        "WordPress": "5.8.1",
        "jQuery": "3.4.1",
    }


async def test_fingerprint_silent_on_clean(make_ctx, clean_app: FixtureApp) -> None:
    ctx = make_ctx(clean_app.url)
    assert await TechnologyFingerprint().run(ctx.target, ctx) == []
    assert ctx.observations["technologies"] == []


# --- DNS records -----------------------------------------------------------


async def test_dns_fires_on_vulnerable(make_ctx) -> None:
    ctx = make_ctx(f"https://{VULNERABLE}")
    findings = await DnsRecords().run(ctx.target, ctx)
    assert_well_formed(findings)
    assert titles(findings) == [
        "No CAA record restricts certificate issuance",
        "Zone is not signed with DNSSEC",
    ]
    assert [f.severity for f in findings] == [Severity.LOW, Severity.INFO]
    assert findings[0].evidence[0].kind == "dns"
    assert findings[0].evidence[0].request == f"DNS query: {VULNERABLE} IN CAA"
    records = ctx.observations["dns"]["records"]
    assert records[f"{VULNERABLE} A"] == ["192.0.2.10"]
    assert records[f"{VULNERABLE} MX"] == [f"10 mail.{VULNERABLE}."]


async def test_dns_silent_on_clean(make_ctx) -> None:
    ctx = make_ctx(f"https://{CLEAN}")
    assert await DnsRecords().run(ctx.target, ctx) == []
    assert ctx.observations["dns"]["zone"] == CLEAN


async def test_dns_uses_the_zone_apex_for_a_subdomain(make_ctx) -> None:
    # app.clean-fixture.test has no CAA of its own; the record at the apex covers it.
    ctx = make_ctx(f"https://app.{CLEAN}")
    assert await DnsRecords().run(ctx.target, ctx) == []
    assert ctx.observations["dns"]["zone"] == CLEAN
    vulnerable = make_ctx(f"https://app.{VULNERABLE}")
    assert len(await DnsRecords().run(vulnerable.target, vulnerable)) == 2


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:8080/", "http://localhost/", "http://[::1]/", "http://intranet/"]
)
async def test_dns_checks_do_not_apply_to_ip_or_local_targets(
    make_ctx, dns_server: FixtureDns, url: str
) -> None:
    for check in (DnsRecords(), EmailAuthentication(), SubdomainEnumeration()):
        ctx = make_ctx(url)
        with pytest.raises(CheckSkipped):
            await check.run(ctx.target, ctx)
    assert dns_server.queries == []


async def test_dns_checks_skip_a_name_that_does_not_exist(make_ctx) -> None:
    for check in (DnsRecords(), EmailAuthentication()):
        ctx = make_ctx("https://nonexistent-fixture.test")
        with pytest.raises(CheckSkipped):
            await check.run(ctx.target, ctx)


# --- email authentication --------------------------------------------------


async def test_email_auth_fires_on_vulnerable(make_ctx) -> None:
    ctx = make_ctx(f"https://{VULNERABLE}")
    findings = await EmailAuthentication().run(ctx.target, ctx)
    assert_well_formed(findings)
    assert titles(findings) == [
        "SPF record allows any sender (+all)",
        "DMARC policy is not enforced",
        "No DKIM key found at common selectors",
    ]
    assert [f.severity for f in findings] == [Severity.MEDIUM, Severity.LOW, Severity.INFO]
    assert "v=spf1 a:legacy-relay.vulnerable-fixture.test +all" in findings[0].evidence[0].response
    assert findings[1].evidence[0].request == f"DNS query: _dmarc.{VULNERABLE} IN TXT"


async def test_email_auth_silent_on_clean(make_ctx) -> None:
    ctx = make_ctx(f"https://app.{CLEAN}")  # a subdomain: the zone apex is what gets checked
    assert await EmailAuthentication().run(ctx.target, ctx) == []
    observed = ctx.observations["email_authentication"]
    assert observed["domain"] == CLEAN
    assert observed["DKIM selectors found"] == ["selector1"]


async def test_email_auth_reports_missing_records(make_ctx) -> None:
    ctx = make_ctx("https://bare-fixture.test")
    findings = await EmailAuthentication().run(ctx.target, ctx)
    assert titles(findings) == [
        "No SPF record",
        "No DMARC policy",
        "No DKIM key found at common selectors",
    ]
    assert findings[0].severity is Severity.MEDIUM
    assert "NXDOMAIN" in findings[1].evidence[0].response


def test_spf_and_dmarc_parsing() -> None:
    assert spf_all_qualifier("v=spf1 include:_spf.example.com -all") == "-"
    assert spf_all_qualifier("v=spf1 mx ~all") == "~"
    assert spf_all_qualifier("v=spf1 all") == "+"
    assert spf_all_qualifier("v=spf1 include:allowed.example.com") is None
    assert dmarc_policy("v=DMARC1; p=reject; sp=none") == "reject"
    assert dmarc_policy("v=DMARC1; rua=mailto:a@example.com") is None


# --- subdomain enumeration -------------------------------------------------


async def test_subdomains_fires_on_vulnerable(make_ctx, vulnerable_app: FixtureApp) -> None:
    ctx = make_ctx(f"http://{VULNERABLE}", routes={VULNERABLE: vulnerable_app.url})
    findings = await SubdomainEnumeration().run(ctx.target, ctx)
    assert_well_formed(findings)
    assert titles(findings) == ["5 subdomain(s) discovered passively"]
    assert findings[0].severity is Severity.INFO
    found = {row["subdomain"]: row["seen in"] for row in ctx.observations["subdomains"]}
    assert found == {
        f"ns1.{VULNERABLE}": f"NS record of {VULNERABLE}",
        f"ns2.{VULNERABLE}": f"NS record of {VULNERABLE}",
        f"mail.{VULNERABLE}": f"MX record of {VULNERABLE}",
        f"legacy-relay.{VULNERABLE}": f"TXT record of {VULNERABLE}",
        f"staging.{VULNERABLE}": "link on the target page",
    }
    assert {evidence.kind for evidence in findings[0].evidence} == {"dns", "http"}


async def test_discovered_subdomains_are_recorded_and_never_contacted(
    make_ctx, vulnerable_app: FixtureApp
) -> None:
    routes = {VULNERABLE: vulnerable_app.url, f"staging.{VULNERABLE}": vulnerable_app.url}
    ctx = make_ctx(f"http://{VULNERABLE}", routes=routes)
    await SubdomainEnumeration().run(ctx.target, ctx)
    assert {request.host for request in vulnerable_app.requests} == {VULNERABLE}
    recorded = {r.host for r in ctx.out_of_scope.records if r.reason == "subdomain"}
    assert f"staging.{VULNERABLE}" in recorded and f"mail.{VULNERABLE}" in recorded


async def test_subdomains_silent_on_clean(make_ctx, clean_app: FixtureApp) -> None:
    ctx = make_ctx(f"http://{CLEAN}", routes={CLEAN: clean_app.url})
    assert await SubdomainEnumeration().run(ctx.target, ctx) == []
    assert ctx.observations["subdomains"] == []


def test_hostname_extraction() -> None:
    text = "v=spf1 a:relay.example.com include:_spf.mail.example.net ip4:192.0.2.1 -all"
    assert hostnames_in(text) == ["relay.example.com", "_spf.mail.example.net"]
    assert hostnames_in("10 MAIL.Example.com.") == ["mail.example.com"]


# --- TLS -------------------------------------------------------------------


async def test_tls_fires_on_vulnerable(make_ctx, vulnerable_tls_app: FixtureApp) -> None:
    ctx = make_ctx(vulnerable_tls_app.url)
    findings = await TlsAnalysis().run(ctx.target, ctx)
    assert_well_formed(findings)
    assert titles(findings) == [
        "TLS certificate has expired",
        "TLS certificate does not match the host name",
        "TLS certificate is not trusted",
        "Deprecated TLS versions accepted: TLS 1.0, TLS 1.1",
        "Weak cipher suites accepted",
        "Cipher suites without forward secrecy accepted",
    ]
    assert [f.severity for f in findings] == [Severity.MEDIUM] * 5 + [Severity.LOW]
    assert all(f.evidence[0].kind == "tls" for f in findings)
    assert "self-signed" in findings[2].why
    assert "legacy.fixture.test" in findings[1].why
    observed = ctx.observations["tls"]
    assert observed["deprecated protocols"] == ["TLS 1.0", "TLS 1.1"]
    assert observed["chain"].startswith("not trusted")


async def test_tls_silent_on_clean(make_ctx, clean_tls_app: FixtureApp) -> None:
    ctx = make_ctx(clean_tls_app.url)
    assert await TlsAnalysis().run(ctx.target, ctx) == []
    observed = ctx.observations["tls"]
    assert observed["chain"] == "trusted"
    assert observed["deprecated protocols"] == ["none accepted"]
    assert observed["weak ciphers"] == observed["forward secrecy"] == "not accepted"
    assert clean_tls_app.requests == [], "TLS analysis sends handshakes only, no HTTP requests"


async def test_tls_reports_a_certificate_about_to_expire(
    make_ctx, expiring_tls_app: FixtureApp
) -> None:
    findings = await run(TlsAnalysis(), make_ctx, expiring_tls_app.url)
    assert titles(findings) == ["TLS certificate expires soon"]
    assert findings[0].severity is Severity.LOW


async def test_tls_reports_an_untrusted_issuer(make_ctx, clean_tls_app: FixtureApp) -> None:
    # Same well-configured server, but the fixture CA is not in the trust store this time.
    findings = await run(TlsAnalysis(), make_ctx, clean_tls_app.url, trust_fixture_ca=False)
    assert titles(findings) == ["TLS certificate is not trusted"]


async def test_plain_http_is_reported_except_on_loopback(
    make_ctx, vulnerable_app: FixtureApp
) -> None:
    findings: list[Finding] = await run(
        TlsAnalysis(), make_ctx, f"http://{VULNERABLE}", routes={VULNERABLE: vulnerable_app.url}
    )
    assert_well_formed(findings)
    assert titles(findings) == ["Site is served without transport encryption"]
    assert findings[0].severity is Severity.MEDIUM and findings[0].cwe == "CWE-319"

    with pytest.raises(CheckSkipped, match="loopback"):
        await run(TlsAnalysis(), make_ctx, vulnerable_app.url)


async def test_tls_probe_refuses_hosts_outside_scope(make_ctx, clean_tls_app: FixtureApp) -> None:
    ctx = make_ctx(f"https://127.0.0.1:{clean_tls_app.port}")
    with pytest.raises(Exception, match="not in scope"):
        await tlsutil.probe(ctx.scope, "localhost", clean_tls_app.port)


def test_certificate_rules() -> None:
    now = dt.datetime(2026, 6, 1, tzinfo=dt.UTC)

    def cert(**overrides) -> tlsutil.CertInfo:
        values = {
            "subject": "CN=site.example",
            "issuer": "CN=Some CA",
            "not_before": now - dt.timedelta(days=30),
            "not_after": now + dt.timedelta(days=60),
            "sans": ["site.example", "*.site.example"],
            "key_type": "RSA",
            "key_bits": 2048,
            "signature_hash": "sha256",
        }
        return tlsutil.CertInfo(**{**values, **overrides})

    def problems(certificate: tlsutil.CertInfo, host: str = "site.example") -> list[str]:
        return [title for title, *_ in certificate_problems(certificate, host, now)]

    assert problems(cert()) == []
    assert problems(cert(), host="www.site.example") == []  # wildcard covers one label
    assert problems(cert(), host="a.b.site.example") == [
        "TLS certificate does not match the host name"
    ]
    assert problems(cert(key_bits=1024)) == ["TLS certificate uses a weak key"]
    assert problems(cert(key_type="EC", key_bits=256)) == []
    assert problems(cert(signature_hash="sha1")) == ["TLS certificate is signed with a broken hash"]
    assert problems(cert(not_before=now + dt.timedelta(days=1))) == [
        "TLS certificate is not yet valid"
    ]
    assert tlsutil.hostname_matches("127.0.0.1", ["localhost", "127.0.0.1"])
    assert not tlsutil.hostname_matches("example", ["*.example"])
