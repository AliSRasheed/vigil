"""The shared HTTP client: politeness, retries, body cap, evidence capture."""

from __future__ import annotations

import json
import time

import pytest

from aegisscan import __version__
from aegisscan.http import (
    HttpClient,
    RequestFailed,
    UnsafeMethodError,
    http_evidence,
    parse_retry_after,
    redact_set_cookie,
    redact_values,
)
from aegisscan.scope import authorize
from tests.fixtures.app import FixtureApp


def client_for(app: FixtureApp, **kwargs: object) -> HttpClient:
    kwargs.setdefault("rate", None)
    return HttpClient(authorize(app.url), **kwargs)  # type: ignore[arg-type]


async def test_user_agent_identifies_the_scanner(clean_app: FixtureApp) -> None:
    async with client_for(clean_app) as http:
        response = await http.get(f"{clean_app.url}/echo-headers")
    sent = {name.lower(): value for name, value in json.loads(response.text).items()}
    assert sent["user-agent"].startswith(f"AegisScan/{__version__}")


async def test_requests_to_a_host_are_rate_limited(clean_app: FixtureApp) -> None:
    async with client_for(clean_app, rate=20.0) as http:
        began = time.monotonic()
        for _ in range(5):
            await http.get(f"{clean_app.url}/page2")
        elapsed = time.monotonic() - began
    assert elapsed >= 0.19, f"5 requests at 20/s must take at least 0.2s, took {elapsed:.3f}s"
    assert http.requests_sent == 5


async def test_retry_after_is_honoured(clean_app: FixtureApp) -> None:
    async with client_for(clean_app) as http:
        began = time.monotonic()
        response = await http.get(f"{clean_app.url}/retry-after?t=honoured")
        elapsed = time.monotonic() - began
    assert response.status == 200
    assert elapsed >= 0.95, "the client must wait the Retry-After second before retrying"
    assert len(clean_app.paths()) == 2


async def test_an_excessive_retry_after_is_not_waited_out(clean_app: FixtureApp) -> None:
    async with client_for(clean_app) as http:
        response = await http.get(f"{clean_app.url}/retry-long")
    assert response.status == 429
    assert len(clean_app.paths()) == 1


async def test_503_is_retried_with_backoff(clean_app: FixtureApp) -> None:
    async with client_for(clean_app, backoff=0.01) as http:
        response = await http.get(f"{clean_app.url}/busy?t=backoff")
    assert response.status == 200
    assert len(clean_app.paths()) == 2


async def test_retries_are_bounded(clean_app: FixtureApp) -> None:
    async with client_for(clean_app, retries=2) as http:
        response = await http.get(f"{clean_app.url}/always-busy")
    assert response.status == 503
    assert len(clean_app.paths()) == 3


async def test_connection_failure_raises_request_failed() -> None:
    async with HttpClient(
        authorize("http://127.0.0.1:1/"), rate=None, retries=1, backoff=0.01, timeout=2.0
    ) as http:
        with pytest.raises(RequestFailed):
            await http.get("http://127.0.0.1:1/")


async def test_response_bodies_are_capped(clean_app: FixtureApp) -> None:
    async with client_for(clean_app, max_body=4096) as http:
        response = await http.get(f"{clean_app.url}/big")
    assert response.truncated
    assert len(response.body) == 4096


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
async def test_state_changing_methods_are_refused(clean_app: FixtureApp, method: str) -> None:
    async with client_for(clean_app) as http:
        with pytest.raises(UnsafeMethodError):
            await http.request(method, f"{clean_app.url}/")
    assert clean_app.requests == []


async def test_in_scope_redirects_are_followed_only_on_request(clean_app: FixtureApp) -> None:
    async with client_for(clean_app) as http:
        plain = await http.get(f"{clean_app.url}/redirect-in")
        followed = await http.get(f"{clean_app.url}/redirect-in", follow_redirects=True)
    assert plain.status == 302
    assert followed.status == 200
    assert followed.url.endswith("/page2")
    assert [hop.status for hop in followed.history] == [302]


async def test_evidence_captures_request_response_and_reason(vulnerable_app: FixtureApp) -> None:
    async with client_for(vulnerable_app) as http:
        response = await http.get(f"{vulnerable_app.url}/", headers={"Origin": "https://x.example"})
    evidence = http_evidence(response, "why this was flagged")
    assert evidence.request.startswith("GET / HTTP/1.1")
    assert "Origin: https://x.example" in evidence.request
    assert "User-Agent: AegisScan/" in evidence.request
    assert evidence.response.startswith("HTTP/1.1 200 OK")
    assert "X-Powered-By: PHP/7.4.3" in evidence.response
    assert "Fixture Shop" in evidence.response
    assert evidence.note == "why this was flagged"
    # session identifiers are data: never copied into a report
    assert "7f3a9c2e5b1d4f60a8c1" not in evidence.response
    assert "Set-Cookie: PHPSESSID=<redacted>; path=/" in evidence.response


def test_redaction_helpers() -> None:
    assert redact_set_cookie("sid=abc123; Path=/; HttpOnly") == "sid=<redacted>; Path=/; HttpOnly"
    redacted = redact_values("APP_ENV=production\nDB_PASSWORD=hunter2\n# comment\n")
    assert "hunter2" not in redacted and "production" not in redacted
    assert "DB_PASSWORD=<redacted>" in redacted


def test_retry_after_parsing() -> None:
    assert parse_retry_after("7") == 7.0
    assert parse_retry_after(None) is None
    assert parse_retry_after("soon") is None
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0
