"""Shared async HTTP client.

Every HTTP request the scanner makes goes through `HttpClient._send`, which
enforces the scope gate, the per-host rate limit, retry/backoff and the
`Retry-After` header, and captures what is needed for evidence.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import re
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from http import HTTPStatus
from urllib.parse import urljoin, urlsplit

import httpx

from vigil import __version__
from vigil.models import Evidence, host_of
from vigil.scope import OutOfScopeError, OutOfScopeLog, Permit

USER_AGENT = f"Vigil/{__version__} (authorized security testing; non-destructive)"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
RETRY_STATUSES = frozenset({429, 503})
_REDACTED = "<redacted>"
_SENSITIVE_REQUEST_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


class RequestFailed(Exception):
    """The request could not be completed (connection error, timeout, bad response)."""


class UnsafeMethodError(Exception):
    """A state-changing HTTP method was attempted. v1 checks are read-only."""


@dataclass
class Response:
    method: str
    url: str
    status: int
    headers: httpx.Headers
    body: bytes
    truncated: bool
    request_headers: dict[str, str]
    http_version: str = "HTTP/1.1"
    history: list[Response] = field(default_factory=list)
    blocked_redirect: str | None = None

    @property
    def text(self) -> str:
        charset = "utf-8"
        match = re.search(r"charset=([\w-]+)", self.headers.get("content-type", ""), re.I)
        if match:
            charset = match.group(1)
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return self.content_type in ("text/html", "application/xhtml+xml")

    @property
    def is_redirect(self) -> bool:
        return self.status in REDIRECT_STATUSES and "location" in self.headers


class RateLimiter:
    """Spaces requests to each host at least ``1 / rate`` seconds apart."""

    def __init__(self, rate: float | None) -> None:
        self.interval = 1.0 / rate if rate else 0.0
        self._next_slot: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def wait(self, host: str) -> None:
        if not self.interval:
            return
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            slot = max(now, self._next_slot.get(host, 0.0))
            self._next_slot[host] = slot + self.interval
        if slot > now:
            await asyncio.sleep(slot - now)


def parse_retry_after(value: str | None) -> float | None:
    """Seconds to wait according to a Retry-After header (delta-seconds or HTTP-date)."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    return max(0.0, (when - dt.datetime.now(dt.UTC)).total_seconds())


class HttpClient:
    """Scope-gated, rate-limited HTTP client. Requires a `Permit` to exist."""

    def __init__(
        self,
        permit: Permit,
        *,
        rate: float | None = 5.0,
        concurrency: int = 5,
        timeout: float = 10.0,
        retries: int = 2,
        backoff: float = 0.5,
        max_retry_after: float = 30.0,
        max_body: int = 256 * 1024,
        transport: httpx.AsyncBaseTransport | None = None,
        out_of_scope: OutOfScopeLog | None = None,
    ) -> None:
        if not isinstance(permit, Permit):
            raise TypeError("HttpClient requires a Permit from vigil.scope.authorize()")
        self.permit = permit
        self.scope = permit.scope
        self.limiter = RateLimiter(rate)
        self.retries = retries
        self.backoff = backoff
        self.max_retry_after = max_retry_after
        self.max_body = max_body
        self.out_of_scope = out_of_scope if out_of_scope is not None else OutOfScopeLog()
        self.requests_sent = 0
        self._semaphore = asyncio.Semaphore(concurrency)
        # Certificate validity is assessed by the TLS check; the HTTP client must still be
        # able to scan a host whose certificate is invalid. Environment proxies are ignored
        # so that requests go to the named host and nowhere else.
        self._client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            timeout=timeout,
            follow_redirects=False,
            verify=False,
            trust_env=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> Response:
        return await self.request("GET", url, headers=headers, follow_redirects=follow_redirects)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
        max_redirects: int = 5,
    ) -> Response:
        """Send one request. Redirects are followed only on request and only while in scope."""
        method = method.upper()
        if method not in SAFE_METHODS:
            raise UnsafeMethodError(f"{method} is not allowed: v1 checks send read-only requests")
        history: list[Response] = []
        current = url
        while True:
            response = await self._send(method, current, headers)
            response.history = list(history)
            if not response.is_redirect:
                return response
            location = urljoin(current, response.headers["location"])
            reason = self.scope.violation(location)
            if reason is not None:
                # Recorded for the report, never followed.
                kind = (
                    "redirect"
                    if not self.scope.host_in_scope(host_of(location))
                    else ("excluded-path")
                )
                self.out_of_scope.record(location, kind, source=current)
                response.blocked_redirect = location
                return response
            if not follow_redirects or len(history) >= max_redirects:
                return response
            history.append(response)
            current = location

    async def _send(self, method: str, url: str, headers: dict[str, str] | None) -> Response:
        # The scope gate. Nothing below this line runs for an out-of-scope URL.
        try:
            self.scope.check_url(url)
        except OutOfScopeError as exc:
            kind = "blocked" if not self.scope.host_in_scope(exc.host) else "excluded-path"
            self.out_of_scope.record(url, kind, source="request refused by the scope gate")
            raise

        host = host_of(url)
        attempt = 0
        while True:
            await self.limiter.wait(host)
            try:
                async with self._semaphore:
                    response = await self._send_once(method, url, headers)
            except httpx.TransportError as exc:
                if attempt >= self.retries:
                    raise RequestFailed(f"{method} {url} failed: {exc!r}") from exc
                await asyncio.sleep(self.backoff * 2**attempt)
                attempt += 1
                continue
            except httpx.HTTPError as exc:
                raise RequestFailed(f"{method} {url} failed: {exc!r}") from exc

            if response.status in RETRY_STATUSES and attempt < self.retries:
                delay = parse_retry_after(response.headers.get("retry-after"))
                if delay is None:
                    delay = self.backoff * 2**attempt
                if delay <= self.max_retry_after:
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
            return response

    async def _send_once(self, method: str, url: str, headers: dict[str, str] | None) -> Response:
        request = self._client.build_request(method, url, headers=headers)
        sent_url = str(request.url)
        request_headers = dict(request.headers)
        self.requests_sent += 1
        raw = await self._client.send(request, stream=True)
        try:
            chunks: list[bytes] = []
            size = 0
            truncated = False
            async for chunk in raw.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= self.max_body:
                    # Enough to analyse; do not download the rest (e.g. a large backup file).
                    truncated = True
                    break
        finally:
            await raw.aclose()
        return Response(
            method=method,
            url=sent_url,
            status=raw.status_code,
            headers=raw.headers,
            body=b"".join(chunks)[: self.max_body],
            truncated=truncated,
            request_headers=request_headers,
            http_version=raw.http_version or "HTTP/1.1",
        )


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy value into {directive: [sources]}, lower-cased."""
    policy: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens and tokens[0].lower() not in policy:
            policy[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return policy


# --- evidence --------------------------------------------------------------


def redact_set_cookie(value: str) -> str:
    """Keep a Set-Cookie header's name and attributes, drop its value."""
    pair, sep, attributes = value.partition(";")
    name, eq, _ = pair.partition("=")
    if not eq:
        return value
    return f"{name}={_REDACTED}{sep}{attributes}"


def redact_values(text: str) -> str:
    """Mask the value of every KEY=VALUE or key: value line (for secrets files)."""
    return re.sub(
        r"(?m)^(\s*[\w.\-]+\s*[=:]\s*)\S.*$", lambda match: match.group(1) + _REDACTED, text
    )


def format_request(response: Response) -> str:
    parts = urlsplit(response.url)
    target = parts.path or "/"
    if parts.query:
        target += f"?{parts.query}"
    lines = [f"{response.method} {target} HTTP/1.1"]
    for name, value in response.request_headers.items():
        if name.lower() in _SENSITIVE_REQUEST_HEADERS:
            value = _REDACTED
        lines.append(f"{name.title()}: {value}")
    return "\n".join(lines)


def format_response(response: Response, excerpt: str | None = None, limit: int = 400) -> str:
    try:
        phrase = HTTPStatus(response.status).phrase
    except ValueError:
        phrase = ""
    lines = [f"{response.http_version} {response.status} {phrase}".rstrip()]
    for name, value in response.headers.multi_items():
        if name.lower() == "set-cookie":
            value = redact_set_cookie(value)
        lines.append(f"{name.title()}: {value}")
    if excerpt is None:
        if not response.body:
            excerpt = ""
        elif b"\x00" in response.body[:512]:
            excerpt = f"<{len(response.body)} bytes of binary data>"
        else:
            excerpt = response.text.strip()
    if len(excerpt) > limit:
        excerpt = excerpt[:limit].rstrip() + "\n[... truncated]"
    if excerpt:
        lines += ["", excerpt]
    return "\n".join(lines)


def http_evidence(response: Response, note: str, *, excerpt: str | None = None) -> Evidence:
    """Evidence for a finding: the request sent, the relevant response excerpt, and why."""
    return Evidence(
        kind="http",
        request=format_request(response),
        response=format_response(response, excerpt),
        note=note,
    )
