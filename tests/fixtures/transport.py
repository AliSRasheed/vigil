"""Routes fixture hostnames to the local fixture servers.

Lets tests scan a non-loopback *name* (so the authorization gate applies) while every
byte still goes to 127.0.0.1. It also records each host the scanner tried to reach,
which is what the "never requests an out-of-scope host" tests assert on.
"""

from __future__ import annotations

import httpx


class RewriteTransport(httpx.AsyncBaseTransport):
    def __init__(self, routes: dict[str, str]) -> None:
        self.routes = routes  # hostname -> base URL of a local fixture server
        self.seen: list[str] = []  # every host a request was addressed to
        self._inner = httpx.AsyncHTTPTransport(verify=False)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        self.seen.append(host)
        if host not in self.routes:
            raise httpx.ConnectError(f"no fixture route for {host}: tests never touch the internet")
        base = httpx.URL(self.routes[host])
        request.url = request.url.copy_with(scheme=base.scheme, host=base.host, port=base.port)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
