"""Deliberately misconfigured local web application used as the scan target in tests.

Two modes share the same routes:

* ``vulnerable``: every weakness the v1 checks look for.
* ``clean``: hardened. It answers unknown paths with a "soft 404" (HTTP 200 and a generic
  page), which is what makes naive scanners report false positives.

Standard library only. All "secrets" served here are fake.

Run it by hand:  python -m tests.fixtures.app --mode vulnerable --port 8808 [--tls]
"""

from __future__ import annotations

import argparse
import json
import ssl
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

TRUSTED_ORIGIN = "https://trusted.partner.example"
FAKE_SECRET = "fixture-not-a-real-secret"

VULNERABLE_HEADERS = [
    ("Server", "Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3"),
    ("X-Powered-By", "PHP/7.4.3"),
]
CLEAN_HEADERS = [
    (
        "Content-Security-Policy",
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    ),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
]

VULNERABLE_HOME = """<!doctype html>
<html><head><title>Fixture Shop</title>
<meta name="generator" content="WordPress 5.8.1">
<link rel="stylesheet" href="/wp-content/themes/shop/style.css">
<script src="/static/js/jquery-3.4.1.min.js"></script>
</head><body>
<h1>Fixture Shop</h1>
<p><a href="/static/">Downloads</a> <a href="/redirect-out">Partner offer</a></p>
<p><a href="{foreign}/landing">Partner site</a>
<a href="https://cdn.thirdparty.example/lib.js">CDN</a>{staging}</p>
<img src="/uploads/logo.png" alt="logo">
</body></html>
"""

CLEAN_HOME = """<!doctype html>
<html><head><title>Fixture Shop</title>
<link rel="stylesheet" href="/static/app.css">
</head><body>
<h1>Fixture Shop</h1>
<p><a href="/about">About</a></p>
</body></html>
"""

SOFT_404 = """<!doctype html>
<html><head><title>Fixture Shop</title></head><body>
<h1>Page not found</h1><p>Sorry, we could not find that page. <a href="/">Home</a></p>
</body></html>
"""

VERBOSE_404 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>500 Internal Server Error</title></head><body>
<h1>Unhandled exception</h1>
<pre>Traceback (most recent call last):
  File "/var/www/shop/app/router.py", line 42, in dispatch
    handler = self.routes[path]
KeyError: '{path}'
</pre>
<hr><address>Apache/2.4.49 (Unix) Server at {host} Port 80</address>
</body></html>
"""

DIRECTORY_INDEX = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of {path}</title></head><body>
<h1>Index of {path}</h1>
<table><tr><th>Name</th><th>Last modified</th><th>Size</th></tr>
<tr><td><a href="../">Parent Directory</a></td><td>&nbsp;</td><td>-</td></tr>
<tr><td><a href="report-2024.pdf">report-2024.pdf</a></td><td>2024-03-01 10:12</td><td>88K</td></tr>
<tr><td><a href="old/">old/</a></td><td>2023-11-20 08:01</td><td>-</td></tr>
</table></body></html>
"""

# path -> (content type, body). Served in vulnerable mode only.
EXPOSED_FILES: dict[str, tuple[str, bytes]] = {
    "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
    "/.git/config": (
        "text/plain",
        b'[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n'
        b"\turl = https://git.fixture.invalid/shop.git\n",
    ),
    "/.env": (
        "text/plain",
        f"APP_ENV=production\nDB_PASSWORD={FAKE_SECRET}\nSECRET_KEY={FAKE_SECRET}\n".encode(),
    ),
    "/backup.zip": ("application/zip", b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 64),
    "/config.php.bak": (
        "application/octet-stream",
        f"<?php\n$db_host = 'localhost';\n$db_password = '{FAKE_SECRET}';\n".encode(),
    ),
    "/database.sql": (
        "application/sql",
        b"-- MySQL dump 10.13\nCREATE TABLE users (id INT, email VARCHAR(255));\n"
        b"INSERT INTO users VALUES (1, 'fixture@example.invalid');\n",
    ),
    "/phpinfo.php": (
        "text/html",
        b"<html><head><title>phpinfo()</title></head><body><h1>PHP Version 7.4.3</h1>"
        b"<table><tr><td>System</td><td>Linux fixture 5.4.0</td></tr></table></body></html>",
    ),
    "/server-status": (
        "text/html",
        b"<html><head><title>Apache Status</title></head><body>"
        b"<h1>Apache Server Status for fixture</h1><dl><dt>Server Version: Apache/2.4.49</dt></dl>"
        b"</body></html>",
    ),
    "/.DS_Store": ("application/octet-stream", b"\x00\x00\x00\x01Bud1" + b"\x00" * 32),
}
STATIC_FILES: dict[str, tuple[str, bytes]] = {
    "/static/js/jquery-3.4.1.min.js": ("application/javascript", b"/*! jQuery v3.4.1 */\n"),
    "/wp-content/themes/shop/style.css": ("text/css", b"body { font-family: sans-serif }\n"),
    "/uploads/logo.png": ("image/png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16),
}
LISTED_DIRECTORIES = ("/static/", "/uploads/", "/backup/")


@dataclass
class RecordedRequest:
    method: str
    path: str
    host: str
    headers: dict[str, str] = field(default_factory=dict)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    app: FixtureApp

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    # -- plumbing ----------------------------------------------------------

    def _respond(
        self,
        status: int,
        body: bytes | str = b"",
        content_type: str = "text/html; charset=utf-8",
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        if isinstance(body, str):
            body = body.encode()
        self.send_response_only(status)
        vulnerable = self.app.mode == "vulnerable"
        for name, value in VULNERABLE_HEADERS if vulnerable else CLEAN_HEADERS:
            self.send_header(name, value)
        for name, value in self._cors_headers():
            self.send_header(name, value)
        for name, value in headers or []:
            self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _cors_headers(self) -> list[tuple[str, str]]:
        origin = self.headers.get("Origin")
        if not origin:
            return []
        allow = [
            ("Access-Control-Allow-Origin", origin),
            ("Access-Control-Allow-Credentials", "true"),
            ("Vary", "Origin"),
        ]
        if self.app.mode == "clean":
            return allow if origin == TRUSTED_ORIGIN else []
        path = urlsplit(self.path).path
        hostname = self._hostname()
        if path == "/cors/null":
            return allow if origin == "null" else []
        if path == "/cors/prefix":
            return allow if origin.startswith(f"https://{hostname}") else []
        if path == "/cors/reflect-no-credentials":
            return [("Access-Control-Allow-Origin", origin)]
        return allow

    def _hostname(self) -> str:
        host = self.headers.get("Host", "")
        if host.startswith("["):
            return host[1 : host.index("]")]
        return host.rsplit(":", 1)[0] if ":" in host else host

    def _counter(self, name: str) -> int:
        key = name + "?" + (urlsplit(self.path).query or "")
        with self.app.lock:
            self.app.counters[key] = self.app.counters.get(key, 0) + 1
            return self.app.counters[key]

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    do_HEAD = do_GET  # noqa: N815
    do_OPTIONS = do_GET  # noqa: N815
    do_POST = do_GET  # noqa: N815

    def _dispatch(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path
        with self.app.lock:
            self.app.requests.append(
                RecordedRequest(
                    self.command, self.path, self.headers.get("Host", ""), dict(self.headers)
                )
            )
        vulnerable = self.app.mode == "vulnerable"

        if path == "/":
            self._home()
        elif path == "/redirect-out":
            self._respond(302, headers=[("Location", f"{self.app.foreign}/landing")])
        elif path == "/redirect-in":
            self._respond(302, headers=[("Location", "/page2")])
        elif path == "/redirect-elsewhere-in-scope":
            self._respond(302, headers=[("Location", f"{self.app.foreign}/landing")])
        elif path in (
            "/page2",
            "/landing",
            "/about",
            "/admin/panel",
            "/cors/null",
            "/cors/prefix",
            "/cors/reflect-no-credentials",
        ):
            self._respond(200, f"<html><body><h1>{path}</h1></body></html>")
        elif path == "/echo-headers":
            self._respond(200, json.dumps(dict(self.headers)), "application/json")
        elif path == "/big":
            self._respond(200, b"A" * (1024 * 1024), "application/octet-stream")
        elif path == "/retry-after":
            if self._counter("retry-after") == 1:
                self._respond(429, "slow down", "text/plain", [("Retry-After", "1")])
            else:
                self._respond(200, "ok", "text/plain")
        elif path == "/retry-long":
            self._respond(429, "slow down", "text/plain", [("Retry-After", "3600")])
        elif path == "/busy":
            if self._counter("busy") == 1:
                self._respond(503, "busy", "text/plain")
            else:
                self._respond(200, "ok", "text/plain")
        elif path == "/always-busy":
            self._respond(503, "busy", "text/plain", [("Retry-After", "0")])
        elif path == "/static/app.css" and not vulnerable:
            self._respond(200, "body { margin: 0 }\n", "text/css")
        elif path == "/static/" and not vulnerable:
            self._respond(403, "<html><body><h1>Forbidden</h1></body></html>")
        elif vulnerable and path in LISTED_DIRECTORIES:
            self._respond(200, DIRECTORY_INDEX.format(path=path))
        elif vulnerable and path in EXPOSED_FILES:
            content_type, body = EXPOSED_FILES[path]
            self._respond(200, body, content_type)
        elif vulnerable and path in STATIC_FILES:
            content_type, body = STATIC_FILES[path]
            self._respond(200, body, content_type)
        else:
            self._not_found(path)

    def _home(self) -> None:
        if self.app.mode == "vulnerable":
            hostname = self._hostname()
            named = any(ch.isalpha() for ch in hostname) and ":" not in hostname
            staging = f'\n<a href="http://staging.{hostname}/">Staging</a>' if named else ""
            body = VULNERABLE_HOME.format(foreign=self.app.foreign, staging=staging)
            cookies = [
                ("Set-Cookie", "PHPSESSID=7f3a9c2e5b1d4f60a8c1; path=/"),
                ("Set-Cookie", "prefs=dark; Path=/; SameSite=None"),
            ]
        else:
            body = CLEAN_HOME
            cookies = [
                (
                    "Set-Cookie",
                    "__Host-session=5d0c1f7e9a3b4c62; Path=/; Secure; HttpOnly; SameSite=Lax",
                )
            ]
        self._respond(200, body, headers=cookies)

    def _not_found(self, path: str) -> None:
        if self.app.mode == "vulnerable":
            self._respond(404, VERBOSE_404.format(path=path, host=self._hostname()))
        else:
            self._respond(200, SOFT_404)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def handle_error(self, request: object, client_address: object) -> None:
        pass  # failed TLS handshakes from protocol probes are expected


class FixtureApp:
    def __init__(
        self,
        mode: str = "vulnerable",
        *,
        tls: ssl.SSLContext | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        public_host: str | None = None,
    ) -> None:
        if mode not in ("vulnerable", "clean"):
            raise ValueError(mode)
        self.mode = mode
        self.tls = tls
        self.lock = threading.Lock()
        self.requests: list[RecordedRequest] = []
        self.counters: dict[str, int] = {}
        self.foreign = "https://partner.thirdparty.example"
        handler = type("Handler", (_Handler,), {"app": self})
        self._server = _Server((host, port), handler)
        if tls is not None:
            self._server.socket = tls.wrap_socket(
                self._server.socket, server_side=True, do_handshake_on_connect=False
            )
        self.port = self._server.server_address[1]
        self.host = public_host or host
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        scheme = "https" if self.tls is not None else "http"
        return f"{scheme}://{self.host}:{self.port}"

    def start(self) -> FixtureApp:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def reset(self) -> None:
        with self.lock:
            self.requests.clear()
            self.counters.clear()
        self.foreign = "https://partner.thirdparty.example"

    def paths(self) -> list[str]:
        with self.lock:
            return [request.path for request in self.requests]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=["vulnerable", "clean"], default="vulnerable")
    parser.add_argument("--port", type=int, default=8808)
    parser.add_argument("--tls", action="store_true", help="serve HTTPS with a test certificate")
    args = parser.parse_args()
    tls = None
    if args.tls:
        import tempfile
        from pathlib import Path

        from tests.fixtures.certs import make_tls_material

        material = make_tls_material(Path(tempfile.mkdtemp(prefix="aegisscan-fixture-")))
        tls = material.vulnerable if args.mode == "vulnerable" else material.clean
        if args.mode == "clean":
            print(f"CA bundle for --ca-bundle: {material.ca_file}")
    app = FixtureApp(args.mode, tls=tls, port=args.port, public_host="localhost").start()
    print(f"{args.mode} fixture app listening on {app.url}  (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        app.stop()


if __name__ == "__main__":
    main()
