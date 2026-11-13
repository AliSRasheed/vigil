"""Shared fixtures. Everything runs on loopback; no test may touch the internet."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator

import pytest

from tests.fixtures.app import FixtureApp
from tests.fixtures.certs import TlsMaterial, make_tls_material
from tests.fixtures.dns_server import FixtureDns
from tests.fixtures.transport import RewriteTransport
from vigil import engine as engine_module
from vigil.engine import ScanContext, ScanOptions
from vigil.http import HttpClient
from vigil.resolver import DnsClient
from vigil.scope import ENV_VAR, Permit, authorize

FAST = ScanOptions(rate=None, timeout=5.0, retries=1)


def _is_loopback(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode()
    if not isinstance(host, str):
        return True  # e.g. None: wildcard bind
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True, scope="session")
def no_internet() -> Iterator[None]:
    """Safety net: name resolution and connects to anything but loopback fail loudly."""
    patcher = pytest.MonkeyPatch()
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect

    def guarded_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        if not _is_loopback(host):
            raise socket.gaierror(f"test tried to resolve non-loopback host {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    def guarded_connect(self, address):  # noqa: ANN001, ANN202
        if isinstance(address, tuple) and not _is_loopback(address[0]):
            raise OSError(f"test tried to connect to non-loopback address {address!r}")
        return real_connect(self, address)

    patcher.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    patcher.setattr(socket.socket, "connect", guarded_connect)
    yield
    patcher.undo()


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)


# --- servers ----------------------------------------------------------------


@pytest.fixture(scope="session")
def _servers(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict]:
    material = make_tls_material(tmp_path_factory.mktemp("tls"))
    servers = {
        "vulnerable": FixtureApp("vulnerable").start(),
        "clean": FixtureApp("clean").start(),
        "foreign": FixtureApp("clean").start(),
        "vulnerable_tls": FixtureApp(
            "vulnerable", tls=material.vulnerable, public_host="localhost"
        ),
        "clean_tls": FixtureApp("clean", tls=material.clean, public_host="localhost"),
        "expiring_tls": FixtureApp("clean", tls=material.expiring, public_host="localhost"),
    }
    for name in ("vulnerable_tls", "clean_tls", "expiring_tls"):
        servers[name].start()
    dns = FixtureDns().start()
    yield {**servers, "dns": dns, "tls": material}
    for server in servers.values():
        server.stop()
    dns.stop()


def _app(servers: dict, name: str) -> FixtureApp:
    app: FixtureApp = servers[name]
    app.reset()
    return app


@pytest.fixture
def vulnerable_app(_servers: dict) -> FixtureApp:
    return _app(_servers, "vulnerable")


@pytest.fixture
def clean_app(_servers: dict) -> FixtureApp:
    return _app(_servers, "clean")


@pytest.fixture
def foreign_app(_servers: dict) -> FixtureApp:
    """Stands in for a host the operator did not name. It must never receive a request."""
    return _app(_servers, "foreign")


@pytest.fixture
def vulnerable_tls_app(_servers: dict) -> FixtureApp:
    return _app(_servers, "vulnerable_tls")


@pytest.fixture
def clean_tls_app(_servers: dict) -> FixtureApp:
    return _app(_servers, "clean_tls")


@pytest.fixture
def expiring_tls_app(_servers: dict) -> FixtureApp:
    return _app(_servers, "expiring_tls")


@pytest.fixture
def tls_material(_servers: dict) -> TlsMaterial:
    return _servers["tls"]


@pytest.fixture
def dns_server(_servers: dict) -> FixtureDns:
    server: FixtureDns = _servers["dns"]
    server.queries.clear()
    return server


@pytest.fixture
def dns_client(dns_server: FixtureDns) -> DnsClient:
    return DnsClient(nameservers=["127.0.0.1"], port=dns_server.port, timeout=3.0)


@pytest.fixture(autouse=True)
def fixture_resolver(monkeypatch: pytest.MonkeyPatch, _servers: dict) -> None:
    """The engine's default resolver is the system one; in tests it is the fixture server."""
    port = _servers["dns"].port

    def make(**kwargs: object) -> DnsClient:
        return DnsClient(nameservers=["127.0.0.1"], port=port, timeout=3.0)

    monkeypatch.setattr(engine_module, "DnsClient", make)


# --- helpers ----------------------------------------------------------------


@pytest.fixture
def make_ctx(dns_client: DnsClient, tls_material: TlsMaterial):
    """Build a ScanContext for a URL, optionally routing fixture hostnames to local servers."""
    clients: list[HttpClient] = []

    def build(
        url: str,
        *,
        routes: dict[str, str] | None = None,
        permit: Permit | None = None,
        trust_fixture_ca: bool = True,
    ) -> ScanContext:
        permit = permit or authorize(url, flag=True)
        transport = RewriteTransport(routes) if routes is not None else None
        http = HttpClient(permit, rate=None, timeout=5.0, retries=1, transport=transport)
        clients.append(http)
        options = ScanOptions(
            rate=None, timeout=5.0, ca_file=tls_material.ca_file if trust_fixture_ca else None
        )
        return ScanContext(permit, http, dns_client, options)

    return build
