"""DNS lookups for the recon checks.

Queries go to the operator's configured resolver (or one passed explicitly),
never to the target or to third-party lookup services. Checks only ask about
names derived from the target host.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from vigil.models import Evidence


@dataclass
class DnsAnswer:
    name: str
    rdtype: str
    status: str  # NOERROR | NODATA | NXDOMAIN | ERROR
    records: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def found(self) -> bool:
        return self.status == "NOERROR" and bool(self.records)

    @property
    def failed(self) -> bool:
        return self.status == "ERROR"

    def evidence(self, note: str) -> Evidence:
        if self.records:
            body = "\n".join(self.records)
        elif self.status == "ERROR":
            body = f"lookup failed: {self.error}"
        else:
            body = f"{self.status} (no {self.rdtype} record)"
        return Evidence(
            kind="dns", request=f"DNS query: {self.name} IN {self.rdtype}", response=body, note=note
        )


class DnsClient:
    def __init__(
        self, nameservers: list[str] | None = None, port: int = 53, timeout: float = 3.0
    ) -> None:
        self._nameservers = nameservers
        self._port = port
        self._timeout = timeout
        self._resolver: dns.asyncresolver.Resolver | None = None
        self._cache: dict[tuple[str, str], DnsAnswer] = {}
        self._lock = asyncio.Lock()
        self.queries_sent = 0

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        if self._resolver is None:
            resolver = dns.asyncresolver.Resolver(configure=self._nameservers is None)
            if self._nameservers is not None:
                resolver.nameservers = list(self._nameservers)
            resolver.port = self._port
            resolver.timeout = self._timeout
            resolver.lifetime = self._timeout
            self._resolver = resolver
        return self._resolver

    async def query(self, name: str, rdtype: str) -> DnsAnswer:
        name = name.rstrip(".").lower()
        rdtype = rdtype.upper()
        key = (name, rdtype)
        async with self._lock:
            if key not in self._cache:
                self._cache[key] = await self._query(name, rdtype)
            return self._cache[key]

    async def _query(self, name: str, rdtype: str) -> DnsAnswer:
        self.queries_sent += 1
        try:
            answer = await self._get_resolver().resolve(name, rdtype, search=False)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(name, rdtype, "NXDOMAIN")
        except dns.resolver.NoAnswer:
            return DnsAnswer(name, rdtype, "NODATA")
        except (dns.exception.DNSException, OSError) as exc:
            return DnsAnswer(name, rdtype, "ERROR", error=f"{type(exc).__name__}: {exc}")
        wanted = dns.rdatatype.from_text(rdtype)
        records = []
        for rdata in answer:
            if rdata.rdtype != wanted:
                continue
            if rdtype == "TXT":
                records.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
            else:
                records.append(rdata.to_text())
        return DnsAnswer(name, rdtype, "NOERROR" if records else "NODATA", records)


def is_ip_literal(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


async def zone_apex(dns_client: DnsClient, host: str) -> str:
    """Closest enclosing zone for ``host``: the first ancestor that answers an SOA query.

    Used as the organizational domain for email and CA policy lookups. Falls back to the
    host itself when no SOA is found.
    """
    labels = host.split(".")
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        answer = await dns_client.query(candidate, "SOA")
        if answer.found:
            return candidate
    return host
