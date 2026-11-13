"""Tiny authoritative DNS server on loopback, so DNS checks are tested without the internet."""

from __future__ import annotations

import socketserver
import threading

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

_DNSKEY = (
    "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl"
    "+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
)


def _soa(zone: str) -> list[str]:
    return [f"ns1.{zone}. hostmaster.{zone}. 2024010101 7200 3600 1209600 3600"]


# name -> record type -> rdata in zone-file text form
ZONES: dict[str, dict[str, list[str]]] = {
    # Weak email posture, no CAA, no DNSSEC, and records that reveal subdomains.
    "vulnerable-fixture.test": {
        "SOA": _soa("vulnerable-fixture.test"),
        "A": ["192.0.2.10"],
        "NS": ["ns1.vulnerable-fixture.test.", "ns2.vulnerable-fixture.test."],
        "MX": ["10 mail.vulnerable-fixture.test."],
        "TXT": ['"v=spf1 a:legacy-relay.vulnerable-fixture.test +all"'],
    },
    "_dmarc.vulnerable-fixture.test": {"TXT": ['"v=DMARC1; p=none"']},
    "app.vulnerable-fixture.test": {"A": ["192.0.2.11"]},
    # A domain with no email authentication records at all.
    "bare-fixture.test": {
        "SOA": _soa("bare-fixture.test"),
        "A": ["192.0.2.30"],
        "NS": ["ns1.dnshost.example."],
    },
    # Hardened: strict SPF, enforcing DMARC, DKIM, CAA, DNSSEC; nothing points at a subdomain.
    "clean-fixture.test": {
        "SOA": [
            "ns1.dnshost.example. hostmaster.dnshost.example. 2024010101 7200 3600 1209600 3600"
        ],
        "A": ["192.0.2.20"],
        "NS": ["ns1.dnshost.example.", "ns2.dnshost.example."],
        "MX": ["10 mx.mailhost.example."],
        "TXT": ['"v=spf1 include:_spf.mailhost.example -all"'],
        "CAA": ['0 issue "letsencrypt.org"'],
        "DNSKEY": [_DNSKEY],
    },
    "_dmarc.clean-fixture.test": {
        "TXT": ['"v=DMARC1; p=reject; rua=mailto:dmarc-reports@mailhost.example"']
    },
    "selector1._domainkey.clean-fixture.test": {
        "TXT": ['"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDfixture"']
    },
    "app.clean-fixture.test": {"A": ["192.0.2.21"]},
}


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        try:
            query = dns.message.from_wire(data)
        except Exception:  # noqa: BLE001
            return
        question = query.question[0]
        name = question.name.to_text(omit_final_dot=True).lower()
        rdtype = dns.rdatatype.to_text(question.rdtype)
        server: FixtureDns = self.server.fixture  # type: ignore[attr-defined]
        with server.lock:
            server.queries.append((name, rdtype))
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        records = server.zones.get(name)
        if records is None:
            is_parent = any(known.endswith("." + name) for known in server.zones)
            if not is_parent:
                response.set_rcode(dns.rcode.NXDOMAIN)
        elif rdtype in records:
            response.answer.append(
                dns.rrset.from_text(question.name, 300, "IN", rdtype, *records[rdtype])
            )
        sock.sendto(response.to_wire(), self.client_address)


class FixtureDns:
    def __init__(self, zones: dict[str, dict[str, list[str]]] | None = None) -> None:
        self.zones = ZONES if zones is None else zones
        self.queries: list[tuple[str, str]] = []
        self.lock = threading.Lock()
        self._server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), _Handler)
        self._server.daemon_threads = True
        self._server.fixture = self  # type: ignore[attr-defined]
        self.port = self._server.server_address[1]

    def start(self) -> FixtureDns:
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
