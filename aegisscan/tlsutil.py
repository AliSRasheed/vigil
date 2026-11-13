"""TLS handshake probing.

A probe is one TLS handshake with chosen parameters, closed straight after it
completes. No application data is sent. Every probe passes the scope gate.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import ipaddress
import socket
import ssl
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from aegisscan.scope import Scope


class TlsProbeError(Exception):
    """The handshake did not complete."""

    def __init__(
        self, message: str, *, verify_message: str | None = None, local: bool = False
    ) -> None:
        super().__init__(message)
        self.verify_message = verify_message  # set when certificate verification failed
        self.local = local  # True when our own TLS library could not build the probe


@dataclass
class CertInfo:
    subject: str
    issuer: str
    not_before: dt.datetime
    not_after: dt.datetime
    sans: list[str] = field(default_factory=list)
    key_type: str = "unknown"
    key_bits: int = 0
    signature_hash: str = "unknown"
    self_signed: bool = False
    sha256: str = ""

    def days_remaining(self, now: dt.datetime | None = None) -> int:
        now = now or dt.datetime.now(dt.UTC)
        return (self.not_after - now).days

    def summary(self) -> str:
        return "\n".join(
            [
                f"subject:    {self.subject}",
                f"issuer:     {self.issuer}",
                f"valid from: {self.not_before:%Y-%m-%d %H:%M} UTC",
                f"valid to:   {self.not_after:%Y-%m-%d %H:%M} UTC",
                f"names:      {', '.join(self.sans) or '(none)'}",
                f"key:        {self.key_type} {self.key_bits} bits",
                f"signature:  {self.signature_hash}",
                f"sha256:     {self.sha256}",
            ]
        )


@dataclass
class Handshake:
    protocol: str
    cipher: str
    bits: int
    cert: CertInfo | None


def parse_certificate(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    sans: list[str] = []
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [*extension.get_values_for_type(x509.DNSName)]
        sans += [str(address) for address in extension.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", key.curve.key_size
    else:
        key_type, key_bits = type(key).__name__.replace("PublicKey", ""), 0
    algorithm = cert.signature_hash_algorithm
    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sans=sans,
        key_type=key_type,
        key_bits=key_bits,
        signature_hash=algorithm.name if algorithm is not None else "none",
        self_signed=cert.subject == cert.issuer,
        sha256=hashlib.sha256(der).hexdigest(),
    )


def hostname_matches(host: str, names: list[str]) -> bool:
    """RFC 6125 style match of ``host`` against certificate names (left-most wildcard only)."""
    host = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for name in names:
        name = name.lower().rstrip(".")
        if address is not None:
            try:
                if ipaddress.ip_address(name) == address:
                    return True
            except ValueError:
                pass
            continue
        if name == host:
            return True
        if name.startswith("*.") and "." in host:
            first, rest = host.split(".", 1)
            if first and rest == name[2:]:
                return True
    return False


def _context(
    *,
    verify: bool,
    ca_file: Path | None,
    min_version: ssl.TLSVersion | None,
    max_version: ssl.TLSVersion | None,
    ciphers: str | None,
) -> ssl.SSLContext:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        if verify:
            context = ssl.create_default_context()
            # Judge certificates the way browsers do, not by the stricter RFC 5280 profile.
            context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
            if ca_file is not None:
                context.load_verify_locations(cafile=str(ca_file))
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if ciphers is not None:
            context.set_ciphers(ciphers)
        if min_version is not None:
            context.minimum_version = min_version
        if max_version is not None:
            context.maximum_version = max_version
    return context


def _handshake(host: str, port: int, context: ssl.SSLContext, timeout: float) -> Handshake:
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        context.wrap_socket(raw, server_hostname=host) as tls,
    ):
        name, _, bits = tls.cipher() or ("unknown", "", 0)
        der = tls.getpeercert(binary_form=True)
        protocol = tls.version() or "unknown"
        with contextlib.suppress(OSError):
            tls.unwrap()
    return Handshake(
        protocol=protocol,
        cipher=name,
        bits=bits or 0,
        cert=parse_certificate(der) if der else None,
    )


async def probe(
    scope: Scope,
    host: str,
    port: int,
    *,
    verify: bool = False,
    ca_file: Path | None = None,
    min_version: ssl.TLSVersion | None = None,
    max_version: ssl.TLSVersion | None = None,
    ciphers: str | None = None,
    timeout: float = 10.0,
) -> Handshake:
    """Perform one TLS handshake with ``host``. Raises `TlsProbeError` if it fails."""
    scope.check_host(host)  # the scope gate
    try:
        context = _context(
            verify=verify,
            ca_file=ca_file,
            min_version=min_version,
            max_version=max_version,
            ciphers=ciphers,
        )
    except (ssl.SSLError, ValueError, OSError) as exc:
        raise TlsProbeError(
            f"local TLS library cannot build this probe: {exc}", local=True
        ) from exc
    try:
        return await asyncio.to_thread(_handshake, host, port, context, timeout)
    except ssl.SSLCertVerificationError as exc:
        raise TlsProbeError(str(exc), verify_message=exc.verify_message) from exc
    except (ssl.SSLError, OSError) as exc:
        raise TlsProbeError(f"{type(exc).__name__}: {exc}") from exc
