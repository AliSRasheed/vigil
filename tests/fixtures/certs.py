"""Throwaway certificates for the HTTPS fixture servers, generated at test time."""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
import warnings
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisScan test fixtures"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _alt_names(names: list[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = []
    for name in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name))
    return x509.SubjectAlternativeName(entries)


def make_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    name = _name("AegisScan Fixture Root CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue(
    names: list[str],
    *,
    ca: tuple[rsa.RSAPrivateKey, x509.Certificate] | None = None,
    valid_from_days: int = -1,
    valid_to_days: int = 90,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Issue a leaf certificate. Without ``ca`` it is self-signed."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    subject = _name(names[0])
    issuer_key, issuer_name = (ca[0], ca[1].subject) if ca else (key, subject)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + dt.timedelta(days=valid_from_days))
        .not_valid_after(now + dt.timedelta(days=valid_to_days))
        .add_extension(_alt_names(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca[0].public_key()), critical=False
        )
    return key, builder.sign(issuer_key, hashes.SHA256())


def write_pem(directory: Path, stem: str, key: rsa.RSAPrivateKey, cert: x509.Certificate) -> Path:
    """Write key and certificate into one PEM file and return its path."""
    path = directory / f"{stem}.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        + cert.public_bytes(serialization.Encoding.PEM)
    )
    return path


def server_context(pem: Path, *, legacy: bool) -> ssl.SSLContext:
    """TLS server context. ``legacy`` enables TLS 1.0/1.1 and every cipher OpenSSL has."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if legacy:
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.set_ciphers("ALL:@SECLEVEL=0")
        else:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    context.load_cert_chain(str(pem))
    return context


@dataclass
class TlsMaterial:
    ca_file: Path
    vulnerable: ssl.SSLContext  # self-signed, expired, wrong name, legacy protocols
    clean: ssl.SSLContext  # CA-issued for localhost, TLS 1.2+, forward-secret AEAD suites
    expiring: ssl.SSLContext  # CA-issued for localhost but expires in 10 days


def make_tls_material(directory: Path) -> TlsMaterial:
    directory.mkdir(parents=True, exist_ok=True)
    ca = make_ca()
    ca_file = directory / "fixture-ca.pem"
    ca_file.write_bytes(ca[1].public_bytes(serialization.Encoding.PEM))
    hosts = ["localhost", "127.0.0.1"]
    bad = write_pem(
        directory,
        "vulnerable",
        *issue(["legacy.fixture.test"], valid_from_days=-400, valid_to_days=-30),
    )
    good = write_pem(directory, "clean", *issue(hosts, ca=ca))
    soon = write_pem(directory, "expiring", *issue(hosts, ca=ca, valid_to_days=10))
    return TlsMaterial(
        ca_file=ca_file,
        vulnerable=server_context(bad, legacy=True),
        clean=server_context(good, legacy=False),
        expiring=server_context(soon, legacy=False),
    )
