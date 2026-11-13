"""TLS and certificate analysis.

A handful of TLS handshakes with the target, each offering a different set of
protocol versions or cipher suites. A handshake that completes proves the server
accepts what was offered. No application data is exchanged.
"""

from __future__ import annotations

import datetime as dt
import ssl
import warnings

from aegisscan import tlsutil
from aegisscan.checks.base import Check, CheckSkipped
from aegisscan.engine import ScanContext
from aegisscan.http import http_evidence
from aegisscan.models import Evidence, Finding, Severity, Target
from aegisscan.scope import is_loopback

CERT_INVALID = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"  # 6.5
WEAK_CRYPTO = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 5.9
MINOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 3.7
EXPIRY_WARNING_DAYS = 30

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    LEGACY_PROTOCOLS = (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1))
WEAK_CIPHERS = "3DES:RC4:DES:eNULL:EXPORT:aNULL:MD5:@SECLEVEL=0"
NO_FORWARD_SECRECY = "kRSA:@SECLEVEL=0"
ANY_CIPHER = "ALL:@SECLEVEL=0"


def certificate_problems(
    cert: tlsutil.CertInfo, host: str, now: dt.datetime
) -> list[tuple[str, str, str, str]]:
    """(title, why, vector, cwe) for each defect in the certificate itself."""
    problems = []
    if now > cert.not_after:
        days = (now - cert.not_after).days
        problems.append((
            "TLS certificate has expired",
            f"The certificate expired on {cert.not_after:%Y-%m-%d} ({days} days ago). Browsers "
            "show a full-page warning and API clients refuse to connect.",
            CERT_INVALID, "CWE-298",
        ))  # fmt: skip
    elif now < cert.not_before:
        problems.append((
            "TLS certificate is not yet valid",
            f"The certificate is only valid from {cert.not_before:%Y-%m-%d}.",
            CERT_INVALID, "CWE-298",
        ))  # fmt: skip
    elif cert.days_remaining(now) < EXPIRY_WARNING_DAYS:
        problems.append((
            "TLS certificate expires soon",
            f"The certificate expires on {cert.not_after:%Y-%m-%d}, in "
            f"{cert.days_remaining(now)} days.",
            MINOR, "CWE-298",
        ))  # fmt: skip
    if not tlsutil.hostname_matches(host, cert.sans):
        problems.append((
            "TLS certificate does not match the host name",
            f"The certificate is issued for {', '.join(cert.sans) or '(no names)'}, not for "
            f"{host}. Clients cannot tell this server from an impostor.",
            CERT_INVALID, "CWE-297",
        ))  # fmt: skip
    if (cert.key_type == "RSA" and cert.key_bits < 2048) or (
        cert.key_type == "EC" and cert.key_bits < 224
    ):
        problems.append((
            "TLS certificate uses a weak key",
            f"The certificate key is {cert.key_type} {cert.key_bits} bits; at least RSA 2048 or "
            "EC 256 is required today.",
            WEAK_CRYPTO, "CWE-326",
        ))  # fmt: skip
    if cert.signature_hash in ("md5", "sha1"):
        problems.append((
            "TLS certificate is signed with a broken hash",
            f"The certificate signature uses {cert.signature_hash.upper()}, for which "
            "collisions are practical.",
            WEAK_CRYPTO, "CWE-328",
        ))  # fmt: skip
    return problems


class TlsAnalysis(Check):
    id = "recon.tls"
    title = "TLS and certificate analysis"
    severity = Severity.MEDIUM
    cwe = "CWE-326"
    owasp = "A04:2025 Cryptographic Failures"
    category = "recon"
    description = (
        "Certificate validity, trust chain, host name, expiry, key and signature strength; "
        "deprecated protocol versions; weak and non-forward-secret cipher suites."
    )

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        if target.scheme == "http":
            return await self._plain_http(target, ctx)

        host, port = target.host, target.port
        endpoint = f"{host}:{port}"
        handshake = await ctx.tls_probe()  # default offer, certificate not verified
        cert = handshake.cert
        findings: list[Finding] = []
        observed: dict[str, object] = {
            "negotiated": f"{handshake.protocol}, {handshake.cipher} ({handshake.bits} bits)"
        }

        def add(title: str, why: str, vector: str, cwe: str, evidence: Evidence, fix: str) -> None:
            findings.append(
                self.finding(
                    title=title,
                    url=target.origin,
                    description=(
                        "TLS protects the confidentiality and integrity of everything sent to "
                        "and from the site, and the certificate is what proves the server's "
                        "identity."
                    ),
                    why=why,
                    evidence=[evidence],
                    remediation=fix,
                    cvss_vector=vector,
                    cwe=cwe,
                )
            )

        # --- certificate ---------------------------------------------------
        if cert is not None:
            now = dt.datetime.now(dt.UTC)
            observed |= {
                "certificate subject": cert.subject,
                "issuer": cert.issuer,
                "valid": f"{cert.not_before:%Y-%m-%d} to {cert.not_after:%Y-%m-%d}",
                "names": cert.sans,
                "key": f"{cert.key_type} {cert.key_bits} bits, signed with {cert.signature_hash}",
            }
            cert_evidence = Evidence(
                kind="tls",
                request=f"TLS handshake with {endpoint} (SNI {host})",
                response=f"negotiated {handshake.protocol} {handshake.cipher}\n{cert.summary()}",
            )
            problems = certificate_problems(cert, host, now)
            for title, why, vector, cwe in problems:
                add(title, why, vector, cwe, cert_evidence.model_copy(update={"note": why}),
                    "Install a certificate that is valid, issued for this host name by a "
                    "publicly trusted CA, with an RSA 2048+ or EC P-256+ key, and automate its "
                    "renewal.")  # fmt: skip

            # Trust chain: a second handshake with normal certificate verification.
            try:
                await ctx.tls_probe(verify=True, ca_file=ctx.options.ca_file)
                observed["chain"] = "trusted"
            except tlsutil.TlsProbeError as exc:
                reason = exc.verify_message
                observed["chain"] = f"not trusted: {reason}" if reason else "could not be verified"
                # Expiry and name mismatch are already reported above with more detail.
                already = reason and any(
                    word in reason.lower() for word in ("expired", "not yet valid", "mismatch")
                )
                if reason and not already:
                    why = (
                        f"Certificate verification failed: {reason}. The certificate does not "
                        "chain to a trusted certificate authority"
                        + (" (it is self-signed)." if cert.self_signed else ".")
                    )
                    add("TLS certificate is not trusted", why, CERT_INVALID, "CWE-295",
                        Evidence(
                            kind="tls",
                            request=f"TLS handshake with {endpoint}, verifying the certificate "
                            "chain against the trusted CA store",
                            response=f"verification failed: {reason}\n{cert.summary()}",
                            note=why,
                        ),
                        "Use a certificate issued by a publicly trusted CA and serve the full "
                        "intermediate chain.")  # fmt: skip

        # --- protocol versions ---------------------------------------------
        accepted: list[str] = []
        lines: list[str] = []
        for label, version in LEGACY_PROTOCOLS:
            result = await self._offer(ctx, min_version=version, max_version=version,
                                       ciphers=ANY_CIPHER)  # fmt: skip
            if isinstance(result, tlsutil.Handshake):
                accepted.append(label)
                lines.append(f"{label}: handshake completed ({result.cipher})")
            else:
                lines.append(f"{label}: {result}")
        observed["deprecated protocols"] = accepted or ["none accepted"]
        if accepted:
            why = (
                f"The server completed a handshake using {' and '.join(accepted)}. These "
                "versions were formally deprecated in 2021 (RFC 8996) and have known weaknesses."
            )
            add(f"Deprecated TLS versions accepted: {', '.join(accepted)}", why, WEAK_CRYPTO,
                "CWE-326",
                Evidence(
                    kind="tls",
                    request=f"TLS handshakes with {endpoint}, each offering a single legacy "
                    "protocol version",
                    response="\n".join(lines),
                    note=why,
                ),
                "Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.")  # fmt: skip

        # --- cipher suites (TLS 1.2 and below, where the suite list is negotiable) ---
        for offer, key, title, why_text, vector, cwe, fix in (
            (
                WEAK_CIPHERS, "weak ciphers",
                "Weak cipher suites accepted",
                "The server completed a handshake when offered only weak cipher suites (3DES, "
                "RC4, DES, NULL, EXPORT, anonymous or MD5-based)",
                WEAK_CRYPTO, "CWE-327",
                "Remove 3DES, RC4, DES, NULL, EXPORT, anonymous and MD5 suites from the server "
                "configuration.",
            ),
            (
                NO_FORWARD_SECRECY, "forward secrecy",
                "Cipher suites without forward secrecy accepted",
                "The server completed a handshake using static RSA key exchange, which has no "
                "forward secrecy: anyone who records traffic now and obtains the server key "
                "later can decrypt it",
                MINOR, "CWE-326",
                "Allow only ECDHE (or DHE) key exchange, for example the Mozilla "
                "'intermediate' configuration.",
            ),
        ):  # fmt: skip
            result = await self._offer(ctx, max_version=ssl.TLSVersion.TLSv1_2, ciphers=offer)
            if isinstance(result, tlsutil.Handshake):
                observed[key] = f"accepted ({result.cipher})"
                why = f"{why_text}. Negotiated: {result.cipher} over {result.protocol}."
                add(title, why, vector, cwe,
                    Evidence(
                        kind="tls",
                        request=f"TLS handshake with {endpoint}, offering only: {offer}",
                        response=f"handshake completed: {result.protocol}, {result.cipher}",
                        note=why,
                    ),
                    fix)  # fmt: skip
            else:
                observed[key] = "not accepted" if result == "refused" else result

        ctx.observe("tls", observed)
        return findings

    @staticmethod
    async def _offer(ctx: ScanContext, **kwargs: object) -> tlsutil.Handshake | str:
        """One probe: the handshake, 'refused', or why it could not be tested locally."""
        try:
            return await ctx.tls_probe(**kwargs)
        except tlsutil.TlsProbeError as exc:
            return "not tested (unsupported by the local TLS library)" if exc.local else "refused"

    async def _plain_http(self, target: Target, ctx: ScanContext) -> list[Finding]:
        if is_loopback(target.host):
            raise CheckSkipped("target is plain HTTP on loopback; nothing crosses a network")
        response = await ctx.baseline()
        upgraded = response.url.startswith("https://") or (
            response.blocked_redirect or ""
        ).startswith("https://")
        if upgraded:
            raise CheckSkipped(
                "target redirects to HTTPS; scan the https:// URL to analyse its TLS setup"
            )
        why = (
            f"{target.url} is served over plain HTTP and does not redirect to HTTPS. Everything "
            "sent and received, including credentials and session cookies, can be read and "
            "altered by anyone on the network path."
        )
        return [
            self.finding(
                title="Site is served without transport encryption",
                url=response.url,
                description="Without TLS there is no confidentiality, no integrity and no proof "
                "of the server's identity.",
                why=why,
                evidence=[http_evidence(response, why, excerpt="")],
                remediation="Serve the site over HTTPS, redirect all HTTP requests to it, and "
                "send Strict-Transport-Security.",
                cvss_vector=WEAK_CRYPTO,
                cwe="CWE-319",
            )
        ]
