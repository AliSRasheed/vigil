# Decisions

Design choices made where the spec was silent or ambiguous. Simpler option chosen each time, as CLAUDE.md asks. Newest section last.

## Stage 1: engine

### Scope and authorization

- **The command-line target is always in scope.** A scope file adds hosts; it cannot remove the target. "Narrowing" is done with `exclude_paths`.
- **Scope is by host name, not by port or scheme.** `http://app.example.com:8080` is in scope when `app.example.com` is named. Only `http` and `https` URLs are ever requested.
- **Scope is by the literal name the operator typed.** `127.0.0.1` and `localhost` are different hosts: scanning one never contacts the other. No DNS resolution is involved in the decision.
- **Loopback means exactly `localhost`, `127.0.0.1`, `::1`**, as listed in CLAUDE.md. Other `127.0.0.0/8` addresses need an assertion. The loopback exemption applies only when *every* in-scope host is loopback and `include_subdomains` is off; a loopback target with an external host added by a scope file needs an assertion.
- **`AEGISSCAN_AUTHORIZED` must be exactly `1`.** `true`, `yes`, `0` do not count.
- **Precedence when several assertions are present:** flag, then environment, then scope file. The first one found is the one logged.
- **Scope file is strict.** Unknown keys are an error (so a typo such as `authorisation:` cannot silently drop the authorization block). `hosts` entries must be bare host names: no URLs, no wildcards (`include_subdomains` covers that).
- **`exclude_paths` matching:** an entry without a wildcard excludes that path and everything beneath it (`/admin` excludes `/admin/users`, not `/administrator`); an entry with `*` or `?` is a glob over the whole path.
- **Where the gate lives.** `scope.authorize()` is the only producer of a `Permit`; `HttpClient` and `Engine` refuse to be constructed without one. Every HTTP request passes `Scope.check_url` in `HttpClient._send`, and every TLS probe passes `Scope.check_host` in `tlsutil.probe`. There is no parameter anywhere that disables either.
- **Audit trail in three places:** the `aegisscan.audit` logger (printed to stderr by the CLI), an `audit.log` JSON-lines file appended in the output directory, and the `authorization` block of every report.
- **Exit code 2** for a blocked scan or a usage error (unknown check, unknown format). Exit 0 for a completed scan regardless of findings; failing a build on severity is v3 (CI integration).

### HTTP client

- **Only `GET`, `HEAD`, `OPTIONS` can be sent in v1.** Anything else raises `UnsafeMethodError` before the network. v2 will need a narrower rule for forms the scope file allows.
- **Redirects are not followed by default.** A check asks for it explicitly, and each hop is re-checked against scope. An out-of-scope `Location` is recorded and the 3xx response is returned.
- **TLS verification is off in the HTTP client.** A scanner must be able to scan a staging host with a self-signed certificate. Certificate validity is assessed and reported by the `recon.tls` check instead.
- **Environment proxies are ignored** (`trust_env=False`), so traffic goes to the named host and nowhere else. Proxy support (for example through Burp) would be an explicit option later.
- **Response bodies are capped at 256 KB.** Enough to analyse, and it means an exposed backup or database dump is identified from its first bytes, not downloaded.
- **Defaults:** 5 requests/second per host, 5 concurrent requests, 2 retries with exponential backoff, `Retry-After` honoured up to 30 seconds (a longer wait returns the 429/503 as is).
- **Evidence is redacted.** `Set-Cookie` values and `Authorization`/`Cookie` request headers are masked in evidence. Secrets-file excerpts keep key names and mask values.

### Models and checks

- **Severity is derived from the CVSS v3.1 vector.** A finding with a vector gets its score and severity band computed from it, so the three cannot disagree. Findings without a vector are `info`.
- **A check's `severity` attribute is the highest severity it can report**; each finding carries its own.
- **OWASP mapping uses the Top 10 2021 edition.** Remapping to the 2025 edition is a follow-up; 2021 was chosen because its category names are certain.
- **Recon data that is not a weakness goes to `observations`** (DNS records, technologies, certificate details), shown in the report's reconnaissance section. Findings are reserved for things worth acting on, which is what lets every check stay silent on a clean target.
- **`register=False`** on a `Check` subclass keeps test doubles out of the registry.

### Extra modules beyond the CLAUDE.md layout

- `cvss.py` (score calculation), `resolver.py` (DNS client), `tlsutil.py` (TLS handshake probe), `htmlutil.py` (link extraction). Small, single-purpose, and kept out of `engine.py` and `http.py` to keep those readable.
- **`cryptography` added as a runtime dependency.** Python's `ssl` only exposes parsed certificate fields for certificates that already validated; analysing an invalid one (the interesting case) needs a real X.509 parser.

### Tests

- **Fixture app is standard library only** (`http.server`), two modes on the same routes: `vulnerable` and `clean`. The clean mode answers unknown paths with a soft 404 (HTTP 200) on purpose, to catch false positives.
- **Non-loopback names in tests** (`app.fixture.test`) are routed to the local fixture by a test-only httpx transport, which also records every host a request was addressed to. That is how "an out-of-scope host is never requested" is asserted: the other host is routable in the test, so only the gate stops it.
- **DNS in tests** is a small authoritative server on loopback UDP, not a mock, so the dnspython code path is real.
- **Certificates for HTTPS fixtures are generated at test time.** No private keys are committed.
- **A session-wide guard** makes name resolution and `connect` to anything but loopback fail, as a backstop for "no test may touch the internet".
