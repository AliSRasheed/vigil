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
- **OWASP mapping:** originally the Top 10 2021 edition; replaced by the 2025 edition after v0.1.0 (see "OWASP Top 10:2025 mapping" below).
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

## Stage 2: checks and reports

### Across all checks

- **One URL per scan.** v1 has no crawler, so checks look at the target URL and at well-known paths relative to its directory (normally the site root). Crawling is v2.
- **Twelve checks, one per roadmap bullet.** "DNS records + passive subdomain enumeration" became two checks (`recon.dns`, `recon.subdomains`) because they fail and skip independently.
- **Checks that do not apply say so.** DNS-based checks skip for IP addresses, `localhost` and names with no DNS zone; the report lists them as "not applicable" with the reason, so a clean result is never mistaken for full coverage.
- **Findings are grouped where repetition adds nothing:** one finding per cookie (listing all its weak flags), one for all listed directories, one per kind of exposed file (`.git/HEAD` and `.git/config` are one finding with two pieces of evidence).

### Recon

- **Subdomain enumeration is strictly passive and uses no third-party service.** Certificate-transparency sites such as crt.sh are the usual source, but querying them would mean contacting a host the operator did not name. Sources are DNS records of the zone, host names in the target page and its headers, and names on the target's own certificate. No wordlist guessing. Coverage is therefore narrower than dedicated tools; that is the price of the scope rule.
- **DNS lookups go to the operator's configured resolver.** They are questions about the named domain, not requests to another host. Zone transfers (AXFR) are not attempted: that is data extraction from the name servers.
- **"The domain" for email and CAA checks is the zone apex**, found by walking up from the host until a name answers an SOA query. This avoids shipping a public-suffix list.
- **DKIM absence can only be reported as informational.** Selectors cannot be enumerated from outside; the check tries 15 common ones and says so.
- **`~all` in SPF is not flagged** (it is the normal setting alongside DMARC). `+all` is medium, `?all` or no `all` is low.
- **TLS analysis is done with handshakes, using Python's `ssl`.** It tests TLS 1.0/1.1 acceptance, weak suites (3DES, RC4, DES, NULL, EXPORT, anonymous, MD5) and static-RSA key exchange. SSLv2/SSLv3 cannot be tested because modern OpenSSL builds no longer contain them; if the local library cannot build a probe, the report says "not tested" instead of "not accepted". It proves a server accepts *some* suite in a group, not a full per-suite inventory.
- **Certificates are judged the way browsers do**, not by Python 3.13's stricter RFC 5280 defaults, to avoid calling a working certificate untrusted.
- **A plain-HTTP target is reported as "no transport encryption"** unless it is loopback or redirects to HTTPS.
- **Fingerprinting reports what is identified, not whether it is outdated.** A built-in table of end-of-life versions would go stale and start making false claims.

### Config and exposure

- **`config.security_headers` does not cover X-Frame-Options / frame-ancestors**; `config.clickjacking` does, so the same gap is not reported twice.
- **HSTS and the cookie `Secure` flag are judged only over HTTPS.** Browsers ignore both over plain HTTP.
- **Header grade:** starts at 100, minus 30 missing CSP (15 weak), 25 missing HSTS (10 short max-age), 15 missing nosniff, 5 or 10 Referrer-Policy, 5 Permissions-Policy. A 90+, B 75+, C 60+, D 40+, F below. Only the first CSP header is analysed when several are sent.
- **Cookies:** `HttpOnly` and `SameSite` are required only of session-like cookies (name contains sess, auth, token, ...). CSRF tokens are exempt from `HttpOnly` because page script reads them by design. This keeps preference cookies from generating noise.
- **CORS:** `Access-Control-Allow-Origin: *` without credentials is not reported; it is correct for public resources. The check reports reflected arbitrary origins, the `null` origin, and prefix/suffix validation bypasses, rated high with credentials and low without. Probe origins use the reserved `.example` domain.
- **Exposed files are confirmed by content, not status code.** Each of the 28 probes has a signature (magic bytes, format markers), so a site that returns 200 for everything produces nothing. Excerpts are masked or cut to one line: the report proves the file is there without reproducing it.
- **Version disclosure is low severity; stack traces on error pages are medium.**

### Reports

- **The HTML report is one self-contained file**: no scripts, no external assets, light and dark themes, printable. Everything from the target is HTML-escaped.
- **The executive summary text is generated from the results**, and states how many checks did not run.
- **JSON is the full result model plus a `summary` block.** `aegisscan report` re-renders HTML from it.
- **The sample report scans the vulnerable fixture over HTTPS on `localhost`**, so the three DNS-based checks appear as "not applicable". They are covered by tests against the fixture DNS server.

### Not done in v1

- Juice Shop / DVWA were not run as part of this build (no Docker run was performed); the README documents the command. The roadmap's "each check fires on vulnerable, silent on clean" is met by the fixture app instead, as CLAUDE.md specifies.
- No `--fail-on` severity threshold, proxy support or SARIF: those are v3 or later.
- `PROGRESS.md` (mentioned in PROJECT-INSTRUCTIONS.md for the planning project) was not created.

## OWASP Top 10:2025 mapping (after v0.1.0)

- **The mapping moved from the 2021 edition to the 2025 edition**, and is now driven by CWE. `aegisscan/owasp.py` holds one table, CWE to category, and a finding's category is looked up from its CWE. Under 2021 nearly everything was labelled A05 Security Misconfiguration by judgement; under 2025 each label is the category whose official "List of Mapped CWEs" contains the CWE.
- **Source:** the category pages at https://owasp.org/Top10/2025/ (which redirects to top10.owasp.org/2025), read on 2026-11-14. Each CWE AegisScan reports was looked up in those lists, not recalled from memory. The pages themselves do not state a release status or date.
- **Result, by CWE:**
  - A01 Broken Access Control: CWE-200, 538, 548, 552, 1275
  - A02 Security Misconfiguration: CWE-614, 942, 1004
  - A04 Cryptographic Failures: CWE-319, 326, 327, 328
  - A06 Insecure Design: CWE-693, 1021
  - A07 Authentication Failures: CWE-290, 295, 297, 298, 350
  - A10 Mishandling of Exceptional Conditions: CWE-209
- **Some placements look odd and are kept as OWASP publishes them.** Missing security headers and missing CAA (CWE-693) and clickjacking (CWE-1021) fall under A06 Insecure Design, not Security Misconfiguration; information disclosure, exposed files and directory listing (CWE-200, 538, 548) fall under A01 Broken Access Control. Following the published lists was preferred over a judgement call that would differ from other tools.
- **CWE-527 (exposed version-control repository) and CWE-530 (exposed backup file) are in no 2025 category.** They keep their precise CWE and are mapped through their parent, CWE-552 (Files or Directories Accessible to External Parties), which is listed under A01.
- **A check's `owasp` is the category of its primary CWE; a finding's follows its own CWE.** So one check can produce findings in several categories: `recon.tls` is A04 by its primary CWE-326, but its certificate findings (CWE-295/297/298) are A07; `config.cookies` is A02, but a SameSite-only finding (CWE-1275) is A01; `config.info_disclosure` is A01, but a stack trace (CWE-209) is A10.
- **Guard rails:** registering a check whose `owasp` does not match its CWE in the table raises `TypeError`, and a test asserts every finding from the fixture scan matches the table.
- The `v0.1.0` tag still points at the 2021 mapping; this change is a later commit.
