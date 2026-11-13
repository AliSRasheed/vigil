# AegisScan — Versioned Roadmap

Each version is independently shippable. You can stop at any tier and have something real; each one is a LinkedIn "build in public" post.

---

## v1 — Core Engine + Safe Detection (MVP, shippable today)

**Goal:** a working, tested scanner that is already more than a student project because of its architecture and reporting.

**Engine**
- Async HTTP core (httpx), concurrency control, per-host rate limiting, retry/backoff
- Plugin-based check system (each check is a self-contained module with metadata)
- **Scope/authorization gate** — scan aborts unless target is asserted in-scope
- Structured findings model: id, title, severity, CVSS vector, evidence (request/response), remediation, OWASP + CWE mapping

**Recon (passive / low-touch)**
- DNS records + passive subdomain enumeration
- Technology fingerprinting (server, framework, CMS, versions)
- TLS/certificate analysis (protocols, cipher strength, expiry, chain)
- Email auth posture: SPF / DMARC / DKIM

**Config & exposure (safe active)**
- Security headers (CSP, HSTS, X-Frame-Options, etc.) — presence + quality grading
- Cookie flags (HttpOnly, Secure, SameSite)
- CORS misconfiguration
- Clickjacking exposure
- Directory listing enabled
- Exposed sensitive files (`.git/`, `.env`, backups, config files)
- Server/version/banner information disclosure

**Reporting**
- HTML report (executive summary + per-finding detail + evidence)
- JSON export (machine-readable)

**Testing**
- Runs against OWASP Juice Shop / DVWA in Docker
- Assertions: each check fires on the vulnerable target, stays silent on a clean one

---

## v2 — Surface Mapping + Authenticated Coverage (planned, not yet built)

**Goal:** see more of the application and report on it. v2 maps and reports; it does not exploit. The full plan is in [V2-PLAN.md](V2-PLAN.md).

**Upgrades**
- **Site mapper / crawler** — walk the named host only, within depth and page limits, and inventory pages, forms, input fields and URL parameters
- **Authenticated scanning** — log in with credentials the operator supplies, to the login URL the operator names, hold the session, and re-run v1's config and exposure checks on pages that only appear when logged in
- **Passive risk flags** — risky-looking patterns noted for human review (a form with no CSRF token, an input echoed back without escaping, a page missing the security headers v1 checks); flagged, not confirmed by sending inputs
- **Report extensions** — the crawl map, the authenticated findings and the flagged spots, kept separate from v1's confirmed findings
- **Request-method rule** — POST only for the login request and operator-allowed forms; never PUT, PATCH or DELETE; every other discovered form is inventoried, never submitted

**Deferred** — active injection detection (sending crafted inputs to detect SQL injection, XSS, SSRF and similar, with a confirmation engine) is not part of v2. Whether it returns, and in what form, is a separate later decision.

How this section changed from the original v2 is recorded in [V2-HISTORY.md](V2-HISTORY.md).

---

## v3 — Platform / Pro

**Goal:** deployable product, not a script.

**Upgrades**
- **Plugin SDK** — third parties (or future-you) add checks without touching the core
- **CI/CD integration** — run in a pipeline, fail the build on high-severity findings
- **SARIF export** — integrates with GitHub code scanning and standard dashboards
- **Diff scanning** — compare runs, surface newly introduced issues
- Scheduled + resumable scans (persistent state)
- REST API + lightweight web dashboard
- **Cloud posture checks** (ties to your cloud-security interest): detection of exposed storage buckets, misconfigured metadata endpoints, public cloud resources

---

## What makes it "professional" (none of it is destructiveness)

| Dimension | Where it's addressed |
|---|---|
| Low false positives | v1 content-confirmed checks and clean-fixture tests; v2 keeps flagged-for-review items separate from confirmed findings |
| Detection depth | v1 probe + response analysis; v2 crawl and authenticated coverage |
| Coverage (OWASP-mapped checks) | v1, extended to more pages by v2 |
| Architecture | v1 plugin engine, async |
| Reporting | v1 HTML/JSON, v3 SARIF |
| Evidence per finding | v1 findings model |
