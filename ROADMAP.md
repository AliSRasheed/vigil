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

## v2 — Active Detection + Confirmation (the depth layer)

**Goal:** this is where it stops being a config-checker and becomes a real scanner. The hard engineering is here.

**Upgrades**
- **Crawler/spider** to map the app's attack surface (forms, params, endpoints)
- **Authenticated scanning** — session handling, login flows, cookie/token management
- **Injection-class detection (non-destructive):** reflected XSS, SQL injection (error / boolean / time-based *detection* via safe probes), SSRF, open redirect, path traversal, host-header injection, LFI
- **Confirmation engine** — the single most valuable component: re-tests each candidate finding to prove it's real and suppress false positives. This is what separates senior-grade tooling from noise.
- IDOR / access-control heuristics; missing rate-limiting detection

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
| Low false positives | v2 confirmation engine |
| Detection depth | v2 probe + response analysis |
| Coverage (30+ checks, OWASP-mapped) | v1 + v2 |
| Architecture | v1 plugin engine, async |
| Reporting | v1 HTML/JSON, v3 SARIF |
| Evidence per finding | v1 findings model |
