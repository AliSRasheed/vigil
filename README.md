# AegisScan

A web application security scanner for **authorized** testing — the "breaker" counterpart to SpecTackle's "builder."

## What it is

AegisScan performs reconnaissance and non-destructive vulnerability **detection** against web applications you own or are explicitly authorized to test. It identifies security weaknesses, confirms them to cut false positives, and produces a professional, client-ready report.

It follows the model of production tools (Nessus "safe checks", Burp's scan profiles, OWASP ZAP): detection by careful probing and response analysis — not destructive exploitation. That is the professional standard, and it is what keeps the tool legal to run and safe on a live target.

## Positioning

- **SpecTackle** → ships websites.
- **AegisScan** → tests them.

One builder, one breaker. Together they tell a single portfolio story.

## Hard constraints (by design)

1. **Scope gate.** The engine only contacts the host the operator named (plus any added in an optional scope file), and only after the operator has asserted authorization (owned / written permission) with `--i-have-authorization`. It never follows links or redirects to other hosts.
2. **Non-destructive.** Detection via safe probes and response analysis. No data exfiltration, no payloads intended to damage or persist.
3. **Evidence-based.** Every finding carries the request/response proof, severity, CVSS, and remediation.

## Target users

Security engineers and pentesters running authorized engagements; developers hardening their own apps; it integrates into CI/CD to gate releases on security findings.

## Legal

Running this against systems you do not own or have written permission to test is illegal in most jurisdictions (e.g. unauthorized-access statutes). See `SCOPE-AND-ETHICS.md`. The authorization gate exists to make misuse a deliberate act, not an accident.
