# CLAUDE.md — AegisScan

Read `README.md`, `ROADMAP.md` and `SCOPE-AND-ETHICS.md` before writing code. They are the spec.

## What this is

A web application security scanner for authorized testing: reconnaissance plus non-destructive vulnerability detection, with confirmed findings and a professional report. Owner: Ali. Portfolio project, will be public on GitHub.

## Current scope

Build **v1, then v2** from `ROADMAP.md`. v3 is out of scope.
v1 must be complete, tested and committed before any v2 work starts.

## Stack

- Python 3.11+, developed on Windows (use `pathlib`, no shell-specific assumptions)
- `httpx` (async) for HTTP, `dnspython` for DNS, `typer` for the CLI, `pydantic` for models, `jinja2` for reports, `pyyaml` for the scope file
- `pytest` + `pytest-asyncio` for tests, `ruff` for lint/format
- Packaged with `pyproject.toml`; entry point `aegisscan`

## Architecture

```
aegisscan/
  cli.py            # typer commands: scan, list-checks, report
  engine.py         # orchestration, concurrency, rate limiting
  scope.py          # scope (CLI target + optional scope file) + authorization gate
  http.py           # shared async client, retries, evidence capture
  models.py         # Target, Finding, Evidence, Severity
  checks/           # one module per check, auto-discovered
    base.py         # Check base class + registry
    recon/  config/  injection/
  crawler.py        # v2
  auth.py           # v2 session handling
  confirm.py        # v2 confirmation engine
  report/           # html + json renderers, templates
tests/
  fixtures/         # local deliberately-misconfigured test app
```

Every check is a plugin: a class with `id`, `title`, `severity`, `cwe`, `owasp`, `category`, `safe: bool`, and an async `run(target, ctx) -> list[Finding]`. The engine discovers checks; nothing in the engine knows about individual checks.

## Non-negotiable rules

1. **Scope gate.** Two conditions must both hold before any request leaves the tool:
   - **In scope:** scope is the set of hosts the operator explicitly named. By default that is exactly the host in the target URL given on the command line (`aegisscan scan https://app.example.com`) — no file needed. An optional `scope.yaml` (`--scope`) widens or narrows it: extra hosts, `include_subdomains`, excluded paths, an `authorization:` block. The tool never requests a host outside this set: links, redirects and subdomains that lead elsewhere are recorded in the report, never followed. This has no off switch, no flag, no env var.
   - **Authorization asserted**, by any one of:
     - `--i-have-authorization` on the command line — the normal path;
     - `AEGISSCAN_AUTHORIZED=1` in the environment, for CI or a dev shell;
     - an `authorization:` block in a scope file (`asserted_by`, `date`, `basis: owned | written-permission`), for repeat engagements.
   - Loopback targets (`localhost`, `127.0.0.1`, `::1`) need no assertion.
   - Every scan logs which assertion was used, with a timestamp, and the report prints it.
   - If either condition fails, exit non-zero with a message saying exactly what is missing. Do not add any option that skips the in-scope check.
2. **Non-destructive only.** Checks detect by sending benign probes and analysing responses. No data extraction, no state-changing requests against discovered forms unless the scope file marks them allowed, no payloads meant to damage, persist or deny service.

   **Request methods (v2).** GET, HEAD and OPTIONS are the default. POST is allowed in exactly two cases:
   - the login request, using credentials the operator supplied, to the login URL the operator named;
   - forms the operator explicitly allowed in the scope file.

   Every other discovered form is inventoried and probed only through GET parameters; it is never submitted. PUT, PATCH and DELETE are never sent. Tests must prove an un-allowed form is never submitted.
3. **Evidence.** Every finding stores the request, the relevant response excerpt, and why it was flagged.
4. **Confirm before reporting (v2).** Injection-class candidates go through `confirm.py`; unconfirmed ones are reported as "tentative", never as confirmed.
5. **Polite.** Default rate limit, honour `Retry-After`, identifiable User-Agent.

## Testing

- Tests run against the local fixture app in `tests/fixtures/` (started by a pytest fixture on localhost). No test may touch the internet.
- Each check needs two tests: fires on the vulnerable fixture route, silent on the clean route.
- OWASP Juice Shop in Docker is an optional manual integration target, documented in the README, not required for `pytest`.
- `pytest` and `ruff check` must pass before every commit.

## Working style

- Small commits, conventional messages (`feat(checks): add cors misconfiguration check`).
- When a design choice is unclear, pick the simpler option and note it in `DECISIONS.md`.
- Do not add checks beyond the roadmap without asking.
- Keep the README's check table in sync with the registry (`aegisscan list-checks --markdown`).

## Definition of done

- v1: all v1 checks implemented and tested, HTML + JSON report generated from a fixture scan, README has install/usage/sample report screenshot, tagged `v0.1.0`.
- v2: crawler, authenticated scanning, injection-class detection with confirmation, false-positive tests, tagged `v0.2.0`.
