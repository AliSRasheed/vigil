# Build prompts for Claude Code

Run from the repository root. Three runs. Do not start the next run until the previous one has passing tests and a tag.

## Run A — all of v1 (engine, checks, report)

Read CLAUDE.md, README.md, ROADMAP.md and SCOPE-AND-ETHICS.md. Build all of v1 in two stages, without stopping to ask me between them.

Stage 1: initialise git and the Python package. Build the v1 engine: models, scope and authorization gate, shared async HTTP client with rate limiting and evidence capture, check base class with auto-discovery, the typer CLI, and the local fixture app for tests. Include tests for the scope gate exactly as specified in CLAUDE.md: a target given on the command line is in scope with no scope file; a host other than the named one (via link, redirect or discovered subdomain) is never requested under any assertion method; a named host without an assertion is blocked; each of the three assertion methods allows the scan; a loopback target runs with no assertion; a scope file can add hosts and exclusions; the assertion used is logged. Run pytest and ruff, fix failures, commit.

Stage 2: implement every v1 recon and config/exposure check from ROADMAP.md as plugins, each with a fires/silent test pair against the fixture app. Build the HTML and JSON reports. Run a full scan against the fixture app, save the sample report under `docs/`, write the README usage section and check table. Run pytest and ruff, fix failures, commit, tag v0.1.0.

Do not begin stage 2 until stage 1's tests pass and are committed. At the end, give me a summary: checks implemented, test count, anything you skipped or decided (also logged in DECISIONS.md).

## Run B — all of v2 (site mapper, authenticated scanning, passive risk flags, report)

Read CLAUDE.md, ROADMAP.md and V2-PLAN.md again. v2 maps and reports; it does not exploit. Build all of v2 in two stages, without stopping to ask me between them.

Stage 1: add the site mapper (named host only, depth and page limits, inventory of pages, forms, input fields and URL parameters) and session handling for authenticated scans: log in with credentials the operator supplies, to the login URL the operator names, hold the session, and re-run the v1 config and exposure checks on pages that only appear when logged in. Enforce the request-method rule: POST only for that login request and for forms the scope file explicitly allows; never PUT, PATCH or DELETE; every other discovered form is inventoried, never submitted. Extend the fixture app with a login area and with forms that are not allowed, and add tests proving an un-allowed form is never submitted. Run pytest and ruff, fix failures, commit.

Stage 2: add passive risk flags noted while crawling, for human review and never confirmed by sending inputs (for example a form with no CSRF token, an input echoed back without escaping, a page missing the security headers v1 checks), each with a fires/silent test pair. Extend the report to show the crawl map, the authenticated findings and the flagged spots, kept separate from confirmed findings. Run pytest and ruff, fix failures, commit, tag v0.2.0.

Do not begin stage 2 until stage 1's tests pass and are committed. Do not build active injection detection: it is deferred in V2-PLAN.md. End with the same summary as Run A.

## Run C — ship

Review the whole repo as a hiring manager would: README clarity, install from scratch, LICENSE, legal notice, sample report, architecture diagram. Fix what is weak. Then create the GitHub repo and push.
