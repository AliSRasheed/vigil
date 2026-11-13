# Build prompts for Claude Code

Run from inside the `AegisScan` folder. Three runs. Do not start the next run until the previous one has passing tests and a tag.

## Run A — all of v1 (engine, checks, report)

Read CLAUDE.md, README.md, ROADMAP.md and SCOPE-AND-ETHICS.md. Build all of v1 in two stages, without stopping to ask me between them.

Stage 1: initialise git and the Python package. Build the v1 engine: models, scope and authorization gate, shared async HTTP client with rate limiting and evidence capture, check base class with auto-discovery, the typer CLI, and the local fixture app for tests. Include tests for the scope gate exactly as specified in CLAUDE.md: a target given on the command line is in scope with no scope file; a host other than the named one (via link, redirect or discovered subdomain) is never requested under any assertion method; a named host without an assertion is blocked; each of the three assertion methods allows the scan; a loopback target runs with no assertion; a scope file can add hosts and exclusions; the assertion used is logged. Run pytest and ruff, fix failures, commit.

Stage 2: implement every v1 recon and config/exposure check from ROADMAP.md as plugins, each with a fires/silent test pair against the fixture app. Build the HTML and JSON reports. Run a full scan against the fixture app, save the sample report under `docs/`, write the README usage section and check table. Run pytest and ruff, fix failures, commit, tag v0.1.0.

Do not begin stage 2 until stage 1's tests pass and are committed. At the end, give me a summary: checks implemented, test count, anything you skipped or decided (also logged in DECISIONS.md).

## Run B — all of v2 (crawler, auth, detection, confirmation)

Read CLAUDE.md and ROADMAP.md again. Build all of v2 in two stages, without stopping to ask me between them.

Stage 1: add the crawler (named host only, depth and page limits, form and parameter inventory) and session handling for authenticated scans. Extend the fixture app with a login area. Run pytest and ruff, fix failures, commit.

Stage 2: implement the v2 injection-class detection checks from ROADMAP.md using benign probes, and the confirmation engine that re-tests each candidate before it is reported as confirmed. Add fixture routes that look vulnerable but are not, and assert zero confirmed findings on them. Update the report to show confirmed vs tentative. Run pytest and ruff, fix failures, commit, tag v0.2.0.

Do not begin stage 2 until stage 1's tests pass and are committed. End with the same summary as Run A.

## Run C — ship

Review the whole repo as a hiring manager would: README clarity, install from scratch, LICENSE, legal notice, sample report, architecture diagram. Fix what is weak. Then create the GitHub repo and push.
