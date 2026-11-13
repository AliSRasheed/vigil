# AegisScan v2 — Plan (not yet built)

Status: planning only. No v2 code exists. This is the spec to build from when you return to it with a clear head.

## The line v2 must not cross

v2 **maps and reports**. It does not **exploit**. Every component below stays on the reporting side of that line. The moment a feature's job is to *trigger* a weakness to prove it works, it belongs in the deferred section, not here.

## In scope for v2 (clearly defensive)

1. **Site mapper / crawler.** Walk the named host only, within depth and page limits, and build an inventory: pages, forms, input fields, URL parameters. This is *looking*, not attacking. Output is a map of the attack surface — valuable on its own.

2. **Authenticated scanning.** Log in using credentials the operator supplies, to the login URL the operator names, hold the session, and re-run v1's existing config/exposure checks on pages that only appear when logged in. This extends v1's reporting into authenticated areas. No new offensive behaviour — same checks, more coverage.

3. **Passive risk flags.** While crawling, note risky-looking patterns and flag them for a human to review: a form with no CSRF token, an input echoed back without escaping, a page missing the security headers v1 already checks. Flagged for review — not confirmed by firing inputs.

4. **Report extensions.** Show the crawl map, the authenticated findings, and the flagged spots, kept separate from v1's confirmed findings.

5. **Request-method rule (already recorded in CLAUDE.md/DECISIONS.md).** POST only for login and operator-allowed forms; never PUT/PATCH/DELETE; every other discovered form is inventoried, never submitted.

## Deliberately deferred — a decision to make later, not tonight

**Active injection detection** — sending crafted inputs into forms and parameters to detect SQL injection, XSS, SSRF, and a confirmation engine that re-tests candidates. This is the part that sits on the offensive line, and it is what kept getting stopped when built in a normal chat.

Before building it, decide two things with a clear head:
- How far active probing is allowed to go, in plain rules.
- Whether it belongs in this tool at all, or in a separate, clearly-scoped one.

Do not build this in a rushed late-night session. It is not a code problem; it is a scoping decision.

## Build order when ready

1. Crawler + surface inventory (with tests)
2. Authenticated session handling; re-run v1 checks while logged in (with tests)
3. Passive risk flags (with tests)
4. Report extensions
5. (Deferred) Active injection detection — separate decision first

## Where to build each part

Parts 1–4 are ordinary defensive engineering and fine to build in Claude Code with normal prompting. Part 5, if you pursue it, is better suited to a dedicated security context than a general chat, and should follow its own scoping decision.
