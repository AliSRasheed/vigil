# Vigil v2 — Original and Revised

## v2 (original)

The first v2 plan, from ROADMAP.md:

- Site crawler to map pages, forms and inputs
- Authenticated scanning
- Active vulnerability detection with a confirmation step
- Report showing confirmed and tentative findings
- Target tag: v0.2.0

## v2 (revised)

The current v2 plan, detailed in V2-PLAN.md. It maps and reports; it does not exploit.

1. Site mapper: inventory of pages, forms, inputs and parameters on the named host
2. Authenticated scanning: log in with operator-supplied credentials and re-run v1's checks on logged-in pages
3. Passive risk flags: risky-looking patterns noted for human review, not confirmed by sending inputs
4. Report extensions: crawl map, authenticated findings and flagged spots, kept separate from confirmed findings
5. Request-method rule: POST only for login and operator-allowed forms; never PUT, PATCH or DELETE

Active vulnerability detection is removed from v2. Whether it returns, and in what form, is a separate later decision.
