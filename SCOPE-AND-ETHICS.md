# Scope, Authorization & Ethics

This is not boilerplate. The authorization model is a core feature of Vigil and a deliberate portfolio signal: it demonstrates that the author understands the legal and professional frame of offensive security work.

## The rule

**Only scan systems you own or have explicit written authorization to test.**

Unauthorized scanning/access violates computer-misuse law in most jurisdictions (e.g. the US CFAA, the UK Computer Misuse Act, and equivalents elsewhere). Intent is not a defense.

## How the tool enforces it

- **Scope = what the operator named:** by default, exactly the host in the target URL given on the command line. The scanner never contacts any other host: links, redirects and discovered subdomains that lead elsewhere are recorded, not followed. Nothing disables this.
- **Optional scope file:** `scope.yaml` is only needed to go beyond one host — extra hosts, subdomains, excluded paths, or a stored authorization record for a repeat engagement.
- **Authorization assertion:** the operator states that they own the target or hold written permission. Any one of these counts:
  - `--i-have-authorization` on the command line;
  - `VIGIL_AUTHORIZED=1` for CI pipelines or a dev shell;
  - an `authorization:` block in a scope file (who, when, on what basis).
- **Local development:** loopback targets need no assertion.
- **Audit trail:** each scan logs the assertion used and a timestamp, and the report shows it.
- **Non-destructive by default:** detection via safe probes and response analysis. The tool does not exfiltrate data, does not attempt to damage or persist, and does not fire payloads intended to take a target down.
- **Rate limiting:** respectful request pacing so a scan does not degrade a live service.

## Safe test targets (use these to develop)

- **OWASP Juice Shop** (Docker) — deliberately vulnerable, legal to attack
- **DVWA** (Damn Vulnerable Web Application)
- **PortSwigger Web Security Academy** labs
- Your own deployed apps (e.g. a LuxuryStay staging instance you control)

## Repo hygiene

- Ship a clear `LICENSE` and a prominent legal notice in the README
- Never commit real scan results against third-party targets
- Keep the scope gate un-bypassable in the default path
