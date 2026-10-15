---
name: 55-client-side-attacks
description: Use when attacking the victim's browser context rather than the server - missing CSRF tokens and SameSite protection gaps, frameable pages and clickjacking, unvalidated open redirects, postMessage listeners without origin checks, and turning a confirmed XSS into account-action impact.
---

# Client-side attacks (P6)

The victim's browser is the target, not the server: CSRF, clickjacking,
open redirects, postMessage misuse, XSS impact.

## The way

- CSRF evidence is server behavior under token mutilation — removed,
  blank, borrowed, expired, method-spoofed, origin-dropped — one mutation
  per replay. A missing token in HTML is a lead, not a finding.
- SameSite=Lax still carries top-level GET: audit GET-based state changes
  as their own class.
- Clickjacking's real value is the chain: a Referer/Origin-validated
  endpoint becomes CSRF-able when the click happens inside the framed
  real page. "Page is frameable" alone is `50`'s header gap.
- Open-redirect severity comes from what it chains into — OAuth code
  interception (`30`), allowlist hops. A bare redirect is low; still
  report it.
- postMessage: listener without an origin check *plus* a sink is the
  finding pair; senders with `'*'` leak to any embedder.
- XSS impact = one canary account action via `fetch`, on engagement
  accounts only. Keylogging is a capability sentence, never a planted
  payload.
- Victim simulation runs in agent_browser with screenshots as evidence —
  never real users.

## Handoffs

Header-gap detection -> `50`; redirect-into-OAuth -> `30`; XSS
source/context -> `40`; D2 impact proofs -> `90`.

## Tools

agent_browser for all victim-side verification; `redirect_probe.py`
(guarded), `postmessage_scan.py` (offline). PoC page templates in
`references/`.
