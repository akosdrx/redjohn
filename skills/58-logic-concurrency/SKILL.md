---
name: 58-logic-concurrency
description: Use when the flaw is in business rules or timing rather than a bug class - price, quantity, coupon and currency manipulation, workflow state-machine skips, mass assignment of hidden object fields, and race conditions exploited with parallel request bursts.
---

# Logic and concurrency (P6)

Flaws in business rules and timing rather than bug classes. Start from
what the business *assumes* — price authority, once-only actions,
check-then-act ordering — because that's where the divergence lives.

## The way

- D2 is a replayed final-state divergence: the finding is the end-state
  read (GET) after the action, twice. A single odd response is a
  candidate, nothing more.
- Race wins come from window alignment, not thread count: pre-connect,
  release on a barrier, read the final state after each burst. Ceilings
  come from the RoE — the runner refuses > 32 and that's a feature.
- Bursts miss; rerun them a few times before calling a window closed.
- Mass assignment: a response delta is a candidate; persistence (GET the
  object back, field stuck) is the confirmation.
- Canary values for anything monetary or countable; restore or reverse
  what you created.
- Vertical-specific heuristics (ecommerce/fintech/SaaS money and flow
  models) are lookup tables in `references/` — the model supplies the
  creativity, the tables supply coverage.

## Handoffs

Rate-limit posture discovered mid-burst -> `30`; API-shaped variants ->
`60`; tampering that surfaces injection -> `40`; D2 divergences -> `90`.

## Tools

`race_runner.py`, `field_probe.py` (both guarded). Per-vertical tables
and the alignment procedure in `references/`.
