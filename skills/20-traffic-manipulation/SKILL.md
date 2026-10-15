---
name: 20-traffic-manipulation
description: Use when replaying or editing captured raw HTTP requests, when diffing two server responses to detect subtle behavioral changes or blind flaws, or when planting out-of-band (OOB) DNS/HTTP callbacks to prove blind SSRF, XXE, or asynchronous command injection.
---

# Traffic manipulation harness (P3)

The harness every later phase leans on: raw request replay, structured
response diffing, and the OOB callback listener. Nothing past P3 runs
until it works.

## The way

- One variable per replay; every request file carries its auth-context
  label — an unlabeled request is not evidence. Never edit an evidence
  original.
- A delta is only a delta against a stable baseline: A/A calibration
  first; whatever moves A/A is noise for that endpoint and gets excluded.
- Cache-bust both arms; normalize volatile fields (timestamps, nonces,
  request ids) before hashing.
- Timing is medians over N >= 5 with the warm-up dropped, never single
  shots.
- Blind classes are proved by effect: one unique canary subdomain per
  probe, 1:1 with the probe id. A callback proves the sink reached out —
  check source, timing and uniqueness before granting D1.
- "No response" is never "probably vulnerable". Give async sinks a
  >= 10 minute patience window and record it either way.

## Handoffs

Canary-confirmed blind SSRF/XXE/async-cmdi -> `40`/`45`; role and
behavior deltas -> `30`/`58`; every D2 -> `90`.

## Tools

`req_replay.py` (guarded — validates the final Host against scope before
any socket), `resp_diff.py` (offline). Interactsh-style listener, domain
via env. Diff dimensions and OOB payload-placement families in
`references/`.
