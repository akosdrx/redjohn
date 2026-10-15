---
name: rj_race_conditions
description: 'Race conditions: window widening and safety (from logic_concurrency_audit
  specialist reference library)'
---

# Race conditions: window widening and safety

Companion to section 2 of `SKILL.md`; executed via `scripts/race_runner.py`.
CWE-362/CWE-367 (TOCTOU).

## Target selection

Prefer endpoints implementing check-then-act over shared state:

| Pattern | Example action | Divergence to measure |
|---|---|---|
| one-shot resource | redeem code / claim gift / apply coupon | N successes vs 1 |
| balance movement | withdraw / transfer | debited once, credited N (or overdraft) |
| rate/limit counter | one-per-account draw / vote once | N effects vs cap |
| counter increment | referral credit / points award | total > correct sum |
| stock/inventory | buy last item | oversell |

## Window widening methods

1. Pre-connect: establish TCP/TLS per thread BEFORE firing so connection
   setup does not spread arrivals (race_runner connects first, then waits
   on the barrier).
2. Barrier alignment: all threads block on one barrier; release sends every
   request in the same instant. `race_runner --delay-ms 0` (default) is
   aligned.
3. Last-packet-synchronization concept: hold back the final bytes of the
   HTTP request so connections are idle-but-warm, then release the tail
   together — implementations differ per stack; with race_runner the
   closest analog is pre-connect + barrier; for byte-level control use the
   Burp MCP single-packet-style burst (Turbo-style) where available, same
   ceilings.
4. Stagger (`--delay-ms K`): thread i sleeps i*K ms after the barrier — use
   only when probing a known slow window (long check-then-act gap).
5. Burst repetition: single aligned bursts often straddle ticks; repeat
   rounds (`--rounds`) with a pause between and a final-state read after
   each round.
6. Server-side gap widening (only when authorized): preceding slow request
   classes (expensive report, file upload) are out of scope here unless the
   engagement lists them — default to no-gap-forging.

## Alignment procedure (manual, for evidence notes)

1. Save the raw request to `req.txt` (method, path, headers, body) — the
   exact request captured from the P3 harness.
2. `race_runner --scope-file scope.json --request-file req.txt --threads 8`
   (or 16 when RoE allows).
3. Record per-run statuses and body hashes from the output; capture the
   summary verdict.
4. Final-state read: `--verify-file final.txt` (a GET of the affected
   object) or replay the GET through the P3 harness.
5. Re-run from clean state (D2): reset the resource (new code, new
   account, restored balance) and repeat.

## Safety ceiling (binding)

- Default 8 threads; 16 acceptable; absolute script cap 32.
- The engagement's written RoE overrides defaults downward, never upward.
- Bursts target ONE endpoint at a time; no mixed-endpoint storms.
- Between rounds, pause (race_runner waits 1s) and watch error rates; abort
  the run if the target degrades (5xx spike) — availability is not the
  target.
- No bursts against auth endpoints (that is `30` rate-limit testing with
  its own rules).

## Measurement and verdicts

| Observation | Meaning |
|---|---|
| N identical successes + final state shows N effects | race confirmed (D1 -> replay for D2) |
| N identical successes + final state shows 1 effect | serialization present; record negative |
| mixed statuses (200 + 409) with N effects | partial win; report exact mix |
| statuses uniform, bodies diverge | response-level divergence only; needs final-state read |
| uniform response + uniform state | no race at this alignment; try stagger/rounds, then stop (dead-end rule) |

Evidence per run: burst definition, per-run status/hash list, final-state
GET pair, replay run. Response divergence alone is never the finding.

