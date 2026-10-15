# Targeted mutation, replay and bounded fuzzing

Grammar sketching, mutation ladders, budget/stop rules, and the
differential setup for custom surfaces. Everything here is model-driven
mutation through a sketched grammar — never blind random fuzzing.

## 1. Input grammar sketching (before the first probe)

Write the grammar as a table; every probe must be expressible as a row.

| Field | Type | Delimiter/encoding | Documented limits | Boundary set |
|---|---|---|---|---|
| `query` | string | URL-encoded, then JSON-quoted | len <= 200 | empty, 1, 199, 200, 201, unicode, `%00` |
| `page` | int (1-based) | plain | 1..999 | 0, 1, 999, 1000, -1, `1.5`, `0x1`, `1e3` |
| `filter` | DSL string | base64 body -> parsed | depth <= 3 | depth 4, duplicate keys, unknown ops |
| `sort` | enum-ish | comma list | `name,-date` | unknown field, empty element, doubled commas |

Steps: capture 3 real requests through the `20` harness -> decompose each
field (type, delimiter, encoding layer, limit) -> mark which layers decode
client- vs server-side -> the encode-decode ladder runs through EVERY
decoding layer found.

## 2. Mutation ladders

1. **Boundary values per field** (one per request): empty, `1`, `max-1`,
   `max`, `max+1`, negative, zero, type confusion (`1.5` into an int
   field), duplicate keys (last-wins vs first-wins divergence is a
   differential signal), nested depth one beyond the documented limit,
   unicode (`\u0000`, overlong UTF-8 `xC0xAF`), `%00` terminator.
2. **Encode-decode ladder** (from `40`, verbatim): raw -> single
   URL-encode -> double URL-encode -> Unicode overlong -> `%00`. The rung
   that first produces a delta is part of the finding.
3. **Delimiter injection** at every grammar delimiter: the delimiter
   character, its escaped form, and a premature terminator.
4. **Enum/whitelist probing**: one unknown value, one mixed-case known
   value, one deleted field, one field with wrong type.

## 3. Differential setup

- **Harness**: `20-traffic-manipulation` replay + diff (status/len/sha256).
- **Axes** (one at a time): same input across two endpoints that share the
  parser; two roles (anonymous vs authenticated); two environments (the
  custom parser vs a reference implementation, or pre-patch vs post-patch
  builds from patch diffing).
- **Baseline discipline**: capture the unmutated request's response per
  axis FIRST; every mutation's diff is against that axis's baseline.
- **Signal definition**: a response difference that TRACKS the mutation
  (present with the payload, absent with the baseline value, reproducible
  on replay). One-off glitches are not signals.
- **Invariant: one variable per request.** Stacked mutations are only for
  MINIMIZING an already-reproduced signal: shrink the input until the
  signal disappears, then step back one change — that minimal input is
  what enters evidence.

## 4. Budget and stop rules (binding)

| Rule | Default | Notes |
|---|---|---|
| Generation cap per surface per run | 500 requests | operator sets lower for fragile targets |
| Sleep between probes | >= 0.2 s | serial only; the master's concurrency allowance never applies to research probes |
| Rate ceiling | engagement RoE | never exceeded for a "few more" mutations |
| Stop 1 — signal | first reproducible differential | stop mutating, start minimizing, then verify D2 |
| Stop 2 — budget | cap reached | log the negative result for the coverage statement; move on |
| Stop 3 — error spike | 5xx rate jumps | STOP — availability risk; inform the operator immediately |
| Stop 4 — timebox | section 1 of SKILL.md | research never eats P9 budget |
| Dead-end rule | 3 generations without signal | log negative, move to the next hunk/surface |

## 5. Hygiene

- No fuzzing of third-party SaaS endpoints or out-of-scope hosts; the scope
  guard in every request-sending script enforces this — never bypass it.
- Crash artifacts (stack traces, core dumps surfaced in responses) are
  evidence, not trophies: capture, redact secrets, move on; do not retry
  "to see it again" beyond the D2 replay.
- Log-pollution awareness: mutated inputs land in target logs; keep the
  inventory for the `85` debrief.
- Everything runs inside the assessment container; nothing is uploaded
  anywhere.
