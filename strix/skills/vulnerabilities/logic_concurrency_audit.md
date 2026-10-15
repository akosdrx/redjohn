---
name: logic_concurrency_audit
description: Use when the flaw is in business rules or timing rather than a bug class
  - price, quantity, coupon and currency manipulation, workflow state-machine skips,
  mass assignment of hidden object fields, and race conditions exploited with parallel
  request bursts.
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

---

## Reference Module: `business-logic-heuristics`

# Business-logic heuristics per vertical

Companion to section 1 of `SKILL.md`. One variable at a time, baseline
diffed via the P3 harness. Canary/engagement values only.

## Ecommerce

| Surface | Checks | Signal |
|---|---|---|
| Cart item price | resend cart POST with `price` field changed (unit price re-read from client) | total computed from client price |
| Quantity | `0`, `-1`, `-100`, `0.5`, `1e3`, `2147483647`, `2147483648`, very long digit strings | negative totals, refunds, overflow/underflow, integer coercion |
| Coupon | apply twice, apply expired, apply another user's code, stack incompatible codes, apply then remove after checkout render, currency of discount different from cart | double discount, expired honored, cross-user reuse, stacking |
| Currency | pay 1 unit, item priced in another (`currency=USD` vs `EUR` at checkout), comma/dot decimal swap (`1.000` vs `1,000`) | mispriced totals |
| Rounding | totals at `.005`, `.5`, `.99` boundaries; quantity * unit vs displayed total | off-by-a-cent loops, negative remainder |
| Tax/shipping | set `shipping=0`, `taxRate=0` in the request | client-controlled fees |
| Gift cards | redeem the same code in parallel (see race playbook), partial redemption twice, negative redemption | double spend |
| Checkout flow | reorder steps: payment confirmation before address validation; replay the success callback | state machine skips |

## Fintech

| Surface | Checks | Signal |
|---|---|---|
| Transfers | amount > balance by +1; negative amount; zero; amount = balance exactly; two transfers same moment (race) | overdraft, reverse movement, double spend |
| Balance checks | ordering of check vs debit: fire debit bursts right after a deposit (window between check and commit) | TOCTOU on balance |
| Audit fields | client-sent `createdBy`, `timestamp`, `referenceId`, `narrative` on a transfer | spoofable audit trail |
| Limits | daily/transaction limit boundary +/- smallest unit; limit check on one currency but debit in another | limit bypass |
| Statements/refs | reuse `referenceId` / idempotency key with a different payload | idempotency confusion |
| Refunds | refund more than paid, refund twice, refund a cancelled transaction | inflation |

## SaaS

| Surface | Checks | Signal |
|---|---|---|
| Seats/licenses | plan N seats: invite the N+1st user, remove then re-invite racing the count | off-by-one seat bypass |
| Trials | trial->paid upgrade without a payment token; downgrade then keep paid features; extend trial by re-issuing start | free upgrade |
| Referrals | refer yourself with a second engagement account, credit both sides twice, loop the same referral | double credit |
| Permissions | role/plan fields on profile or invitation endpoints (mass assignment table applies) | self-elevation |
| Quotas | API-call/storage quota boundary: burst past the counter check (race), quota check per-period vs per-request | quota bypass |

## Generic state machines

| Check | How |
|---|---|
| Step skipping | POST the final-step endpoint directly with a guessed/fetched intermediate object id |
| Terminal action replay | re-issue a completed cancel/approve/refund/logout-everywhere; look for double effect |
| Idempotency-key absence | same key different payload; same payload no key in parallel (race) |
| UUID/sequence reuse | submit two objects with identical external ids |
| Hidden status values | set `status` to values the UI never offers (`approved`, `verified`, `shipped`) |

## Discipline

1. Baseline each endpoint once before any mutation.
2. One field/value change per request; record which rung changed behavior.
3. Reverse or restore mutations where the engagement expects cleanup;
   destructive end states need written approval first.
4. D2 = replay from clean state twice with final-state reads captured.


---

## Reference Module: `mass-assignment`

# Mass assignment: field candidates and confirmation

Companion to section 3 of `SKILL.md`; executed via
`scripts/field_probe.py`. CWE-915.

## Field candidate tables per framework

### Generic candidates (try everywhere)

`role isAdmin admin adminFlag active verified status plan planId price
amount discount ownerId owner userId accountId organizationId tenantId
teamId permissions scopes balance credit quota isStaff isPremium deleted
mfaEnabled emailVerified`

### By framework/runtime (typical binding names)

| Framework | Shapes to watch |
|---|---|
| Rails | `user[admin]`, `user[role]`, strong-params gaps on nested models (`user[profile][visibility]`) |
| Django | form/MODEL_FIELDS over-posting: `is_superuser`, `user_permissions`, `groups` |
| Laravel | fillable gaps: `is_admin`, `role_id`, guarded attribute reflection in `$request->all()` |
| Spring | Jackson polymorphic binding on DTOs: nested `{"user": {"role": ...}}`, `@JsonIgnoreProperties` gaps |
| Node/Express | body-parsed objects merged into models (mongoose `findOneAndUpdate` with spread body): `__v`, nested `role` |
| ASP.NET | model binder over-posting: `IsAdmin`, `AspNetUserRoles` nav properties |

### Discovery sources (in order)

1. GET the object: every response key is a write candidate somewhere.
2. OpenAPI/Swagger schemas (P1 artifact) — request bodies name fields.
3. Client JS models/ORM definitions.
4. Error messages naming rejected fields (a 400 listing fields is a gift).

## Confirmation workflow (binding)

1. Capture the legitimate write request (e.g., profile update) via the P3
   harness; save it as `req.txt`.
2. `field_probe.py --scope-file scope.json --request-file req.txt --fields role,isAdmin,planId`
   replays the baseline once, then one request per field with a benign
   sentinel added (`--value` overrides; default `fieldprobe-sentinel`,
   numeric-typed fields: use `--value 1`).
3. Read the verdicts:

| Verdict | Meaning | Next |
|---|---|---|
| REJECTED (4xx vs baseline) | schema knows the field, refuses it | negative; record |
| ACCEPTED-CANDIDATE (2xx + response delta) | server processed the extra field | GET the object back |
| NO-EFFECT (identical) | field dropped server-side | negative; record |

4. Confirm persistence: GET the object; the field present with your
   sentinel = mass assignment confirmed (D1). For sensitive fields where a
   sentinel is unacceptable (e.g., `role` on a shared account), use the
   second engagement account and restore immediately.
5. D2: replay the accepted write + read-back from a clean state.

## Safety rules

- Sentinel values only: `fieldprobe-sentinel` or numeric `1`; never real
  privilege values unless the engagement explicitly authorizes an
  escalation proof, and then only on engagement accounts with a restore
  path.
- One field per request; stacking hides which field mattered.
- Restore every persisted sentinel before closing the phase.

## Evidence

- Baseline replay pair; one pair per field; the read-back GET showing
  persistence; the replay run. Named
  `evidence/p6-massassign-<endpoint>-<field>.{req,resp}.txt`.


---

## Reference Module: `race-conditions`

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

