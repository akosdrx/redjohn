---
name: business_logic_heuristics
description: Business-logic heuristics per vertical (from logic_concurrency_audit
  specialist reference library)
---

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

