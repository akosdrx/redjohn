---
name: idor_matrix
description: IDOR/BOLA matrix template (from auth_access_control_matrix specialist
  reference library)
---

# IDOR/BOLA matrix template

The P4 core artifact: one grid per application/API, filled from the P1
surface inventory and replayed with the P0 contexts via
`scripts/token_swap_replay.py`.

## Contexts file shape

`contexts.json` - one entry per P0 auth context; secrets never literal,
always `env:` indirection resolved at runtime from the operator-supplied
environment:

```json
{
  "anon":     { "headers": {}, "cookies": {} },
  "user-a":   { "headers": { "Authorization": "env:REDJOHN_TOKEN_USER_A" },
                "cookies": {} },
  "user-b":   { "headers": {},
                "cookies": { "sid": "env:REDJOHN_COOKIE_USER_B" } },
  "admin":    { "headers": { "Authorization": "env:REDJOHN_TOKEN_ADMIN" },
                "cookies": { "sid": "env:REDJOHN_COOKIE_ADMIN" } }
}
```

Semantics (as implemented by `token_swap_replay.py`):

- `headers` entries replace any same-named header from the raw request.
- If the `cookies` key is present, the `Cookie` header is built exactly from
  it (empty dict -> the request's original `Cookie` header is REMOVED - that
  is how the `anon` arm is produced). If `cookies` is absent, the original
  `Cookie` header passes through unchanged.
- First context in file order is the baseline arm; every later context is
  diffed against it (status, size, body sha256).
- One replay per context, serial, no retries - pace per master rules.

## Matrix template (roles x object x action)

Duplicate this block per object type; object types and id shapes come from
the P1 inventory (`evidence/p1-*` surface listing).

```text
Object type: invoices (/api/v1/invoices/{id})
Owner-context fixture: invoice created by user-a during the engagement
Id source: sequential | UUID | opaque-ticket  (observed from P1)

| Role    | GET {id} (read) | PATCH/PUT (canary modify) | POST (create) | Notes |
|---------|-----------------|---------------------------|---------------|-------|
| anon    | 401 baseline    | 401 baseline              | 401 baseline  | |
| user-a  | 200 (OWNER)     | 200 (owner write)         | 201           | baseline arm |
| user-b  | ?               | ?                         | ?             | same-tenant |
| admin   | ? (policy?)     | ?                         | ?             | cross-tenant |
```

Fill each cell with the observed status + body-hash short id from the swap
run output. Verdict column per row after fresh-token re-run:

- `user-b`/`admin` GET returns 200 with user-a's data -> candidate CWE-639.
- 403 vs 404 differing between existing and absent objects -> CWE-204
  enumeration side-note.
- 200 but sanitized/different body hash -> data-exposure candidate; open
  the first divergent body line before claiming.

## Id-source rules

| Id source | Procedure | Boundary |
|---|---|---|
| Sequential integer | walk user-a's own id +-1, +-2 only | never more than a handful of neighbors; a wider sweep is engagement-authorized fuzzing, not matrix work |
| UUID | swap in user-b's object id (operator-created fixtures) | NEVER enumerate UUID space |
| Opaque ticket/ref | swap two engagement-created refs between contexts | no guessing beyond the two fixtures |

## Fresh-token rules (D2 promotion path)

1. First pass: run the swap with current contexts -> any candidate cell is
   **D1** only.
2. Before D2: re-issue fresh tokens/sessions for EVERY context (operator
   re-login or fresh OAuth code flow), rebuild `contexts.json` env values,
   replay the same matrix rows that flagged.
3. Same result with fresh tokens -> D2 candidate; different result ->
   session artifact (stale token / expiry), log the negative and re-test
   once from a clean browser context.
4. Attach to the finding: both evidence pairs per context, the A/A
   calibration output for that endpoint, and the matrix row id
   (`<object-type>/<role>/<action>`).

## Evidence naming

- Swap runs: `evidence/p4-<object>-<seq>.<context>.{req,resp}.txt`
  (e.g. `evidence/p4-invoices-003.user-b.req.txt`).
- The tool writes pairs per context when `--save evidence/p4-<object>-<seq>`
  is given; baseline context = first label.
- Matrix file itself lives in the run notes namespace
  (`runs/<engagement>/p4-matrix-<app>.md`), never in global sharing.

## Verdict ladder per cell

1. `blocked-403` / `blocked-404` / `auth-401` -> access control holds.
2. `allowed-identical` (200, same hash as owner) -> full IDOR, strongest.
3. `allowed-partial` (200, different hash) -> inspect divergence; may be
   intentional role scoping (admin preview) - check the false-positive
   list before claiming.
4. `error-5xx` -> note; re-run once serial (race/noise), then record.
5. `inconsistent` (differs across fresh-token runs) -> session artifact,
   not a finding.

False-positive shortlist: admin preview features, per-role response
filtering (different fields, same object), caching layers (cache-bust with
`rjpt=<nonce>` on BOTH arms), and A/B flags.

