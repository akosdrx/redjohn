# REST gap checklist: methods, versions, errors, idempotency

Consumes the P1 surface inventory (schema rows from openapi discovery and
JS extraction). All requests serial, scope-guarded, evidence pairs per
probe. Substitute `https://target.example.com`.

## 1. Method acceptance map

For each resource endpoint, one request per verb, same auth context, empty
or minimal body; record the full matrix:

| Path | GET | POST | PUT | PATCH | DELETE | OPTIONS | HEAD |
|---|---|---|---|---|---|---|---|
| `/api/v1/orders` | 200 list | 201 | 405 | 405 | 405 | allow list | 200 |
| `/api/v1/orders/{id}` | 200 | 405 | 200 | 405 | 204 | - | - |

Interpretation rules:

- 405 vs 404: 405 proves the path exists under another verb; 404 can hide a
  verb-routed controller — retest discovered paths with all verbs once.
- "Silent" acceptance: 200 on a verb the documentation/schema does not list
  is an undocumented method finding — capture the body diff vs documented
  behavior.
- OPTIONS: read `Allow:`; compare against the observed map — server-claimed
  but never-tested verbs get one probe each.
- Method override: on a POST-only endpoint, send POST with
  `X-HTTP-Method-Override: DELETE`, `X-Method-Override: DELETE`, and body
  `_method=delete` (urlencoded). Any state change = bypass of the verb
  policy.
- TRACE: send once; a reflected body is a classic observation (usually
  proxied frameworks disable it — 405 is the normal keepable negative).

## 2. Version skew checks

For each resource present in more than one version prefix:

1. Same object id, same role token, both `/v1/` and `/v2/` (also `/api/v1`,
   `/api/v2`, unversioned `/api`): diff status, shape, field set — old
   versions leaking fields the new one filters is a common authz regression
   (pair with the field-diff from `30`'s matrix).
2. Validation strictness: send the SAME invalid payload (extra field, wrong
   type, negative amount) to both versions; a 400 in v2 and silent 200 in v1
  means the old surface never received the new validation.
3. Deprecated surfaces: look for `Deprecation`/`Sunset` headers; absence of
   deprecation markers on an older version is an observation, not a finding.
4. Undocumented intermediate versions: probe `/v0/`, `/v3/`, `/internal/`,
   `/private/`, `/mobile/`, `/legacy/` prefixes on 5-10 known resource
   paths — bounded, serial.
5. Changelog/JS diff: older client bundles (web archives, mobile captures
  if provided) referencing `/v1/` endpoints that the current schema dropped
  = shadow endpoints to retest.

## 3. Error verbosity triggers

One request each, capture the pair, classify:

| Trigger | Example | Leak class |
|---|---|---|
| Type error | `?id=abc` where `?id=1` works | stack trace, ORM error |
| Validation | negative quantity, overlong string | field list, framework signature |
| Duplicate | replay a unique-value create | SQL fragment (CWE-209) |
| Unknown field | extra JSON property on write | validation policy map |
| Malformed JSON | `{` | parser fingerprint (FastAPI/Express/Django shapes) |

Any stack trace -> `50-config-baseline` observation; framework signature ->
`70-exploit-intel` fingerprint row with version confidence.

## 4. Idempotency checks

Operator-created synthetic data only; never real user records.

1. POST create replay: send the identical POST twice (same token); second
   response 201 again (duplicate created) vs 409 (enforced) vs same id
   (idempotent).
2. Idempotency keys: if the API documents `Idempotency-Key`, replay the key
   with a DIFFERENT body — some implementations return the cached first
   response without checking body match (a cache-confusion finding).
3. PUT/PATCH replay: same PATCH twice; state must land on the same value —
   non-idempotent PATCH semantics produce drift (record the exact two
   states).
4. DELETE replay: first 204, second 204 vs 404; 404-after-204 is normal.
5. Concurrency depth (two parallel requests racing) belongs to
   `58-logic-concurrency`; capture the pair here and hand off.

## 5. Registration

Append rows to the surface inventory for every accepted-but-undocumented
method/version found:

```text
surface | method=PATCH | path=/api/v1/orders/{id} | source=method-map
  | auth=role:user-a | evidence=evidence/p6-api-rest-003.{req,resp}.txt
```

Then loop-back: new path -> `30` matrix row per role; new parameter ->
`40` input-surface row; error leak -> `50`; fingerprint -> `70`.
