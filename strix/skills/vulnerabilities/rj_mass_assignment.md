---
name: rj_mass_assignment
description: 'Mass assignment: field candidates and confirmation (from logic_concurrency_audit
  specialist reference library)'
---

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

