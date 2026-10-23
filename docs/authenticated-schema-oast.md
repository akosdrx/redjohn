# Authenticated selected-input POST jobs and session recovery

TInjA, Schemathesis and the Interactsh protocol adapter reuse RedJohn's existing
private v2 replay vault, Chromium POST capture, body-token rotation and persistent
SQLite scheduler. Existing anonymous GET and Nuclei workflows remain available.
Optional tools start only for selected jobs, sequentially under shared budgets.

## Supported requests

| Adapter | Captured GET | Named-actor POST field | Remaining boundaries |
|---|---|---|---|
| TInjA 1.2.0 | One benign query value, anonymous or named | JSON string via JSON Pointer; one form or multipart text field | Finite 71-item expression profile; no arbitrary runtime/file probes or CSTI |
| Schemathesis 4.31.1 | One bounded integer query value, anonymous or named | Top-level JSON integer; integer form/multipart text field | One pinned OpenAPI selected-input projection and flat JSON response contract; no CRUD/stateful/GraphQL |
| Interactsh protocol 1.4.1 | One selected query value, anonymous or named | JSON string, form or multipart text field | One generated HTTP callback delivery to separately approved infrastructure; bounded durable late polls |

Legacy body approvals retain their original strict MIME interpretation. Automatic
capture now records supported MIME variants with per-request
`body_contract_version: 2`, including Chromium's compact `;charset=UTF-8`,
case/quoted parameter variants and quoted multipart boundaries. The raw approved
header and bytes remain unchanged. See [MIME replay and restart](mime-replay-and-restart.md)
for the separate vault/body version fields and remaining encoding boundaries.

POST requires `active-staging`/`isolated-lab`, a named actor, exact
`policy.allowed_replay_urls`, an actual successful complete capture, private body
approval and `idempotent=False`. No generic POST seeds or arbitrary raw HTTP are
admitted. XML, array/object mutation, repeated selected fields, file-part mutation
and unreviewed inputs are unsupported. Repeated unselected form/JSON fields,
original encoding, multipart framing, part order and upload bytes remain intact.

The existing 64 KiB body ceiling also applies after mutation. JSON walking is
bounded to 64 levels / 4096 nodes; multipart permits at most 32 parts and 4 KiB
part headers. One selected value is at most 4096 UTF-8 bytes. Protected private
`body_tokens` selectors cannot overlap the mutation field. Proxy response,
request/rate, worker/output/file, campaign, queue and allocation limits remain.
RAM admission remains cooperative, not a universal OS hard memory limit.

## Private host transport

The host supplies a public local HTTP GET/query carrier as scanner input.
It does not put original bodies, uploads, CSRF tokens, cookies or Authorization
headers in worker arguments, request files or generated schemas. Target responses
remain untrusted scanner input; the adapter stores bounded structured metadata
and hashes rather than raw response/tool logs. The trusted host validates
each proposed value, constructs real POST bytes by replacing only the reviewed
scalar span, restores the exact target URL/method/content type and injects current
credentials. Real target policy precedes budget admission, DNS pinning and the
upstream TLS-verified connection. Direct CONNECT escapes remain denied.
Client-nominated hop fields are stripped before private materialization, so a
worker's `Connection: Content-Type, Cookie, Authorization` cannot suppress host
framing or credentials. The real native CLI regression exercises this boundary.

This is a RedJohn transport bridge. It does not claim native arbitrary
JSON/multipart scanning from TInjA's JSONL output or full Schemathesis requestBody
generation. Schemathesis executes its real positive generator and response checks
against the selected-input projection; fixed private fields are materialized only
by the host. Two previously excluded upstream out-of-operation probes remain
explicit SKIP. Remote untrusted scanner/browser workers still require the attested
Linux kernel boundary. The separate macOS loopback lab profile proves no remote
kernel containment.

## Persistent selection and refresh

Use the existing [browser capture/body-token](browser-post-body-tokens.md) private
rules and [session provider](session-refresh.md). This configuration fragment
adds selected adapter children to an otherwise approved assessment:

```json
{
  "continuous_replay": {
    "version": 1,
    "rules": [],
    "adapter_rules": [{
      "actor_id": "alice",
      "tenant_id": "tenant-a",
      "url": "https://authorized.example:443/input",
      "content_type": "application/json",
      "capability": "tinja_validate",
      "input_location": "json",
      "input_name": "/value"
    }],
    "session_recovery": {"max_refreshes": 1, "cooldown_seconds": 0}
  }
}
```

Other selections are `schemathesis_validate` and `oast_correlate`. For URL-encoded
or multipart fields use `input_location: "form"` / `"multipart"` and the exact
field name. Only TInjA/OAST allow nested JSON string pointers. Schemathesis POST
snapshots must contain exactly one `post` operation, a required `requestBody`
with one selected integer property, and the existing flat JSON response schema.
It describes the selected-input projection, not every fixed/private field.

Secret-free configuration examples: `examples/assessment-authenticated-schema-oast.json`
and `examples/reviewed-post-input-schema.json`. Replace all placeholders and keep
actual vault/provider/capture approval files outside the repository.

There are at most 64 combined Nuclei/adapter rules. Adapter-only configurations
need no Nuclei lock; existing nonempty Nuclei `rules` still require their reviewed
lock. Body/vault/capture approvals never enter scheduler options. A direct
selected job uses an observed input surface and reviewed `hint_ref` as before.

Successful capture commits a durable follow-up event. Atomically submitted
children bind the actual body digest, actor/tenant/session, selected field, policy
and engine/profile revision. A fresh hint ID alone does not authorize repetition.
Batch limits count capture, refresh, adapter and poll jobs; ready work survives
controller exit. `--wait-ready-seconds` drains future ready work within its finite
budget and never holds a worker lease while sleeping.

A complete trusted target 401 or precise preflight credential expiry can enter
the existing fenced recovery outbox and persistent per-identity refresh budget.
Refresh advances the same actor's revision and rotates reviewed token bindings;
actual fresh Chromium capture must approve the new body before new adapter jobs
start. Old failed/stale POSTs are not relabelled, retried or anonymously replayed.
403/challenges, truncated responses and unknown effects do not authorize refresh.
Historical failures remain visible, so a CLI may exit 1 while the separately
identified new-revision jobs succeed.

Profile fingerprints advance with this extension. Outdated queued profiles and
allocations retain their original identities; they are not relabelled or resent.
Review/reconcile work bound to an older profile before selecting current-version
jobs. The existing v1/v2 private vault schemas remain compatible.

Token rotation is per session/provider refresh. Automatic acquisition of a new
single-use nonce between every scanner probe remains unsupported.

Already dispatched OAST allocations keep polling their original approved receiver
after target credentials rotate. Polling sends no target request and needs no
obsolete target credential. New target delivery requires fresh capture/current
credentials. Interrupted dispatch or draining poll remains inconclusive and
requires reconciliation. Callback receipt remains candidate evidence, not RCE.

## Start and verify

From the repository root, after explicit pinned installation from the
[adapter runbook](schema-oast-adapters.md):

```sh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/approved.json \
  --output /absolute/private/engagement --max-jobs 32 --wait-ready-seconds 65

PYTHONPATH=. REDJOHN_REQUIRE_SCHEMA_OAST_E2E=1 \
  .venv/bin/python -m pytest \
  tests/test_authenticated_schema_oast_contract.py \
  tests/test_authenticated_schema_oast_live.py \
  tests/test_authenticated_schema_oast_recovery_live.py -q -s
```

Set `REDJOHN_REQUIRE_REMOTE_E2E=1` on Linux to require remote kernel tests rather
than skip missing isolation. Measurements use `REDJOHN_AUTH_SCHEMA_MEASUREMENTS`.
The contract file contains synthetic private-input/crypto/state controls; both
live files execute actual Chromium, pinned engines, HTTPS provider and official
receiver. Original active tests remain in the full regression suite.

No additional tool version or license is introduced. Native CLI flags were
checked against the installed release and [pinned TInjA documentation](https://github.com/Hackmanit/TInjA/blob/a434f525798cdc942427b22894608a5d9181037b/README.md).
[Schemathesis CLI documentation](https://schemathesis.readthedocs.io/en/stable/reference/cli/)
and the existing commit/license locks remain references, not E2E proof.
