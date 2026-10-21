# Reviewed stateful GraphQL workflows

RedJohn's existing `workflow_execute` adapter can validate and execute a pinned
GraphQL operation as one durable reviewed workflow step. It uses the same
scheduler, request budget, rate limiter, private authenticated capture, verified
HTTPS proxy, inventory/session fences and resource governor. A query sent as
POST still requires the separate POST replay grant. Discovery, schema import
and a readable SDL file do not grant execution.

The optional parser is pinned to `graphql-core==3.3.0`. Installation from the
repository root is explicit:

```sh
.venv/bin/python -m pip install -e './RedJohn[graphql]'
```

The installed package metadata identifies upstream
`https://github.com/graphql-python/graphql-core` and license expression `MIT`.
The parser's source is not copied into RedJohn; its upstream license remains
applicable independently of RedJohn's Apache-2.0 metadata.

The same exact pin is in `RedJohn/requirements-assessment.lock` and the hosted
CI dependency lock. Existing core paths do not import the GraphQL parser or
require that extra. A selected GraphQL profile without the exact parser fails
configuration; it is not reported as an integration success.

## Host configuration

Add `graphql_contracts` and a protected `private_state_file` to the existing
`workflow_execution` configuration. A definition step selects a contract by
name with `graphql_contract`. Its URL, method, state transition, actor/tenant,
session revision, observed surface and private approved request must still
match exactly. For example, a reviewed read step can use:

```json
{
  "name": "read",
  "from_state": "created",
  "to_state": "read",
  "method": "POST",
  "url": "https://approved.example/graphql",
  "effect": "read_only",
  "graphql_contract": "read-item"
}
```

A matching contract has these fields (replace both SHA256 values with the
actual reviewed schema/document hashes):

```json
{
  "name": "read-item",
  "schema_file": "/absolute/reviewed/schema.graphql",
  "schema_sha256": "<64 lowercase hex characters>",
  "document_sha256": "<64 lowercase hex characters>",
  "operation_name": "ReadItem",
  "operation_type": "query",
  "variable_bindings": [["id", "object"]],
  "actor_pointer": "/data/read/owner",
  "expected_fields": [["/data/read/value", "created"]]
}
```

The private capture contains the exact JSON envelope `query`, `operationName`
and `variables`. Its query bytes must match the document pin. The SDL must be a
regular owner-owned file, with no group/other write permission, at most 64 KiB.
It is opened without following a final symlink and its digest and descriptor
identity are rechecked. No introspection request or schema download is made.

A create contract can declare `extracts: [["object", "/data/create/id"]]`.
Only after a completely framed successful response, no GraphQL errors, and all
reviewed assertions pass does RedJohn save that bounded string in the protected
state file. A later reviewed operation can substitute it into the one exact
string variable named by `variable_bindings`. Other body bytes remain intact;
authentication/CSRF token variables cannot be overwritten. Body bytes, scalar
values and credentials stay out of job options, SQLite, prompts and reports.

The state file starts as mode 0600 JSON:

```json
{
  "version": 1,
  "engagement_id": "approved-engagement",
  "owner_id": "operator",
  "policy_revision": "1",
  "flows": {}
}
```

The existing private-file protection and atomic fingerprint CAS apply. Values
are bound to workflow instance, definition, actor, tenant and policy, with a
committed workflow revision. At most 64 private instances, 16 scalar values per
instance and 16 KiB of scalar bytes are retained. A private checkpoint ahead of
SQLite is blocked; it never becomes permission to repeat a mutation. A real
SQLite/runtime restart can restore a committed object ID without repeating its
create request. Empty additive fields are omitted from serialized legacy
definitions, preserving their existing IDs and payload comparisons.

## Assertions and limits

Only one named query or mutation with one root field is accepted. Subscription,
batch envelopes, multiple operations, fragments and introspection are denied.
The request document is at most 8 KiB/1024 parser tokens; schema parsing is at
most 4096 tokens; AST depth is at most 32 and aliases at most 16. JSON envelopes
have separate byte/depth/node budgets and reject duplicate keys and nonfinite
numbers. Requests remain within the existing 64 KiB private-body limit;
responses are bounded by the smaller workflow limit and 256 KiB.

HTTP 200 alone does not pass a step: ordinary `errors` responses and malformed
error envelopes fail, do not advance state, and retain the admitted inflight
lease. RedJohn does not infer that an API error rolled back a mutation. Unknown
outcomes need explicit reconciliation; there is no automatic resend. Cleanup
is an exact reviewed step against the committed private object ID, with the
same independent authorization. An uncertain mutation without a known object
identity is not cleaned up by guessing or a broad delete.

For an explicit read-only authorization control, a query contract can require
an exact `expected_error_code` and a `denied_data_pointer` which must be null.
That verifies the expected denial; it is distinct from ordinary CRUD success
and cannot be used on a mutation contract. Generic errors remain failure.

## Starting and verification

Use the existing owner-bound `workflow_submit_step` control operation with the
workflow instance, selected observed surface, exact step name, expected workflow
revision and current policy revision. No GraphQL document or variables are
accepted in that API. The normal launcher is unchanged:

```sh
redjohn assess run --config /absolute/approved.json --output /absolute/run --max-jobs 16
```

Focused verification from the repository root:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_graphql_workflow_contract.py \
  RedJohn/tests/test_graphql_workflow_live.py -q
```

The contract file contains manufactured private bindings and parser/SQLite
checks, not transport evidence. The live case uses an actual CA-verified TLS
application and real `graphql-core` resolvers, two actors, production
`ConfiguredAssessment`, persistent SQLite and real runtime restart. Its oracle
separates nine actual baseline/capture HTTPS requests from eight scheduled CRUD
requests and two scheduled denial/error requests. It checks error-as-failure,
cross-actor denial, zero residual objects, no secret/object ID in SQLite and no
active proxy/governor resources. The intentionally failed query retains one
inflight workflow lease; that is recorded uncertainty, not a leaked process or
an integration pass. No LLM/provider, external credentials, HTTP mock or live
external cloud/Kubernetes access is used. Hosted Linux isolation remains a
separate platform check.
