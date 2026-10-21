# Durable inventory and reviewed workflows

The existing RedJohn SQLite assessment store now keeps assets, services,
provenance, surface bindings, reviewed workflow definitions, actor-specific
workflow instances, exclusive step leases and bounded transition history. The
additive `rj_inventory_schema` does not rewrite the existing `rj_schema`, surface
payloads, `Surface.key`, or job IDs. Legacy HTTP rows can be linked in bounded
pages with `inventory_backfill`; there is no unbounded startup corpus scan.

## Inventory and permission

Asset kinds cover HTTP origins, DNS names, IP addresses/CIDRs, source artifact
manifest SHA256 identities, and external cloud-account/cluster identifiers.
Metadata is labelled `observed`, `imported`, or `inferred`. An observed item must
reference existing evidence from the same engagement. A discovered/imported
item never adds an origin, IP, source grant, credential or executable capability
to the policy. Cloud/cluster identities are metadata; live external access was
explicitly deferred by the operator and is not represented as verified.

HTTP surfaces automatically link to origin assets and HTTP(S) services in the
same transaction. Historical `observed` surfaces without valid provenance stay
readable; their new inventory metadata is labelled inferred. Retirement uses
revision CAS. Retired assets/services block both new submissions and queued-job
admission. Recording another observation never reactivates a retired entity.
A source surface uses its explicit `source_artifact` asset reference and pinned
manifest digest, with an empty URL: no artificial web URL grants source access.
Source execution still requires the explicit current policy manifest grant.
Immutable source manifest evidence can opt into transactional
`evidence_put(..., deduplicate=True)`; ordinary measurement events remain distinct.

Owner-bound control operations include `asset_search/get/set_state`,
`service_search/set_state`, `inventory_observations/backfill` and filtered
`surface_search` (`actor_id`, `tenant_id`, `session_revision`, `method`, `source`,
`workflow_state`, `asset_id`). Pages contain 1–100 rows. Limits bound assets,
services, observations, links, definitions, instances and history independently.
The control API retains its 64 KiB input/output limits and policy-revision fence.
No control operation can insert arbitrary response evidence or workflow code.

## Explicit workflow configuration

The existing assessment configuration may opt into `workflow_execution` only
with an owner-protected `auth_vault_file`. This does not launch optional scanners
or create assessment jobs. Definitions are operator-reviewed host configuration;
clients can discover their IDs through `workflow_definition_search` and start
instances with `workflow_start`. Example configuration fragment:

```json
{
  "workflow_execution": {
    "enabled": true,
    "timeout_seconds": 10,
    "max_response_bytes": 262144,
    "definitions": [{
      "name": "owned-object",
      "revision": "1",
      "initial_state": "empty",
      "terminal_states": ["cleaned"],
      "steps": [
        {"name":"create","from_state":"empty","to_state":"created",
         "method":"POST","url":"https://approved.example/api/create",
         "effect":"mutation","expected_statuses":[201]},
        {"name":"cleanup","from_state":"created","to_state":"cleaned",
         "method":"POST","url":"https://approved.example/api/cleanup",
         "effect":"cleanup","expected_statuses":[204]}
      ]
    }]
  }
}
```

Each URL/method must independently satisfy the current policy; POST requires the
existing explicit replay URL grant. `response_sha256` optionally requires an
exact reviewed response-body digest. Without that field, the declared success
assertion is the bounded complete response plus the explicitly listed status;
it is not proof of arbitrary application business semantics. Definitions accept
no shell, JavaScript, Python, credential, request body, URL template or arbitrary
assertion evaluator. Every mutation must have a reachable cleanup transition.
There are at most 16 configured definitions, 64 steps per definition, and bounded
serialized metadata. The outer existing configuration-file limit also applies.

`workflow_submit_step` accepts exactly `instance_id`, `step_name`, `surface_id`,
`expected_revision` and the mandatory `policy_revision`. It constructs one
non-idempotent durable `workflow_execute` job. The planner never discovers a
workflow or automatically grants permission. The named observed surface and
private replay vault must match the actor, tenant, current session revision,
exact method/URL, request reference, MIME type and POST body hash.

`WorkflowExecutionAdapter` uses the existing `Scheduler`, persistent request
budget/limiter, resource governor and bounded `BrowserEgressProxy`. The trusted
host sends one request, injects exact approved private bytes/credentials at the
proxy, verifies upstream TLS, pins allowed numeric destinations, and disables
redirects and environment proxy inheritance. No untrusted external worker runs
inside this adapter. It does not weaken native scanner/browser isolation or
replace their namespace/cgroup gates. Response streaming has a configurable
1 KiB–1 MiB bound, a wire cap, a timeout and a response hash; private bodies,
credentials and response bodies do not enter job options or public evidence.

## Restart, unknown outcomes and session refresh

The workflow state is bound to engagement, actor, tenant, policy revision and
session revision. CAS and exclusive lease UUIDs serialize state transitions.
Scheduler owner/attempt/cancellation/lease checks run before request admission
and after the response. A request is marked inflight before numeric connect.
Only a complete response from the trusted producer can commit a transition.
A response with a failed assertion, a timeout, cancellation, truncated/oversized
body, or lost job lease cannot be reported as a completed step. The admitted
inflight lease remains durable and blocks automatic replay, including after
restart. Repeated scheduler submission deduplicates the existing job. An
expired prepared lease can be safely released/replaced; an expired inflight
lease requires explicit outcome reconciliation, never an automatic resend.
`workflow_get` includes the bounded active lease for owner reconciliation.

`workflow_claim_step`, `workflow_mark_sent`, `workflow_complete_step`,
`workflow_reconcile_step` and `workflow_release_prepared` are owner-bound state
operations. They cannot forge the trusted HTTP producer's proof or relax policy.
An unresolved failed mutation can therefore remain blocked: RedJohn does not
pretend that an uncertain action was rolled back or silently issue cleanup
against an unknown object.

The production session refresh adapter and workflow request reservations
mutually exclude each other for the same actor/tenant/policy. Committed refresh
proof is derived from `rj_session_refresh`, not arbitrary client evidence.
`workflow_refresh_session` preserves the workflow state, increments its CAS
revision, and accepts only the exact succeeded refresh and current ready
session. A refreshed observed capture/private vault can then supply the next
reviewed step after restart. The real E2E explicitly performs this handoff; it
does not claim a general automatic application login/MFA/CSRF-flow generator.

## Verification and limits

Focused commands from the workspace root:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_inventory_workflows_contract.py \
  RedJohn/tests/test_inventory_workflows_live.py \
  RedJohn/tests/test_workflow_execution_failures_live.py -q

PYTHONPATH=RedJohn .venv/bin/mypy --config-file RedJohn/pyproject.toml \
  RedJohn/redjohn/assessment/inventory.py \
  RedJohn/redjohn/assessment/workflow_models.py \
  RedJohn/redjohn/assessment/workflow_execution.py \
  RedJohn/redjohn/assessment/store.py RedJohn/redjohn/assessment/control.py
```

The normal configured CLI remains
`redjohn assess run --config /absolute/approved.json --output /absolute/run --max-jobs 16`.
Configuration only registers reviewed definitions; an authorized host/control
client must explicitly start and submit the desired instance/step. No secrets
belong in the JSON job options or command line.

`test_inventory_workflows_contract.py` is explicitly SQLite/control/metadata
contract coverage. Its manufactured outcome records are not network proof.
`test_inventory_workflows_live.py` uses an actual CA-verified loopback TLS
application, performs real HTTP baseline observations, then runs both actors'
create/read/update/cleanup through the production control, scheduler and private
replay adapter. It rotates Alice's credentials through the production scheduled
refresh adapter, closes/reopens SQLite, rejects old credentials/revisions and
cross-actor access, resumes, and verifies zero remaining application objects,
workflow leases and active governor resources. JUnit suite properties record
actual counts and elapsed time. The eight baseline setup requests and two denial
requests are labelled separately from the nine scheduler-admitted requests.
Five additional real HTTPS cases cover 403, redirects, oversized/truncated bodies
and a wrong reviewed hash, with no advancement or automatic repeat.

These owned-fixture tests use no transport/client/worker mocks. They do not use
an external language model, external credentials, or a real cloud/Kubernetes
account. Native Chromium/Nuclei/source-engine E2Es and platform namespace/cgroup
proof remain separate active suites. Full x64/ARM64 regression belongs in hosted
Actions; these focused local checks do not replace a completed hosted run.
