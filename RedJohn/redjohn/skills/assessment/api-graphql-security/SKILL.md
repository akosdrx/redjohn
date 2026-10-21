---
name: api-graphql-security
description: "Checks a captured GET or selected private POST input projection with pinned Schemathesis and bounded integer generation."
version: "2.2.0"
status: implemented_fixture_tested
---

# RedJohn — api-graphql-security

## Purpose and activation
Checks a captured GET or selected private POST input projection with pinned Schemathesis and bounded integer generation.

OpenAPI, Swagger or GraphQL schema available; API traffic detected by the headless browser.

Before activation, `AssessmentSkillRegistry.eligibility` checks the target domain,
impact profile, actor/fixture prerequisites and actual capability registry.
This document does not run tools; execution uses the RedJohn controller, scheduler and policy.

## Prerequisites and context
- schema ref and version
- auth contexts
- API business invariants
- request budget

Bind every action to `engagement_id`, `policy_revision`, `actor_ref`, `tenant_id`,
`session_revision`, `workflow_state` and `request_ref`/`asset_ref`. Use the explicit
`anonymous` actor for anonymous access; never substitute another identity for a missing actor.
Authentication/authorization comparisons require separate actors/tenants and test objects with known ownership.
State-changing workflows require designated disposable fixtures and verifiable cleanup.

## Supported input and body formats
Input mode: `recorded_request`. Supported: captured GET, application/json,
application/x-www-form-urlencoded and multipart/form-data under the reviewed
private POST contract. XML, raw bodies and file-part mutation are unsupported.
Repeated unselected parameters, ordering and encoding stay byte-exact; repeated
selected fields are unsupported. JSONL output alone never establishes body support.

## Current implemented profile

Schemathesis 4.31.1 accepts one hash-pinned OpenAPI 3.0.3 operation, either GET
or a reviewed POST selected-input projection. POST JSON uses one top-level integer;
form/multipart uses one integer text field. The worker sees only a public GET
carrier/schema. The host materializes real POST bytes from current private capture;
unselected fields, session tokens and uploads stay out of worker input and remain unchanged.
Response conformance checks and bounded upstream positive generation remain real.
The projection is not a complete requestBody/CRUD/stateful/GraphQL contract.
Refs, servers, links, hooks, plugins and extra operations are rejected. Two
out-of-operation internal preflight probes remain explicit SKIP, not coverage.
POST requires a named actor, current v2 vault, complete successful browser capture,
exact policy URL, reviewed field and non-idempotent job. No mutating retry occurs.

With explicit `continuous_replay.adapter_rules`, successful fresh browser capture
queues only selected TInjA/Schemathesis/OAST jobs. A complete trusted 401 or precise
private-credential expiry can enter the existing bounded same-actor recovery
outbox. Refresh -> new Chromium capture -> new-revision adapter jobs proceeds
without restarting the scheduler. Old failed/stale POSTs retain their revision
and never retry. Truncated responses, 403/challenges and unknown effects do not
authorize refresh. See `docs/authenticated-schema-oast.md` and the separate real
integration files `tests/test_authenticated_schema_oast_live.py` and
`tests/test_authenticated_schema_oast_recovery_live.py`; synthetic contracts are
in `tests/test_authenticated_schema_oast_contract.py`.

## Canonical capability and RedJohn mapping
schemathesis_validate.

Optional capability: none.
Readiness requires the explicit reviewed configuration and dependencies in the capability registry.
Declared status: `implemented_fixture_tested`. Runtime health reports missing
binaries/dependencies separately; loading a `SKILL.md` does not establish execution coverage.
Legacy dotted tool names are neither MCP nor shell calls and are not registered as tools.

## Impact profile and execution limits
Applicable target domain: web; profiles: active-staging, isolated-lab.
Original maximum required impact profile: `active-staging`; the actual policy may be stricter.
Discovery alone cannot authorize new targets, accounts, regions or scope expansion.
ResourceEnvelope and the shared governor bound workers, browsers, pages, contexts and caches.
Each job has a finite timeout (default 30 s, validated ceiling 600 s), with campaign deadlines
and request, queue and artifact quotas. Optional engines do not start together.

## Procedure and control measurements
1. Import API operations, field types and relationships and correlate them with observed endpoints.
2. Use schema-based tests for valid/invalid input and bounded stateful workflows on disposable fixture data.
3. For GraphQL, map query/mutation/subscription and field-level policy rather than merely scanning introspection.
4. Assess authenticated error handling and documented query complexity/rate rules without load testing production.
5. Pass authorization-related evidence to the dedicated access-control skills.

Record baseline/positive fixtures separately from fixed or rejecting controls.
A missing control is `not_run`/`inconclusive`; never invent a completed measurement.
Routine inventory, routing and parsing target zero internal LLM calls; provide only references
and a short coverage delta to the model.

## Result criteria and evidence
- schema operation IDs
- observed versus expected result
- resource workflow refs
- coverage by operation/field

Require expected and observed behavior, actor/workflow context, controls, evidence references,
tool/template versions and reproducibility. Matching a CVE to a product establishes applicability,
not a dynamic finding. A scanner message, a single HTTP 500 or timing difference, a callback,
or agreement between two agents is not independent proof and does not automatically establish RCE impact.

## Three separate status dimensions
`execution_status`: queued, running, retry_wait, succeeded, failed, cancelled,
timed_out, resource_exhausted. `coverage_status`: not_tested, completed, partial,
blocked, unsupported, inconclusive. `finding_status`: candidate, confirmed_weakness,
confirmed_impact, false_positive, fixed, reopened. An empty result from a valid, actually executed
test supports at most `no_finding_observed`; there is no global "safe" status.
The legacy pack's combined `passed`/`confirmed` enum is not part of the RedJohn schema.

## Timeout, stop, cleanup and recovery
Policy denial, missing prerequisites, unexpected side effects, storage failure or budget
exhaustion stop the affected work. Propagate cancellation; release subprocesses, pages,
contexts, listeners and leases in `finally`, and audit cleanup failures. Retry only safe,
idempotent work within shared attempt, retry and deadline budgets. Reconcile uncertain
side effects after a crash before proceeding. Refresh sessions for the same actor with a new
session revision and cache invalidation. Share cooldown after 429/Retry-After; classify 403
as a separate authorization/challenge outcome. Fallback must preserve authentication,
TLS verification, the Chrome sandbox and the engagement scope.

## False positives and coverage limits
Introspection being available or a 500 error alone does not prove exploitability.

An unimplemented or blocked capability remains a coverage gap; its absence is not a negative
vulnerability test. Without a real control fixture for this subtask, record the measurement as
`not_run_missing_fixture` and the original RCE as `not_reproduced_missing_fixture`.

## Version, provenance and test references
RedJohn contract version: `2.2.0`; manifest schema: `1`.
Adapted from a user-supplied initial contract without a separate license file; original source: `skills/api-graphql-security/SKILL.md`, SHA-256: `e40100b2a8fae65f18ede0637c858a9dc9f76449b73f0c4421f4d8e15a5cbb4b`. This is not upstream Strix/HexStrike code and does not grant a license to external tools.

Contract references: tests/test_schema_oast_contract.py.
Actual integration controls: tests/test_schema_oast_live.py.
Registry/provenance: tests/test_assessment_skills.py.
Registry tests verify wiring; they do not establish positive/fixed detection controls for every
vulnerability family. A missing configured dependency is blocked and is never a clean negative.
External background: OWASP WSTG/ASVS; record the specific edition in each assessment.
