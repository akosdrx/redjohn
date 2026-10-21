---
name: oast-correlation
description: "Correlates HTTP callbacks from a reviewed GET or authenticated private POST with durable Interactsh polling."
version: "2.2.0"
status: implemented_fixture_tested
---

# RedJohn — oast-correlation

## Purpose and activation
Correlates HTTP callbacks from a reviewed GET or authenticated private POST with durable Interactsh polling.

SSRF, XXE, blind server processing or other pre-approved test requires an out-of-band observation.

Before activation, `AssessmentSkillRegistry.eligibility` checks the target domain,
impact profile, actor/fixture prerequisites and actual capability registry.
This document does not run tools; execution uses the RedJohn controller, scheduler and policy.

## Prerequisites and context
- run_id/test_id
- self-hosted OAST endpoint
- allowed callback protocols
- expiry window

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

A trusted host client implements the pinned Interactsh 1.4.1 protocol. The
receiver origin/IP and credentials remain separate from target authorization.
One captured anonymous/named GET or approved named POST string/text field carries
one generated HTTP callback URL. JSON, form and multipart text fields preserve
all unselected bytes/uploads and reject protected session-token selectors.
Private client keys/tokens remain in bounded 0600/0700 host state. Successful
parent commit releases bounded late polls through the durable SQLite outbox.
Target session refresh never redelivers an old callback request. Already dispatched
allocations can continue correlation after target credentials rotate; polling
requires the original allocation/policy proof, not obsolete target credentials.
Registration, dispatch and draining poll uncertainty remain inconclusive. Keys
retire after acknowledged deregistration. Real encrypted HTTP callbacks, late
polling, fixed controls and refresh are tested. Public DNS/IPv6 reachability,
other callback protocols, XML, file-part mutation and Nuclei OAST binding remain
unverified/unsupported. A callback is a candidate observation, never proof of RCE.

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
oast_correlate.

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
1. Allocate a unique token for each test and bind it to a request_ref and actor_ref before execution.
2. Receive DNS/HTTP events on an approved OAST service and store time, protocol and correlation metadata.
3. Link each event to the exact originating test and include non-trigger controls.
4. Summarize observable server behavior without claiming file access or code execution unless independently proven.
5. Expire callback tokens and redact identifiers before sharing evidence.

Record baseline/positive fixtures separately from fixed or rejecting controls.
A missing control is `not_run`/`inconclusive`; never invent a completed measurement.
Routine inventory, routing and parsing target zero internal LLM calls; provide only references
and a short coverage delta to the model.

## Result criteria and evidence
- correlation token fingerprint
- request/event timestamps
- protocol observation
- control result

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
Public OAST services may expose target metadata to third parties; prefer self-hosting when assessment confidentiality matters.

An unimplemented or blocked capability remains a coverage gap; its absence is not a negative
vulnerability test. Without a real control fixture for this subtask, record the measurement as
`not_run_missing_fixture` and the original RCE as `not_reproduced_missing_fixture`.

## Version, provenance and test references
RedJohn contract version: `2.2.0`; manifest schema: `1`.
Adapted from a user-supplied initial contract without a separate license file; original source: `skills/oast-correlation/SKILL.md`, SHA-256: `7328dc9e492989c007d7854421f337436b7699989cba96de21405b86547fe879`. This is not upstream Strix/HexStrike code and does not grant a license to external tools.

Contract references: tests/test_schema_oast_contract.py.
Actual integration controls: tests/test_schema_oast_live.py.
Registry/provenance: tests/test_assessment_skills.py.
Registry tests verify wiring; they do not establish positive/fixed detection controls for every
vulnerability family. A missing configured dependency is blocked and is never a clean negative.
External background: OWASP WSTG/ASVS; record the specific edition in each assessment.
