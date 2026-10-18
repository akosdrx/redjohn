---
name: execution-scheduling
description: "Schedules bounded independent test jobs from inventory state while limiting LLM context and repeated work."
version: "2.1.0"
status: implemented_fixture_tested
---

# RedJohn — execution-scheduling

## Purpose and activation
Schedules bounded independent test jobs from inventory state while limiting LLM context and repeated work.

Every scan iteration or when new endpoints, versions or actor states are discovered.

Before activation, `AssessmentSkillRegistry.eligibility` checks the target domain,
impact profile, actor/fixture prerequisites and actual capability registry.
This document does not run tools; execution uses the RedJohn controller, scheduler and policy.

## Prerequisites and context
- current inventory
- skill manifest
- impact profile
- token/HTTP/time budgets

Bind every action to `engagement_id`, `policy_revision`, `actor_ref`, `tenant_id`,
`session_revision`, `workflow_state` and `request_ref`/`asset_ref`. Use the explicit
`anonymous` actor for anonymous access; never substitute another identity for a missing actor.
Authentication/authorization comparisons require separate actors/tenants and test objects with known ownership.
State-changing workflows require designated disposable fixtures and verifiable cleanup.

## Supported input and body formats
Input mode: `metadata`. Formats supported by the manifest: no active request-body support.
Unsupported: any format not declared by the capability. Observed body metadata does not prove active replay support;
JSONL scanner output does not imply JSON request-body support. Preserve raw requests,
repeated parameters, query ordering and encoding in evidence references. The adapter's
input validation is authoritative; an unknown format is `unsupported`, not a negative test.

## Canonical capability and RedJohn mapping
No scanner adapter; internal module: redjohn.assessment.scheduler, redjohn.assessment.store.

Optional capability: none.
Unimplemented prerequisite: see the capability registry for current dependency/health status.
Declared status: `implemented_fixture_tested`. Runtime health reports missing
binaries/dependencies separately; loading a `SKILL.md` does not establish execution coverage.
Legacy dotted tool names are neither MCP nor shell calls and are not registered as tools.

## Impact profile and execution limits
Applicable target domain: web; profiles: safe-production, active-staging, isolated-lab.
Original maximum required impact profile: `safe-production`; the actual policy may be stricter.
Discovery alone cannot authorize new targets, accounts, regions or scope expansion.
ResourceEnvelope and the shared governor bound workers, browsers, pages, contexts and caches.
Each job has a finite timeout (default 30 s, validated ceiling 600 s), with campaign deadlines
and request, queue and artifact quotas. Optional engines do not start together.

## Procedure and control measurements
1. Compute applicable skill × endpoint × actor × state combinations deterministically.
2. Prioritize untested high-value surfaces, then confirmed hypotheses; maintain fairness so one test family cannot monopolize the run.
3. Batch independent jobs into subprocess workers with deadlines, request caps and cancellation tokens.
4. Preserve bounded stdout and selected body evidence in storage; give the LLM only compact counts, new findings and evidence references.
5. Requeue only upon explicit new evidence or transient failure policy; terminal states are completed, unsupported, blocked and inconclusive.
6. Produce a final uncovered matrix and stop on budget exhaustion rather than unbounded exploratory loops.

With explicit `continuous_replay` mappings, durable successful-parent events
continue refresh -> actual fresh Chromium POST capture -> exactly selected
Nuclei replay in the same running scheduler. Child submission and event
acknowledgement are atomic; each selected request still needs current private
approval and complete 2xx sent evidence. Aggregate partial browser coverage stays
visible. The batch limit includes parents and children; a blocked follow-up
cannot retry its mutating parent. See `docs/continuous-refresh-replay.md`.

Record baseline/positive fixtures separately from fixed or rejecting controls.
A missing control is `not_run`/`inconclusive`; never invent a completed measurement.
Routine inventory, routing and parsing target zero internal LLM calls; provide only references
and a short coverage delta to the model.

## Result criteria and evidence
- job key/status/version
- consumed budget
- batch outputs and refs
- remaining gaps

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
Missing expected evidence should create a coverage gap, not repeat an identical expensive scan indefinitely.

An unimplemented or blocked capability remains a coverage gap; its absence is not a negative
vulnerability test. Without a real control fixture for this subtask, record the measurement as
`not_run_missing_fixture` and the original RCE as `not_reproduced_missing_fixture`.

## Version, provenance and test references
RedJohn contract version: `2.1.0`; manifest schema: `1`.
Adapted from a user-supplied initial contract without a separate license file; original source: `skills/execution-scheduling/SKILL.md`, SHA-256: `3b0653e4c15839b339888fabe665a743feccbbfa9fc03f0ce312df821062a874`. This is not upstream Strix/HexStrike code and does not grant a license to external tools.

Contract/integration references: tests/test_assessment_skills.py::test_manifest_contract_and_missing_adapters.
Registry tests verify wiring; they do not establish positive/fixed detection controls for every
vulnerability family. A missing engine's control is `not_run_adapter_not_implemented`.
External background: OWASP WSTG/ASVS; record the specific edition in each assessment.

Continuous workflow references: tests/test_continuous_scheduler_outbox.py; tests/test_continuous_browser_workflow.py; tests/test_continuous_refresh_pipeline.py (real Linux integration).

With explicit `session_recovery` configuration, trusted complete proxy 401 or
precise private-credential expiry can admit a separate refresh under persistent
per-identity/policy budgets and cooldown. Repeated failures coalesce by session
revision. Truncated responses, missing credentials, unknown execution and
403/challenges do not authorize recovery. Historical failed POSTs remain failed;
new capture and reviewed replay require a fresh session and real evidence. See
`docs/automatic-session-recovery.md` and the actual Linux integration in
`tests/test_automatic_session_recovery_pipeline.py`; synthetic recovery contracts
are tested separately. This does not implement general login/MFA automation.


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
