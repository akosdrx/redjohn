---
name: authentication-session
description: "Plans controlled authentication/session lifecycle checks and routes exact replay/refresh without claiming full login or MFA automation."
version: "2.1.0"
status: adapter_not_implemented
---

# RedJohn — authentication-session

## Purpose and activation
Plans controlled authentication/session lifecycle checks and routes exact replay/refresh without claiming full login or MFA automation.

An application has login/logout, recovery, MFA or long-lived session flows.

Before activation, `AssessmentSkillRegistry.eligibility` checks the target domain,
impact profile, actor/fixture prerequisites and actual capability registry.
This document does not run tools; execution uses the RedJohn controller, scheduler and policy.

## Prerequisites and context
- anonymous and test-user contexts
- approved test credentials refs
- documented session policy
- reversible account state

Bind every action to `engagement_id`, `policy_revision`, `actor_ref`, `tenant_id`,
`session_revision`, `workflow_state` and `request_ref`/`asset_ref`. Use the explicit
`anonymous` actor for anonymous access; never substitute another identity for a missing actor.
Authentication/authorization comparisons require separate actors/tenants and test objects with known ownership.
State-changing workflows require designated disposable fixtures and verifiable cleanup.

## Supported input and body formats
Input mode: `recorded_request`. The implemented exact replay subset accepts body-free
GET/HEAD and approved JSON, URL-encoded form and multipart POST bodies up to 64 KiB;
XML is unsupported. This does not implement the entire authentication lifecycle skill.
The required `controlled_session_replay` workflow remains unavailable, so this broad
skill stays ineligible even for a supported format. Route the implemented subset through
explicit `browser_post_capture`, `nuclei_scan` and `session_refresh` capabilities, subject to their actual policy,
private-provider, template-lock and observed-evidence checks. Preserve exact bytes,
encoding, duplicate parameters, upload contents and actor/tenant/revision bindings.

## Canonical capability and RedJohn mapping
browser_discover.

Optional capabilities: nuclei_scan, session_refresh, browser_post_capture.
Implemented subset modules: assessment.capture, assessment.browser_capture, assessment.auth_replay, assessment.body_tokens, assessment.session_refresh, assessment.browser_workflow.
Unimplemented prerequisite: controlled_session_replay.
Declared status: `adapter_not_implemented`. Runtime health reports missing
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
1. Map successful and rejected login flows and verify the browser is using the intended test identity.
2. Observe cookie/token issuance, rotation and invalidation across login, logout and recovery sequences.
3. Compare expected access after transitions using isolated contexts; never mix credentials between test users.
4. Test only pre-approved account-control transitions, avoiding lockout or broad credential guessing.
5. Record discrepancies and retest with a fresh session.

For the implemented subset, explicitly queue a non-idempotent `session_refresh` job
with a private provider and exact refresh endpoint. Rotate header/cookie/CSRF credentials
and advance a numeric revision with fenced SQLite CAS. Keep old jobs and evidence intact;
new-revision POST replay requires a real fresh capture and private vault approval.
The configured `browser_post_capture` path uses actual Chromium POST bytes with
exact private automatic-approval rules and complete proxy response proof. Startup
reconciles private start URLs/current revisions into deterministic capture jobs.
Capture reservations and request budgets are durable and atomic. A lost response,
worker loss or uncertain commit blocks further automatic resend. Reconcile server and
private state before a newly reviewed policy revision. Never fall back to anonymous.

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
- state transitions
- expected/observed access
- redacted cookie/token attributes
- baseline refs

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
A token visible to the browser or long expiry is not automatically a compromise;
compare against server policy. General login/logout/MFA/password-reset automation and
cross-account lifecycle comparisons remain unimplemented. Refresh changes embedded credential/CSRF strings only through explicit private
JSONPointer/form/multipart text bindings. Other bytes and uploads remain intact;
updated body approval stays pending until real fresh Chromium capture. This is
not heuristic token substitution or full login/MFA automation. The provider's own
refresh token is not rotated from a response. See `docs/browser-post-body-tokens.md`
and `docs/session-refresh.md` in the RedJohn package for the implemented contract.

An unimplemented or blocked capability remains a coverage gap; its absence is not a negative
vulnerability test. Without a real control fixture for this subtask, record the measurement as
`not_run_missing_fixture` and the original RCE as `not_reproduced_missing_fixture`.

## Version, provenance and test references
RedJohn contract version: `2.1.0`; manifest schema: `1`.
Adapted from a user-supplied initial contract without a separate license file; original source: `skills/authentication-session/SKILL.md`, SHA-256: `31dc68a017c33b87e052549680fc76cce1f519d008021d032b6e62ce40856897`. This is not upstream Strix/HexStrike code and does not grant a license to external tools.

Contract/integration references: tests/test_assessment_skills.py::test_manifest_contract_and_missing_adapters; tests/test_assessment_session_refresh.py; tests/test_capture_reservations.py; tests/test_post_refresh_pipeline.py.
Additional actual-capture/token references: tests/test_body_token_refresh.py; tests/test_browser_token_pipeline.py.
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
