---
name: template-injection-validation
description: "Validates a captured GET or one approved private POST field with pinned TInjA and a finite host-enforced template profile."
version: "2.2.0"
status: implemented_fixture_tested
---

# RedJohn — template-injection-validation

## Purpose and activation
Validates a captured GET or one approved private POST field with pinned TInjA and a finite host-enforced template profile.

Template-like rendering input or source code connecting untrusted input to template evaluation.

Before activation, `AssessmentSkillRegistry.eligibility` checks the target domain,
impact profile, actor/fixture prerequisites and actual capability registry.
This document does not run tools; execution uses the RedJohn controller, scheduler and policy.

## Prerequisites and context
- request ref
- rendering flow
- suspected template engine
- reviewed scanner profile

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

TInjA 1.2.0 still uses its finite 71-item host-enforced expression catalogue.
Captured anonymous/named GET and named POST JSON strings, form values and multipart
text fields are supported. POST requires complete successful real capture, private
v2 vault approval, exact policy URL and a non-idempotent job. The upstream worker
sees a public GET/query carrier; the host constructs the real authenticated POST.
This is a RedJohn transport bridge, not native arbitrary JSON/multipart support.
Every unselected byte/upload remains unchanged; bound body-token fields cannot
be mutation inputs. Multiple selected occurrences, file parts, XML, arbitrary
runtime/file/shell probes and CSTI remain unsupported. Other template engines
remain unverified; sandboxed Jinja and escaped controls are actual fixtures.

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
tinja_validate.

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
1. Identify whether rendering happens on the server or in the browser and capture a deterministic baseline.
2. Use TInjA or approved engine-aware checks only for supported content types and bodies.
3. Compare output interpretation with controls and rule out ordinary string interpolation.
4. If server-side evaluation is established, record it as SSTI separately from unproven execution privileges.
5. Mark unreviewed body fields, unsupported file mutation and blind scenarios as not covered.

Record baseline/positive fixtures separately from fixed or rejecting controls.
A missing control is `not_run`/`inconclusive`; never invent a completed measurement.
Routine inventory, routing and parsing target zero internal LLM calls; provide only references
and a short coverage delta to the model.

## Result criteria and evidence
- rendering location
- engine evidence and confidence
- baseline and observed output
- tool supported/unsupported state

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
Do not label every template injection as RCE. Check the installed TInjA release for supported body formats.

An unimplemented or blocked capability remains a coverage gap; its absence is not a negative
vulnerability test. Without a real control fixture for this subtask, record the measurement as
`not_run_missing_fixture` and the original RCE as `not_reproduced_missing_fixture`.

## Version, provenance and test references
RedJohn contract version: `2.2.0`; manifest schema: `1`.
Adapted from a user-supplied initial contract without a separate license file; original source: `skills/template-injection-validation/SKILL.md`, SHA-256: `8871a03c432bd3ed434feef06f4f1fd2568479820fd990ec4b4ef5dc7203bc9c`. This is not upstream Strix/HexStrike code and does not grant a license to external tools.

Contract references: tests/test_schema_oast_contract.py.
Actual integration controls: tests/test_schema_oast_live.py.
Registry/provenance: tests/test_assessment_skills.py.
Registry tests verify wiring; they do not establish positive/fixed detection controls for every
vulnerability family. A missing configured dependency is blocked and is never a clean negative.
External background: OWASP WSTG/ASVS; record the specific edition in each assessment.
