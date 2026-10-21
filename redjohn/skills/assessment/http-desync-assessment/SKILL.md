---
name: http-desync-assessment
description: "Evaluates HTTP framing risks through controlled gateway/backend comparisons in an isolated environment."
version: "2.0.0"
status: adapter_not_implemented
---

# RedJohn — http-desync-assessment

## Purpose and activation
Evaluates HTTP framing risks through controlled gateway/backend comparisons in an isolated environment.

Reverse proxy and origin servers disagree on request framing or code/config suggests a parsing mismatch.

Before activation, `AssessmentSkillRegistry.eligibility` checks the target domain,
impact profile, actor/fixture prerequisites and actual capability registry.
This document does not run tools; execution uses the RedJohn controller, scheduler and policy.

## Prerequisites and context
- test gateway configuration
- designated isolated endpoint
- explicit raw-protocol profile

Bind every action to `engagement_id`, `policy_revision`, `actor_ref`, `tenant_id`,
`session_revision`, `workflow_state` and `request_ref`/`asset_ref`. Use the explicit
`anonymous` actor for anonymous access; never substitute another identity for a missing actor.
Authentication/authorization comparisons require separate actors/tenants and test objects with known ownership.
State-changing workflows require designated disposable fixtures and verifiable cleanup.

## Supported input and body formats
Input mode: `recorded_request`. Formats supported by the manifest: no active request-body support.
Unsupported: application/json, application/xml, multipart/form-data, application/x-www-form-urlencoded. Observed body metadata does not prove active replay support;
JSONL scanner output does not imply JSON request-body support. Preserve raw requests,
repeated parameters, query ordering and encoding in evidence references. The adapter's
input validation is authoritative; an unknown format is `unsupported`, not a negative test.

## Canonical capability and RedJohn mapping
No scanner adapter or internal execution module is implemented.

Optional capability: none.
Unimplemented prerequisite: raw_http_framing_lab_harness.
Declared status: `adapter_not_implemented`. Runtime health reports missing
binaries/dependencies separately; loading a `SKILL.md` does not establish execution coverage.
Legacy dotted tool names are neither MCP nor shell calls and are not registered as tools.

## Impact profile and execution limits
Applicable target domain: web; profiles: isolated-lab.
Original maximum required impact profile: `isolated-lab`; the actual policy may be stricter.
Discovery alone cannot authorize new targets, accounts, regions or scope expansion.
ResourceEnvelope and the shared governor bound workers, browsers, pages, contexts and caches.
Each job has a finite timeout (default 30 s, validated ceiling 600 s), with campaign deadlines
and request, queue and artifact quotas. Optional engines do not start together.

## Procedure and control measurements
1. Review the proxy/backend HTTP protocol configuration and identify potentially inconsistent framing behavior.
2. Run only the reviewed protocol conformance harness on an isolated test instance.
3. Maintain byte-exact request traces, connection IDs, timing and expected response boundaries.
4. Compare repeated tests and controls; never infer desynchronization from a timeout or a single 400 error.
5. Stop if shared connections, other users or production request queues could be affected.

Record baseline/positive fixtures separately from fixed or rejecting controls.
A missing control is `not_run`/`inconclusive`; never invent a completed measurement.
Routine inventory, routing and parsing target zero internal LLM calls; provide only references
and a short coverage delta to the model.

## Result criteria and evidence
- raw trace hashes
- framing expectation
- connection-scoped observation
- configuration refs

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
Generic browser fetch APIs cannot faithfully generate all raw HTTP framing variants. This is isolated-lab only.

An unimplemented or blocked capability remains a coverage gap; its absence is not a negative
vulnerability test. Without a real control fixture for this subtask, record the measurement as
`not_run_missing_fixture` and the original RCE as `not_reproduced_missing_fixture`.

## Version, provenance and test references
RedJohn contract version: `2.0.0`; manifest schema: `1`.
Adapted from a user-supplied initial contract without a separate license file; original source: `skills/http-desync-assessment/SKILL.md`, SHA-256: `3964d700369cd8f7039536d55845a5a55002b5069b878699fb5970d1d69798f1`. This is not upstream Strix/HexStrike code and does not grant a license to external tools.

Contract/integration references: tests/test_assessment_skills.py::test_manifest_contract_and_missing_adapters.
Registry tests verify wiring; they do not establish positive/fixed detection controls for every
vulnerability family. A missing engine's control is `not_run_adapter_not_implemented`.
External background: OWASP WSTG/ASVS; record the specific edition in each assessment.
