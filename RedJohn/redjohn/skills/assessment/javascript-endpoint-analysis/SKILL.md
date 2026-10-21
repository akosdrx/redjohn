---
name: javascript-endpoint-analysis
description: "Finds candidate API routes and client-side sinks in bundled JavaScript and correlates them with live browser traffic."
version: "2.0.0"
status: adapter_not_implemented
---

# RedJohn — javascript-endpoint-analysis

## Purpose and activation
Finds candidate API routes and client-side sinks in bundled JavaScript and correlates them with live browser traffic.

JavaScript-heavy applications, low endpoint coverage, or unobserved routes in bundles.

Before activation, `AssessmentSkillRegistry.eligibility` checks the target domain,
impact profile, actor/fixture prerequisites and actual capability registry.
This document does not run tools; execution uses the RedJohn controller, scheduler and policy.

## Prerequisites and context
- in-scope JS asset refs
- optional source tree
- observed browser network events

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
browser_discover.

Optional capability: none.
Unimplemented prerequisite: ast_endpoint_analysis.
Declared status: `adapter_not_implemented`. Runtime health reports missing
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
1. Collect only scripts served by permitted origins or explicitly supplied source files.
2. Parse fetch/XHR/websocket usage, route definitions, form handlers, and URL construction using an AST-aware helper when available.
3. Relate candidate paths to runtime-observed requests; distinguish static strings from reachable actions.
4. Identify obvious source-to-sink candidates for a later specialist review but do not label a vulnerability solely from a sink name.
5. Queue reachable high-value unexplored endpoints; keep nonreproducible literals as candidates.

Record baseline/positive fixtures separately from fixed or rejecting controls.
A missing control is `not_run`/`inconclusive`; never invent a completed measurement.
Routine inventory, routing and parsing target zero internal LLM calls; provide only references
and a short coverage delta to the model.

## Result criteria and evidence
- JS file hash + line/offset
- route candidate
- observed request correlation
- confidence and provenance

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
Minified code, source maps and runtime-generated URLs can distort findings. Do not feed entire JS bundles into the LLM.

An unimplemented or blocked capability remains a coverage gap; its absence is not a negative
vulnerability test. Without a real control fixture for this subtask, record the measurement as
`not_run_missing_fixture` and the original RCE as `not_reproduced_missing_fixture`.

## Version, provenance and test references
RedJohn contract version: `2.0.0`; manifest schema: `1`.
Adapted from a user-supplied initial contract without a separate license file; original source: `skills/javascript-endpoint-analysis/SKILL.md`, SHA-256: `59035c56a45752d2f70cc50d1efc537f1f1bbb5cf946a02b960e0d8cc30cd2dc`. This is not upstream Strix/HexStrike code and does not grant a license to external tools.

Contract/integration references: tests/test_assessment_skills.py::test_manifest_contract_and_missing_adapters.
Registry tests verify wiring; they do not establish positive/fixed detection controls for every
vulnerability family. A missing engine's control is `not_run_adapter_not_implemented`.
External background: OWASP WSTG/ASVS; record the specific edition in each assessment.
