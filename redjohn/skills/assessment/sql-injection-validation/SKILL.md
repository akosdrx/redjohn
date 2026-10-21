---
name: sql-injection-validation
description: "Checks an explicit SQLi hint on a captured GET query parameter with bounded boolean-only sqlmap."
version: "2.1.0"
status: implemented_fixture_tested
---

# RedJohn — sql-injection-validation

## Purpose and activation
Checks an explicit SQLi hint on a captured GET query parameter with bounded boolean-only sqlmap.

A parameter reaches database-backed behavior or a scanner/code review flags plausible SQL injection.

Before activation, `AssessmentSkillRegistry.eligibility` checks the target domain,
impact profile, actor/fixture prerequisites and actual capability registry.
This document does not run tools; execution uses the RedJohn controller, scheduler and policy.

## Prerequisites and context
- request_ref
- input position
- auth context
- approved test profile
- baseline fixture

Bind every action to `engagement_id`, `policy_revision`, `actor_ref`, `tenant_id`,
`session_revision`, `workflow_state` and `request_ref`/`asset_ref`. Use the explicit
`anonymous` actor for anonymous access; never substitute another identity for a missing actor.
Authentication/authorization comparisons require separate actors/tenants and test objects with known ownership.
State-changing workflows require designated disposable fixtures and verifiable cleanup.

## Supported input and body formats
Current adapter: one selected GET query parameter, a completed browser request reference and an explicit reviewed SQLi hint. Only level 1/risk 1 boolean checks are enabled. Named actors use the host-only existing vault; no database dump, file access, shell, tamper plugins or arbitrary arguments are exposed. SQLite positive/fixed controls are live tested; other DBMS profiles require separate validation.

Input mode: `recorded_request`. Formats supported by the manifest: no active request-body support.
Unsupported: application/json, application/xml, multipart/form-data, application/x-www-form-urlencoded. Observed body metadata does not prove active replay support;
JSONL scanner output does not imply JSON request-body support. Preserve raw requests,
repeated parameters, query ordering and encoding in evidence references. The adapter's
input validation is authoritative; an unknown format is `unsupported`, not a negative test.

## Canonical capability and RedJohn mapping
sqlmap_validate.

Optional capability: none.
Unimplemented prerequisite: see the capability registry for current dependency/health status.
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
1. Confirm an actual input parameter and stable baseline before running any specialist checks.
2. Apply only the pre-approved, non-destructive detection profile to the identified request and parameter.
3. Compare repeated controls and target behavior; retain structured scanner evidence, not large raw logs in context.
4. Check whether anomalies are repeatable and attributable to the input rather than caching or app variance.
5. Stop before data extraction or database-modifying features; pass credible findings to independent verification.

Record baseline/positive fixtures separately from fixed or rejecting controls.
A missing control is `not_run`/`inconclusive`; never invent a completed measurement.
Routine inventory, routing and parsing target zero internal LLM calls; provide only references
and a short coverage delta to the model.

## Result criteria and evidence
- parameter and request IDs
- detection mechanism summary
- control responses
- tool version/exit state

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
A SQL error, long response or sqlmap heuristic is a candidate signal, not automatically confirmed injection.

An unimplemented or blocked capability remains a coverage gap; its absence is not a negative
vulnerability test. Without a real control fixture for this subtask, record the measurement as
`not_run_missing_fixture` and the original RCE as `not_reproduced_missing_fixture`.

## Version, provenance and test references
RedJohn contract version: `2.1.0`; manifest schema: `1`.
Adapted from a user-supplied initial contract without a separate license file; original source: `skills/sql-injection-validation/SKILL.md`, SHA-256: `a78a3749c06a177a786f835feae90cc57f1ed9c78aff4f8e85fc1454a95a27cc`. This is not upstream Strix/HexStrike code and does not grant a license to external tools.

Contract/integration references: tests/test_specialists_contract.py; tests/test_specialists_live.py::test_actual_specialists_restart_browser_sqlite_and_xss_chain.
Registry tests verify wiring; they do not establish positive/fixed detection controls for every
vulnerability family. A missing engine's control is `not_run_adapter_not_implemented`.
External background: OWASP WSTG/ASVS; record the specific edition in each assessment.
