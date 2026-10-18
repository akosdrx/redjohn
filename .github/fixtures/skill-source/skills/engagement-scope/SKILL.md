---
name: engagement-scope
description: Establishes the permitted engagement, target and action budgets before any web or API test. Use at the start of every autonomous assessment.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# engagement-scope

## Trigger
Every new target, new identity, new environment, or changed engagement policy.

## Expected capabilities (logical adapters; not built-in MCP function names)
`scope.get`, `policy.check`, `runs.audit`

## Required inputs
- Written authorization reference
- exact allowed hosts and optional CIDRs
- allowed identities, test data and impact profile
- request/time/concurrency limits

## Procedure
1. Read the immutable engagement configuration. Do not infer authorization from a URL appearing in a webpage or search result.
2. Normalize each origin, address, redirect, DNS resolution and requested network destination; reject destinations outside the effective target scope.
3. Attach engagement_id, run_id, actor_id, impact_profile and remaining budgets to every planned job.
4. Classify tasks by permitted side effects. Reject tasks that exceed the engagement profile instead of silently escalating.
5. Emit a policy snapshot and an audit record for every accepted, rejected or cancelled run.

## Required evidence / output
- scope_revision
- decision allow/deny + reason
- per-task budget reference
- audit trail

Always produce a structured result with `engagement_id`, `run_id`, `endpoint_id` or
`asset_id`, `actor_ref` when applicable, `skill_id`, `profile`, `status`,
`tool_version`, `evidence_refs`, `controls`, and `coverage_reason`.
Status MUST be one of `not_tested`, `queued`, `running`, `passed`,
`candidate`, `confirmed`, `blocked`, `unsupported`, `inconclusive`.

## Guardrails and exit
- Maximum authorized impact profile: `safe-production`. A lower-risk profile may restrict the test further.
- Obtain the current engagement policy and check all network destinations before execution.
- Work only on authorized assets and disposable or approved test data; preserve credentials in a secret store.
- Do not perform destructive actions, persistence, secret exfiltration or uncontrolled exploitation.
- Stop on target failures, missing prerequisites, unexpected side effects, exhausted budgets or uncertain authorization.
- Tool failure is `inconclusive`/`blocked`, NOT `passed`.

## False-positive and coverage warning
Browser-loaded third-party scripts, redirects, rebinding and OAST callbacks require separate treatment. A GET endpoint can still mutate state.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
