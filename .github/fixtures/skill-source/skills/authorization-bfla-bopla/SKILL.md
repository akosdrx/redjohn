---
name: authorization-bfla-bopla
description: Tests endpoint/function-level and field/property-level privilege boundaries for assigned application roles.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# authorization-bfla-bopla

## Trigger
Role-based API functions, privileged endpoints, or objects with editable/readable sensitive properties.

## Expected capabilities (logical adapters; not built-in MCP function names)
`surface.operations`, `traffic.replay`, `auth.expected_policy`

## Required inputs
- role matrix
- operation list
- field-level policy
- test actors

## Procedure
1. Map which roles may invoke each function and read/write each field, including partial update semantics.
2. Capture an allowed baseline with the intended actor and compare against a lower-privilege test actor.
3. Check the actual side effect and response fields, not only HTTP status codes.
4. Keep function-level and property-level findings distinct for remediation.
5. Retest reproducibly with fresh objects and document denied or untestable functions.

## Required evidence / output
- role/function/property matrix
- expected versus actual access
- before/after evidence

Always produce a structured result with `engagement_id`, `run_id`, `endpoint_id` or
`asset_id`, `actor_ref` when applicable, `skill_id`, `profile`, `status`,
`tool_version`, `evidence_refs`, `controls`, and `coverage_reason`.
Status MUST be one of `not_tested`, `queued`, `running`, `passed`,
`candidate`, `confirmed`, `blocked`, `unsupported`, `inconclusive`.

## Guardrails and exit
- Maximum authorized impact profile: `active-staging`. A lower-risk profile may restrict the test further.
- Obtain the current engagement policy and check all network destinations before execution.
- Work only on authorized assets and disposable or approved test data; preserve credentials in a secret store.
- Do not perform destructive actions, persistence, secret exfiltration or uncontrolled exploitation.
- Stop on target failures, missing prerequisites, unexpected side effects, exhausted budgets or uncertain authorization.
- Tool failure is `inconclusive`/`blocked`, NOT `passed`.

## False-positive and coverage warning
Disabled UI buttons are not server-side authorization checks; a 200 response may still indicate denial in body.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
