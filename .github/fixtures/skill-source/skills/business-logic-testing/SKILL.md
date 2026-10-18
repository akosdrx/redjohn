---
name: business-logic-testing
description: Models multi-step business workflows and checks documented invariants that generic scanners cannot infer.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# business-logic-testing

## Trigger
Applications expose checkout, transfers, discounts, approvals, invitations or other multi-step flows.

## Expected capabilities (logical adapters; not built-in MCP function names)
`workflow.graph`, `browser.execute_fixture`, `state.snapshot`, `auth.expected_policy`

## Required inputs
- business rules from owner/spec
- test personas
- disposable workflow fixtures
- allowed transitions

## Procedure
1. Convert product requirements into states, transitions, actor permissions and invariants.
2. Identify normal and exceptional paths from browser traces and API contracts.
3. Run approved, reversible transition sequences including cancellation and retry cases.
4. Compare authoritative state against invariants and role restrictions rather than relying only on UI messages.
5. Record the shortest reproducible failing workflow and cleanup all fixture data.

## Required evidence / output
- state graph and fixture IDs
- expected/actual invariant
- step references
- before/after state

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
A surprising business result is not a defect unless an explicit invariant or policy is violated.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
