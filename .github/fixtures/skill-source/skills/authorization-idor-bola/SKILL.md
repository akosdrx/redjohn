---
name: authorization-idor-bola
description: Tests object-level authorization across isolated accounts, object owners and tenants.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# authorization-idor-bola

## Trigger
An endpoint addresses objects by identifier or accepts object ownership fields.

## Expected capabilities (logical adapters; not built-in MCP function names)
`surface.objects`, `browser.session`, `traffic.replay`, `auth.expected_policy`

## Required inputs
- test actors A and B
- owned object fixtures
- expected ACL/tenant model
- read/write operation inventory

## Procedure
1. Create or select designated fixture objects with known owner and tenant; record their baseline authorized access.
2. Build actor × object owner × operation × tenant × object state cases from the application policy.
3. Run a bounded comparison through isolated test identities, recording responses and persistent state changes.
4. Compare both data exposure and actual mutation; distinguish an error page from a successful unauthorized operation.
5. Clean up fixtures, then verify any observed violation against the declared policy.

## Required evidence / output
- actor/object ownership
- expected authorization
- before/after references
- response and state evidence

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
Guessable identifiers are not sufficient evidence. A cross-account comparison requires known ownership and expected policy.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
