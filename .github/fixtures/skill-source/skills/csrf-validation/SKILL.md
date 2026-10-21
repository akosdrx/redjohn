---
name: csrf-validation
description: Checks browser-origin protections for actual state-changing operations with isolated test accounts.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# csrf-validation

## Trigger
Cookie-authenticated state mutations reachable through web forms or APIs.

## Expected capabilities (logical adapters; not built-in MCP function names)
`browser.cross_origin_fixture`, `traffic.capture`, `auth.expected_policy`

## Required inputs
- approved cross-origin test page
- test accounts
- state-changing fixture action
- expected CSRF policy

## Procedure
1. Identify a concrete authorized state change and its normal browser request pattern.
2. Inspect cookies, origin/referrer validation and anti-CSRF mechanisms in the actual session.
3. Run controlled cross-origin comparisons with disposable test objects only.
4. Verify whether the protected state actually changed, not merely whether a request was sent.
5. Clean up fixtures and report any inconclusive browser policy conditions.

## Required evidence / output
- source origin
- auth cookie properties
- request and before/after state refs
- controls

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
CORS headers, lack of a token, or a 200 response alone does not establish CSRF exploitability.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
