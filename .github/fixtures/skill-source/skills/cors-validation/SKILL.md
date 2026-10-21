---
name: cors-validation
description: Assesses cross-origin browser access against explicit origin and credential policies using headless Chromium.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# cors-validation

## Trigger
API responds to cross-origin requests and may expose authenticated data.

## Expected capabilities (logical adapters; not built-in MCP function names)
`browser.cross_origin_fixture`, `traffic.capture`, `auth.expected_policy`

## Required inputs
- policy for trusted origins
- test origin(s)
- non-sensitive protected fixture response

## Procedure
1. Observe Access-Control response headers across allowed and disallowed test origins.
2. Use the browser to verify whether a script from the test origin can read the protected fixture response.
3. Check credential mode, preflight behavior and actual browser enforcement, not just a header string.
4. Reproduce the result with a negative control and the expected legitimate origin.
5. Only report a security failure when unauthorized origin access to relevant data is established.

## Required evidence / output
- origin and credential context
- browser read decision
- expected policy
- response refs

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
Wildcard CORS without credentialed protected data is often not a meaningful security finding.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
