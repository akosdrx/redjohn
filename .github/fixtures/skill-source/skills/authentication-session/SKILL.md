---
name: authentication-session
description: Tests expected login, logout, password reset, rotation and session lifecycle boundaries with controlled accounts.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# authentication-session

## Trigger
An application has login/logout, recovery, MFA or long-lived session flows.

## Expected capabilities (logical adapters; not built-in MCP function names)
`browser.session`, `traffic.replay`, `auth.expected_policy`

## Required inputs
- anonymous and test-user contexts
- approved test credentials refs
- documented session policy
- reversible account state

## Procedure
1. Map successful and rejected login flows and verify the browser is using the intended test identity.
2. Observe cookie/token issuance, rotation and invalidation across login, logout and recovery sequences.
3. Compare expected access after transitions using isolated contexts; never mix credentials between test users.
4. Test only pre-approved account-control transitions, avoiding lockout or broad credential guessing.
5. Record discrepancies and retest with a fresh session.

## Required evidence / output
- state transitions
- expected/observed access
- redacted cookie/token attributes
- baseline refs

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
A token visible to the browser or long expiry is not automatically a compromise; compare against server policy.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
