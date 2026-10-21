---
name: jwt-security
description: Checks JWT validation and lifetime expectations without accepting decoded token content as a security proof.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# jwt-security

## Trigger
JWT-authenticated API, changed signing/verification configuration, or a suspected token validation defect.

## Expected capabilities (logical adapters; not built-in MCP function names)
`auth.token_metadata`, `traffic.replay`, `auth.expected_policy`

## Required inputs
- test token refs
- issuer/audience/policy expectations
- test accounts and endpoints

## Procedure
1. Parse and classify token metadata locally; redact tokens from output and do not send them to external lookup services.
2. Validate expected issuer, audience, expiry, algorithm policy and session revocation against observed server behavior.
3. Compare privileged and unprivileged actions using only designated test accounts and authorized profiles.
4. Use negative control tests and fresh token issuance to rule out cached or stale responses.
5. Escalate only a reproducible server-side acceptance mismatch to a confirmed finding.

## Required evidence / output
- policy field
- token fingerprint (not token)
- request refs
- server decision
- control result

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
Base64 decoding of a JWT payload proves nothing about signature acceptance or access control.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
