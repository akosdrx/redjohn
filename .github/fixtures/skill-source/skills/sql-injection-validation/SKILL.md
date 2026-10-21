---
name: sql-injection-validation
description: Triage suspected SQL injection at an observed input with deterministic baselines and a controlled specialist runner.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# sql-injection-validation

## Trigger
A parameter reaches database-backed behavior or a scanner/code review flags plausible SQL injection.

## Expected capabilities (logical adapters; not built-in MCP function names)
`surface.inputs`, `sqlmap.run_profile`, `traffic.replay`

## Required inputs
- request_ref
- input position
- auth context
- approved test profile
- baseline fixture

## Procedure
1. Confirm an actual input parameter and stable baseline before running any specialist checks.
2. Apply only the pre-approved, non-destructive detection profile to the identified request and parameter.
3. Compare repeated controls and target behavior; retain structured scanner evidence, not large raw logs in context.
4. Check whether anomalies are repeatable and attributable to the input rather than caching or app variance.
5. Stop before data extraction or database-modifying features; pass credible findings to independent verification.

## Required evidence / output
- parameter and request IDs
- detection mechanism summary
- control responses
- tool version/exit state

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
A SQL error, long response or sqlmap heuristic is a candidate signal, not automatically confirmed injection.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
