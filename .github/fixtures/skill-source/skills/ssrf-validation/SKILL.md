---
name: ssrf-validation
description: Evaluates whether server-side URL fetching violates intended destination restrictions, using controlled OAST targets.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# ssrf-validation

## Trigger
Backend can fetch URLs, proxy resources, import feeds or process callbacks.

## Expected capabilities (logical adapters; not built-in MCP function names)
`surface.inputs`, `oast.allocate`, `oast.events`, `traffic.replay`

## Required inputs
- server-side URL input ref
- approved external test receiver
- allowed destination policy

## Procedure
1. Document legitimate URL-fetch behavior and expected destination allow/deny rules.
2. Use only an engagement-owned callback endpoint and bounded requests; verify each resolved destination against test policy.
3. Correlate the callback with exact request ID, time and unique marker; include negative controls.
4. Assess whether the observed destination is disallowed by the documented application policy.
5. Avoid internal address discovery, metadata services and data extraction in autonomous operation.

## Required evidence / output
- callback correlation
- expected fetch policy
- baseline/result refs
- inferred impact limit

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
A benign server-side HTTP request is not automatically SSRF; callbacks without linkage are insufficient.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
