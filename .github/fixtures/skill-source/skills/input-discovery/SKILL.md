---
name: input-discovery
description: Discovers query, form, JSON and XML parameter names from observed requests and bounded parameter mining.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# input-discovery

## Trigger
An in-scope endpoint has missing/uncertain input schema or behavior suggests optional parameters.

## Expected capabilities (logical adapters; not built-in MCP function names)
`surface.search`, `traffic.replay`, `arjun.run`

## Required inputs
- endpoint_id
- baseline request_ref
- method/content type
- budget
- actor_ref

## Procedure
1. Use recorded requests and schemas first; extract nested structured input paths without guessing values.
2. Run bounded parameter discovery only where the engagement and endpoint method permit it.
3. Compare candidate responses against baseline behavior and response variability; reject random response noise.
4. Add confirmed parameters to the inventory and label speculative candidates separately.
5. Pass parameter identifiers, not request dumps, to downstream testing skills.

## Required evidence / output
- parameter position/type
- baseline and changed response references
- discovery status
- request count

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
Parameter discovery can be costly or state-mutating; never blindly expand all POST bodies.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
