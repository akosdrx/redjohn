---
name: api-graphql-security
description: Maps OpenAPI/GraphQL APIs and evaluates schema behavior, resolver authorization and bounded resource controls.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# api-graphql-security

## Trigger
OpenAPI, Swagger or GraphQL schema available; API traffic detected by the headless browser.

## Expected capabilities (logical adapters; not built-in MCP function names)
`api.schema_import`, `schemathesis.run_profile`, `traffic.replay`

## Required inputs
- schema ref and version
- auth contexts
- API business invariants
- request budget

## Procedure
1. Import API operations, field types and relationships and correlate them with observed endpoints.
2. Use schema-based tests for valid/invalid input and bounded stateful workflows on disposable fixture data.
3. For GraphQL, map query/mutation/subscription and field-level policy rather than merely scanning introspection.
4. Assess authenticated error handling and documented query complexity/rate rules without load testing production.
5. Pass authorization-related evidence to the dedicated access-control skills.

## Required evidence / output
- schema operation IDs
- observed versus expected result
- resource workflow refs
- coverage by operation/field

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
Introspection being available or a 500 error alone does not prove exploitability.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
