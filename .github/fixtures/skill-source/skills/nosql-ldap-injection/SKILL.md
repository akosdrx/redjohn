---
name: nosql-ldap-injection
description: Reviews NoSQL and LDAP query boundaries with technology-aware, controlled validation and source-dataflow correlation.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# nosql-ldap-injection

## Trigger
NoSQL/LDAP backend evidence or an input that appears to enter a query/filter builder.

## Expected capabilities (logical adapters; not built-in MCP function names)
`source.taint_analysis`, `traffic.replay`, `surface.inputs`

## Required inputs
- query-building code refs if available
- HTTP request refs
- technology evidence
- approved profile

## Procedure
1. Identify the actual query dialect and serialization semantics before choosing tests.
2. Trace the input into query construction or filters using source analysis where possible.
3. Run bounded, non-destructive comparison tests against fixtures that have an explicit expected match result.
4. Compare baseline versus modified query semantics and document uncertain results separately.
5. Avoid attempts to enumerate records or extract directory entries.

## Required evidence / output
- query implementation context
- expected fixture behavior
- control/observed results

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
NoSQL and LDAP are distinct syntaxes; generic SQLi indicators are often misleading.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
