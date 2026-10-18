---
name: web-surface-inventory
description: Builds a durable, queryable inventory of routes, requests and states from browser, proxy and crawler observations.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# web-surface-inventory

## Trigger
After crawling, proxy capture, imports from API specs, or specialist-tool discovery.

## Expected capabilities (logical adapters; not built-in MCP function names)
`surface.upsert`, `surface.search`, `traffic.index`

## Required inputs
- browser/proxy request references
- crawl observations
- API schemas
- normalization policy

## Procedure
1. Normalize scheme, host, path template, method and content type while preserving each original request.
2. Collect parameter names and locations: path, query, form, JSON, XML, header and cookie.
3. Link requests to actor, tenant, navigation flow, object ownership and observed response schema.
4. Merge overlapping discoveries without hiding method, role, request-body or state differences.
5. Set source=observed, imported or hypothesized; only observed requests count as confirmed live endpoints.

## Required evidence / output
- endpoint_id
- request_ref
- parameters and evidence sources
- discovery provenance
- coverage_state

Always produce a structured result with `engagement_id`, `run_id`, `endpoint_id` or
`asset_id`, `actor_ref` when applicable, `skill_id`, `profile`, `status`,
`tool_version`, `evidence_refs`, `controls`, and `coverage_reason`.
Status MUST be one of `not_tested`, `queued`, `running`, `passed`,
`candidate`, `confirmed`, `blocked`, `unsupported`, `inconclusive`.

## Guardrails and exit
- Maximum authorized impact profile: `safe-production`. A lower-risk profile may restrict the test further.
- Obtain the current engagement policy and check all network destinations before execution.
- Work only on authorized assets and disposable or approved test data; preserve credentials in a secret store.
- Do not perform destructive actions, persistence, secret exfiltration or uncontrolled exploitation.
- Stop on target failures, missing prerequisites, unexpected side effects, exhausted budgets or uncertain authorization.
- Tool failure is `inconclusive`/`blocked`, NOT `passed`.

## False-positive and coverage warning
Deduplication by URL alone loses POST endpoints, bodies and role-specific behavior.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
