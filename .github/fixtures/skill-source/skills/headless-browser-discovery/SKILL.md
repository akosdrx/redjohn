---
name: headless-browser-discovery
description: Maps a JavaScript-heavy application with headless Playwright and authenticated BrowserContexts. Use for SPAs, UI workflows and DOM-driven endpoints.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# headless-browser-discovery

## Trigger
Initial application exploration, a new login flow, or a UI route not represented in the endpoint inventory.

## Expected capabilities (logical adapters; not built-in MCP function names)
`browser.navigate`, `browser.capture_traffic`, `surface.upsert`, `scope.get`

## Required inputs
- seed URL
- per-role isolated BrowserContext/state reference
- crawl depth/page budget
- allowed domains
- allowed test workflows

## Procedure
1. Create separate isolated contexts per test identity; never merge cookies or storage states across roles.
2. Navigate seeded pages within scope. Record DOM links, forms, visible route changes and navigation failures.
3. Capture requests/responses and XHR/fetch methods from the browser network events; keep raw bodies in the evidence store rather than model context.
4. Perform only approved non-destructive interactions. Do not guess that a button is harmless from its label.
5. Deduplicate into method + normalized path + parameter schema + auth context; put discoveries in the surface inventory.
6. Stop on budgets and report unmapped screens or authentication failures as coverage gaps.

## Required evidence / output
- discovered routes
- forms and input positions
- request_ref/response_ref
- actor + workflow context
- crawl coverage and blocked URLs

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
Headless browser crawling is not complete API coverage. Service workers and dynamically reached states can hide traffic; track these explicitly.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
