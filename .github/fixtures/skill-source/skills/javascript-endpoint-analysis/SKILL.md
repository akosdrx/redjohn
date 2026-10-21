---
name: javascript-endpoint-analysis
description: Finds candidate API routes and client-side sinks in bundled JavaScript and correlates them with live browser traffic.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# javascript-endpoint-analysis

## Trigger
JavaScript-heavy applications, low endpoint coverage, or unobserved routes in bundles.

## Expected capabilities (logical adapters; not built-in MCP function names)
`browser.inspect_scripts`, `source.scan_js`, `surface.upsert`

## Required inputs
- in-scope JS asset refs
- optional source tree
- observed browser network events

## Procedure
1. Collect only scripts served by permitted origins or explicitly supplied source files.
2. Parse fetch/XHR/websocket usage, route definitions, form handlers, and URL construction using an AST-aware helper when available.
3. Relate candidate paths to runtime-observed requests; distinguish static strings from reachable actions.
4. Identify obvious source-to-sink candidates for a later specialist review but do not label a vulnerability solely from a sink name.
5. Queue reachable high-value unexplored endpoints; keep nonreproducible literals as candidates.

## Required evidence / output
- JS file hash + line/offset
- route candidate
- observed request correlation
- confidence and provenance

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
Minified code, source maps and runtime-generated URLs can distort findings. Do not feed entire JS bundles into the LLM.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
