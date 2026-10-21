---
name: prototype-pollution
description: Examines JavaScript object merge and parsing paths for unsafe prototype handling with local isolated fixtures.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# prototype-pollution

## Trigger
JavaScript app merges untrusted JSON or query params into objects or a scanner flags unsafe object assignment.

## Expected capabilities (logical adapters; not built-in MCP function names)
`source.js_ast`, `browser.isolated_fixture`, `runtime.observe`

## Required inputs
- JS source/asset refs
- affected input location
- isolated test page/worker

## Procedure
1. Identify merge, clone, parser or setter paths through source analysis.
2. Run controlled checks only in isolated browser contexts or a local replica; never modify shared app settings.
3. Observe whether prototype changes escape their expected object boundary and persist in subsequent controlled operations.
4. Separate the primitive from any alleged authentication bypass, XSS or server-side impact.
5. Discard isolated context and capture exact code location and state evidence.

## Required evidence / output
- source/sink path
- isolated object-state evidence
- affected runtime
- controls

Always produce a structured result with `engagement_id`, `run_id`, `endpoint_id` or
`asset_id`, `actor_ref` when applicable, `skill_id`, `profile`, `status`,
`tool_version`, `evidence_refs`, `controls`, and `coverage_reason`.
Status MUST be one of `not_tested`, `queued`, `running`, `passed`,
`candidate`, `confirmed`, `blocked`, `unsupported`, `inconclusive`.

## Guardrails and exit
- Maximum authorized impact profile: `isolated-lab`. A lower-risk profile may restrict the test further.
- Obtain the current engagement policy and check all network destinations before execution.
- Work only on authorized assets and disposable or approved test data; preserve credentials in a secret store.
- Do not perform destructive actions, persistence, secret exfiltration or uncontrolled exploitation.
- Stop on target failures, missing prerequisites, unexpected side effects, exhausted budgets or uncertain authorization.
- Tool failure is `inconclusive`/`blocked`, NOT `passed`.

## False-positive and coverage warning
Client-side prototype changes are not automatically a server-side vulnerability.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
