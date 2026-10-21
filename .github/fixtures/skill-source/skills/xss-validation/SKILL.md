---
name: xss-validation
description: Validates reflected, stored and DOM XSS in a real isolated headless browser, preserving execution context.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# xss-validation

## Trigger
Input is rendered into HTML/DOM, a scanner reports XSS, or JS analysis finds a plausible source-to-sink flow.

## Expected capabilities (logical adapters; not built-in MCP function names)
`dalfox.run_profile`, `browser.observe_dom`, `browser.capture_traffic`

## Required inputs
- input/request ref
- rendering page/flow
- test accounts
- approved marker profile

## Procedure
1. Classify the reflection context: text, attribute, URL, script or DOM transformation.
2. Use a bounded specialist test against non-sensitive fixture data; navigate the actual rendering workflow in a fresh BrowserContext.
3. Record DOM changes and safe execution indicators within the test origin; never use real session secrets as proof.
4. For stored behaviors, record separate write and read contexts and expected visibility.
5. Reject simple reflection findings without actual unsafe interpretation evidence.

## Required evidence / output
- input and rendering location
- browser/DOM evidence
- write/read flow refs
- controls and execution indicator

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
HTTP response reflection, a scanner confidence flag or a popup mock by itself is insufficient for a verified XSS report.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
