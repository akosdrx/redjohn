---
name: template-injection-validation
description: Examines server-side and client-side template handling and identifies plausible engines with bounded validation.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# template-injection-validation

## Trigger
Template-like rendering input or source code connecting untrusted input to template evaluation.

## Expected capabilities (logical adapters; not built-in MCP function names)
`tinja.run_profile`, `browser.observe_dom`, `source.taint_analysis`

## Required inputs
- request ref
- rendering flow
- suspected template engine
- reviewed scanner profile

## Procedure
1. Identify whether rendering happens on the server or in the browser and capture a deterministic baseline.
2. Use TInjA or approved engine-aware checks only for supported content types and bodies.
3. Compare output interpretation with controls and rule out ordinary string interpolation.
4. If server-side evaluation is established, record it as SSTI separately from unproven execution privileges.
5. Mark unsupported JSON/multipart and blind scenarios as not covered rather than passed.

## Required evidence / output
- rendering location
- engine evidence and confidence
- baseline and observed output
- tool supported/unsupported state

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
Do not label every template injection as RCE. Check the installed TInjA release for supported body formats.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
