---
name: oast-correlation
description: Correlates controlled DNS/HTTP callbacks with originating tests and separates observable effects from inferred impact.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# oast-correlation

## Trigger
SSRF, XXE, blind server processing or other pre-approved test requires an out-of-band observation.

## Expected capabilities (logical adapters; not built-in MCP function names)
`oast.allocate`, `oast.poll`, `evidence.store`

## Required inputs
- run_id/test_id
- self-hosted OAST endpoint
- allowed callback protocols
- expiry window

## Procedure
1. Allocate a unique token for each test and bind it to a request_ref and actor_ref before execution.
2. Receive DNS/HTTP events on an approved OAST service and store time, protocol and correlation metadata.
3. Link each event to the exact originating test and include non-trigger controls.
4. Summarize observable server behavior without claiming file access or code execution unless independently proven.
5. Expire callback tokens and redact identifiers before sharing evidence.

## Required evidence / output
- correlation token fingerprint
- request/event timestamps
- protocol observation
- control result

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
Public OAST services may expose target metadata to third parties; prefer self-hosting when assessment confidentiality matters.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
