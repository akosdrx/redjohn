---
name: deserialization-risk
description: Reviews serializer formats and unsafe decoding paths, combining SAST evidence with bounded runtime validation.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# deserialization-risk

## Trigger
Untrusted serialized objects are accepted or a dependency/configuration flags unsafe deserialization.

## Expected capabilities (logical adapters; not built-in MCP function names)
`source.taint_analysis`, `source.dependency_scan`, `traffic.replay`

## Required inputs
- deserializer implementation refs
- message formats
- dependency versions
- test fixtures

## Procedure
1. Identify serializers/deserializers and whether data from untrusted origins reaches them.
2. Classify available type restrictions, allowed classes and trust boundaries from source/config.
3. Perform fixture-based parsing/error-handling tests without gadget chains or command execution.
4. Correlate affected library versions with actual reachable code paths.
5. Escalate any potential execution claim only with an independently reviewed isolated proof.

## Required evidence / output
- input-to-deserializer flow
- library and code refs
- fixture response
- security controls

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
Presence of a vulnerable library or base64-looking blob alone does not prove a reachable deserialization issue.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
