---
name: http-desync-assessment
description: Evaluates HTTP framing risks through controlled gateway/backend comparisons in an isolated environment.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# http-desync-assessment

## Trigger
Reverse proxy and origin servers disagree on request framing or code/config suggests a parsing mismatch.

## Expected capabilities (logical adapters; not built-in MCP function names)
`protocol.test_harness`, `infra.proxy_config`, `evidence.store`

## Required inputs
- test gateway configuration
- designated isolated endpoint
- explicit raw-protocol profile

## Procedure
1. Review the proxy/backend HTTP protocol configuration and identify potentially inconsistent framing behavior.
2. Run only the reviewed protocol conformance harness on an isolated test instance.
3. Maintain byte-exact request traces, connection IDs, timing and expected response boundaries.
4. Compare repeated tests and controls; never infer desynchronization from a timeout or a single 400 error.
5. Stop if shared connections, other users or production request queues could be affected.

## Required evidence / output
- raw trace hashes
- framing expectation
- connection-scoped observation
- configuration refs

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
Generic browser fetch APIs cannot faithfully generate all raw HTTP framing variants. This is isolated-lab only.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
