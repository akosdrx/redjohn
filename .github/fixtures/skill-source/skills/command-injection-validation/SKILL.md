---
name: command-injection-validation
description: Assesses suspected server-side command execution paths using authorized non-destructive evidence and explicit impact gates.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# command-injection-validation

## Trigger
A server input may reach a command/shell interpreter or source code shows a possible command sink.

## Expected capabilities (logical adapters; not built-in MCP function names)
`commix.run_profile`, `source.taint_analysis`, `oast.correlate`

## Required inputs
- observed request
- suspected input
- server technology if known
- isolated test profile

## Procedure
1. Confirm whether the behavior is consistent with server-side command interpretation instead of normal application processing.
2. Correlate source-code paths and test evidence where available; prioritize direct, non-destructive runtime observations.
3. Allow only the preapproved verification profile in the designated test environment. No reverse shells, persistence or arbitrary data reads.
4. If out-of-band validation is used, correlate callback ID and time with the exact test request and control.
5. Keep command injection, application-level code evaluation and confirmed RCE impact as distinct conclusions.

## Required evidence / output
- sink mechanism
- request/worker refs
- repeatable safe effect
- OAST or server trace when relevant

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
A callback or anomalous error alone does not prove arbitrary code execution. Halt any test that risks data modification.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
