---
name: race-toctou
description: Checks state invariants under controlled concurrency and compares them with sequential baseline behavior.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# race-toctou

## Trigger
An operation relies on uniqueness, quota, balance, inventory, redemption or other state-dependent rule.

## Expected capabilities (logical adapters; not built-in MCP function names)
`workflow.fixture`, `concurrency.run_bounded`, `state.snapshot`

## Required inputs
- reversible fixture
- business invariant
- approved worker cap
- before/after snapshot

## Procedure
1. Define a test invariant in plain terms and create a disposable test state.
2. Record sequential baseline results for equivalent operations.
3. Run a small, configured concurrent test batch in an isolated environment.
4. Read authoritative final state, not only HTTP statuses; compare with the invariant and sequential controls.
5. Clean up any created objects and report instability separately from a confirmed rule violation.

## Required evidence / output
- invariant and baseline
- task timing/sequence
- final state evidence
- cleanup confirmation

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
Parallel 200 responses are not sufficient to establish a race vulnerability. Do not stress production endpoints.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
