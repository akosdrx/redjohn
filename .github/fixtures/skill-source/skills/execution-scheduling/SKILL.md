---
name: execution-scheduling
description: Schedules bounded independent test jobs from inventory state while limiting LLM context and repeated work.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# execution-scheduling

## Trigger
Every scan iteration or when new endpoints, versions or actor states are discovered.

## Expected capabilities (logical adapters; not built-in MCP function names)
`jobs.enqueue`, `jobs.status`, `coverage.query`, `policy.check`

## Required inputs
- current inventory
- skill manifest
- impact profile
- token/HTTP/time budgets

## Procedure
1. Compute applicable skill × endpoint × actor × state combinations deterministically.
2. Prioritize untested high-value surfaces, then confirmed hypotheses; maintain fairness so one test family cannot monopolize the run.
3. Batch independent jobs into subprocess workers with deadlines, request caps and cancellation tokens.
4. Preserve full stdout and bodies in storage; give the LLM only compact counts, new findings and evidence references.
5. Requeue only upon explicit new evidence or transient failure policy; terminal states are completed, unsupported, blocked and inconclusive.
6. Produce a final uncovered matrix and stop on budget exhaustion rather than unbounded exploratory loops.

## Required evidence / output
- job key/status/version
- consumed budget
- batch outputs and refs
- remaining gaps

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
Missing expected evidence should create a coverage gap, not repeat an identical expensive scan indefinitely.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
