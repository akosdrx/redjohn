---
name: finding-triage-retest
description: Validates, deduplicates and retests candidate findings using independent controls and persisted evidence.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# finding-triage-retest

## Trigger
Any scanner/agent emits a candidate or a previously fixed finding needs retesting.

## Expected capabilities (logical adapters; not built-in MCP function names)
`evidence.get`, `findings.upsert`, `tests.replay`

## Required inputs
- candidate evidence refs
- test plan and profile
- expected property
- retest environment

## Procedure
1. Require a concrete claim and traceable evidence rather than an LLM confidence score.
2. Identify which observation supports the specific claimed impact and which controls could refute it.
3. Reproduce with fresh fixture state when authorized and compare expected versus actual effects.
4. Merge duplicates by root cause and affected control, preserving separate affected endpoints as instances.
5. Classify confirmed, candidate, false positive, inconclusive, fixed or reopened with explicit rationale.

## Required evidence / output
- evidence chain
- control/retest refs
- status and confidence explanation
- root cause

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
Agreement between two agents is not an independent test. Tool crashes and blocked tests are not negatives.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
