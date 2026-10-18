---
name: report-coverage
description: Builds concise reports with source-linked findings, residual gaps, fixes and machine-readable artifacts.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# report-coverage

## Trigger
At run completion, scheduled checkpoint, or after a remediation cycle.

## Expected capabilities (logical adapters; not built-in MCP function names)
`findings.query`, `coverage.query`, `report.export`

## Required inputs
- engagement/run IDs
- confirmed/candidate findings
- coverage matrix
- environment restrictions

## Procedure
1. Include only validated findings in the confirmed section and clearly label candidates.
2. Use precise technical impact and actual observed scope rather than hypothetical escalation.
3. Provide remediation, verification steps, affected identities/objects and evidence pointers without embedding secrets.
4. Summarize tested, not tested, blocked, unsupported and inconclusive categories separately.
5. Export JSON/SARIF/Markdown as configured and record generator/source revisions.

## Required evidence / output
- finding IDs and CWE/WSTG refs
- evidence pointers
- coverage statistics
- limitations/retest outcome

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
Never infer that untested surfaces are safe; do not include raw tokens, personal data or credentials in exports.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
