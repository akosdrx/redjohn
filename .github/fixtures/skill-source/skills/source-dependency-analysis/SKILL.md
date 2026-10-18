---
name: source-dependency-analysis
description: Combines source taint analysis and package vulnerability data to prioritize reachable security defects.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# source-dependency-analysis

## Trigger
An authorized source checkout, dependency lockfile, SBOM or container image is available.

## Expected capabilities (logical adapters; not built-in MCP function names)
`semgrep.scan`, `trivy.scan`, `vulnx.query`, `source.callgraph`

## Required inputs
- source checkout/commit
- approved scan rules
- lockfile/SBOM
- deployment versions

## Procedure
1. Pin the project revision and run only reviewed SAST/SCA rule sets.
2. Correlate dependency advisories with installed versions and reachable application entry points.
3. For potentially dangerous dataflow, note source, transformations, sink and existing guards.
4. Produce focused dynamic verification tasks tied to known endpoint IDs rather than a long speculative report.
5. Keep unverified code findings separate from confirmed runtime exploitability.

## Required evidence / output
- commit + file/line
- rule ID and scanner version
- affected version data
- entrypoint reachability

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
An installed vulnerable dependency is not necessarily reachable; scanner rules and license terms must be reviewed.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
