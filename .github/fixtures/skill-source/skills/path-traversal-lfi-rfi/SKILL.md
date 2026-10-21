---
name: path-traversal-lfi-rfi
description: Checks file path normalization and inclusion boundaries using controlled fixture files and evidence-aware comparison.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# path-traversal-lfi-rfi

## Trigger
Inputs select file paths, templates, documents, downloads or remote includes.

## Expected capabilities (logical adapters; not built-in MCP function names)
`traffic.replay`, `source.file_access`, `surface.inputs`

## Required inputs
- designated fixture paths/files
- request refs
- document-root expectations
- test profile

## Procedure
1. Identify the intended root directories and legitimate file-selection behavior.
2. Use only designated, non-sensitive fixture files to observe whether path boundaries are enforced.
3. Analyze canonicalization and file resolution in source when available and correlate with runtime behavior.
4. Distinguish traversal, local file inclusion, remote file inclusion and ordinary file disclosure.
5. If remote fetch or execution would be required for proof, mark as higher-impact and defer to isolated review.

## Required evidence / output
- fixture file ID
- expected allowed path
- observed access/inclusion evidence
- comparison refs

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
An error referencing a filesystem path is not proof that data outside the intended root was returned.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
