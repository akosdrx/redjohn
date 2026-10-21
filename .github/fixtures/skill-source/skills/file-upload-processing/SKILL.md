---
name: file-upload-processing
description: Maps upload, transformation and download workflows for authorization, validation and unsafe processing issues.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# file-upload-processing

## Trigger
Upload forms, import/export endpoints, image/document processing or archive handling.

## Expected capabilities (logical adapters; not built-in MCP function names)
`browser.upload_fixture`, `traffic.capture`, `source.file_handlers`

## Required inputs
- benign test fixtures
- authorized actor
- accepted format policy
- cleanup plan

## Procedure
1. Record allowed file types, server-side validation, storage and download workflow.
2. Upload only benign fixtures and observe resulting metadata, processed outputs and access controls.
3. Check cross-role access to resulting artifacts and whether metadata and content type match policy.
4. Correlate any server-side processing anomaly with source code or logs when available.
5. Cleanup uploads and do not submit executable archives, web shells or destructive processing content.

## Required evidence / output
- upload/download request refs
- storage reference
- policy outcomes
- cleanup results

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
Client-side accept attributes are not server-side enforcement. A successful upload is not evidence of executable content.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
