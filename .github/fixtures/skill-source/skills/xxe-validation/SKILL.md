---
name: xxe-validation
description: Reviews XML parsing and external entity handling, corroborating any observed callbacks with parser and request context.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# xxe-validation

## Trigger
XML or SOAP input, XML-bearing uploads, or known parser frameworks.

## Expected capabilities (logical adapters; not built-in MCP function names)
`traffic.replay`, `source.xml_parser_config`, `oast.correlate`

## Required inputs
- XML request ref
- content type/parser evidence
- safe OAST receiver
- test profile

## Procedure
1. Inventory which XML entry points actually parse incoming data and whether DTD/entity features are required.
2. Prefer parser configuration analysis and harmless, isolated tests over access to target files.
3. Where approved, correlate external fetch events with uniquely tracked requests and controls.
4. Separate confirmed external-entity resolution from unproven file access or RCE impact.
5. Report unsupported XML variants separately from negative test results.

## Required evidence / output
- parser/version/config if known
- request/OAST refs
- expected and actual external fetch decision

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
HTTP 500 or XML parsing errors alone are weak evidence. Do not read local files or internal network services.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
