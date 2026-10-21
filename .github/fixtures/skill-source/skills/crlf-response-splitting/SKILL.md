---
name: crlf-response-splitting
description: Checks whether untrusted data improperly changes HTTP header boundaries or logging metadata.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# crlf-response-splitting

## Trigger
Inputs appear in redirects, response headers, cookies, logging or proxy-derived metadata.

## Expected capabilities (logical adapters; not built-in MCP function names)
`traffic.replay`, `browser.capture_traffic`, `source.header_construction`

## Required inputs
- header-writing endpoint
- input request ref
- expected header policy

## Procedure
1. Locate header construction paths in observed responses or source code.
2. Use harmless, bounded marker comparisons that do not set cookies or force redirects to external destinations.
3. Inspect raw response headers and browser interpretation independently to rule out normalization artifacts.
4. Distinguish log formatting issues, reflected text and actual response-header boundary changes.
5. Confirm only if the observed header structure diverges from intended policy.

## Required evidence / output
- raw header evidence
- marker correlation
- control request/response refs

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
An encoded newline in a body or a URL is not proof of response splitting.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
