---
name: subdomain-takeover
description: Assesses dangling DNS and provider ownership with evidence of real claimability rather than DNS heuristics.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# subdomain-takeover

## Trigger
An authorized subdomain resolves to a deprovisioned or suspect external service.

## Expected capabilities (logical adapters; not built-in MCP function names)
`dns.records`, `provider.fingerprint`, `asset.ownership`

## Required inputs
- authorized DNS zone/subdomains
- provider metadata
- ownership policy

## Procedure
1. Collect CNAME/ALIAS and relevant provider response fingerprints for authorized names.
2. Identify the original service binding and whether provider-side domain verification exists.
3. Use non-claiming, passive checks by default; do not register or attach domains automatically.
4. Classify dangling reference, suspected takeover and verified claimability as distinct states.
5. Attach remediation instructions for removing stale DNS and configuring provider ownership checks.

## Required evidence / output
- DNS record chain
- provider response refs
- claimability assessment and limits

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
NXDOMAIN or a generic error page is not proof that an attacker can claim the hostname.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
