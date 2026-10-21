---
name: technology-fingerprinting
description: Correlates headers, static assets, observed behavior and source manifests to identify technologies with evidence.
metadata:
  author: headless-strix-skillpack
  version: "1.0.0"
---

# technology-fingerprinting

## Trigger
Before choosing CVE checks or framework-specific vulnerability tests.

## Expected capabilities (logical adapters; not built-in MCP function names)
`browser.observe`, `httpx.probe`, `source.manifest`, `surface.upsert`

## Required inputs
- in-scope origins
- captured responses
- optional source manifest or SBOM

## Procedure
1. Fingerprint using independent observations such as response headers, asset patterns and package manifests.
2. Separate product family from exact version. Record uncertainty and conflicting signals.
3. Prefer verified server-side version or SBOM over client-visible banners; do not infer server runtime solely from JavaScript libraries.
4. Write product + version range + evidence to the technology inventory.
5. Only enable technology-specific tests where applicability prerequisites are met.

## Required evidence / output
- product and version confidence
- evidence refs
- fingerprint source
- mismatches

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
A framework-looking URL is not proof that the framework or a specific vulnerable version is running.

## Background reference
- OWASP Web Security Testing Guide (versioned): https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
