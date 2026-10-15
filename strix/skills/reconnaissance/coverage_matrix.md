---
name: coverage_matrix
description: Coverage matrix (from master_pentest_methodology specialist reference
  library)
---

# Coverage matrix

Proof that the folder taxonomy covers the agreed threat model cell-by-cell, and
an explicit record of what is out of scope. Sources: OWASP Top 10:2021, OWASP
API Security Top 10, common extras list, operator-named additions (zero-day,
Oracle, Proxmox). Maintained with the library — update when folders change.

## OWASP Top 10:2021

| Item | Folder(s) | Notes |
|---|---|---|
| A01 Broken Access Control | `30-auth-access-control` | IDOR/BOLA token-swap matrix; object/function level split with `60` for API field authz |
| A02 Cryptographic Failures | `35-cryptographic-failures` | TLS, ciphers, hashing, padding oracles, secrets transit/at rest; JWT crypto overlaps `30` via handoff |
| A03 Injection | `40-injection-engine` | SQL/NoSQL/LDAP/OS command/XSS-context/SSTI/XXE |
| A04 Insecure Design | `58-logic-concurrency` + `00-master` | Business-logic abuse checklists; design-level observations feed report "insecure design" section |
| A05 Security Misconfiguration | `50-config-baseline` + `25-waf-edge-posture` | Headers/CSP/CORS/exposed files/verbose errors/takeover; WAF/CDN edge vs origin exposure, header trust, path normalization; default creds checked per-stack in `80`/`82` |
| A06 Vulnerable & Outdated Components | `70-exploit-intel` + `15-cms-ecommerce-rce` (+`75` when no CVE exists) | P1.5 fast-path fingerprint->version->CVE/OSV/KEV/EPSS->benign proof correlation; zero-day path for custom components |
| A07 Identification & Authentication Failures | `30-auth-access-control` + `32-mfa-captcha-audit` | Password policy, MFA presence/step-up skips, TOTP single-use replay, OTP rate limiting, CAPTCHA parameter bypass, session mgmt |
| A08 Software & Data Integrity Failures | `45-rce-exploitation` (exec side) + `65-supply-chain-integrity` (pipeline side) | Deserialization vs CI/CD/unsigned updates/dependency integrity |
| A09 Security Logging & Monitoring Failures | `85-logging-monitoring` | Detection coverage as deliverable; log injection; sensitive data in logs |
| A10 SSRF | `40-injection-engine` (probing) + `20-traffic-manipulation` (OOB) | Metadata endpoints (169.254.169.254), internal ranges; post-SSRF pivot stays in scope discipline |

## Extras from the operator list

| Item | Folder(s) |
|---|---|
| Cross-Site Scripting (XSS) | `40` (context-aware detection) -> `55` (chaining/impact) |
| CSRF | `55-client-side-attacks` |
| Clickjacking | `55` (framing) + `50` (X-Frame-Options/CSP frame-ancestors baseline) |
| Open redirects | `55-client-side-attacks` |
| File upload vulnerabilities | `45-rce-exploitation` (upload->RCE chains; validation bypass matrix) |
| Business logic flaws | `58-logic-concurrency` |
| Insufficient rate limiting / brute-force protection | `30` (auth surfaces) + `58` (burst/race windows) |

## OWASP API Security Top 10 (coverage for `60-api-graphql-websockets`)

| Item | Folder(s) |
|---|---|
| BOLA | `30` |
| Broken authentication | `30` |
| Broken object property level authorization (mass assignment/exposure) | `58` + `60` |
| Unrestricted resource consumption | `58` + `60` (query depth/batching) |
| Broken function level authorization | `30` + `60` |
| Unrestricted access to sensitive business flows | `58` |
| SSRF | `40` |
| Security misconfiguration | `50` |
| Improper inventory management | `10` (schema/version discovery) |
| Unsafe consumption of APIs | `58` |

## Operator-named additions

| Item | Folder(s) |
|---|---|
| Strategic attack surface planning, soft-404 baselines, signal-to-skill dispatch table | `05-attack-surface-planner` |
| Edge vs origin normalization, direct-to-origin bypass, mid-engagement IR / virtual patch detection | `25-waf-edge-posture` |
| Server-side MFA state machine, TOTP single-use, CAPTCHA integration auditing | `32-mfa-captcha-audit` |
| CMS & E-Commerce RCE / SSTI fast-path surfaces | `15-cms-ecommerce-rce` + `70-exploit-intel` + `45-rce-exploitation` |
| Swarm anti-hallucination & independent D2 finding verification | `95-finding-verifier` + `90-evidence-reporting` |
| Zero-day / unknown vulns on custom surfaces | `75-zeroday-research` |
| Oracle systems (DB, WebLogic, EBS) | `80-oracle-stack` |
| Proxmox VE | `82-proxmox-ve` |
| CWE/CVSS classification discipline | `70-exploit-intel` + `90-evidence-reporting` |
| RCE coverage beyond public exploits | `45-rce-exploitation` + `75` |

## Out of scope (recorded, not covered)

- Active Directory / Kerberos attack paths.
- General cloud (AWS/Azure/GCP) misconfiguration beyond SSRF metadata impact
  verification inside the engagement scope.
- Mobile application testing.
- Binary/memory exploitation, firmware.

Adding any of these requires a taxonomy revision and a coverage-matrix update,
not a silent skill.

