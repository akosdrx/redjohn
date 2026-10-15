---
name: dispatch_map
description: Dispatch map (from master_pentest_methodology specialist reference library)
---

# Dispatch map

Symptom-to-skill routing with preconditions. Load at most the skills the
current phase needs; prefer one deep-load over repeated shallow loads.
The desktop loader accepts full names and unique numeric prefixes (for
example `10`). Local/repository profiles skip live-web phases that lack
preconditions and state those coverage gaps.

## By phase

| Phase | Skill | Precondition |
|---|---|---|
| P1 | `05-attack-surface-planner`, `10-recon-endpoint-mapping`, `15-cms-ecommerce-rce` | scope file ready, soft-404 baseline needed |
| P1.5 | `70-exploit-intel`, `15-cms-ecommerce-rce`, `45-rce-exploitation` | Tier 1/2 component or CMS/shop fingerprint observed in P1 |
| P2 | `25-waf-edge-posture`, `50-config-baseline`, `35-cryptographic-failures` | P1 surface inventory exists, edge/WAF detected |
| P3 | `20-traffic-manipulation` | at least one crawlable target |
| P4 | `30-auth-access-control`, `32-mfa-captcha-audit` | >= 2 auth contexts, or login/MFA/CAPTCHA flow observed |
| P5 | `40-injection-engine` | P1.5 fast-path triaged, P3 harness ready, input surfaces inventoried |
| P6 | `45-rce-exploitation`, `55-client-side-attacks`, `58-logic-concurrency`, `60-api-graphql-websockets` | relevant P1.5/P4/P5 findings or surfaces |
| P7 | `70-exploit-intel`, `65-supply-chain-integrity` | CWE/CVSS 4.0 scoring or source/CI supply-chain access |
| P8 | `75-zeroday-research`, `80-oracle-stack`, `82-proxmox-ve`, `85-logging-monitoring` | triggers below |
| P9 | `95-finding-verifier` -> `90-evidence-reporting` | coverage complete or interrupted; High/Critical findings verified by `95` |

## By trigger

| Trigger | Skill |
|---|---|
| Scope ingested, need prioritized execution blueprint (P1 -> P1.5 -> P2-P9), per-host soft-404 baselines | `05` |
| Cloudflare/Akamai/AWS WAF/Fastly/ALB edge detected; direct-to-origin candidate IPs; path normalization discrepancy (`/api/admin;v=1`); `X-Forwarded-*` trust; mid-engagement finding stops reproducing (pre/post baseline delta) | `25` |
| MFA/TOTP prompt, SMS/email OTP step-up, CAPTCHA challenge (Turnstile, reCAPTCHA, hCaptcha) on login/registration/reset; mobile-vs-web endpoint parity | `32` |
| Directory/file fuzzing, hidden params (`?debug=`, `?admin=`), JS endpoint extraction | `10` |
| E-commerce / CMS / shop surface (Magento, Shopware, WooCommerce, PrestaShop, WordPress, Drupal, Struts, Spring, Next.js) | `15` -> `70` -> `45` |
| OpenAPI/Swagger/GraphQL/WSDL definitions found | `10` -> `60` |
| Server banner/framework/package version observed (Tier 1/2) | `10` -> `70` (P1.5 fast-path via `redjohn-vuln-intel`) |
| Known RCE/Auth-Bypass CVE or CISA KEV match on fingerprinted component | `70` -> `45` (benign canary proof before generic P5 fuzzing) |
| Need to resend edited raw request; compare two responses; wait on OOB DNS/HTTP | `20` |
| User A's token works on User B's object; sequential/guessable ids across roles | `30` |
| JWT with `alg:none`, missing `exp`, weak HMAC key, `kid` tricks | `30` (+`35` for crypto primitives) |
| Cookie missing HttpOnly/Secure/SameSite; logout keeps session alive; fixation | `30` |
| OAuth `redirect_uri` manipulation, missing `state`, code reuse, PKCE absent | `30` |
| No lockout/throttle on login or reset endpoints | `30` |
| TLS <= 1.1, RC4/3DES/NULL ciphers, SHA-1 certs, self-signed in prod | `35` |
| Passwords stored/hashed with MD5/SHA-1/unsalted; ECB mode; static IV | `35` |
| Padding-oracle behavior (differing decrypt error/timing) | `35` |
| Error text changes with quote/paren input; boolean/time deltas; UNION column math | `40` |
| Reflected input breaking into HTML/attribute/script/URL context | `40` -> `55` |
| URL-fetching feature; internal ranges/metadata IP reachable | `40` (+`20` OOB for blind) |
| `{{7*7}}` evaluated; template engine or shop email/invoice preview fingerprinted | `15` / `40` -> `45` |
| Command delimiters alter output/timing | `40` -> `45` |
| XML parser processes external entities | `40` -> `45` |
| Upload accepted; need bypass/validation matrix/polyglots | `45` |
| Serialized blobs (Java/PHP/Python/Node) in cookies/params/files | `45` |
| LFI confirmed; log poisoning/Wrapper chains considered | `45` |
| State-changing request lacks anti-CSRF token; SameSite lax window | `55` |
| Page frameable; missing X-Frame-Options/frame-ancestors | `50` -> `55` |
| Redirect param trusts arbitrary domains; open-redirect->OAuth code theft chain | `55` |
| `postMessage` listener without origin check | `55` |
| Price/quantity/flow/coupon manipulation; negative values; state machine skips | `58` |
| Parallel requests produce inconsistent end state; double-spend/limit bypass | `58` |
| Hidden/extra object fields accepted on write (role, price, owner) | `58` |
| GraphQL introspection open; depth/batching abuse; field-level authz gaps | `60` |
| WebSocket missing origin check; message authz gaps | `60` |
| GitHub Actions `pull_request_target` + checkout of PR head; script from untrusted input | `65` |
| Unsigned update channel; dependency names squattable | `65` |
| Version pinned + public CVE possible; need OSV/NVD/KEV/EPSS priority & CWE/CVSS | `70` |
| searchsploit/nuclei empty but surface is custom/niche; patch diff available upstream | `75` |
| Port 1521/TNS banner; WebLogic :7001 console/T3; EBS `/OA_HTML` | `80` |
| pveproxy :8006; PVE API `/api2/json/version`; PAM/PVE realm | `82` |
| Need to state what the blue side saw; log canary/injection checks | `85` |
| Specialist claims Medium/High/Critical finding or CVE reproduction | `95` -> `90` |
| Findings at D2 and engagement closing | `90` |

## Negative routing (what NOT to load)

- No version proof yet -> do not open `70`; go fingerprint (`10`, `15`).
- Unchecked P1.5 RCE/KEV leads -> do not sink budget into blind P5 SQLi fuzzing until high-EV P1.5 checks finish.
- No OOB listener ready -> do not claim blind SSRF/XXE; set up `20` first.
- Single auth context only -> `30` runs in degraded mode (session/JWT/static
  checks); document that IDOR/BOLA coverage is partial in the report.
- Out-of-scope stack (AD, general cloud, mobile, binary) -> record observation,
  do not load a skill; there is none by design.

