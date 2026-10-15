# Execution Blueprint: Phase Machine, EV Routing & Load Budgeting

## 1. P0–P9 Phase Machine

RedJohn executes assessments in structured, progressive phases. Every phase transition requires calibrated baseline evidence.

| Phase | Name | Focus & Mandatory Inputs | Key Skills & Actions |
|---|---|---|---|
| **P0** | **Prep & Onboarding** | Scope JSON, RoE rules, account credentials ($\ge 2$ roles), out-of-band canary tokens. | Validate scope CIDRs/hosts; initialize session profiles; generate unique canary tokens. |
| **P1** | **Recon & Baseline** | Host enumeration, crawling, JS bundle extraction, soft-404 baseline calibration. | `10-recon-endpoint-mapping`, `05-attack-surface-planner` (`--probe-baseline`). |
| **P1.5** | **Fast-Path Triage** | Tier 1/2 exact component versions, known CVEs, CISA KEV catalog entries. | `70-exploit-intel`, `15-cms-ecommerce-rce`, `45-rce-exploitation`. Direct EV verification. |
| **P2** | **Passive Baseline** | TLS posture, security headers, CORS, direct origin exposure, DNS leakage. | `50-config-baseline`, `35-cryptographic-failures`, `25-waf-edge-posture`. |
| **P3** | **Harness & Normalization** | Raw request replay, response diffing harness, edge path normalization. | `20-traffic-manipulation`, `25-waf-edge-posture`. OOB listener verification. |
| **P4** | **Auth & State-Machine** | Identity fabric, RBAC/ABAC matrix, MFA step-up, CAPTCHA server-side integration. | `30-auth-access-control`, `32-mfa-captcha-audit`. |
| **P5** | **Injection & Sinks** | Parameter discovery, SQLi, SSTI, command injection, path traversal. | `40-injection-engine`. Negative-control diffing on all parameter inputs. |
| **P6** | **Depth & Multi-Step** | RCE proof generation, DOM/XSS, business logic workflows, race conditions. | `45-rce-exploitation`, `55-client-side-attacks`, `58-logic-concurrency`, `60-api-graphql-websockets`. |
| **P7** | **Supply Chain & Scoring** | Dependency audit, CI/CD pipeline posture, CVSS 4.0 / CWE classification. | `65-supply-chain-integrity`, `70-exploit-intel`. |
| **P8** | **Special Stacks & Telemetry** | Zero-day patch gaps, Oracle/Proxmox stacks, SIEM/IDS alert validation. | `75-zeroday-research`, `80-oracle-stack`, `82-proxmox-ve`, `85-logging-monitoring`. |
| **P9** | **Verification & Delivery** | Independent finding verification, compliance cross-walk, deliverable generation. | `95-finding-verifier`, `90-evidence-reporting`. |

---

## 2. Expected-Value (EV) Priority Routing

Rather than exhaustively scanning every parameter blindly, RedJohn ranks testing actions by Expected Value (EV):

$$\text{EV Priority} = \frac{\text{Impact} \times \text{TierConfidence} \times \text{Maturity}}{\text{VerificationCost}}$$

### Factor Weights
- **Impact (1–10)**:
  - Critical RCE / Auth Bypass / Unauth Data Exfiltration = 10
  - Privilege Escalation / Server-Side SSRF / SQLi = 8
  - Stored XSS / Sensitive Info Leak / CAPTCHA bypass = 5
  - Reflected XSS / Missing Headers / TLS weak ciphers = 2
- **TierConfidence (0.0–1.0)**:
  - Tier 1 (Exact semver from official manifest or banner) = 1.0
  - Tier 2 (Stable tag / build signature / unique endpoint match) = 0.8
  - Tier 3 (Header / cookie / DOM fingerprint match) = 0.5
  - Tier 4 (Heuristic / behavioral inference) = 0.2
- **Maturity (1.0–3.0)**:
  - CISA KEV or weaponized public PoC documented = 3.0
  - Known CVE with documented advisory = 2.0
  - Generic vulnerability pattern or configuration defect = 1.0
- **VerificationCost (1–10)**:
  - Single read-only GET / version check = 1
  - Multi-step auth / parameter probe = 3
  - OOB listener / blind timing verification = 5
  - Blind brute-force / high-rate fuzzing = 10

High-EV items (e.g. Tier 1 CVE on public CMS with score > 2.0) are routed directly to **P1.5 Fast-Path** before Phase P2–P5 execution.

---

## 3. Load Budget Discipline (Cap 8 Platform Skills)

To prevent LLM context exhaustion, redundant network requests, and hallucinated findings:
1. **Hard Limit**: Maximum **8** active platform skills can be loaded concurrently during any single execution stage.
2. **Precedence Hierarchy**:
   - `Tier 1`: Identity & Access Control (`30-auth-access-control`, `32-mfa-captcha-audit`)
   - `Tier 2`: Perimeter & Appliances (`70-exploit-intel`, `80-oracle-stack`, `82-proxmox-ve`)
   - `Tier 3`: Cloud & Edge (`25-waf-edge-posture`, `50-config-baseline`)
   - `Tier 4`: Application Frameworks & CMS (`15-cms-ecommerce-rce`, `60-api-graphql-websockets`)
   - `Tier 5`: Generic Vulnerability Classes (`20-traffic-manipulation`, `40-injection-engine`, `45-rce-exploitation`, `55-client-side-attacks`, `58-logic-concurrency`)
3. **De-duplication**: When more than 8 candidate skills are triggered, lowest-tier skills with no direct component evidence are deferred to on-demand execution.

---

## 4. Fact-vs-Hypothesis Blackboard Discipline

Maintain strict separation in working memory:
- **`[FACTS]`**: Confirmed observations backed by signed evidence files (`evidence/p*-<host>-<seq>.{req,resp}.txt`) and verified by negative controls. Only facts can trigger P1.5 fast-path or P6 multi-step exploits.
- **`[HYPOTHESES]`**: Inferred opportunities, unconfirmed fingerprints, or potential attack paths. Hypotheses require baseline validation before tool execution.
