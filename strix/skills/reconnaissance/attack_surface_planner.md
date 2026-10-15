---
name: attack_surface_planner
description: Use when ingesting engagement scope, RoE constraints, soft-404 baselines,
  and recon fingerprints to produce a prioritized phase execution blueprint (P1 ->
  P1.5 -> P2-P9), evidence collection checklist, and signal-to-skill dispatch table
  before or during active testing.
---

# Attack surface & engagement planner (P0/P1)

Strategic orchestrator that turns scope, rules of engagement (RoE), and
reconnaissance signals into an EV-ranked phase blueprint and swarm dispatch
matrix. Nothing past P1 executes without a calibrated plan.

## The way

- Calibrate per-host and per-depth soft-404 baselines before fuzzing:
  record status, size, and body hash on two random bogus paths per host
  and per depth (`/x` vs `/a/b/x`).
- Expected-Value (EV) priority routing: triage high-confidence, low-cost
  Tier 1/2 CVEs and fast-path RCE (`P1.5`) before committing budget to
  blind parameter fuzzing (`P5`).
- Enforce load budget discipline: cap active platform skills at 8 to prevent
  context exhaustion and redundant probing.
- Maintain a strict fact-vs-hypothesis blackboard: treat confirmed
  evidence (`D2`/`D3`) as facts; keep speculative leads as hypotheses.
- Fail closed on scope boundaries: reject unlisted hosts immediately; log
  discovered out-of-scope assets as passive observations only.
- Continuous blueprint calibration: re-evaluate the phase plan whenever
  new fingerprints, auth boundaries, or edge defenses emerge.

## Handoffs

Scope and RoE -> `P0`; recon fingerprints and soft-404 baselines from `10` ->
`05`; fast-path Tier 1/2 components -> `70`/`15`/`45`; edge and baseline
posture -> `25`/`50`; auth boundaries -> `30`/`32`.

## Tools

`attack_plan_gen.py` (guarded baseline probe, plan generation, and offline
`--self-test`). Phase blueprint, evidence checklist, and signal-to-skill
dispatch matrix in `references/`.

---

## Reference Module: `evidence-checklist`

# Evidence Checklist: Taxonomy, Required Fields & Negative Control Rules

## 1. D1–D4 Evidence Taxonomy

Every piece of security evidence collected during an assessment is categorized into one of four rigor levels:

| Level | Name | Description | Verification State |
|---|---|---|---|
| **D1** | **Observed** | Single observation from an active or passive probe (status code, header, body snippet). | Unverified candidate lead. |
| **D2** | **Verified** | Replayed and reproducible; passes negative control differential; validated by `verify_finding_gate.py`. | Confirmed technical vulnerability. |
| **D3** | **Operator Validated** | Confirmed by a human operator or verified in secondary staging environment. | Actionable high-confidence finding. |
| **D4** | **Reported** | Formatted into compliance-mapped deliverable with remediation guidance via `90-evidence-reporting`. | Deliverable ready. |

---

## 2. Mandatory Finding Metadata Fields

A finding cannot progress to D2 without all of the following fields populated:

- `id`: Unique identifier (e.g., `FIND-2026-001`).
- `title`: Clear, descriptive title naming vulnerability class and affected component.
- `target_uri`: Full URI of the affected endpoint (e.g. `https://target.example.com/api/v1/user`).
- `method`: HTTP method (`GET`, `POST`, `PUT`, `DELETE`, etc.).
- `parameter`: Affected parameter, header, or path segment (or `N/A` for architectural/header flaws).
- `cwe`: Canonical CWE identifier (e.g., `CWE-287`, `CWE-89`).
- `severity`: Standard severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `request_file`: Path to preserved raw HTTP request (`evidence/p*-<slug>.<seq>.req.txt`).
- `response_file`: Path to preserved raw HTTP response (`evidence/p*-<slug>.<seq>.resp.txt`).
- `negative_control_ref`: Path to negative control request/response proving differential behavior.
- `observed_differential`: Summary of delta metrics:
  - `status_delta`: Expected rejection status vs observed bypass status (e.g., `401 -> 200`).
  - `byte_delta`: Length difference between negative control and valid response.
  - `hash_delta`: SHA256 differential between negative control and trigger response.

---

## 3. Negative Control Rules & Anti-Hallucination Disqualification

To eliminate hallucinations and false positives, the following disqualification rules are strictly enforced:

### Rule 1: The Soft-404 Trap
- **Condition**: An endpoint returns HTTP 200 or 403, but the response body SHA256 matches the host's calibrated soft-404 baseline.
- **Verdict**: **DISQUALIFIED**. The endpoint does not actually exist or is returning a catch-all SPA/landing page.

### Rule 2: The Layer-Ordering Trap
- **Condition**: An unauthenticated request to an API endpoint returns HTTP 400 Bad Request or HTTP 422 Unprocessable Entity (e.g. `{"error": "Missing required field: username"}`).
- **Verdict**: **CLAMPED / REJECTED AS AUTH BYPASS**. When schema validation middleware runs before authentication middleware, input validation errors do not prove unauthenticated access. An auth bypass finding is only granted if a well-formed request produces HTTP 200/201 and exposes protected data or executes unauthorized state changes.

### Rule 3: The Missing Negative Control Clamp
- **Condition**: A probe claims an authentication or authorization bypass (e.g. step-up skip, CAPTCHA omission) without providing a negative control showing that an invalid token or unauthenticated request is properly rejected.
- **Verdict**: **CLAMPED TO SUSPECTED**. Without proof of active enforcement on invalid inputs, successful completion of a request may indicate that the feature is disabled, mock, or a no-op.

### Rule 4: Edge Block vs Origin Finding
- **Condition**: A probe returns HTTP 403 or 429 containing CDN branding (e.g., `Cloudflare Ray ID`, `AWS WAF Block Page`, `Akamai Reference Error`).
- **Verdict**: **LOG AS EDGE POSTURE ONLY**. The request was intercepted and rejected by the edge layer before reaching the backend application.


---

## Reference Module: `execution-blueprint`

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


---

## Reference Module: `signal-dispatch-table`

# Signal-to-Skill Dispatch Table

This table maps reconnaissance fingerprints, infrastructure indicators, and behavioral cues to prioritized RedJohn assessment skills across Tiers 1 through 5.

## 1. Five-Tier Signal-to-Skill Matrix

| Tier | Category | Concrete Fingerprints & Surface Signals | Target RedJohn Skills | Phase |
|---|---|---|---|---|
| **Tier 1** | **Identity & SSO Fabric** | Okta (`/oauth2/`, `okta-hosted`), Entra/M365 (`login.microsoftonline.com`), Auth0 (`/authorize`, `auth0.js`), Keycloak (`/auth/realms/`), Ping Identity, SAML assertions. | `30-auth-access-control`<br>`32-mfa-captcha-audit` | P4 |
| **Tier 2** | **Perimeter Appliances** | Fortinet FortiOS (`/remote/login`), Ivanti Connect Secure (`/dana-na/`), Citrix NetScaler (`/vpn/index.html`), VMware vCenter (`/ui/login`), Palo Alto GlobalProtect (`/global-protect/`). | `70-exploit-intel`<br>`80-oracle-stack`<br>`82-proxmox-ve` | P1.5 / P8 |
| **Tier 3** | **Cloud & Edge Infrastructure** | Cloudflare (`cf-ray`, `__cf_bm`), AWS CloudFront (`x-amz-cf-id`), Akamai (`x-akamai-transformed`), Fastly, GCP Cloud Armor, Nginx reverse proxy headers. | `25-waf-edge-posture`<br>`50-config-baseline` | P2 / P3 |
| **Tier 4** | **Application Frameworks & CMS** | Next.js (`__NEXT_DATA__`), Spring Boot (`/actuator`), Laravel (`laravel_session`, Ignition), ASP.NET (`VIEWSTATE`), WordPress (`/wp-json/`), Drupal (`/core/CHANGELOG.txt`), Joomla! (`/administrator/manifests/files/joomla.xml`), PrestaShop (`/config/xml/channel.xml`). | `15-cms-ecommerce-rce`<br>`60-api-graphql-websockets`<br>`70-exploit-intel` | P1.5 / P4 |
| **Tier 5** | **Protocols & Vulnerability Classes** | GraphQL (`/graphql`, `__schema`), WebSocket (`Upgrade: websocket`), Java serialization (`rO0AB`), Python pickle markers, SSRF canary reflection. | `20-traffic-manipulation`<br>`40-injection-engine`<br>`45-rce-exploitation`<br>`55-client-side-attacks`<br>`58-logic-concurrency` | P3 / P5 / P6 |

---

## 2. Precedence and Load Budget Allocation Rules

When multiple signals fire simultaneously:
1. **Tier 1 (Identity)** and **Tier 2 (Perimeter Appliances)** take top priority for immediate execution.
2. If exact component versions are detected (Tier 1/2 confidence), route directly to **P1.5 Fast-Path Triage** (`70-exploit-intel` + `15-cms-ecommerce-rce`).
3. If an edge layer (Tier 3) is detected, run `25-waf-edge-posture` to establish direct origin exposure and normalization baselines before heavy fuzzing.
4. Cap the active platform skill roster at **8**. If more than 8 skills match, defer Tier 5 generic class skills until specific endpoint parameters are identified.

