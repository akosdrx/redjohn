---
name: verification_checklist
description: Anti-Hallucination & D2 Verification Checklist (95-finding-verifier)
  (from deterministic_finding_verifier specialist reference library)
---

# Anti-Hallucination & D2 Verification Checklist (95-finding-verifier)

Mandatory checklist enforced by `verify_finding_gate.py` and the core engine's
`builtin:report_finding` provenance gate before any finding can be marked
`Verified` (D2).

---

## 1. Universal Provenance Gate (All Findings)

| Check | Requirement | Failure Action |
|---|---|---|
| **Session Artifact Existence** | Every referenced `evd_*` ID or `evidence/<phase>-<surface>-<seq>.{req,resp}.txt` file must exist in the current engagement workspace and be $>0$ bytes. | Hard reject (`ERROR`) — never fabricate or guess evidence filenames. |
| **Negative Control Differential** | For `Medium` / `High` / `Critical` findings, a benign baseline capture (`negative_control_ref`) or $\ge 2$ distinct capture pairs must show a concrete difference (status code, header, or body digest) vs the positive probe. | Clamp status from `verified` to `suspected` (D1). |
| **Correlation-Only Cap** | Findings derived solely from banner/version correlation (`70-exploit-intel`) without an active behavioral proof (`45`, `40`, `30`) must state `[correlation-only]` and cannot claim `verified` exploitation. | Clamp status to `suspected` (D1) and require operator/probe verification. |

---

## 2. Vulnerability-Class Specific D2 Gates

### A. Remote Code Execution / SSTI / Deserialization (`45-rce-exploitation`)
- **Required Positive Signal:** Computed canary output (e.g., evaluated arithmetic
  or non-destructive property string) in the HTTP response body (`resp.txt`) or
  verified engagement-scoped OOB callback record.
- **Required Negative Control:** Inert string without expression delimiters
  returning normal output without the computed canary.
- **Automatic Rejections:**
  - Raw response echoes the literal uncomputed expression (e.g. `{{ ... }}`
    rendered client-side or escaped).
  - HTTP 500 error page without computed canary output or OOB confirmation.

### B. SQL / NoSQL / Command / LDAP Injection (`40-injection-engine`)
- **Boolean / Error-Based:** Two pairs (`true` condition vs `false` condition)
  demonstrating reproducible content/row count differential across two runs.
- **Time-Based Blind:** Never accept a single slow HTTP response. Require 5
  interleaved baseline (`0s`) and sleep (`Ns`) probes where the minimum delayed
  response exceeds the maximum baseline response by at least $0.8 \times N$.

### C. Broken Access Control / IDOR / Auth Bypass (`30-auth-access-control`)
- **Required Captures:**
  1. Authorized owner request (`user-a`) succeeding (`200 OK` with private fields).
  2. Unauthenticated or cross-tenant request (`user-b`) replaying the resource
     identifier and receiving the same private fields.
- **Automatic Rejections:**
  - Publicly cacheable or intentionally public profile/catalog endpoints.
  - Identical `200 OK` HTML login/redirect shell (soft-404 / soft-401).

### D. Business Logic & Concurrency (`58-logic-concurrency`)
- **Required Captures:** Pre-state read (`GET`), concurrent burst log, and
  post-state read (`GET`) proving a persistent invariant violation (e.g.,
  single-use coupon applied twice or negative balance).

---

## 3. The Layer-Ordering Trap (Auth Bypass Verification)

A validation error does **NOT** prove authentication bypass.

### The Failure Mechanism
In modern API gateways and web frameworks, global input sanitizers, body parsers,
or JSON schema validation middleware frequently execute **before** authentication
and authorization middleware:

```text
[ Incoming Request ]
         │
         ▼
[ 1. Input Sanitizer / Schema Validator ] ── Malformed input / missing field? ──► HTTP 400 / 422
         │ (Valid input only)
         ▼
[ 2. Authentication Middleware ] ──────── Missing / invalid credentials? ─────► HTTP 401 / 403
         │ (Authenticated only)
         ▼
[ 3. Business Logic Handler ]
```

When an unauthenticated probe sends a malformed body, missing required parameters,
or unexpected data types, Layer 1 rejects the request with HTTP 400 Bad Request
or HTTP 422 Unprocessable Entity (e.g., `{"error": "email is required"}` or
`{"code": "ERR-INPUT-0001", "message": "Invalid text"}`).

### The False-Positive Trap
An analyst or automated agent falsely infers: *"The server parsed my parameters
and complained about a missing field; therefore authentication was bypassed and
business logic was reached."*

### Mandatory Minimal Well-Formed Body Protocol
Layer ordering is not observable from a single error response:
1. Probe with a **minimal well-formed body** that satisfies parser schema:
   ```bash
   # Step A: Malformed body trips sanitizer (layer 1) - NOT proof of auth bypass
   curl -s -i -X POST https://target/api/v1/resource -d '{'
   # HTTP/400 {"error": "Invalid JSON syntax"}
   
   # Step B: Minimal well-formed body reaches auth layer (layer 2)
   curl -s -i -X POST https://target/api/v1/resource \
     -H 'Content-Type: application/json' -d '{}'
   # HTTP/401 {"error": "Unauthorized. Token missing."}
   ```
2. **Enforcement Rule:** If positive evidence for an authentication bypass or
   unauthenticated access claim shows HTTP 400 or 422 schema validation without
   a companion capture demonstrating that a well-formed request accesses
   protected data or performs unauthorized actions, the finding is
   automatically **clamped** to `suspected` (D1) or **rejected**.

---

## 4. The 7-Question Gate (Triage Validation)

Before any candidate finding is promoted to `Verified` (D2) or submitted to
reporting (`90-evidence-reporting`), it must answer all 7 questions in order.
A single failure stops the finding:

| Gate Question | Verification Test | Failure Action |
|---|---|---|
| **Q1: Scope Verification** | Is the target host, port, and endpoint verified within explicit engagement scope? | Hard reject (`REJECTED`) — out-of-scope testing is prohibited. |
| **Q2: Observable Captures** | Is the vulnerability claim supported by observable request/response pairs on disk? | Hard reject (`REJECTED`) — claims without real captures are hallucinations. |
| **Q3: Target Backend Reached** | Did the probe reach the target application backend without being intercepted/blocked by edge WAF/CDN? | Clamp / Reject — WAF 403/captcha challenge is not application behavior. |
| **Q4: Negative Control Differential** | Does the observed behavior deviate deterministically from expected negative controls? | Clamp to `suspected` — no differential means no observable vulnerability. |
| **Q5: Error Differentiation** | Is the response differentiated from a generic framework error, default template, or soft-404? | Clamp to `suspected` — generic 404/500 is not vulnerability proof. |
| **Q6: Layer-Ordering Avoided** | Is the layer-ordering trap avoided (schema validation error not mistaken for auth bypass)? | Clamp / Reject — 400/422 validation cannot prove auth bypass without well-formed 2xx capture. |
| **Q7: Non-Destructive Reproducibility** | Is the impact strictly reproducible without destructive side-effects or persistent data corruption? | Reject if destructive or non-reproducible. |


