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
