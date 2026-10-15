# Authentication State-Machine & Anti-Automation Audit Checklists

## 1. Multi-Step State-Machine Audit Workflow

Execute the following verification sequence when evaluating multi-factor authentication or CAPTCHA integration:

```
[Step 1: Map Endpoints] -> [Step 2: Negative Control] -> [Step 3: State-Skip Probe] -> [Step 4: Omission/Replay] -> [Step 5: Evidence Capture]
```

---

## 2. Step-by-Step Execution Checklist

### Step 1: Map Authentication & Verification Surface
- [ ] Identify Primary Auth endpoint (e.g. `POST /api/v1/auth/login`).
- [ ] Identify Second-Factor Verification endpoint (e.g. `POST /api/v1/auth/mfa/verify`).
- [ ] Identify Protected Post-Auth endpoints (e.g. `GET /api/v1/me`, `GET /dashboard`, `POST /api/v1/user/settings`).
- [ ] Identify Alternative / Mobile endpoints (e.g. `/api/mobile/login`, GraphQL mutation).

### Step 2: Establish Negative Control Baseline
- [ ] Send deliberately invalid credentials $\rightarrow$ confirm HTTP 401/400 rejection.
- [ ] Send deliberately invalid OTP code (`000000`) $\rightarrow$ confirm HTTP 400/401 rejection and record error message.
- [ ] Send deliberately invalid CAPTCHA token (`CANARY_INVALID_TOKEN`) $\rightarrow$ confirm HTTP 400/403 rejection.
- [ ] *Gate Condition*: If the negative control is not rejected, verification is inactive; do not proceed with omission claims until the baseline is clarified.

### Step 3: Pre-MFA Session Step-Up Test
- [ ] Authenticate with valid primary credentials.
- [ ] Capture the provisional session cookie or Bearer token (without completing Step 2 OTP).
- [ ] Replay the provisional session against protected endpoints (`/api/v1/me`).
- [ ] If HTTP 200 and user profile data is returned $\rightarrow$ **VULNERABLE: Pre-MFA Step-Up Skip**.

### Step 4: Parameter Omission & Dummy Value Test
- [ ] Submit form/JSON payload with CAPTCHA field omitted.
- [ ] Submit payload with `captcha=""`.
- [ ] Submit payload with `captcha=null`.
- [ ] Submit payload with `captcha="dummy_canary_test"`.
- [ ] Compare responses against the Step 2 negative control rejection.

### Step 5: TOTP & CAPTCHA Token Replay Test
- [ ] Obtain one valid OTP or solved CAPTCHA token.
- [ ] Submit the token to complete Request A $\rightarrow$ confirm HTTP 200 success.
- [ ] Immediately replay the exact same token in Request B within 5 seconds.
- [ ] If Request B also succeeds $\rightarrow$ **VULNERABLE: Missing Single-Use Enforcement / Token Replay**.

### Step 6: Web vs API Parity Check
- [ ] Submit identical action via mobile API endpoint or GraphQL route without CAPTCHA parameter.
- [ ] If mobile/API processes without requiring CAPTCHA $\rightarrow$ **FINDING: Anti-Automation Parity Gap**.

### Step 7: Evidence Preservation
- [ ] Preserve Request/Response pair for Negative Control: `evidence/p4-mfa-<host>-ctrl.{req,resp}.txt`.
- [ ] Preserve Request/Response pair for Trigger/Bypass: `evidence/p4-mfa-<host>-vuln.{req,resp}.txt`.
- [ ] Verify that diff proves differential treatment (status code, byte length, JSON response keys).
