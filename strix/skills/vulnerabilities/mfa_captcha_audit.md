---
name: mfa_captcha_audit
description: Use when auditing server-side MFA, TOTP and CAPTCHA application state
  machines - testing pre-MFA session step-up skips, TOTP single-use replay within
  the validity window, OTP rate-limiting or error oracles, omitted or null CAPTCHA
  tokens, token reuse, or web-vs-API parity gaps.
---

# MFA & CAPTCHA state-machine audit (P4/P6)

Non-destructive auditing of application-side authentication state transitions
and anti-automation controls. Strictly audits server-side verification logic
without attacking third-party CAPTCHA challenge providers.

## The way

- Audit application-side verification, never attack CAPTCHA providers:
  test whether the server validates tokens via `/siteverify`; do not
  attempt to solve or defeat third-party visual/audio puzzles.
- Pre-MFA session step-up skip: after submitting primary credentials,
  test whether the provisional pre-MFA cookie or token already grants access
  to protected endpoints (`/api/me`, `/dashboard`) before factor completion.
- TOTP single-use enforcement: verify that a valid OTP is consumed and
  invalidated immediately upon first use, rather than remaining replayable
  within its RFC 6238 time-step window (missing consumed-code cache).
- Rate limiting and error oracles: check whether `/mfa/verify` lacks attempt
  throttling or leaks code prefix validity through timing or distinct error
  codes (use strictly bounded probe rates; no brute-force flooding).
- CAPTCHA parameter omission and dummy values: test omitting the token field
  entirely, or submitting `""`, `null`, `0`, or a dummy string to detect
  client-side-only enforcement.
- Token replay and endpoint parity: test whether a single solved CAPTCHA
  token can be reused across submissions, or whether mobile/REST API routes
  omit the CAPTCHA required on web forms.
- Negative control requirement: always establish that an invalid token
  returns a rejection baseline before asserting that omission succeeds.

## Handoffs

Recon auth endpoints from `10`; session tokens from `30` -> `32`; step-up
bypasses and CAPTCHA omission findings -> `30` (access control), `58`
(logic flaws), and `95` (finding verifier).

## Tools

`auth_flow_audit.py` (guarded prober for step-up skips, OTP replay, CAPTCHA
omission, and offline `--self-test`). MFA flaw taxonomy, CAPTCHA matrix,
and state-machine checklists in `references/`.

---

## Reference Module: `captcha-integration-matrix`

# Server-Side CAPTCHA Integration Vulnerability Matrix

## 1. Scope Boundary: Integration vs Provider Security

RedJohn audits **how the target application implements and enforces CAPTCHA server-side**.
- **Out of Scope**: Attacking, reverse-engineering, or breaking third-party CAPTCHA challenge algorithms (e.g. Google reCAPTCHA, Cloudflare Turnstile, hCaptcha).
- **In Scope**: Verifying whether the target application's server-side backend actually verifies the token with `/siteverify`, requires the token parameter, and prevents replay.

---

## 2. Server-Side Integration Vulnerability Classes

| Vulnerability Pattern | Implementation Defect | Test Vector | Expected Secure Behavior | Vulnerable Behavior |
|---|---|---|---|---|
| **Parameter Omission** | Server processes form without checking whether CAPTCHA field exists in payload. | Omit `g-recaptcha-response`, `cf-turnstile-response`, or `h-captcha-response` from POST body. | HTTP 400 `{"error": "CAPTCHA token missing"}`. | HTTP 200 / 302: Form processes successfully. |
| **Empty / Null / Zero** | Server checks key existence (`if 'captcha' in body:`) but does not validate value non-emptiness. | Send `captcha=""`, `captcha=null`, or `captcha=0`. | HTTP 400 `{"error": "Invalid CAPTCHA token"}`. | HTTP 200: Action executed. |
| **Dummy Value Acceptance** | Server checks `len(token) > 0` but fails to invoke upstream `/siteverify` API (e.g. missing API key or mock left in production). | Send `captcha="dummy_canary_test_string"`. | Upstream `/siteverify` rejects dummy token; HTTP 400. | HTTP 200: Server accepts dummy token. |
| **Token Replay (Reuse)** | Server does not invalidate or track solved tokens; accepts the same token across multiple submissions. | Intercept one genuinely solved token; replay in 2+ separate requests within validity window (2–5 min). | Second request rejected as `timeout-or-duplicate`. | Both requests succeed. |
| **Action / Hostname Mismatch** | Server verifies token with provider but ignores `action` and `hostname` fields returned by `/siteverify`. | Solve low-privilege newsletter token (`action="newsletter"`); submit to high-privilege login (`action="login"`). | Rejects token if `response.action != "login"` or `response.hostname != expected_host`. | Accepts token; action completes. |
| **Web vs API Parity Gap** | Web frontend requires CAPTCHA; mobile or backend API endpoint (`/api/v1/auth/login`) omits CAPTCHA. | Submit same action to mobile/JSON REST route without CAPTCHA parameter. | API enforces equivalent anti-automation or CAPTCHA. | API processes request without CAPTCHA. |

---

## 3. Negative Control Rule for CAPTCHA Auditing

**Mandatory Integrity Check**:
Before claiming that parameter omission or dummy tokens constitute a vulnerability, you **MUST** send an invalid canary token:
```
g-recaptcha-response=INVALID_CANARY_TOKEN_918273
```
- **If the invalid token is rejected** (HTTP 400/403) but omission/dummy token is accepted $\rightarrow$ **CONFIRMED VULNERABILITY: Bypassed CAPTCHA Integration**.
- **If the invalid token is also accepted** (HTTP 200) $\rightarrow$ The CAPTCHA control is **completely disabled/dormant** on the endpoint.
- **If both are rejected** $\rightarrow$ The control is **actively enforced**.


---

## Reference Module: `mfa-stepup-flaws`

# MFA & TOTP State-Machine Failure Modes

## 1. Authentication State-Machine Architecture

Multi-Factor Authentication (MFA) requires multi-stage session transitions:
1. **Primary Authentication**: Username + password submitted; server validates credentials and establishes an intermediate **provisional state** (`PRE_MFA`).
2. **Second Factor Challenge**: Server requests TOTP (RFC 6238), SMS OTP, WebAuthn, or push confirmation.
3. **Session Promotion / Step-Up**: Server verifies the second factor and promotes the session to **fully authenticated** (`POST_MFA` / `AUTHENTICATED`), issuing a full session cookie or updated JWT with `amr: ["pwd", "mfa"]`.

Vulnerabilities arise when the backend state machine improperly enforces access controls between these states.

---

## 2. Common MFA State-Machine Vulnerabilities

### Flaw 1: Pre-MFA Session Step-Up Skip (Workflow Bypass)
- **Mechanism**: The backend issues a cookie or bearer token during Step 1 (e.g. `session_id` or JWT with `mfa_pending: true`).
- **Defect**: Downstream API endpoints (`GET /api/v1/me`, `GET /api/v1/accounts`, `POST /api/v1/transfers`) only check if a valid session exists, failing to check whether `mfa_completed == true`.
- **Verification**: Submit primary credentials; copy the provisional session token without completing the MFA prompt; request protected endpoints directly.

### Flaw 2: Missing Step-Up on Sensitive Actions
- **Mechanism**: An already authenticated user attempts a high-risk operation:
  - Changing account password.
  - Updating MFA phone number or registering a new TOTP device.
  - Adding an authorized user or updating bank payout details.
- **Defect**: The application does not require a fresh re-authentication challenge (`Step-Up Auth`), allowing a compromised session cookie or CSRF to take over the account.

### Flaw 3: TOTP Single-Use Replay (RFC 6238 Validity Window)
- **Mechanism**: RFC 6238 time-based one-time passwords calculate a 6-digit code based on 30-second Unix epoch windows.
- **Defect**: If the server validates `HMAC-SHA1(secret, time_step)` but fails to cache consumed tokens in an in-memory store (e.g. Redis key `consumed:user_id:code` with 60-second TTL), an attacker who intercepts the code can reuse it in a separate session before the 30-second window expires.

### Flaw 4: Client-Side Response Manipulation
- **Mechanism**: The backend returns a structured JSON payload indicating MFA is required:
  ```json
  {"status": "mfa_required", "step": 2, "user_id": 104}
  ```
- **Defect**: If the response is modified to `{"status": "success", "authenticated": true}`, client-side SPA routing redirects to the authenticated dashboard, and poorly designed backend microservices trust client-reported auth state.

### Flaw 5: Prefix and Timing Error Oracles
- **Mechanism**: The server compares the submitted OTP digit-by-digit or executes sequential database operations:
  - Submitting `123000` returns `Incorrect code: digits 1-3 matched`.
  - Measurable latency differences occur depending on how many leading digits are correct.
- **Defect**: Leaks information allowing an attacker to reduce the OTP search space.

### Flaw 6: Uncapped Verification Rate Limits
- **Mechanism**: The `/api/v1/auth/mfa/verify` endpoint allows unlimited validation requests without account lockout, exponential backoff, or IP throttling.
- **Risk**: For a 6-digit code ($10^6$ combinations) across a 90-second window ($\pm 1$ step), an automated attack can iterate thousands of combinations.


---

## Reference Module: `state-machine-checklists`

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

