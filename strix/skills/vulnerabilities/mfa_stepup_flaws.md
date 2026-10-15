---
name: mfa_stepup_flaws
description: MFA & TOTP State-Machine Failure Modes (from mfa_captcha_audit specialist
  reference library)
---

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

