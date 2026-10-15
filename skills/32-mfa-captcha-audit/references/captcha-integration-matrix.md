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
