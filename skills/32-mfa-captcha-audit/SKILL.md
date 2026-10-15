---
name: 32-mfa-captcha-audit
description: Use when auditing server-side MFA, TOTP and CAPTCHA application state machines - testing pre-MFA session step-up skips, TOTP single-use replay within the validity window, OTP rate-limiting or error oracles, omitted or null CAPTCHA tokens, token reuse, or web-vs-API parity gaps.
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
