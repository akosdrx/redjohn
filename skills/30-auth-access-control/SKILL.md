---
name: 30-auth-access-control
description: Use when testing broken access control and authentication - swapping tokens or cookies between user contexts to find IDOR/BOLA, auditing JWT algorithms, keys and claims, checking session cookie flags, logout invalidation and fixation, OAuth/OIDC redirect and code handling, or login and password-reset rate limiting and credential-stuffing exposure.
---

# Auth and access control (P4)

Authorization between contexts, authentication mechanics, session and
OAuth lifecycle. The matrix is the method: role x object x action.

## The way

- Classify object ids first (sequential / UUID / opaque) — the class
  decides what evidence is safe to collect.
- Fresh tokens before believing any swap finding: a delta that only
  reproduces with stale tokens is a session artifact, not an authz gap.
- Same status, different body = data-leak candidate; a 403-vs-404 split
  between existing and missing objects is an enumeration finding in
  itself.
- JWT: audit the *handling*, not just the token — alg dispatch, kid/jku
  processing, claim enforcement. Offline inspect first, behavioral
  evidence via replay.
- Sessions prove out on lifecycle events: pre/post pairs around login,
  logout, rotation; fixation = the session id survives login.
- OAuth: `redirect_uri` exact-match probes and code single-use are cheap
  and decisive; missing/unvalidated `state` is CSRF on the callback.
- Rate limiting is an exposure statement from observed configuration —
  never a stuffing demo.
- One context = documented degraded mode; cross-role behavior is never
  inferred.
- Zero-Trust gateway boundaries: audit edge stripping of client `X-User-*`
  headers and verify downstream service enforcement of JWT `aud` scoping.

## Handoffs

Crypto primitives (weak keys, key confusion) -> `35`; redirect chains ->
`55`; code-redemption races -> `58`; IdP/SSO versions -> `70`.

## Tools

`token_swap_replay.py` (guarded; creds via `env:` indirection),
`jwt_inspect.py` (offline), agent_browser for redirect chains. Flaw
trees, zero-trust headers, session checklist and matrix in `references/`.
