---
name: auth
description: Identity, session, and object-access traps. Prove a broken decision with two principals, not with a missing header.
---

# Auth

You are looking for a decision the server gets wrong. A login form existing is not a finding. Show two principals, the request each sent, and the different outcome.

## Decisions that fail in practice

**Object access.** Change the id the server uses, not the one the UI shows. It is often in the body, a GraphQL argument, or a nested field. Horizontal access is user A reading user B. Vertical access is a role the route never checks. A 403 on the UI route and a 200 on the API alias is the usual split. Function-level checks on `GET` and missing checks on `PUT`/`DELETE` are the same bug.

**JWT.** `alg: none`, RS256 verified as HS256 with the public key, a `kid` or `jku` you control, and a token accepted after logout or after `exp`. A decoded payload is not a bypass. The server has to accept the forged token on a real route.

**OAuth / OIDC.** `redirect_uri` matched by prefix, path traversal, or an open redirect on the same host. Missing `state`. A code reused, or an implicit token landing in a `Referer` or a web log. The authorization code in your browser is not theft until you show it delivered to an attacker-controlled location.

**MFA and step-up.** The check lives on one request and the sensitive action has a second request that never sees it. A code that still works after use, a step you can skip by calling the later endpoint, or a "remember this device" cookie minted before the second factor.

**Session.** Fixation: the id is the same before and after login. The cookie is not rotated, not scoped, or still valid after password change and logout. Guessing is not the test; reuse across the boundary is.

**Trusted headers.** `X-Forwarded-User`, `X-Remote-User`, and similar identity headers are only as strong as the proxy that strips them. If the app is reachable without that proxy, sending the header yourself is the test.

## Proof bar

Name the principal you started as, the principal you became or the object you touched, and the response that shows it. Account enumeration, a verbose login error, and a missing `Secure` flag stay low unless you show the impact they enable.
