---
name: session_checklist
description: Session management checklist (from auth_access_control_matrix specialist
  reference library)
---

# Session management checklist

Capture the full session lifecycle for ONE engagement account, then diff
against policy. All evidence pairs are raw HTTP saved per the P3 harness
(`evidence/p4-session-<step>-<seq>.{req,resp}.txt`); cookies are redacted
before D4 but preserved unredacted in the engagement namespace.

## Lifecycle capture procedure

1. **Anonymous baseline**: GET a protected resource with no credentials ->
   expected 401/302-to-login; record `Set-Cookie` issued pre-login.
2. **Login** (`POST /login` or the OAuth callback): record every
   `Set-Cookie` (names, attributes, values-at-login), tokens issued, and the
   session id pre vs post login.
3. **Authenticated baseline**: same protected resource with the session ->
   200; capture idle-window behavior by replaying after the stated idle cap.
4. **Logout** (`POST /logout`, then GET the protected resource): record
   which artifacts die.
5. **Re-auth / privilege change**: password change and any role elevation ->
   record rotation.
6. **Second concurrent session**: same account, fresh browser context ->
   both alive?

## Cookie attribute matrix

Fill one row per session-bearing cookie (`Set-Cookie` at login AND at first
authenticated request - attributes can differ between the two):

| Cookie | Issued at | HttpOnly | Secure | SameSite | Domain | Path | Max-Age | Prefix | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| `sid` | login | ? | ? | ? | ? | ? | ? | - | |
| `refresh` | login | ? | ? | ? | ? | ? | ? | - | |
| `csrf` | login | (usually intentionally unset) | ? | ? | ? | ? | ? | - | |

Rules for verdicts:

- `HttpOnly` missing on a session secret -> CWE-1004 (XSS theft path).
- `Secure` missing on any cookie set over HTTPS (or set over plain HTTP at
  all) -> CWE-614.
- `SameSite=None` without `Secure` -> automatic finding (rejected by modern
  browsers; on old ones -> CSRF exposure). `SameSite=None; Secure` on a
  session cookie -> record the CSRF surface and coordinate with `55`.
- `Domain=.example.com` breadth beyond the app subdomain -> cookie scoping
  finding (shared across siblings).
- Session cookie without `Max-Age`/`Expires` (browser-session only) ->
  note; the server-side absolute cap matters more (below).
- `__Host-` prefix present but `Secure`/no-Domain/path!=/ violated ->
  prefix misuse finding.

## Logout invalidation (CWE-613 / CWE-384 adjacent)

1. Save the session artifact (cookie/token) BEFORE logout.
2. `POST /logout` (and any client-side `document.cookie` clearing - note it,
   it is not evidence of server invalidation).
3. Replay the protected resource with the PRE-logout artifact.
   - Rejected (401/403) -> server-side invalidation works.
   - Accepted -> server-side invalidation missing: D2 by replaying the
     whole sequence from a fresh login.
4. Repeat for every artifact type: session cookie, access token (if opaque),
   refresh token (try `grant_type=refresh_token` post-logout), OAuth
   session at the AS (does RP logout kill the AS session? front-channel /
   back-channel logout presence).
5. One-device logout vs global logout: logout in session 1, replay session
   2 - record which policy applies and whether it matches the stated one.

## Session fixation (CWE-384)

1. Establish a pre-auth session id (anonymous cookie or `?sid=` parameter).
2. Authenticate WITHIN that session.
3. Post-login cookie identical to pre-login -> fixation: an id planted
   before login survives authentication. D2 via a second fresh run where the
   pre-login id is "planted" (set explicitly in the request).
4. Session id accepted from URL/POST (`?sid=`, `JSESSIONID` in path
   `;/;jsessionid=`) -> fixation vector + leakage into logs/Referer
   (coordinate `85`).

## Rotation on auth events

| Event | Expected | Observed | Verdict |
|---|---|---|---|
| Login | new session id | ? | |
| Password change | all sessions re-issued | ? | |
| Role elevation | session re-issued | ? | |
| Re-login (second device) | independent id | ? | |
| Logout | id invalidated server-side | ? | |

Any auth event that keeps the old id valid -> rotation finding (CWE-384
family); replay old id after the event for the evidence pair.

## Expiry: absolute vs idle

- Idle: replay the session after (stated idle timeout + margin). Still
  accepted -> idle expiry missing/longer than policy.
- Absolute: keep a session "alive" with minimal requests past the stated
  absolute cap. Still accepted -> absolute expiry missing (CWE-613).
- Token pair: access-token TTL vs refresh rotation window; refresh token
  with no absolute cap -> note for the report.

## Concurrent sessions

- Same credentials in two contexts: both alive after login #2? After
  logout #1?
- Account settings show active sessions / last login? (Security-visibility
  observation for the report, not a finding by itself.)

## Token entropy (observe only)

- Length + charset of the session id across >= 5 logins (engagement
  accounts): pattern-free random vs sequential/timestamp-shaped.
- Predictable shapes are a CWE-330 OBSERVATION; claiming predictability
  requires demonstrated prediction (next-id computed and accepted), which
  needs operator sign-off since it forges sessions.

## Username enumeration side of login (pairs with SKILL section 5)

- Status/body/timing diffing between valid-user+wrong-password and
  invalid-user via the `20` harness; record `Retry-After`, `429`,
  lockout counters, and whether lockout is per-account (DoS vector: never
  test against a real user's account - engagement accounts only).

