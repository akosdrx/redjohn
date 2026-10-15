---
name: auth_access_control_matrix
description: Use when testing broken access control and authentication - swapping
  tokens or cookies between user contexts to find IDOR/BOLA, auditing JWT algorithms,
  keys and claims, checking session cookie flags, logout invalidation and fixation,
  OAuth/OIDC redirect and code handling, or login and password-reset rate limiting
  and credential-stuffing exposure.
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

---

## Reference Module: `idor-matrix`

# IDOR/BOLA matrix template

The P4 core artifact: one grid per application/API, filled from the P1
surface inventory and replayed with the P0 contexts via
`scripts/token_swap_replay.py`.

## Contexts file shape

`contexts.json` - one entry per P0 auth context; secrets never literal,
always `env:` indirection resolved at runtime from the operator-supplied
environment:

```json
{
  "anon":     { "headers": {}, "cookies": {} },
  "user-a":   { "headers": { "Authorization": "env:REDJOHN_TOKEN_USER_A" },
                "cookies": {} },
  "user-b":   { "headers": {},
                "cookies": { "sid": "env:REDJOHN_COOKIE_USER_B" } },
  "admin":    { "headers": { "Authorization": "env:REDJOHN_TOKEN_ADMIN" },
                "cookies": { "sid": "env:REDJOHN_COOKIE_ADMIN" } }
}
```

Semantics (as implemented by `token_swap_replay.py`):

- `headers` entries replace any same-named header from the raw request.
- If the `cookies` key is present, the `Cookie` header is built exactly from
  it (empty dict -> the request's original `Cookie` header is REMOVED - that
  is how the `anon` arm is produced). If `cookies` is absent, the original
  `Cookie` header passes through unchanged.
- First context in file order is the baseline arm; every later context is
  diffed against it (status, size, body sha256).
- One replay per context, serial, no retries - pace per master rules.

## Matrix template (roles x object x action)

Duplicate this block per object type; object types and id shapes come from
the P1 inventory (`evidence/p1-*` surface listing).

```text
Object type: invoices (/api/v1/invoices/{id})
Owner-context fixture: invoice created by user-a during the engagement
Id source: sequential | UUID | opaque-ticket  (observed from P1)

| Role    | GET {id} (read) | PATCH/PUT (canary modify) | POST (create) | Notes |
|---------|-----------------|---------------------------|---------------|-------|
| anon    | 401 baseline    | 401 baseline              | 401 baseline  | |
| user-a  | 200 (OWNER)     | 200 (owner write)         | 201           | baseline arm |
| user-b  | ?               | ?                         | ?             | same-tenant |
| admin   | ? (policy?)     | ?                         | ?             | cross-tenant |
```

Fill each cell with the observed status + body-hash short id from the swap
run output. Verdict column per row after fresh-token re-run:

- `user-b`/`admin` GET returns 200 with user-a's data -> candidate CWE-639.
- 403 vs 404 differing between existing and absent objects -> CWE-204
  enumeration side-note.
- 200 but sanitized/different body hash -> data-exposure candidate; open
  the first divergent body line before claiming.

## Id-source rules

| Id source | Procedure | Boundary |
|---|---|---|
| Sequential integer | walk user-a's own id +-1, +-2 only | never more than a handful of neighbors; a wider sweep is engagement-authorized fuzzing, not matrix work |
| UUID | swap in user-b's object id (operator-created fixtures) | NEVER enumerate UUID space |
| Opaque ticket/ref | swap two engagement-created refs between contexts | no guessing beyond the two fixtures |

## Fresh-token rules (D2 promotion path)

1. First pass: run the swap with current contexts -> any candidate cell is
   **D1** only.
2. Before D2: re-issue fresh tokens/sessions for EVERY context (operator
   re-login or fresh OAuth code flow), rebuild `contexts.json` env values,
   replay the same matrix rows that flagged.
3. Same result with fresh tokens -> D2 candidate; different result ->
   session artifact (stale token / expiry), log the negative and re-test
   once from a clean browser context.
4. Attach to the finding: both evidence pairs per context, the A/A
   calibration output for that endpoint, and the matrix row id
   (`<object-type>/<role>/<action>`).

## Evidence naming

- Swap runs: `evidence/p4-<object>-<seq>.<context>.{req,resp}.txt`
  (e.g. `evidence/p4-invoices-003.user-b.req.txt`).
- The tool writes pairs per context when `--save evidence/p4-<object>-<seq>`
  is given; baseline context = first label.
- Matrix file itself lives in the run notes namespace
  (`runs/<engagement>/p4-matrix-<app>.md`), never in global sharing.

## Verdict ladder per cell

1. `blocked-403` / `blocked-404` / `auth-401` -> access control holds.
2. `allowed-identical` (200, same hash as owner) -> full IDOR, strongest.
3. `allowed-partial` (200, different hash) -> inspect divergence; may be
   intentional role scoping (admin preview) - check the false-positive
   list before claiming.
4. `error-5xx` -> note; re-run once serial (race/noise), then record.
5. `inconsistent` (differs across fresh-token runs) -> session artifact,
   not a finding.

False-positive shortlist: admin preview features, per-role response
filtering (different fields, same object), caching layers (cache-bust with
`rjpt=<nonce>` on BOTH arms), and A/B flags.


---

## Reference Module: `jwt-flaws`

# JWT flaw tree: algorithms, keys, claims

Offline flaw tree for `scripts/jwt_inspect.py` triage plus the behavioral
tests each flaw needs before it is a finding. All tokens below use
documentation claims only (`iss: issuer.example.oauth`, `aud: app.example`,
`sub: user-a@example.com`) and a dummy key `doc-example-only-hmac-key` that
exists solely so the examples decode; none of them authenticates anything.
Structure: header.payload.signature, base64url, no padding.

## Flaw tree

```text
JWT flaw
├── algorithm
│   ├── alg:none accepted ................ forged-token test (T1)
│   ├── RS->HS key confusion ............. public-key-as-HMAC test (T2)
│   ├── weak HMAC key (HS256/384/512) .... hashcat -m 16500 handoff (35)
│   └── alg not bound to kid/jwk lookup .. mixed-family token (T2b)
├── key lookup
│   ├── kid path traversal ............... ../../../../dev/null (T3)
│   ├── kid SQL injection ................ ' UNION SELECT 'static-key' -- (T3)
│   ├── kid/jku command injection ........ $(id) / backticks (T3, 40 handoff)
│   └── jku/x5u unvalidated URL .......... keys.attacker.example (T4)
├── claims validation
│   ├── exp missing / absurd ............. replay after real expiry (T5)
│   ├── nbf ignored ...................... future-iat token accepted (T5)
│   ├── iss not enforced ................. sibling-app token replay (T6)
│   └── aud not enforced ................. cross-audience replay (T6)
└── trust boundaries
    ├── role/scope/groups honored from token without server lookup (T7)
    └── sub accepted without ownership check ............. -> IDOR matrix (1)
```

## T1 alg:none / case variants

Header `{"alg":"none"}` with an empty signature segment. Test all case
variants (`none`, `None`, `NONE`, `nOnE`) and any `alg` the server lists in
an error message or `WWW-Authenticate` header. CWE-347.

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZS5vYXV0aCIsInN1YiI6ImFkbWluQGV4YW1wbGUuY29tIiwicm9sZSI6ImFkbWluIiwiZXhwIjo0MTAyNDQ0ODAwfQ.
```

Behavioral test: set `sub`/`role` to canary values
(`rj-pt-<engagement>-<nonce>`), send to an in-scope protected endpoint,
save the acceptance/rejection pair. Acceptance = D2 with fresh replay.
Sending forged tokens anywhere outside scope is prohibited.

## T2 HS/RS key confusion

Server verifies RS256 but the library treats the `alg` header as a hint:
re-sign the payload with `HS256` where the HMAC secret is the RSA **public**
key (modulus+exponent bytes from the JWKS at the in-scope
`/.well-known/jwks.json`). Preconditions: asymmetric tokens observed, JWKS
fetchable in scope, operator informed. Evidence: both tokens + acceptance
pair. CWE-347. The crypto primitives (key extraction, HMAC assembly) are a
`35-cryptographic-failures` handoff; `30` owns the claim/impact side.

## T3 kid abuse

`kid` is attacker-controlled input to a key lookup:

- Path traversal `../../../../dev/null` -> empty key material, signature
  verifies against an empty secret (alg-none-equivalent):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uLy4uL2Rldi9udWxsIn0.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZS5vYXV0aCIsImF1ZCI6ImFwcC5leGFtcGxlIiwic3ViIjoidXNlci1hQGV4YW1wbGUuY29tIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoiaW52b2ljZXM6cmVhZCJ9.ucv7FYzasFtz8mlF2JxumaJugepOjiuH-wgeAZFpyVM
```

- SQL injection into the key store:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IicgVU5JT04gU0VMRUNUICdzdGF0aWMta2V5JyAtLSAifQ.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZS5vYXV0aCIsImF1ZCI6ImFwcC5leGFtcGxlIiwic3ViIjoidXNlci1hQGV4YW1wbGUuY29tIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoiaW52b2ljZXM6cmVhZCJ9.c8aEn_6lDVlKjVnRiSPtY-R_4aHUH1wBXqBcw_qhxrY
```

- Command injection (`$(id)`, backticks) -> `40-injection-engine` handoff.

The two tokens above are validly HMAC-signed over their exact headers, so a
naive verifier that ignores `kid` still accepts them - which is itself the
T2b observation (key lookup not bound to algorithm family).

## T4 jku / x5u header injection

`jku` points the verifier at an attacker-chosen JWKS. Off-scope URLs are
never fetched during testing; observe whether the header is honored via an
in-scope canary JWKS URL the operator hosts, or reason from the error
behavior. Example header shape (do not fetch attacker.example during the
engagement):

```text
{"alg":"RS256","typ":"JWT","jku":"https://keys.attacker.example/jwks.json","kid":"attacker-key-1"}
```

## T5 exp / nbf validation

- Missing `exp` (thin token, below) -> flag; if accepted indefinitely, test
  by replaying a legitimately captured token after its stated session cap.
- `exp` present but expired value still accepted -> replay-after-expiry
  evidence pair; CWE-613.
- `nbf`/`iat` in the future accepted -> clock-skew abuse candidate; record
  the accepted skew window from repeated probes (bounded, serial).

Thin token (only `sub`, no `exp`/`iss`/`aud`):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWJAZXhhbXBsZS5jb20ifQ.FV850hBYsQhCUXx3gxBBBB0ZwbJv6f5D80fuM_hstrw
```

Expired-but-validly-signed token (`exp` = 2000-01-01):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZS5vYXV0aCIsImF1ZCI6ImFwcC5leGFtcGxlIiwic3ViIjoidXNlci1hQGV4YW1wbGUuY29tIiwiZXhwIjo5NDY2ODQ4MDB9.Vq1e2wwbmOCu5EJeg6dsCw8qMNG7cl8okgK04i5VFmw
```

## T6 iss / aud enforcement & cross-service scoping

Healthy-shape reference token (correct claims for `app.example`):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZS5vYXV0aCIsImF1ZCI6ImFwcC5leGFtcGxlIiwic3ViIjoidXNlci1hQGV4YW1wbGUuY29tIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoiaW52b2ljZXM6cmVhZCJ9.7MsdOXYPWE6l8I-KPGGBWHlL46NuX6ATQHLjbb012uk
```

Cross-Service Audience (`aud`) Scoping Vulnerabilities:
- In microservice architectures, a central IdP signs tokens for multiple
  distinct services (e.g., `service-read-only`, `service-billing`, `service-admin`).
- Vulnerability: Tokens minted for Service A (e.g., `aud: "service-analytics"`)
  are accepted by Service B (e.g., `aud: "service-payments"`) because Service B
  either omits `aud` validation entirely, permits array match with wildcard
  regex, or validates only signature math.
- Behavioral test:
  1. Authenticate to low-privilege Service A and obtain a valid token
     containing `aud: ["service-a"]`.
  2. Send a benign read-only request to a protected endpoint on high-privilege
     Service B presenting Service A's token.
  3. Acceptance (HTTP 200 / protected data access) proves missing audience
     scoping — cross-service token replay vulnerability (CWE-287 / CWE-639).
- If two in-scope apps share a signing secret (operator-confirmed), re-sign
  the payload with the sibling's `aud` or re-test with mismatched audience;
  acceptance = `aud` claim unenforced. Without a shared-secret arrangement,
  behavioral replay of legitimately minted cross-service tokens is the
  authoritative proof.

## T7 claim trust boundaries

Modify `role`/`scope`/`groups`/`permissions`/`is_admin` in your OWN valid
token (canary values only, re-signed with the same key when the test setup
provides it, or via T1/T2 when not) and observe authorization decisions.
A server that re-checks roles server-side shows no delta; one that trusts
the claim shows the escalation directly - CWE-269 escalation path, evidence
pair per step.

## Weak HMAC key -> cracking handoff (engagement-sanctioned only)

Hand the captured HS256/384/512 token to hashcat mode **16500**
(`hashcat -m 16500 <token> <wordlist> -r <rules>`) inside the assessment
container, ONLY when the engagement authorizes password cracking against its
own tokens. A recovered signing key upgrades every token of that family to
forgeable - report the key via the D3 operator channel, redacted in D4.
Primitives and mode table: `35-cryptographic-failures/references/storage-crypto.md`.

## Safe test payloads summary

| Test | Payload family | Boundary |
|---|---|---|
| T1 | alg:none + canary role | in-scope endpoints only, serial |
| T2 | HS256 signed with RSA public key | JWKS fetch in scope, operator informed |
| T3 | kid traversal/SQLi/cmdi strings | no bulk fuzzing; one variant class per run |
| T4 | jku to canary in-scope URL | never fetch out-of-scope hosts |
| T5 | expired/thin own tokens | replay windows bounded by stated policy |
| T6 | sibling-aud re-sign | only with operator-confirmed shared secret |
| T7 | canary claim values | never another user's identity |

All findings keep the evidence pair (token + request + response) under
`evidence/p4-jwt-<seq>.{req,resp}.txt`; redact tokens before D4.


---

## Reference Module: `oauth-oidc-attacks`

# OAuth / OIDC attack tree per flow step

Request sketches use documentation parties only: authorization server
`issuer.example.oauth`, client `app.example`, attacker-controlled stand-in
`attacker.example` (never contacted during the engagement; it appears only
in payloads the target may act on). Every request goes through the P3
harness with the scope guard; the AS/client pair must both be in scope.

## Flow skeleton (authorization code + PKCE)

```text
1. GET  https://issuer.example.oauth/authorize
       ?client_id=app-client-id
       &response_type=code
       &redirect_uri=https://app.example/callback
       &scope=openid+profile
       &state=<random>
       &code_challenge=<S256(verifier)>
       &code_challenge_method=S256
2. 302  Location: https://app.example/callback?code=<code>&state=<state>
3. POST https://issuer.example.oauth/token
       grant_type=authorization_code&code=<code>
       &redirect_uri=https://app.example/callback&client_id=app-client-id
       (&client_secret=... confidential / &code_verifier=... public)
4. GET  https://api.example.com/v1/... Authorization: Bearer <access_token>
```

## Step 1: authorization endpoint

### redirect_uri exact-match tests (one per replay, A/A calibrated)

| Probe | Sketch | Signal |
|---|---|---|
| Trailing dot | `redirect_uri=https://app.example./callback` | 200/302 with code = weak matching |
| Suffix host | `redirect_uri=https://app.example.attacker.example/cb` | code issued to attacker host |
| Path extension | `redirect_uri=https://app.example/callback/../open` | open-redirect style bypass |
| Scheme swap | `redirect_uri=http://app.example/callback` | scheme not pinned to https |
| userinfo confusion | `redirect_uri=https://issuer.example.oauth@app.example/cb` | parser differential |
| Encoding | `%2F`, `%2E%2E`, double-encoded variants | normalization differential |

Accepted off-path `redirect_uri` = code interception candidate (pair with
the `55` open-redirect chain). CWE-601 adjacent.

### state presence/validation

- No `state` parameter generated by the client -> callback CSRF possible
  (login CSRF / session fixation vector).
- Present but unvalidated: complete the callback yourself with a stripped or
  swapped `state` (`https://app.example/callback?code=<own-code>&state=WRONG`)
  using only your own engagement account codes. Acceptance = CWE-352.

### PKCE presence (public clients)

- SPA/native client sending no `code_challenge` -> exposure; record it.
- Downgrade: send `code_challenge_method=plain` where S256 was observed;
  acceptance of plain downgrade = weaker binding, note for report.

## Step 2: callback

- Open-redirect chain into code interception: does the client 302 through a
  `next`/`returnTo`/`continue` parameter before consuming the code?
  `https://app.example/callback?code=...&next=https://attacker.example/`
  - the code then travels to the redirect target if the app forwards the
  query. Coordinate the primitive itself with `55`.
- Fragment handling for implicit/hybrid: token in `Location: ...#access_token=`
  -> check Referer policy (`Referrer-Policy` header) and any `postMessage`
  handoff with `targetOrigin: "*"`.
- Error branch: `error=access_denied` callback without `state` echo ->
  unvalidated-state confirmation.

## Step 3: token endpoint

### Authorization code reuse (CWE-294)

```text
POST /token  grant_type=authorization_code&code=<same-code>&redirect_uri=...
             &client_id=... (repeat the exact step-3 request)
```

Second redemption MUST fail (`invalid_grant`). A 200 with a new token pair =
code reuse; replay once more from a clean session for D2. Also test:
code expiry (redeem after stated TTL), code bound to `redirect_uri` (change
it on redemption), code bound to `client_id` (redeem from the other in-scope
client).

### Other grants

- `grant_type=refresh_token` with a rotated-away refresh token -> old must
  be revoked; refresh-token rotation must invalidate the predecessor
  (replay the predecessor once).
- Scope escalation at redemption: request `scope=admin` on the token
  request though the code was issued for `openid profile` -> must be clamped.
- Client confusion: confidential client's secret used by the public client
  id (if the operator supplies both), PKCE bypass by omitting
  `code_verifier` on redemption.

## Step 4: protected-resource handling

- Audience: redeem for `app.example`, present the access token to the
  sibling in-scope API -> cross-audience acceptance (CWE-347 adjacent).
- `iss` claim vs expected issuer id mismatch ignored by the resource server.
- Token in `Authorization` header vs query param (`?access_token=`) -
  query-param transport is a leakage finding on its own (CWE-598, hand to
  `35` secrets-in-transit checklist).

## Implicit / hybrid flows

`response_type=token` (implicit) or `id_token token` (hybrid):
- Access token in URL fragment -> browser history, extensions, Referer
  leakage; hybrid leaks both code and tokens.
- Record as exposure with the exact `Location` header evidence; the modern
  baseline is code + PKCE, so implicit in production is reportable on its
  own merits (with vendor/version notes for `70`).

## Evidence expectations

- Full transcript per test case: authorize request, redirect response,
  callback, token exchange, replay attempt - named
  `evidence/p4-oauth-<case>-<seq>.{req,resp}.txt`.
- Both arms for every differential (tampered vs clean `redirect_uri`,
  stripped vs valid `state`, first vs second code redemption).
- Never contact `attacker.example`; it exists in payloads only. Canary codes
  use engagement accounts only.

## Handoffs

- Open-redirect primitive -> `55-client-side-attacks`.
- Code-redemption races (parallel redemption) -> `58-logic-concurrency`.
- IdP/SSO product fingerprints -> `70-exploit-intel`.
- Query-param token transport -> `35` secrets-in-transit checklist.


---

## Reference Module: `session-checklist`

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


---

## Reference Module: `zero-trust-gateway-headers`

# Zero-Trust Gateway Header Stripping & Downstream Identity Forgery

Architectural guide and non-destructive verification procedures for Zero-Trust
reverse proxy edge gateways and downstream microservice identity trust boundaries.

## 1. Threat Model & Architecture

In modern microservice architectures, an edge API Gateway (Kong, Envoy, Nginx,
Traefik, AWS API Gateway, Apigee) acts as the single public-facing entry point.
The gateway terminates TLS, authenticates the client (validates session cookies,
mTLS, or OAuth access tokens), and injects trusted identity headers before
forwarding the request upstream:

```text
[ Client ] 
    │ (Public Internet)
    ▼
[ Edge API Gateway ] ──── Strips incoming X-User-* ────► Injects verified context:
    │                                                    • X-User-Id: 1042
    │ (Internal VPC / Service Mesh)                      • X-User-Role: user
    ▼                                                    • X-Authenticated-User: alice
[ Upstream Microservice ] ◄── Trusts X-User-* headers blindly
```

### The Vulnerability: Missing Ingress Header Sanitization
If the edge reverse proxy or gateway fails to sanitize, overwrite, or strip
client-supplied `X-User-*` headers, an external untrusted attacker can inject
arbitrary identity and authorization claims:
- `X-User-Id`: Impersonate any user ID (BOLA / IDOR bypass).
- `X-User-Role` / `X-User-Roles`: Escalate privileges to `admin`, `system`, or `internal`.
- `X-Authenticated-User` / `X-User-Email`: Override the downstream user principal.
- `X-Tenant-Id` / `X-Org-Id`: Break cross-tenant multi-tenancy isolation.

Because upstream microservices treat the internal network as a trusted perimeter
and do not re-verify credentials, the injected header values take immediate
effect.

## 2. Typical Vulnerable Header Conventions

| Header Name | Typical Purpose in Microservices | Exploitation Impact |
|---|---|---|
| `X-User-Id` | Database foreign key / user entity identifier | Direct IDOR / Horizontal privilege escalation |
| `X-User-Role`, `X-User-Roles` | Comma-separated RBAC roles (`admin`, `support`) | Vertical privilege escalation |
| `X-Authenticated-User` | Username or email of authenticated subject | Account impersonation in audit logs / actions |
| `X-Tenant-Id`, `X-Account-Id` | Multi-tenant organization partition key | Cross-tenant data exfiltration / breach |
| `X-Auth-Scope` | OAuth scope list granted to token | Scope expansion / unauthorized API calls |

## 3. Non-Destructive Verification Procedure

All tests must be conducted non-destructively using operator-sanctioned canary
identifiers:

### Step 1: Capture Baseline Negative Control
Send a request to a protected endpoint without any custom identity headers:
```bash
curl -s -i "https://target.example/api/v1/profile" \
  -H "Authorization: Bearer <low-priv-token>"
```
Observe the returned `user_id`, `role`, or status (e.g. `{"user_id": 1042, "role": "member"}`).

### Step 2: Inject Benign Canary Identity Headers
Re-send the request injecting distinct, observable canary values:
```bash
curl -s -i "https://target.example/api/v1/profile" \
  -H "Authorization: Bearer <low-priv-token>" \
  -H "X-User-Id: rj-pt-canary-999999" \
  -H "X-User-Role: rj-pt-canary-admin" \
  -H "X-Authenticated-User: canary-admin@example.com"
```

### Step 3: Test Unauthenticated Header Injection
Send the same canary headers to an internal or protected route without any
`Authorization` header or session cookie:
```bash
curl -s -i "https://target.example/api/v1/admin/status" \
  -H "X-User-Id: 1" \
  -H "X-User-Role: admin"
```

### Step 4: Differential Analysis & Gate Check
Compare Step 1, Step 2, and Step 3 responses:
1. **Positive Verdict (Vulnerability Proven):**
   - The response in Step 2 reflects the injected canary user ID or grants
     admin functionality.
   - The response in Step 3 returns `200 OK` or privileged data instead of
     `401 Unauthorized` / `403 Forbidden`.
2. **False Positive Guard (Layer-Ordering Trap):**
   - If the endpoint returns `400 Bad Request` or `422 Unprocessable Entity`
     citing "Unknown header" or schema validation error, do NOT claim auth
     bypass.
   - Verify that the response is not a generic header reflection (e.g. debug
     page echoing all received headers without semantic processing).

## 4. Remediation & Zero-Trust Best Practices

1. **Unconditional Edge Ingress Stripping:**
   Configure the edge reverse proxy / API gateway to strip all `X-User-*`,
   `X-Tenant-*`, and internal routing headers from incoming client requests
   *before* any routing or plugin processing:
   - Nginx: `proxy_set_header X-User-Id "";`
   - Envoy: Use `request_headers_to_remove: ["x-user-id", "x-user-role", "x-authenticated-user"]`
   - Kong: Enable `pre-function` or header transformation plugins on all public routes.
2. **Cryptographic Identity Propagation (Zero-Trust):**
   Do not pass raw unauthenticated HTTP headers between services. Instead, the
   gateway should issue a short-lived (e.g. 30–60 second) asymmetric internal JWT
   signed by the gateway's private key and verified by upstream microservices via
   JWKS. Upstream services must validate signature, `exp`, and `aud`.
3. **Mutual TLS (mTLS):**
   Enforce mTLS between the gateway and upstream services to prevent lateral
   movement from bypassing the edge gateway.

