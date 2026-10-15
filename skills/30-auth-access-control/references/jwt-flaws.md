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
