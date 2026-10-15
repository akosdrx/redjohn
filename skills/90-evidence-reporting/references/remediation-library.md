# Remediation library (per-class, code-level)

Concise, code-level remediation guidance per vulnerability class, generic
technology only. Start from the class section, then adapt to the engagement
stack; verify version-dependent advice (SameSite defaults, TLS cipher
availability, framework APIs) against the deployed stack before D4. Where a
short-term mitigation and a proper fix both exist, write both, labeled.

## SQL injection (CWE-89 / NoSQL CWE-943 / LDAP CWE-90)

Proper fix — parameterized queries; the driver binds, the SQL text never sees
data:

```
-- vulnerable:  SELECT name FROM invoices WHERE cust = '%s' % cust
-- fixed:       SELECT name FROM invoices WHERE cust = ?
-- bind:        execute(sql, (cust,))
```

ORM binding, same rule (placeholders, never string interpolation):

```
# vulnerable: session.query(Invoice).filter("cust = '%s'" % cust)
# fixed:      session.query(Invoice).filter(Invoice.cust == cust)
```

- Identifiers (column/table names) cannot be bound — use a server-side
  allowlist mapping, never client input.
- `LIKE` user input: bind the value, escape `%`/`_` in the bound value.
- NoSQL: reject operator shapes at the parser boundary (accept scalars only);
  LDAP: encode filter metacharacters with the RFC 4515 escaping routine.
- Short-term: input validation + WAF rule (bypassable; never the fix).

## XSS (CWE-79)

Context-aware output encoding — encode for the context the data lands in:

| Target context | Encoding | Notes |
|---|---|---|
| HTML body / between tags | HTML-entity encode `< > & " '` | Default context |
| HTML attribute (quoted) | HTML-entity encode incl. `"` `'`; attribute must be quoted | Unquoted attributes reject outright |
| JavaScript string literal | JavaScript unicode escapes (`\u003c` style) + encode quotes/newlines; JSON-serialize where possible | Never place raw data in a `<script>` block |
| URL / query parameter | percent-encoding per component (scheme/host/path/query each per spec) | Validate scheme against an allowlist (`http`, `https`) for `href`/`src` |
| CSS (rare) | CSS escapes for non-identifier positions; preferably no user data in CSS at all | `expression()`-class sinks are disallowed |

- Auto-escaping template engines cover the HTML body context only — the table
  above applies the moment data crosses into attributes/scripts/URLs.
- Stored XSS: sanitize on input with an HTML allowlist sanitizer only where
  rich text is a product requirement; otherwise encode on output.
- Add a Content-Security-Policy as defense in depth, not as the fix.

## SSRF (CWE-918)

Allowlist fetch + DNS pinning + metadata blocking:

```
allow_hosts = {"api.partner.example"}          # exact names, config-owned
url = parse(input)
if url.scheme not in ("https",): reject
if url.host not in allow_hosts: reject
addr = resolve_once(url.host)                  # pin: resolve ONE time
if addr is loopback/private/link-local/unique-local: reject
if addr in metadata_ranges: reject             # 169.254.169.254 etc.
fetch(url, connect_to=addr)                    # connect to the resolved IP
```

- Resolve once and connect to that address (DNS rebinding defeats
  resolve-then-check-then-re-resolve).
- Redirects: do not auto-follow; validate each hop against the same rules.
- Block cloud metadata and link-local ranges unconditionally, even behind the
  allowlist.
- Do not render the raw response body to the requester unless the allowlisted
  origin is public anyway.

## CSRF (CWE-352)

Token + SameSite:

- Per-session (or per-request) cryptographically random anti-CSRF token,
  verified server-side on every state-changing request; token never in URLs.
- Cookies: `SameSite=Lax` minimum for session cookies (`Strict` where the
  flow allows), plus `Secure` and `HttpOnly`.
- Where the product is an API consumed by scripts: prefer
  `Authorization: Bearer` headers (not cookies) or double-submit tokens over
  custom header checks alone.
- Verify `Origin`/`Referer` as an additional signal, never as the only one.
- State changes require an explicit method semantics check: no `GET`
  side effects.

## Insecure deserialization (CWE-502)

- Avoid serialized formats (Java/PHP/Python pickle/Node binary) in
  untrusted channels — use JSON with a strict schema.
- If a serialized format is unavoidable: HMAC/integrity-check the blob with a
  server-side key before parsing, restrict to a type allowlist, parse in a
  sandboxed subprocess with no network and a dropped privileges account.
- Never feed signed-but-attacker-influenced structure parsers raw bytes;
  integrity must cover the whole blob.

## Dangerous file upload (CWE-434)

Extension + content validation + storage isolation:

- Extension allowlist by purpose (e.g. `.jpg .png .pdf`), deny-by-default.
- Content validation: check magic bytes AND re-encode (images through a
  real decoder/re-encoder; documents through a sanitizer when available).
- Storage isolation: object store or separate media domain, random
  generated filenames, no execute permissions, served with
  `Content-Disposition: attachment` and a correct `Content-Type`,
  `X-Content-Type-Options: nosniff`.
- Size and rate limits; never keep the user-supplied filename on disk.

## Broken access control (CWE-862/863/639)

Centralized per-object authorization — deny by default, check at the data
layer, not in a route decorator alone:

```
def get_invoice(inv_id, actor):
    inv = db.fetch(Invoice, inv_id)      # 404 on miss
    if actor.tenant_id != inv.tenant_id: # object-level, every object
        deny()                            # 403, logged
    if not policy(actor.role, "invoice:read"):
        deny()
    return inv
```

- One authz module every handler calls; no per-endpoint ad-hoc role checks.
- Prefer non-sequential ids (UUID) but never as the only control —
  authorization is the control, unguessability is hardening.
- Deny-by-default routing: new endpoints require an explicit authz decision.
- Log denials (feeds the detection-coverage table).

## Cryptographic failures (CWE-326/327)

- Password storage: Argon2id (memory >= 19 MiB, 2 iterations, parallelism 1)
  or scrypt (N=2^17, r=8, p=1) or bcrypt (cost >= 12); unique salt per
  password; never MD5/SHA-1/SHA-256-alone for passwords.
- TLS: 1.2+ only (prefer 1.3), forward-secret cipher suites, no RC4/3DES/NULL,
  certificates with RSA >= 2048 or ECDSA >= 256, no SHA-1 signatures.
- Symmetric encryption: AEAD (AES-GCM, ChaCha20-Poly1305) with unique
  nonces; no ECB, no static IVs; random keys from a CSPRNG, rotation
  supported.
- Secrets: no hardcoded keys (CWE-798); secret manager or scoped env
  injection; keys never in logs.

## Headers / CORS (misconfiguration class)

Exact header configurations:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains
Content-Security-Policy: default-src 'self'; object-src 'none';
                         frame-ancestors 'none'; base-uri 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-store          # on authenticated responses
```

- CORS: exact-origin allowlist (`Access-Control-Allow-Origin:
  https://app.example`), never `*` together with
  `Access-Control-Allow-Credentials: true`; validate the `Origin` header
  against the allowlist per request; do not reflect arbitrary origins.
- Cookie attributes: `Secure; HttpOnly; SameSite=Lax` (or `Strict`).
- Remove verbose/framework banners where the platform allows; that is
  hardening, not a fix for anything by itself.

## Race conditions (CWE-362/367)

Locking + idempotency keys:

- Serialize the check-then-act unit: per-key mutex in-process, or
  `SELECT ... FOR UPDATE` / conditional `UPDATE ... WHERE balance >= ?`
  in the database, so the guard and the mutation are one atomic step
  (kills TOCTOU windows on shared rows).
- Idempotency keys for payment/creation endpoints: client supplies a unique
  key; server returns the stored result on replay instead of re-executing.
- Atomic counters only (`DECR`-style guarded updates), never read-modify-write
  in application code on shared state.

## Business logic flaws (state machine / price/flow manipulation)

- State machine validation: explicit states + an allowed-transitions table
  checked server-side on every mutation; reject out-of-table transitions
  with a logged error.

```
transitions = {
  ("created", "paid"): pay_invoice,
  ("paid", "shipped"): ship,
  # no ("created", "shipped"), no return to "created"
}
```

- Server-side price/total recomputation always; client totals are display
  data. Validate quantity signs/ranges against per-role limits.
- One-time consumables (coupons, credits) decrement atomically (see race
  section); re-verification after any external step.

## Logging / monitoring gaps (feeds the detection-coverage table)

- Event coverage: authentication successes/failures, authorization denials,
  input-validation rejections, administrative actions, file upload/download,
  integrity failures — each with actor, object, source IP, timestamp.
- Redaction by design: never log full tokens, passwords, cookies, or PII
  payloads; log token prefixes/ids instead; redact at the serializer, not by
  sweeping logs later.
- Alerting: threshold alerts on auth-failure bursts, authz-denial spikes,
  and canary-pattern hits; alerts reference the runbook entry.
- Log integrity: append-only or shipped off-host; injection-safe encoding of
  logged values (newlines/CRLF stripped) so records cannot be forged.
