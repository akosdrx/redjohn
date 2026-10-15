---
name: cryptographic_failures
description: Use when auditing TLS versions and cipher suites, weak or unsigned certificates,
  broken password hashing and storage encryption (MD5/SHA-1, ECB mode, static IVs),
  padding oracles, and sensitive data transmitted or stored without proper encryption.
---

# Cryptographic failures (P2 baseline + storage audit)

Transport posture (TLS, ciphers, certificates) and storage/processing
primitives (hash formats, KDFs, modes, oracles, secrets in transit).

## The way

- The TLS baseline is read-only and cheap: two handshakes per host, serial,
  negotiated params + cert walk saved verbatim with the tool version
  recorded. Thresholds are judgment calls against the tables in
  `references/`; the evidence is the transcript.
- Hash format before any claim — and *where* it was observed; a bare hash
  is not evidence. Fast unsalted hashes protecting passwords are a finding
  from the format alone; KDFs are judged by their cost parameters, not
  their names.
- ECB/static-IV proofs use engagement-created fixtures only: two
  encryptions of the same controlled plaintext. Never real user data.
- Padding oracles: bounded budget, canary plaintext only, stop at the
  discriminator. Demonstrating the discriminator IS the finding;
  decrypting real data never is.
- Cracking (weak JWT keys included) is engagement-sanctioned only;
  recovered material moves through the operator channel, never into
  evidence files.
- Secrets in URLs and plain-HTTP bodies are findings in their own right —
  and feed `85`'s log-side audit.

## Handoffs

JWT primitives <-> `30`; stack fingerprints -> `70`; secrets-in-logs ->
`85`; TLS findings -> `90`.

## Tools

`tls_probe.py` (guarded), `hash_identify.py` (offline); openssl cookbook,
hash/KDF tables and oracle safety rules in `references/`.

---

## Reference Module: `padding-oracle`

# Padding oracles: detection heuristics, bounded-query safety, when to stop

A padding oracle is an observable difference between "padding was invalid"
and "padding was valid but the content/format failed" when the server
decrypts attacker-modified ciphertext (CBC-encrypted cookie, token, or
parameter). The engagement deliverable is the DISCRIMINATOR, never bulk
decryption.

## Detection heuristics

### 1. Distinct error classes (decrypt-error vs format-error)

Tamper only the LAST ciphertext block (flip bits in the final block, or
drop/append a full block) on an encrypted artifact you own
(engagement-created session/cookie), and compare response classes:

| Signal dimension | Padding-invalid branch | Padding/format-valid branch | Read as |
|---|---|---|---|
| Status code | 500 vs 400/302 mix | distinct pairing = oracle candidate |
| Error body class | "crypto/padding" wording vs "bad format / session reset" | wording classes differ = oracle candidate |
| Redirect target | error page vs re-issue flow | branch divergence |
| Response size / body hash | two tight clusters | bimodal = candidate |

Use the `20` response-diff harness: A/A calibrate the untampered request
first, then tamper one block per request, one variable at a time.

### 2. Timing dichotomy

Padding-valid paths often continue to parsing (slower); padding-invalid
paths abort early. Protocol:

1. N >= 5 interleaved samples per arm (tampered-last-block arm vs
   untampered arm), discard first sample, compare medians (master timing
   protocol; `20` harness).
2. Median delta must exceed observed spread (> 2x larger spread) to count.
3. A single-shot delay is never an oracle.

### 3. Where to look

CBC-encrypted: session cookies, remember-me tokens, password-reset
tokens, encrypted email/username parameters, some SSO tickets, older
framework crypto (ASP.NET ViewState-style padding behavior class, legacy
Java crypto stacks). Version-fingerprint the stack -> `70`; several
padding-oracle classes are CVE-mapped (Lucky13-class TLS CBC, POODLE-class
SSLv3, framework-specific oracle CVEs) - CVE claims need version proof +
advisory citation per library rules.

## SAFE confirmation limits (binding)

1. **Query budget**: <= 256 oracle queries per endpoint per engagement by
   default (enough to demonstrate a stable discriminator on synthetic
   canary values). Log every query: probe id, request file, outcome class,
   running count.
2. **Synthetic plaintext only**: decrypt solely values the engagement
   created (`rj-pt-<engagement>-<nonce>` canary plaintexts). NEVER decrypt
   real user data, other users' cookies, or bulk records. "It could
   decrypt the whole table" is written as the impact statement; doing it
   is out of default scope and needs written authorization.
3. **No decryption dumps**: even on canary values, keep the minimal
   transcript that shows discriminator correctness (a handful of
   block-queries documented, not an automated decryptor run).
4. **Rate discipline**: serial requests; if the endpoint rate-limits,
   throttles, or alarms, STOP immediately and record the reaction (that
   observation itself goes to `85` detection-coverage notes).
5. **Modification boundary**: only artifacts owned by engagement
   accounts; never replay modified ciphertext that carries another
   session's privileges.

## Confirmation procedure (bounded)

1. Own the plaintext: create the encrypted artifact from a known canary
   plaintext via the application's own flow (register with canary value).
2. Baseline: untampered artifact -> expected success class (A/A twice).
3. Tamper last block (one byte flip) x3 -> record outcome class per try.
4. If classes split: tamper second-to-last block / interblock byte to
   confirm the discriminator tracks padding structure, <= 20 more queries.
5. Demonstrate ONE padding-valid event on the canary (e.g. recovered
   intermediate byte written to the run notes) - this is the D2 evidence.
6. Stop. Write the finding: oracle present, discriminator described,
   canary demonstration, query count, impact stated as capability
   (CWE-327 + CWE-204/CWE-208), stack fingerprint attached.

## When to stop (all binding)

| Situation | Action |
|---|---|
| Discriminator demonstrated on canary | stop querying; write D2 finding |
| 256-query budget exhausted, no split | record negative; dead-end rule; move on |
| A/A noise exceeds inter-class distance | endpoint unsuitable; note and stop |
| Endpoint rate-limits/alarms mid-run | stop immediately; note detection coverage |
| Only real-user data available as target | do not proceed; report the structural exposure as D1 observation |
| Operator asks for full decryption | requires written authorization + revised budget; otherwise refuse |

## Evidence expectations

- The query-budget log (per-probe id, request/response class, running
  count) - the count is part of the finding.
- The canary demonstration transcript (artifact creation + the successful
  padding-valid query).
- Baseline A/A calibration output.
- Stack fingerprint for the CVE correlation handoff to `70`.


---

## Reference Module: `storage-crypto`

# Storage crypto: hash identification table + KDF decisions

Input to `scripts/hash_identify.py` triage and the report's storage findings.
All examples are synthetic shapes (well-known digest-of-empty or dummy
strings) - never engagement material.

## Identification table (length / charset / markers)

| Format | Shape | Length | Charset / marker | Salted | Speed class |
|---|---|---|---|---|---|
| MD5 | raw hex | 32 | `[0-9a-f]` (upper variant exists) | no | fast |
| NTLM | raw hex | 32 | `[0-9a-f]` - same shape as MD5 | no (user as salt input) | fast |
| MySQL pre-4.1 | raw hex | 16 | `[0-9a-f]`-ish | no | fast |
| Oracle 10/11 (DES-based) | hex | 16 | often uppercase hex + username salt | partial | fast |
| SHA-1 | raw hex | 40 | `[0-9a-f]` | no | fast |
| RIPEMD-160 | raw hex | 40 | `[0-9a-f]` - ambiguous with SHA-1 | no | fast |
| MySQL 4.1/5.x | `*HEX` | 41 | `*` + 40 `[0-9A-F]` = SHA1(SHA1(pw)) | no | fast |
| SHA-256 | raw hex | 64 | `[0-9a-f]` | no | fast |
| SHA-384 | raw hex | 96 | `[0-9a-f]` | no | fast |
| SHA-512 | raw hex | 128 | `[0-9a-f]` | no | fast |
| MD5 (PostgreSQL) | `md5` + hex | 35 | literal `md5` prefix + 32 hex (md5(pw+user)) | username | fast |
| md5crypt ($1$) | `$1$salt$...` | ~34 | `$1$` + 8-char salt + 22 b64 | yes | slow-ish (1000 iters) |
| APR1 (Apache) | `$apr1$salt$...` | ~37 | `$apr1$` marker | yes | slow-ish |
| sha256crypt | `$5$salt$...` | ~63 | `$5$` marker | yes | KDF |
| sha512crypt | `$6$salt$...` | ~106 | `$6$` marker (+rounds=) | yes | KDF |
| bcrypt | `$2a/$2b/$2y$NN$...` | 60 | `$2[aby]$` + 2-digit cost + 22+31 b64 | yes | KDF (cost-scaled) |
| argon2i/d/id | `$argon2XX$v=19$m=...,t=...,p=...$salt$hash` | ~95+ | `$argon2` marker + params | yes | KDF (memory-hard) |
| django legacy | `md5$salt$hash` / `sha1$salt$hash` | varies | algorithm marker + salt + hex | yes | fast per-iteration |
| django modern | `pbkdf2_sha256$<iter>$salt$hash` | varies | marker + iteration count | yes | KDF (iter-scaled) |
| MSSQL 2000 | `0x0100...` | ~94 hex | `0x0100` prefix | yes | fast |
| MSSQL 2012/2014 | `0x0200...` | ~142 hex | `0x0200` prefix | yes | KDF (PBKDF2) |
| LDAP {SSHA} | `{SSHA}b64` | varies | `{SSHA}`/`{SHA}`/`{CRYPT}` prefix | SSHA yes | SHA-1 fast / CRYPT varies |

Ambiguity rules the script applies (and reports):

- 32 hex -> MD5 **or** NTLM (context decides: Windows capture -> NTLM);
  also truncated-SHA-256 candidates exist.
- 16 hex -> MySQL pre-4.1 or Oracle (charset/case hint only).
- 40 hex -> SHA-1 or RIPEMD-160.
- Uppercase hex with `*` prefix -> MySQL 5.x specifically.

## KDF decision notes

| Observed storage | Verdict | Report language |
|---|---|---|
| Raw MD5/SHA-1/SHA-256 for passwords | CWE-916 finding from format alone | "passwords stored with fast unsalted hash; offline cracking trivial at scale" |
| Salted but fast (django md5$, $1$) | CWE-916 variant | "salted but computationally cheap; upgrade to memory-hard KDF" |
| bcrypt cost >= 10 / pbkdf2 >= 100k iter (2020s baseline) / argon2id sane params | pass | parameters quoted verbatim in the coverage statement |
| bcrypt cost < 5, pbkdf2 < 10k iterations | finding | "KDF present but cost below current baseline" - quote observed params |
| ECB-detected ciphertext (see SKILL section 2) | CWE-327 | never for passwords/PII; deterministic blocks are the proof |
| Static/reused IV CBC | CWE-329 | identical plaintext -> identical ciphertext evidence pairs |
| Secret stored/base64'd, not encrypted | CWE-311 adjacent | "encoding is not encryption" |

Always record the observed cost parameters (bcrypt NN, pbkdf2 iterations,
argon2 m/t/p) - "bcrypt" without the cost says nothing.

## hashcat mode table (engagement-sanctioned cracking only)

Run inside the assessment container with pinned versions; authorization
note attached to the run; recovered material leaves only through the D3
operator channel, redacted in D4.

| Format | Mode |
|---|---|
| MD5 | 0 |
| SHA-1 | 100 |
| SHA-256 | 1400 |
| SHA-512 | 1700 |
| NTLM | 1000 |
| MySQL pre-4.1 | 200 |
| MySQL 4.1/5.x | 300 |
| md5crypt | 500 |
| sha512crypt | 1800 |
| APR1 | 1600 |
| sha256crypt | 7400 |
| bcrypt | 3200 |
| MSSQL 2012 | 1731 |
| django PBKDF2-SHA256 | 10000 |
| JWT HS256/384/512 | 16500 |
| argon2 | no hashcat support - note it and stop |

Handoff shape (to `30` for JWT, to `90` for storage findings): token/hash
family + authorization note + mode + output redacted; no plaintext in
evidence files.

## ECB / IV evidence procedure (fixtures only)

1. Create two engagement fixtures with IDENTICAL plaintext (e.g. same
   profile field value on two operator-created accounts).
2. Capture both ciphertexts (cookie, response field, DB excerpt provided
   by the operator).
3. Identical ciphertext -> ECB or static key+IV; then align 16-byte blocks
   across two plaintexts that differ in exactly one block region to
   separate ECB (block-level determinism) from static-IV CBC (only first
   block identical for same-prefix plaintexts).
4. Predictable-IV check: IVs across three captures increment like
   counters or timestamps -> CWE-329 note with the three IVs as evidence.


---

## Reference Module: `tls-audit`

# TLS audit: openssl command cookbook + interpretation

All commands run inside the RedJohn assessment container against in-scope
hosts only (documentation hosts shown). Record the openssl version with
every result (`openssl version`); output shapes differ slightly between
releases. Serial pace: one host at a time.

## Command cookbook

### 1. Negotiated baseline (what a modern client gets)

```sh
openssl s_client -connect target.example.com:443 -servername target.example.com </dev/null
```

Read: `Protocol : TLSv1.2/1.3`, `Cipher : ECDHE-RSA-AES256-GCM-SHA384`,
`Server certificate` block, `Verify return code`.

### 2. Old-version acceptance (is TLS 1.0/1.1 still enabled?)

```sh
openssl s_client -connect target.example.com:443 -tls1  </dev/null   # TLS 1.0
openssl s_client -connect target.example.com:443 -tls1_1 </dev/null  # TLS 1.1
openssl s_client -connect target.example.com:443 -tls1_2 </dev/null  # floor check
```

Modern OpenSSL builds may refuse to *propose* old versions locally
("no ciphers available"); in that case the acceptance question goes to
testssl.sh or an nmap `ssl-enum-ciphers` run - record which tool answered.

### 3. Weak cipher acceptance

```sh
openssl s_client -connect target.example.com:443 -cipher 'RC4-SHA'        </dev/null
openssl s_client -connect target.example.com:443 -cipher 'DES-CBC3-SHA'   </dev/null
openssl s_client -connect target.example.com:443 -cipher 'aNULL'          </dev/null
openssl s_client -connect target.example.com:443 -cipher 'NULL'           </dev/null
openssl s_client -connect target.example.com:443 -cipher 'EXP'            </dev/null
```

A successful handshake on any of these = the suite is enabled. (RC4/3DES/
EXP ciphers must usually be re-enabled client-side in current OpenSSL; a
local "no ciphers available" error is a client limitation, not a pass
result - say so in the notes.)

### 4. Renegotiation + compression

```sh
openssl s_client -connect target.example.com:443 -reconnect </dev/null
```

Six connections; compare the renegotiation block across connections.
`Secure Renegotiation IS supported` vs `NOT supported` is the verdict line.
TLS compression: `Compression: NONE` expected; `Compression: zlib/deflate`
= CRIME-class exposure (record as CWE-327-family). Python-stdlib probing
cannot see renegotiation - this command or testssl.sh is the source.

### 5. Certificate detail (saved cert)

```sh
openssl s_client -connect target.example.com:443 -servername target.example.com </dev/null 2>/dev/null | sed -n '/BEGIN CERT/,/END CERT/p' > cert.pem
openssl x509 -in cert.pem -noout -text
openssl x509 -in cert.pem -noout -dates -subject -issuer -ext subjectAltName
```

Read: `Signature Algorithm` (SHA-1/MD5 = CWE-328), `Public-Key` (RSA
< 2048 = CWE-326), `Not After` (expired = CWE-295 family), `Subject
Alternative Name` coverage of the requested hostname, issuer == subject
(self-signed) or unknown-CA chain in production.

### 6. Chain and hostname verification verdicts

```sh
openssl s_client -connect target.example.com:443 -servername target.example.com -CApath /etc/ssl/certs </dev/null
```

`Verify return code: 0 (ok)` vs `18 (self signed certificate)` /
`19 (self-signed certificate in certificate chain)` /
`20 (unable to get local issuer certificate)` /
`10 (certificate has expired)` / `62 (hostname mismatch)` -
map directly to the tls_probe.py verification verdicts.

## Interpretation table

| Observation | Threshold / verdict | CWE |
|---|---|---|
| Negotiated or accepted TLS 1.0/1.1 | finding: legacy protocol accepted | CWE-326/327 |
| RC4, 3DES/DES, NULL, EXP, aNULL suite accepted | finding: weak/broken suite | CWE-327 |
| Insecure renegotiation accepted | finding: CVE-era class; fingerprint stack -> `70` | CWE-327 |
| TLS compression enabled | finding: CRIME class | CWE-327 |
| RSA/DSA cert key < 2048 bits | finding: inadequate key size | CWE-326 |
| SHA-1 or MD5 cert signature | finding: weak signature (note issuer-side too) | CWE-328 |
| `notAfter` in the past | finding: expired cert in production | CWE-295 |
| Hostname not in SAN/CN | finding: hostname mismatch | CWE-295 |
| Self-signed / unknown CA in production | finding unless engagement says lab fixture | CWE-295 |
| Wildcard SAN breadth (`*.example.com` on a single-app host) | note: scoping observation | - |

## tls_probe.py vs openssl vs testssl.sh

| Question | Answered by |
|---|---|
| What does a default client negotiate (version/cipher/cert)? | `tls_probe.py` (scripted, evidence path) or command 1 |
| Are old versions/ciphers still accepted? | commands 2-3, or testssl.sh full matrix |
| Renegotiation / compression? | command 4 or testssl.sh (stdlib cannot see it) |
| Full per-version suite enumeration? | testssl.sh / `nmap --script ssl-enum-ciphers` |
| Verification verdict + cert fields in one pass? | `tls_probe.py` (also commands 5-6) |

## Evidence expectations

- One `tls_probe.py` output block per host:port (`evidence/p2-tls-<host>-<seq>.txt`).
- For each threshold finding: the openssl transcript (or testssl.sh section)
  that supports it, plus tool + version line.
- Renegotiation claims: the full `-reconnect` transcript (six connections).
- Negative results (host clean on all thresholds) go to the coverage
  statement with the same output shape - they are report content too.

