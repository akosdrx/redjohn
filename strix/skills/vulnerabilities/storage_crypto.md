---
name: storage_crypto
description: 'Storage crypto: hash identification table + KDF decisions (from cryptographic_failures
  specialist reference library)'
---

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

