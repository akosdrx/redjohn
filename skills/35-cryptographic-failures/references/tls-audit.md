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
