---
name: 35-cryptographic-failures
description: Use when auditing TLS versions and cipher suites, weak or unsigned certificates, broken password hashing and storage encryption (MD5/SHA-1, ECB mode, static IVs), padding oracles, and sensitive data transmitted or stored without proper encryption.
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
