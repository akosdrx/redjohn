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
