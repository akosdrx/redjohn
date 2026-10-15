---
name: siem_logging_monitoring_audit
description: Use when the engagement deliverable includes detection coverage - verifying
  which tested actions generated alerts or audit events, probing log injection and
  log forging, and checking whether sensitive data or credentials are written to logs.
---

# Logging and monitoring (woven P4-P7, summarized P8)

Detection coverage as a first-class deliverable: what the defenders saw,
what they didn't, and what leaks into the logs.

## The way

- One canary per action class, never reused — uniqueness is what makes a
  log match unambiguous. The mapping CSV is the tracking artifact, kept
  current as actions run.
- Log access is the operator's, always: excerpts arrive per the
  engagement's data-access rules. Self-granting log access is a scope
  breach, not cleverness.
- Verdicts are detected / partial / missed per action class. Missed +
  critical action (authn events, privilege changes, exports, config
  changes) = an A09 finding.
- Log injection is verified in the excerpt, not assumed: the canary rides
  in the forged segment, so a match proves the bytes survived into the
  log stream. JNDI-shaped markers are detection canaries only — RoE
  approved, paired with `20`'s listener, never chained into payloads.
- Sensitive-data-in-logs is evidence-driven: from `30`/`40` pairs, list
  what transited, classify hits, redact every copy that leaves the
  namespace.
- Detection gaps are findings with gates too — a miss observed once is
  D1.
- Telemetry pipeline integrity: audit proxy IP masking, JSON log truncation
  (4KB/8KB buffer limits), and NTP clock skew before trusting SIEM alert rules.

## Handoffs

OOB canary callbacks -> `20`; the coverage table + gap findings -> `90`;
crypto/masking root causes -> `35`.

## Tools

`canary_gen.py`, `log_canary_scan.py` (both offline). The action-class ->
log-source mapping and table format in `references/`.

---

## Reference Module: `detection-coverage`

# Detection coverage

The mapping table, the procedure, and the output format for the
detection-coverage deliverable.

## 1. Action class -> expected log source mapping table

| Action class | Typical trigger during the engagement | Expected log sources (check in order) |
|---|---|---|
| `auth_success` | canary-suffixed operator account login | auth log (sshd/PAM), app audit trail |
| `auth_failure` | canary-suffixed username on a failed login (bounded) | auth log, app audit trail |
| `auth_lockout` | only if lockout policy engages during approved bounded tests | auth log, app audit trail |
| `privilege_change` | role/token creation when engagement sanctions one | app audit trail, admin platform audit (PVE `/pve/audit` when `82` in play; DB audit when `80` in play) |
| `config_change` | benign config write on a sanctioned target | app audit trail, config-mgmt log |
| `data_export` | canary export/report download with operator account | app audit trail, DB audit |
| `command_exec` | benign `id`/marker proof during `45` work | host audit (auditd/syslog), app audit trail |
| `file_access` | canary-named file read | app audit trail, file-server log |
| `injection_attempt` | P5 probe requests (canary in payload) | WAF log, web access log |
| `session_event` | logout/timeout of a canary session | session store log, web access log |

The table is a template: the operator confirms which sources exist for THIS
target before actions run; a source that does not exist is recorded as "n/a
(operator-confirmed)" not "missed".

## 2. Procedure (per action)

1. Pick the action class and its canary (from `canary_gen.py` output; one
   canary per class per run).
2. Perform the action through the engagement's normal channel (same request
   path a real user would take), embedding the canary in a field the action
   naturally carries.
3. Record UTC timestamp (and the request evidence pair per master rules) at
   execution time in the mapping CSV.
4. Ask the operator for excerpts from every expected source covering
   [timestamp - 2 min, timestamp + 5 min].
5. Scan the excerpts (`log_canary_scan.py --log ... --engagement ... --map
   ...`).
6. Classify: `detected` / `partial` / `missed` (definitions below).
7. D2 pass: re-run the action once (fresh canary nonce, same class) and
   re-verify; a single observation stays D1.

Classification definitions:

- **detected**: canary present in the expected source, line attributable to
  the action (timestamps align).
- **partial**: canary present only in an unexpected source, or only part of
  the action's trail visible (e.g. request logged but no auth-event line),
  or wrong severity/category.
- **missed**: canary absent from all provided excerpts, while the excerpts
  demonstrably cover the window (another, unrelated entry inside the window
  proves coverage).

## 3. Output format (feeds the `90` report section)

```text
detection-coverage |
  action_class=auth_failure | canary=rj-pt-example-eng-0a1b2c3d4e5f |
  timestamp_utc=2026-10-12T10:14:03Z | performed_via=POST /login |
  detected=partial | where_seen=web-access-log:4471 (expected auth log) |
  latency_estimate=~1s (excerpt granularity 1s) |
  gap_assessment=failed logins reach only the access log; no auth-failure
    event emitted to the audit trail
```

Rules: one row per action class per run; `detected` cites source:line; `missed`
rows state which sources were checked and how window coverage was proven;
latency always names the excerpt granularity; A09 linkage stated when the
class is critical (auth/privilege/export) and missed.

## 4. Canary discipline reminders

- Format `rj-pt-<engagement>-<nonce>` (nonce = 12 hex from `canary_gen.py`);
  never reuse a nonce; never embed a second meaning in the marker.
- Canaries are synthetic data — they are the ONLY strings allowed to
  represent "user data" in coverage tests.
- A canary found in an unexpected source is itself evidence (logging pipeline
  surprises) — record it, don't discard it.

## 5. SIEM / IDS / EDR Telemetry Pipeline Failure Modes

Logging an event at the application or edge tier does not guarantee effective
detection or alerting. Three critical telemetry pipeline failure modes
frequently blind security operations teams (SOC) and SIEM/EDR correlation
engines:

### A. Proxy IP Masking & Untrusted Header Forgery
- **Failure Mechanism:** Load balancers, reverse proxies (ALB, Nginx, Envoy,
  Cloudflare, Traefik), and ingress controllers often record their own
  internal loopback or private subnet IP (`10.x.x.x`, `172.16.x.x`, `127.0.0.1`)
  in downstream application audit logs instead of properly extracting the true
  client IP. Conversely, improperly configured edge proxies may blindly forward
  client-supplied `X-Forwarded-For`, `X-Real-IP`, or `Client-IP` headers without
  prepending or sanitizing.
- **Security Impact:**
  1. SIEM IP-reputation, geographic anomaly, and velocity-based brute-force
     rules fail because all actions appear to originate from the internal proxy
     or a spoofed attacker IP.
  2. Threat hunting queries grouping by client IP aggregate unrelated sessions
     together or mask genuine malicious activity behind trusted proxy identities.
- **Verification Procedure:**
  1. Send a request with a benign canary IP in `X-Forwarded-For: 203.0.113.195`
     and `Client-IP: 203.0.113.195`.
  2. Inspect the log excerpts:
     - If the log records `203.0.113.195` as the true client IP without client
       trust verification, the pipeline is vulnerable to IP spoofing.
     - If the log records only the proxy's internal RFC1918 address without
       the client address, proxy IP masking is blinding SIEM correlation.

### B. JSON Log Truncation & Buffer Overflow Drops
- **Failure Mechanism:** Log shippers, aggregation agents, and message brokers
  (Fluentd, Logstash, Vector, Datadog Agent, AWS CloudWatch Logs Agent, Kafka)
  enforce maximum buffer limits (commonly 4KB or 8KB caps per line or event
  payload). When an HTTP request carries long query strings, nested headers,
  serialized objects, or multi-line parameters exceeding this cap, the forwarder
  truncates the event line.
- **Security Impact:**
  1. **Silent Log Ingest Drops:** Truncating a JSON log line leaves it
     syntactically invalid (`{ "event": "probe", "query": "long-str...` missing
     closing delimiters). Strict SIEM ingest pipelines silently drop malformed
     JSON lines, completely concealing the attack from security analysts.
  2. **Canary & Marker Stripping:** If the attack payload or canary is located
     deep in a long URL, body, or header, truncation discards the trailing
     indicators while logging benign initial fields, creating false confidence
     that no malicious pattern occurred.
- **Verification Procedure:**
  1. Generate canary requests with varying payload sizes: 2KB, 4KB, 8KB, and 16KB
     (e.g., padding inside an inert query parameter or custom header).
  2. Review the resulting log excerpts:
     - Note the exact byte threshold where entries are truncated or dropped.
     - Verify whether truncated entries are dropped by the SIEM indexer or
       logged with an explicit truncation indicator flag.

### C. NTP Clock Skew & Distributed Event Desynchronization
- **Failure Mechanism:** In distributed microservice and multi-cloud
  environments, individual virtual machines, containers, or edge points of
  presence (PoPs) frequently suffer from unsynchronized system clocks or NTP
  drift (ranging from hundreds of milliseconds to several seconds or minutes).
- **Security Impact:**
  1. **Correlation Engine Breakage:** SIEM correlation engines rely on strict
     temporal windows (e.g. "Action X followed within 5 seconds by Event Y").
     If the database server clock lags behind the API gateway by 10 seconds,
     the database query is timestamped *before* the API request arrived,
     breaking causal chain correlation rules.
  2. **Replay Detection & Token Evasion:** Replay-prevention algorithms,
     temporary TOTP codes, and token expiry (`exp` / `nbf`) timestamps depend
     on consistent time across all verifying services. Skew allows replay
     windows to be stretched or expired tokens to be accepted.
- **Verification Procedure:**
  1. Compare the HTTP `Date` response header from edge proxies, application
     backends, and auth endpoints against a trusted reference time
     (`pool.ntp.org`).
  2. Inspect timestamps across multi-tier log excerpts for a single canary
     transaction (Gateway -> Auth Service -> Data Store) to verify whether
     event chronological order is preserved.



---

## Reference Module: `log-injection`

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


---

## Reference Module: `sensitive-data-logs`

# Sensitive data in logs

Audit procedure, data classes, and evidence redaction rules for checking
whether sensitive values from tested requests are written to logs.

## 1. Audit procedure

1. **Collect candidate values from evidence** (never new traffic): from
   `30-auth-access-control` and `40-injection-engine` evidence pairs, list
   sensitive values that transited requests to the target:
   - password fields in POST bodies (login, profile change, reset)
   - session cookies / bearer tokens / API tokens in headers
   - password-reset tokens in URLs
   - PII fields (names, emails, phone numbers, account numbers) where the
   engagement defines them
   - secrets observed in `50` exposure findings that also plausibly got
   logged.
2. **Build the check window**: timestamps of those evidence pairs.
3. **Request operator excerpts**: for each expected log source (web access
   log, app audit trail, error/debug logs, DB audit), an excerpt covering the
   window, per the engagement's data-access rules. We never pull logs
   ourselves.
4. **Scan excerpts for the values**: exact-match the specific values (they
   are known strings); classify each hit per data class below.
5. **Findings**: each hit is D1 — "value of class X appears in source Y
   line Z" with a redacted copy for the report; D2 via one replay of the
   same request class (operator account, synthetic canary value where
   possible instead of a real password).
6. **Remediation feed**: masking/omission of body fields, header allow-lists
   for access logs, disabling debug body logging, token redaction in audit
   trails, retention limits.

## 2. Data classes

| Class | Examples | Default severity anchor |
|---|---|---|
| credential (user password) | plaintext password in body echoed to log | high — direct credential exposure |
| credential (reset token) | reset token in URL logged by access log | high |
| session token | session cookie / bearer token in access log | medium-high — session hijack material |
| API token / key | Authorization header, api_key param logged | high |
| PII | names, emails, phone, account ids | per engagement data classification |
| secret material | private keys, internal secrets observed via `50` | high |

Classification discipline: the class is about the VALUE, not the field name
(`X-Internal-Note: <pii>` is still PII). When unsure, ask the operator —
never guess PII status.

## 3. Evidence redaction rules

- Every excerpt copy that leaves the engagement namespace (report, D3
  review, memory) is redacted: matched values replaced with
  `<redacted:<class>-<n>>` keeping line structure and line numbers intact so
  citations stay valid.
- The unredacted original stays in the engagement namespace only, named
  `evidence/p85-logs-<source>-<window>.txt`, provenance header (operator
  who pulled it, source system, pull time).
- Screenshots of log viewers follow the same rule: mask before anything
  leaves the namespace.
- Nothing from these excerpts enters global sharing or memory — lessons
  ("this app family logs bearer tokens") may be proposed as drafts only,
  with values removed, pending independent review (D3).

## 4. Related checks

- Access-log header policy: does the access log record `Authorization` or
  `Cookie` headers at all (ask operator / read app config if provided)?
- Error paths: stack traces in error logs containing request bodies?
- DB audit when `80` is in play: do failed-login audit rows include the
  attempted username (fine) vs any credential-adjacent material (finding)?
- PVE task log when `82` is in play: do task logs echo secrets passed to
  guest-agent commands or API bodies?

