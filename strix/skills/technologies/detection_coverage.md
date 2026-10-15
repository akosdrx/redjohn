---
name: detection_coverage
description: Detection coverage (from siem_logging_monitoring_audit specialist reference
  library)
---

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


