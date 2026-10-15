---
name: sensitive_data_logs
description: Sensitive data in logs (from siem_logging_monitoring_audit specialist
  reference library)
---

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

