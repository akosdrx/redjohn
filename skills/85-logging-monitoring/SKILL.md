---
name: 85-logging-monitoring
description: Use when the engagement deliverable includes detection coverage - verifying which tested actions generated alerts or audit events, probing log injection and log forging, and checking whether sensitive data or credentials are written to logs.
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
