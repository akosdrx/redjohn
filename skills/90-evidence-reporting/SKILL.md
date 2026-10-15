---
name: 90-evidence-reporting
description: Use when verified findings must become deliverables - rendering minimal reproducible PoCs as curl commands or raw HTTP, writing code-level remediation per vulnerability class, locking CWE and CVSS classification, deduplicating findings, and assembling the final report with detection-coverage notes.
---

# Evidence and reporting (P9)

The last mile: dedupe, render, classify, redact, assemble. No new probing
happens here — everything in the report is already evidenced; assembly
and quality-gating are the work.

## The way

- Dedupe rule: same root cause + same component = one finding with an
  instance list; independent sinks stay separate. Stable `F-NNN` ids,
  never renumbered after operator review.
- The finding record is a contract the validator enforces: D2 pairs
  cited by file name, D3 mark, canonical CWE, CVSS vector + score,
  remediation, detection note. `[gap]` markers make missing pieces loud
  instead of silent.
- PoC rendering: the smallest reproducing request, preconditions + the
  negative control inline, raw HTTP only when verbatim headers matter.
  Redaction before D4 — originals stay in the namespace.
- Severity: vectors from `70`, scores from the official calculator,
  downgrade-on-uncertainty, and no locked severity without D3.
- The report's credibility lives in the coverage statement: what was
  tested, what wasn't, degraded modes, negative results. Exec-summary
  counts must match the technical section exactly.
- Negative routing: a new probe, an impact upgrade or a re-score goes
  back to the owning skill — assembly is not where discoveries happen.
- Compliance mapping: cross-walk canonical CWEs to ISO/IEC 27001:2022,
  NIST CSF 2.0, CIS Controls v8.1, and OWASP Top 10 via `--compliance`.

## Handoffs

Consumes `10`-`85` (findings, cards, detection notes, D3 marks); feeds
D4 delivery via the operator channel and memory drafts (operator
reviewed, engagement-namespaced).

## Tools

`poc_render.py`, `finding_format.py` (offline, execute nothing — replay
belongs to `20` inside scope). Finding template, compliance mapping,
remediation library and report skeleton in `references/`.
