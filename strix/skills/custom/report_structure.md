---
name: report_structure
description: Report structure (section-by-section skeleton) (from evidence_compliance_reporting
  specialist reference library)
---

# Report structure (section-by-section skeleton)

The delivered report is assembled in this order. Everything lives in the
engagement namespace until the redaction pass; only the redacted copy leaves
(via the operator-approved channel).

## 1. Engagement metadata (title block)

- Engagement namespace/id, scope summary (hosts/ranges from the scope file,
  not the raw file itself), test window dates, operator, methodology
  reference: `00-master-pentest-methodology` (name it in the appendix too).
- Classification/handling marking if the engagement requires one.

## 2. Executive summary

Requirements (gate 8 enforces):

- **Counts by severity** — a table of Critical/High/Medium/Low/Info counts
  that matches the technical section exactly. Recount after every edit;
  a mismatched summary fails delivery.
- **Top risks in plain language** — the 3-5 findings that matter most,
  described without jargon: what an attacker could do, what business asset
  is exposed, one sentence each. No CVSS vectors, no CWE ids here.
- Scope and dates restated; degraded coverage named up front (e.g.
  "authentication flows were tested with a single account role, so
  cross-tenant access issues are only partially covered").
- Nothing in the summary may be stronger than the evidence: same
  demonstrated-impact discipline as the finding records.

## 3. Technical findings

- Ordered by severity: Critical -> High -> Medium -> Low -> Info; within a
  band, by component then id.
- Each finding is one record per `finding-template.md` (emitted shape of
  `scripts/finding_format.py`): metadata table (severity D3-locked, CWE,
  CVSS, component/version/tier, evidence refs) then Description, Proof of
  concept, Remediation, Detection coverage prose.
- Deduplicated per SKILL.md section 2: one root cause + one component = one
  finding with an instance list; instance evidence refs inline.
- Superseded/merged ids appear struck through in the appendix index only,
  never as live rows.

## 4. Detection coverage (from 85)

A table, one row per finding class (not per instance):

| Finding class | Logged? | Alerted? | Log source | Gap / recommendation |
|---|---|---|---|---|
| SQL injection attempts | yes (app log) | no | app.log input-rejection events | add alert on rejection bursts |
| Authz denials (IDOR probes) | no | no | — | log object-level denials with actor+object |

- Content comes from the `85-logging-monitoring` notes only — no guessing
  what the blue side saw. "Not assessed" is a valid, honest row.
- Gaps become hardening recommendations with owners if the operator wants
  them tracked.

## 5. Coverage statement

What was tested, per skill/phase — including what was NOT:

- Per phase (P1-P9): surfaces covered, techniques run, and the negative
  results worth recording (e.g. "three probe generations on GraphQL
  mutations without signal — logged, moved on", per the dead-end rule).
- Degraded modes stated explicitly: single-auth-context engagements say
  IDOR/BOLA coverage is partial (dispatch-map negative routing); missing
  OOB listener says blind classes are unverified; time-budget cuts list
  which P6+ surfaces were dropped after half-budget.
- Out-of-scope observations: assets discovered but not tested, recorded as
  observations with no vulnerability claims.
- Tool coverage notes: which scanners/sources returned nothing (a dated
  "no CVE matched as of YYYY-MM-DD, sources 1-5" statement is a result).

## 6. Appendices

- **Methodology**: reference `00-master-pentest-methodology` by name and the
  phase machine; state gate discipline (D2 entry, D3 validation before
  delivery).
- **Evidence index**: file names of the evidence pairs backing each finding
  (redacted copies), grouped by finding id. No bodies inline.
- **Finding id history**: superseded/merged ids and what absorbed them.
- **Tooling**: tools and versions used per phase (assessment container CLIs,
  script names from this library).
- **Memory drafts register**: lessons proposed as drafts (class, tool note),
  tagged with the engagement namespace, pending independent review — listed
  here so promotion is auditable; the drafts themselves stay in the
  engagement namespace.

## Assembly checklist (maps to SKILL.md section 8)

1. Dedupe done, ids stable, no `[gap]` markers.
2. Every record validated through `scripts/finding_format.py` (exit 0).
3. Every PoC rendered through `scripts/poc_render.py` discipline:
   preconditions, negative control, redaction warnings resolved.
4. Detection table rows backed by `85` notes.
5. Coverage statement includes negative results and degraded modes.
6. Redaction sweep recorded; exec summary counts recounted from the
   technical section; stop-condition audit clean.

