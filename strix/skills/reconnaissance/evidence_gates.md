---
name: evidence_gates
description: Evidence gates (from master_pentest_methodology specialist reference
  library)
---

# Evidence gates

Definitions for D1-D4, PoC format, and canary conventions. Every folder's
"Evidence expectations" section refers to these gates.

## Gates

- **D1 draft.** Observed once, artifact saved. May be a hunch with one response
  pair. Not reportable. Subject of false-positive checks.
- **D2 verified.** The finding was reproduced end-to-end a second time from a
  clean state (fresh session/token where applicable), with both runs' evidence
  pairs saved plus an explicit negative control (`negative_control_ref`).
  False-positive alternatives were checked and ruled out via `95-finding-verifier`
  (caching, WAF normalization, random ids, A/B flags, timing noise). D2 is the
  entry requirement for `FindingStatus.VERIFIED` and for exploit-intel confirmation.
- **D3 operator validated.** An independent operator reviewed the evidence and
  reproduction and confirmed classification + impact. Required before any
  external delivery, CVSS severity lock-in, or memory promotion. A model
  proposal is never self-validated.
- **D4 reported.** Finding entered the delivered report with redacted secrets,
  final CWE/CVSS, and remediation guidance.

## Swarm Anti-Hallucination & Provenance Gate (`95-finding-verifier`)

- **Real Session Evidence Only:** Every `evidence_refs` and `negative_control_ref`
  passed to `builtin:report_finding` is validated against the current `run_id`
  evidence store (`evd_*`) or non-empty workspace artifact files. Fabricated or
  cross-session IDs fail with `validation_error`.
- **Differential Negative Control:** Claiming `verification_status="verified"`
  requires a valid `negative_control_ref` (or >=2 distinct session `evidence_refs`
  capturing baseline vs. positive reproduction). Single-probe or correlation-only
  claims are automatically clamped to `suspected`.
- **Fact vs. Hypothesis Separation:** Specialist handoffs must separate `[FACTS]`
  (citing `evd_*` IDs) from `[HYPOTHESES]` (unverified leads).

## Evidence pair format

- File naming: `evidence/<phase>-<surface>-<seq>.<req|resp>.txt`
  (e.g. `evidence/p4-api-invoices-003.req.txt`).
- Request file: raw HTTP as sent (method, path, headers, body) with a leading
  comment line: target origin, timestamp, auth context label, tool used.
- Response file: status line, headers, body; same comment block.
- Redact before D4: session tokens, passwords, API keys, real user PII.
  Keep originals unredacted inside the engagement namespace only.

## PoC requirements (feeds `90-evidence-reporting`)

- Minimal: the smallest request set that reproduces the finding; prefer one
  `curl` command (or raw HTTP block) over a script; include environment
  preconditions (auth context, state).
- Include the negative control: the same request without the payload (or with
  the other role's token) showing the baseline behavior.
- Canary string format `rj-pt-<engagement>-<nonce>`; command-exec proofs are
  limited to `id`, `whoami`, `hostname`, canary echo. No reverse shells as
  "proof" — a canary callback is sufficient and proportionate.

## False-positive checklist (run before granting D2)

1. Reproduce with cache-busting (random query param) — same result?
2. Reproduce from a second session/IP if available — same result?
3. Baseline comparison done via response diffing (`20` harness), not eyeball?
4. Timing findings re-measured N>=5 with median, not single-shot?
5. Role checks re-run with freshly issued tokens for both contexts?
6. Alternative benign explanation (feature flag, admin preview, pagination)
   searched for and documented as ruled out?

## Memory discipline

- At engagement close, propose lessons per finding class and per tool note,
  tagged with the engagement namespace, as **drafts**.
- Promotion to validated memory requires independent operator review (the same
  D3 discipline). Anonymous sharing only happens from the reviewed copy, never
  from raw engagement evidence.

