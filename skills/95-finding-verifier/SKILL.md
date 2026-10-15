---
name: 95-finding-verifier
description: Use as the mandatory anti-hallucination quality and provenance gate before promoting any Medium, High, or Critical vulnerability to Verified (D2) or calling report_finding - checks artifact existence, negative-control differentials, and correlation-only downgrades.
---

# Finding verifier and anti-hallucination gate (D2)

The adversarial critic between active testing (`30`–`82`) and reporting (`90`).
No Medium/High/Critical finding reaches `Verified` unless its session evidence
exists on disk, differs deterministically from a benign negative control, and
survives false-positive checks.

## The way

- Provenance first: every cited `evd_*` ID or `evidence/*.{req,resp}.txt` file
  must exist in the current run and contain non-empty capture data. Fabricated,
  empty, or cross-session IDs are rejected immediately.
- Negative-control differential: a `Verified` finding requires either a named
  inert baseline (`negative_control_ref`) or at least two independent session
  captures showing the benign baseline and the positive vulnerability response
  differ in status, headers, or body content.
- Version correlation is not exploitation: an unprobed CVE match from `70`
  without an active behavioral proof from `45`/`40`/`30` is clamped to
  `Suspected` (D1) and capped at Low/Info until proven.
- Class-specific skepticism:
  - RCE/SSTI (`45`): raw response must contain the *computed* canary output,
    never just the unrendered template syntax or a generic 500 error.
  - Time-based blind SQLi (`40`): require median-of-5 true vs false delay separation.
  - Auth/IDOR (`30`): require fresh tokens and verify the response is not public cache.
- Layer-Ordering Trap: an unauthenticated 400/422 schema validation error
  never proves auth bypass — require a minimal well-formed request demonstrating
  unauthorized access before promoting to Verified.
- 7-Question Gate: validate scope, observable pairs, backend reachability,
  negative controls, error differentiation, layer ordering, and non-destructive
  reproducibility before reporting.

## Handoffs

Passed D2 findings -> `90-evidence-reporting` (`finding_format.py`) and
`builtin:report_finding`; rejected/clamped claims -> back to the owning phase
with the exact missing control.

## Tools

`verify_finding_gate.py` (offline validator). 7-Question Gate and per-class
verification rules in `references/verification-checklist.md`.
