---
name: 75-zeroday-research
description: Use when no public CVE matches a custom or niche attack surface and novelty is suspected - patch diffing upstream releases for n-day rediscovery, targeted mutation and replay against custom parsers, novelty and impact assessment, and handling an undisclosed vulnerability found mid-engagement.
---

# Zero-day research path (P8)

The branch for surfaces where `70` came back empty and the surface is
custom or niche. Everything here is timeboxed, authorized in writing, and
ends either in a downgraded n-day (back to `70`) or a documented
potentially-novel finding whose disclosure is the operator's decision.

## The way

- Entry needs all three or none: `70`'s dated no-match trail, written
  research authorization, a set timebox. Every hour is logged; research
  never eats the P9 budget.
- n-day rediscovery beats novel hunting: diff the pinned version against
  the *next patch release* only. `secdiff` triages hunks into CWE
  hypotheses; a hypothesis is a lead, not a claim.
- Target SAST/DAST blind spots: cross-service taint breaks, dynamic reflection,
  multi-step stateful workflows, and patch gaps where upstream fixes miss
  sibling routes or alternate verbs (`references/sast-dast-blindspots.md`).
- The PoC must discriminate versions — reproduces pre-patch behavior,
  not post-patch, verified against both local builds first. A
  non-discriminating probe proves a feature exists.
- A fix existing does not make the old behavior exploitable: fixes land
  for crashes and defense-in-depth too. Exploitability is claimed only
  from in-scope verification.
- Custom surfaces: sketch the input grammar, then boundary values through
  `40`'s encode ladder, then differential replay via `20`. One variable
  per request; budgets capped; an error-rate spike stops the run.
- Any public record anywhere — advisory, writeup, CVE — means it is not
  a zero-day: downgrade to `70`. The dated search trail *is* the novelty
  evidence; re-run it before delivery.
- Undisclosed findings: report carries the "undisclosed" marking, PoCs
  stay unpublished, vendor contact happens only through the operator.

## Handoffs

Impact proofs -> `45`; downgrades -> `70`; report -> `90` (undisclosed
marked); detection observations -> `85`.

## Tools

`secdiff.py` (offline), git in approved network windows. Procedures —
patch triage, grammar sketching, search discipline, disclosure rules —
in `references/`.
