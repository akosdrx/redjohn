---
name: 05-attack-surface-planner
description: Use when ingesting engagement scope, RoE constraints, soft-404 baselines, and recon fingerprints to produce a prioritized phase execution blueprint (P1 -> P1.5 -> P2-P9), evidence collection checklist, and signal-to-skill dispatch table before or during active testing.
---

# Attack surface & engagement planner (P0/P1)

Strategic orchestrator that turns scope, rules of engagement (RoE), and
reconnaissance signals into an EV-ranked phase blueprint and swarm dispatch
matrix. Nothing past P1 executes without a calibrated plan.

## The way

- Calibrate per-host and per-depth soft-404 baselines before fuzzing:
  record status, size, and body hash on two random bogus paths per host
  and per depth (`/x` vs `/a/b/x`).
- Expected-Value (EV) priority routing: triage high-confidence, low-cost
  Tier 1/2 CVEs and fast-path RCE (`P1.5`) before committing budget to
  blind parameter fuzzing (`P5`).
- Enforce load budget discipline: cap active platform skills at 8 to prevent
  context exhaustion and redundant probing.
- Maintain a strict fact-vs-hypothesis blackboard: treat confirmed
  evidence (`D2`/`D3`) as facts; keep speculative leads as hypotheses.
- Fail closed on scope boundaries: reject unlisted hosts immediately; log
  discovered out-of-scope assets as passive observations only.
- Continuous blueprint calibration: re-evaluate the phase plan whenever
  new fingerprints, auth boundaries, or edge defenses emerge.

## Handoffs

Scope and RoE -> `P0`; recon fingerprints and soft-404 baselines from `10` ->
`05`; fast-path Tier 1/2 components -> `70`/`15`/`45`; edge and baseline
posture -> `25`/`50`; auth boundaries -> `30`/`32`.

## Tools

`attack_plan_gen.py` (guarded baseline probe, plan generation, and offline
`--self-test`). Phase blueprint, evidence checklist, and signal-to-skill
dispatch matrix in `references/`.
