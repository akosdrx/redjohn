---
name: scan-standard
description: Balanced authorized assessment combining baseline review with targeted reproducible validation. Use for every agent assigned the standard scan mode; controls depth, routing and evidence requirements without changing target scope.
---

# Standard scan profile

Start with inventory and baseline; build the request/evidence harness before active validation. For source targets, inspect authentication, authorization, input handling, dependencies and configuration read-only. For web targets, validate a small set of evidence-supported issues using benign canaries and normal engagement accounts. Avoid broad payload spraying, load tests and uncontrolled impact chains.

Route through 05, 10, 15, 20, 25, 30, 32, 35, 40, 45, 50, 60, 70, 95 and 90 skills as relevant. Immediately after P1 recon (`05`, `10`, `15`), run P1.5 (`70` + `mcp:redjohn-vuln-intel:*`) to rank known CVEs by Expected-Value priority score and validate Tier 1/2 RCE or CISA KEV candidates via `45` (benign canary proof only) before spending budget on generic P5 parameter fuzzing (`40`). Use `65` for source dependencies. Route Medium/High/Critical findings through `95-finding-verifier` with a negative control before reporting. Stop a negative branch after three generations without signal.

This profile is inherited by all descendants. Load the master methodology and relevant surface skills with builtin:load_skill. Read referenced files with builtin:read_skill_file. Finish only with evidence references, negative coverage and clear limitations.
