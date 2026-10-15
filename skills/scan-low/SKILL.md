---
name: scan-low
description: Read-only baseline assessment with minimal requests and bounded source review. Use for every agent assigned the low scan mode; controls depth, routing and evidence requirements without changing target scope.
---

# Low scan profile

Prioritize inventory and passive baseline only. For local projects and repositories, read dependency manifests, configuration, authentication boundaries and exposed secrets without running code. For web applications, use a few normal GET requests and browser snapshots to identify routes, headers, TLS observations and public disclosures. Do not run fuzzing, password attempts, exploit payloads, concurrency probes or impact chains. Version matches are hypotheses until independently reproduced.

Route through 05-attack-surface-planner (passive blueprint & soft-404 calibration), 10-recon-endpoint-mapping, 50-config-baseline, 35-cryptographic-failures and 90-evidence-reporting. Delegate only independent read-only surfaces. Finish with baseline findings, explicit limitations and untested areas.

This profile is inherited by all descendants. Load the master methodology and relevant surface skills with builtin:load_skill. Read referenced files with builtin:read_skill_file. Finish only with evidence references, negative coverage and clear limitations.
