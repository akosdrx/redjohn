# Completed Ubuntu phase 3 verification

[Run 39151591978](https://github.com/akosdrx/redjohn/actions/runs/39151591978) completed successfully on both GitHub-hosted Ubuntu 24.04 architectures on 2026-10-18. Source commit `9ff92a8abf4e5ad516bef7b3ce4dd297ea82055c`, tree `1213ef0df295f28f0d95df7f1ea5fd8a28b800c2`, was executed as PR merge `fb6eb8dfac34e5465182535e41c00e616db246b4`. Its parent and identical tree were independently checked. This is a completed earlier source baseline; it does not validate subsequent phase 4 or phase 5 changes.

| Checks per architecture | x64 / Python 3.13.16 | ARM64 / Python 3.12.3 |
| --- | ---: | ---: |
| Python regression: passed / failed / skipped | 1171 / 0 / 0 | 1171 / 0 / 0 |
| Actual integration: passed / failed / skipped | 374 / 0 / 0 | 374 / 0 / 0 |
| Frontend: passed / failed / skipped | 14 / 0 / 0 | 14 / 0 / 0 |
| Go test functions: passed / failed / skipped | 21 / 0 / 0 | 21 / 0 / 0 |
| Mixed workload cycles | 120 | 120 |
| Measured workload seconds | 1205.206369 | 1206.183982 |
| Cycle p50 / p95 seconds | 3.260038 / 3.419796 | 3.122411 / 3.267150 |
| External process-tree peak summed RSS bytes | 775213056 | 797908992 |
| Controller RSS before / after bytes | 111583232 / 179900416 | 109006848 / 196550656 |

The regression totals include 206 mock contracts and 965 unit/contract/mixed cases per architecture. Frontend results include six fetch doubles and eight unit/render contracts. Three Darwin-only cases were explicitly non-applicable and not executed; they are not Linux successes or silently converted skips. Ruff, strict mypy, TypeScript, frontend production build, Go race tests/vet/build, locked installations and the final strict evidence gate also passed.

The controlled real integrations include Playwright/Chromium, Nuclei, authenticated replay and refresh, scanner workers, HTTPS brokers, target-bound MCP, namespace denial and process/cgroup controls. These tests use owned fixtures; they do not authorize external targets. The loopback soak exercised 60 positive and 60 fixed cycles with browser/httpx/Nuclei, 720 actual fixture requests matching 720 persisted request charges, 120/120 contexts closed and no remaining process reservations. File descriptors returned to six, process count to one and listeners to zero on both architectures.

Global AppArmor restrictions stayed `1/1`; the run-owned profile and cgroup were removed with no owned process leak. Summed RSS can double-count shared pages. Controller/native RSS growth is not fully attributed; no leak-free or universal hard-memory guarantee is claimed. Synthetic pressure checks are separate from scanner detection evidence. Live providers, original missing RCE fixture, cloud/Kubernetes audit and public OAST infrastructure remain outside this run.

Local receipts are under `docs/measurements/master-completion-20261018/github-phase3/`, including full job logs, JUnit, source manifests, tool versions, resource measurements and terminal run metadata. Both artifact ZIP SHA256 digests, all 698 source identities and all 229 indexed artifact identities per architecture were independently verified. The evidence directory is intentionally excluded from published source snapshots.
