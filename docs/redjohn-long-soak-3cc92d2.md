# RedJohn hosted 120-cycle mixed load — 2026-10-21

The requested long workload completed successfully on both GitHub-hosted Ubuntu
24.04 architectures. This record describes the actual run on source `3cc92d20ee37fe54663dc7c25a73aeb802f98ef1`;
it does not substitute the earlier short two-cycle run or an older source.

- [Full workflow run 39505094482, attempt 1](https://github.com/akosdrx/redjohn/actions/runs/39505094482), event `workflow_dispatch`.
- [Frozen workflow](https://github.com/akosdrx/redjohn/blob/3cc92d20ee37fe54663dc7c25a73aeb802f98ef1/.github/workflows/redjohn-ubuntu.yml).
- Ref: `codex/redjohn-long-soak-3cc92d2`, created at the exact source SHA without moving the active development branch.
- Explicit inputs: `soak_cycles=120`, `soak_minimum_seconds=1200`.
- Both final job conclusions and the overall workflow conclusion are `success`.
- All 801 frozen source hashes, both final artifact ZIP digests and every indexed evidence file were independently verified.

## Runner and native versions

| Field | x64 | ARM64 |
|---|---|---|
| Hosted runner label | ubuntu-24.04 | ubuntu-24.04-arm |
| Native machine | x86_64 | aarch64 |
| Python | 3.13.16 | 3.12.3 |
| Runner image version | 20261018.339.1 | 20261012.149.1 |
| Platform | Linux-7.0.0-1017-azure-x86_64-with-glibc2.39 | Linux-6.17.0-1022-azure-aarch64-with-glibc2.39 |
| Playwright | 1.58.0 | 1.58.0 |
| Chromium while running | 145.0.7632.6 | 145.0.7632.0 |
| Nuclei | 3.11.1 | 3.11.1 |
| httpx | 1.12.0 | 1.12.0 |

Both runners belong to the `GitHub Actions` runner group. The Chromium version
comes from the live capability probe; `stopped` in the final browser health
record describes normal shutdown, not an engine version or missing browser.

## Actual workload and duration

Each cycle submits three actual serial jobs through the shared SQLite-backed
scheduler: headless Chromium discovery, httpx observation/inventory, then native
Nuclei matching. The owned TLS loopback fixture alternates positive and fixed
controls; the fixed control must produce zero matching findings. Alice/Bob
browser identities and anonymous native probes remain in the declared policy.
Duplicate submission must neither rescan nor repeat network requests.

The interval is 10 seconds. The cycle timeline includes this pacing; it is not
CPU busy time. One warmup cycle is included in the executed-cycle total and
excluded from the latency quantiles. The benchmark may execute extra cycles to
meet the minimum duration. The benchmark total elapsed time below is measured
with a monotonic clock and includes the benchmark's own setup and cleanup; it
excludes dependency installation and the rest of the Actions job. The last
per-cycle work progress is also shown
separately: it precedes any final pacing sleep. The loop returns normally only
when both the cycle count and its own monotonic minimum duration are met; the
frozen source and successful execution establish that lower bound. This source
does not emit an exact workload-loop exit timestamp, so none is invented here.

| Measurement | x64 | ARM64 |
|---|---:|---:|
| Requested cycles / minimum seconds | 120 / 1200 | 120 / 1200 |
| Actual completed cycles | 120 | 120 |
| Actual scheduled jobs | 360 | 360 |
| Positive / fixed control cycles | 60 / 60 | 60 / 60 |
| Last completed cycle work progress | 1194.953 s | 1194.186 s |
| Enforced workload-loop minimum (pacing included) | at least 1200 s | at least 1200 s |
| Benchmark total elapsed time | 1208.382665 s | 1205.942122 s |
| Supervised mixed command wall time | 1210.501778 s | 1207.778772 s |
| Internal resource samples (about 2 s cadence) | 591 | 595 |
| External command RSS samples (about 0.2 s cadence) | 5713 | 5690 |
| Measured cycle latency p50 / p95 | 4.060284 / 4.241732 s | 3.306399 / 3.425933 s |
| Sampled process-tree RSS peak | 792,031,232 B | 794,083,328 B |
| Sampled process-tree RSS p50 / p95 | 181,481,472 / 641,560,576 B | 180,736,000 / 417,247,232 B |
| Process-tree RSS before / after | 115,052,544 / 199,872,512 B | 109,326,336 / 195,600,384 B |
| External command process-tree RSS peak | 797,069,312 B | 796,848,128 B |
| Actual fixture requests / durable budget usage | 720 / 720 | 720 / 720 |
| Processes before / after | 1 / 1 | 1 / 1 |
| File descriptors before / after | 6 / 6 | 6 / 6 |
| TCP listeners before / after | 0 / 0 | 0 / 0 |
| Retained controller traced growth after warmup | 5,765,942 B | 1,961,363 B |
| Retained cycle/cache measurement JSON | 658,037 B | 658,121 B |
| Host-user cooperative ledger memory budget | 4,294,967,296 B | 4,294,967,296 B |
| Resource / isolation / workload invariants | 15 / 15 | 15 / 15 |

All 15 invariants were true: queue/cache/log/body pressure bounds, cycle count,
minimum duration, released reservations, process/listener/descriptor cleanup,
empty native session, closed browser pages/contexts/proxy connections, no browser
cleanup error, exact request accounting, both actors, no forbidden mutation,
no observation error and unchanged source identity. Delegated cgroup and owned
AppArmor cleanup also succeeded in the complete workflow. The original strict
namespace/cgroup/owner controls and all active tests were retained.

Queue pressure uses synthetic submissions with real SQLite persistence; cache,
log and body pressure use generated bounded payloads against real implementations.
Those controls are not scanner detection evidence. The browser/httpx/Nuclei
jobs and alternating positive/fixed oracles are actual integrations.

RSS sums can count shared pages more than once and are observations, not kernel
hard limits. The mixed workload's shared ledger reports `os_hard_limit: false`;
its logical 2 GiB resource envelope is not a global OS memory guarantee. Actual
pre-exec owner/cgroup controls are tested separately in the full Linux E2E
selection, including the WPScan/SBOM owners. Controller tracemalloc excludes
native/browser memory, and retained measurement/cache data contribute to growth.
This run does not establish universal leak freedom or attribute all RSS changes.

## Full workflow regression evidence

| Platform | Python regression passed | Actual integration passed | Frontend passed | Go passed | Failed / errors / skipped |
|---|---:|---:|---:|---:|---|
| x64 | 1558 | 454 | 14 | 21 | 0 / 0 / 0 |
| arm64 | 1558 | 454 | 14 | 21 | 0 / 0 / 0 |

Each regression selection includes 207 explicitly labelled mock contracts and
1351 unit/contract/mixed cases. Six of the 14 frontend tests use fetch doubles.
Three active Darwin-only shell cases are explicitly platform-inapplicable on
Linux, not executed or counted passed. The eleven WPScan/SBOM actual scenarios
are included in the 454 integrations; those tools are not each rerun in every
mixed cycle. Ruff, strict mypy, TypeScript/build, Go vet/race/build and Python
wheel/license gates also passed.

The workload is confined to an owned loopback TLS fixture. There is no live
cloud/Kubernetes audit, public OAST, live LLM/model call or original RCE-fixture
proof in this benchmark. The WPScan observation and controlled two-record Trivy
SBOM scope remains as described in [the runtime verification](redjohn-artifact-runtime-verification.md).

## Commit-bound raw evidence and reproduction

| Platform | Final artifact ID | ZIP SHA-256 | Indexed files |
|---|---:|---|---:|
| x64 | 12306591965 | `6b04e6bd1e2eb4318b623133bb3a8a5461c52a2463eb76dc873ee1a41ba83a19` | 374 |
| arm64 | 12305548333 | `a675ca4d77ca774ba0137ecbcf3f4e33f3af189fac65f3a8681bfd3d36aa3315` | 374 |

Final artifacts contain JUnit, source hashes, tool receipts, full command logs,
`mixed-soak.log` cycle progress, `mixed-soak/mixed-soak.json` raw samples and
cleanup evidence. The workflow configures 14-day artifact retention; this report
keeps the measured summary and digests in source control.

The actual dispatch command was:

```sh
gh workflow run redjohn-ubuntu.yml --repo akosdrx/redjohn \
  --ref codex/redjohn-long-soak-3cc92d2 \
  -f soak_cycles=120 -f soak_minimum_seconds=1200
```

Check that the frozen ref still resolves to the source SHA above before a later
reproduction. This task changed documentation only; product code, test files,
workflow protections, the local Git HEAD/index and private MCP configuration
were preserved. No local full regression or Colima run substituted for Actions.

## Documentation changes for this task

- `docs/redjohn-long-soak-3cc92d2.md`: new measured record and reproduction command.
- `docs/redjohn-completion-status.md`: latest completed long-run pointer.
- `docs/redjohn-artifact-runtime-verification.md`: links this later long run while retaining the earlier short-run measurements.

No product code, active test, dependency pin or workflow file changed in this task.
