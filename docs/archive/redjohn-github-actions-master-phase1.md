# Completed hosted master-continuation verification

Source commit: `5cfd51d286c65558b92a6c070bcd7edd5a8b432b`.
[Workflow](https://github.com/akosdrx/redjohn/blob/5cfd51d286c65558b92a6c070bcd7edd5a8b432b/.github/workflows/redjohn-ubuntu.yml),
[completed successful run](https://github.com/akosdrx/redjohn/actions/runs/39144694827),
[draft PR](https://github.com/akosdrx/redjohn/pull/1).

Both native GitHub-hosted Ubuntu 24.04 jobs completed successfully. This result
verifies that specific source snapshot, not later work in the shared checkout.
Each platform's 637 tracked input hashes and 212 evidence hashes were checked
independently after the artifact ZIP SHA256 was verified. Original JUnit, logs,
source/evidence manifests and signed tool-install receipts are retained under
`docs/measurements/master-completion-20261018/github-phase1/`.

| Check | x64 / Python 3.13.16 | ARM64 / Python 3.12.3 |
|---|---:|---:|
| Python passed / failed / errors / skipped | 1281 / 0 / 0 / 0 | 1281 / 0 / 0 / 0 |
| Actual integration cases within Python | 333 | 333 |
| Other Python cases: mock contracts / unit-contract-mixed | 206 / 742 | 206 / 742 |
| Frontend passed / failed / skipped | 14 / 0 / 0 | 14 / 0 / 0 |
| Frontend reviewed fetch doubles / unit-render contracts | 6 / 8 | 6 / 8 |
| Go tests, including subtests: passed / failed / skipped | 21 / 0 / 0 | 21 / 0 / 0 |
| CI evidence contracts | 10 | 10 |

The frontend's Node22 JUnit omits `file` attributes. The original runner summary
therefore grouped all fourteen frontend cases as unit/contract/mixed. Independent
source review identifies the six named `server-source.test.mjs` fetch doubles;
none is actual network E2E. Raw results remain unchanged. A regression test and
dedicated-frontend-suite classifier correction are in the later hotfix.

The real suites cover controlled Chromium, inventory, authenticated Nuclei
JSON/form/multipart replay and refresh/restart; the existing eleven selected
scanner engines; persistent scheduling, actual CLI/TUI/Web View control-plane
interaction; local cache I/O; stdio cancellation/unknown-outcome and PTY lifetime;
namespace/cgroup enforcement, OOM and cleanup. Interface tests do not prove a
configured external LLM/provider conversation. The original missing RCE fixture
is not replaced by these owned marker/SSTI controls.

## Actual mixed workload

| Measurement | x64 | ARM64 |
|---|---:|---:|
| Completed cycles | 120 | 120 |
| Positive / fixed cycles | 60 / 60 | 60 / 60 |
| Active paced workload duration, seconds | 1204.368569 | 1205.722625 |
| Actual / persisted HTTP requests | 720 / 720 | 720 / 720 |
| Post-warmup cycle p50 / p95, seconds | 2.508981 / 2.704326 | 2.998979 / 3.134825 |
| File descriptors before / after | 6 / 6 | 6 / 6 |
| Processes before / after | 1 / 1 | 1 / 1 |
| TCP listeners before / after | 0 / 0 | 0 / 0 |
| Browser pages and contexts created / closed | 120 / 120 | 120 / 120 |
| Sampled process-forest RSS peak, bytes | 780161024 | 791736320 |
| Controller RSS before / after, bytes | 110866432 / 194592768 | 108167168 / 192425984 |
| Controller traced growth after warmup, bytes | 11015440 | 2098420 |
| Retained cycle/cache-result JSON, bytes | 658311 | 658129 |

Each cycle uses the same durable runtime, real Chromium and selected pinned
httpx/Nuclei sequentially. The observed inventory feeds the scanner. The fixture
alternates a harmless positive marker and a fixed control; deduplicated replay
does not send another request. The benchmark uses its own literal loopback TLS
target; separate actual integration cases prove remote namespace restrictions.
Read-only browser discovery deliberately records partial coverage when its
negative-control mutation is blocked. A successful benchmark does not turn that
blocked browser action into completed scan coverage.

The separate synthetic pressure cases exercise actual supervisor stdout/stderr
limits, maximum proxy wire bytes, durable queue capacity and real cache eviction.
They are capacity/control evidence, not additional scanner findings. All fifteen
benchmark gates passed, with zero active host owners, process reservations,
browser contexts/pages/proxy connections and cleanup errors at completion.

The RSS increase remains a measured limitation. The allocation profile separates
the bounded six-MiB cache, retained result data, JSON/path/Playwright allocations
and controller tracing, but does not explain every native allocator/SSL page.
The report makes no leak-free claim, speedup claim, or OS hard-limit claim from
cooperative admission. Dedicated kernel OOM tests remain separate evidence.

Both jobs removed only their owned cgroup and AppArmor profile. Global
`apparmor_restrict_unprivileged_userns` and
`apparmor_restrict_unprivileged_unconfined` remained `1`; the final unprofiled
namespace negative control remained denied. No full local Ubuntu regression or
Colima stop/delete was used as a substitute.

## Later snapshots

`1ba82ce568c12fdda1468a47c6e08056fd5942df` adds source scanners, stateful workflows,
provider MCP contracts, Darwin Shell and v3 wire bodies. Its first hosted run
found Linux static type reachability in the Darwin-only constructor; it is not
a complete successful run. The minimal guard correction, both static platform
checks, Node evidence fix and reliable PR long-soak request are in
`d35524331c558f9698fc30a95749705356a8199f`.

[That hotfix run](https://github.com/akosdrx/redjohn/actions/runs/39148614630)
is pending behind the earlier active run at this report's capture time. Its
success must be established from its own terminal status, executed merge SHA,
frozen input hashes and artifacts. New adapters and runtime edits under ongoing
development are not verified by this completed phase1 run.
