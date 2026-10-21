# RedJohn mixed workload and limit-pressure verification

This stage adds real Chromium, selected pinned httpx and Nuclei jobs to the
same durable scheduler workload. It preserves TLS validation, ordinary origin
rate admission, browser sandboxing, fixed-control CSP, and strict cleanup gates.
No model/provider is invoked and no arbitrary or remote target is accepted.

## What changed

- `benchmarks/mixed_soak.py`: paced active cycles, actual positive/fixed
  scanner controls, observed inventory, durable deduplication, shared runtime
  cache pressure, bounded observation, controller allocation profiling, partial
  failure receipts, and source identity checks.
- `benchmarks/limit_pressure.py`: separate synthetic byte pressure on
  the actual production supervisor and proxy. This is process/socket limit
  evidence, not vulnerability detection or a substitute scanner.
- `benchmarks/README.md`: reproducible short/long commands and limits.
- `tests/test_soak_limits_live.py`: four actual process/socket/SQLite/
  cache limit checks, including 512-KiB stdout and stderr, 8-MiB wire framing,
  cap+1 rejection, 128 durable queued items, dedup while full and cancellation.
- `tests/test_soak_fault_contracts.py`: eight explicitly synthetic
  invalid-input/failure contracts. A failed later cycle and failed final sampler
  preserve partial evidence, original error and environment/profiler cleanup.
- `.github/workflows/redjohn-ubuntu.yml`, `linux-tests.sh`, `prepare-linux.sh`:
  existing protected x64/ARM64 runners also execute a short mixed workload;
  manual cycle/duration inputs enable longer active workloads, in a separate
  owned launcher cgroup under the existing enforcing AppArmor profile.
- `.github/scripts/ci.py`, `pytest_evidence.py`, `.github/tests/test_ci.py`:
  strict commit-bound soak/frontend/Go evidence; six reviewed fetch-double
  frontend cases remain separate from actual browser/HTTP integrations. Missing
  test functions, skips, failed/wrong-commit soak and absent receipts fail gates.

## Actual targeted results

The focused pressure/fault suite passed **12/12**, no failures/skips, in **1.56 s**.
The four pressure cases are actual production implementation integrations; the
other eight are contract/fault injection and do not claim scanner E2E. The CI
evidence contract suite passed **10/10** in **0.086 s**. Python Ruff checks and
shell/YAML syntax checks passed. These are targeted working-tree checks.

A genuine two-cycle macOS ARM64 workload with installed Chromium, httpx 1.12.0
and Nuclei 3.11.1 completed in **13.202461292 s**, with all workload checks true.
Observed inventory fed the real Nuclei engine: positive/fixed finding counts
were **1/0**, and actual fixture/persistent budget counts were **12/12**.
Process count returned **1→1**, file descriptors **9→9**, TCP listeners **0→0**;
two browser pages and two actor contexts were created and closed. There were
zero active proxy connections, browser cleanup errors, native reservations or
host owners after close. Source hashes remained unchanged during this run.
This short real E2E is not a long-soak or Ubuntu validation claim.

The first actual run exposed a benchmark fixture mistake: enabling the fixed
control's strict CSP before browser readiness prevented the inline SPA script
from running. Browser discovery now uses the normal fixture, then only the
scanner stages switch to the fixed control; its CSP remains strict.

The strict descriptor gate then exposed one retained macOS Unix socket. Fresh
minimal processes reproduced it with `socket.getfqdn('127.0.0.1')` and fixture
construction, while sampler-only and subprocess-only loops stayed flat. The
owned literal-IP fixture now binds via `TCPServer.server_bind` and sets its
literal server name/port directly, avoiding unnecessary reverse DNS. The guard
contract failed before this fix; both HTTP and CA-verified HTTPS behavior and
existing TLS cases then passed **8/8** in **2.79 s**. No descriptor tolerance,
warmup trick, Chromium/TLS exception or weakened policy was introduced.

Evidence, including unsuccessful/superseded short attempts, is retained under
`docs/measurements/master-completion-20261018/mixed-soak/`; focused JUnit is
`docs/measurements/master-completion-20261018/soak-focused.junit.xml`.
Private fixture databases, generated keys and native binaries are not published
as measurement artifacts.

## Completed hosted long workload

The protected x64/ARM64 run for `5cfd51d286c65558b92a6c070bcd7edd5a8b432b`
has now completed successfully: **120 cycles per platform**, **1204.37 / 1205.72 s**,
**720 / 720 actual/persisted requests**, with all benchmark gates true and
descriptors **6→6**, processes **1→1**, listeners **0→0**. Each platform passed
1281 Python cases including 333 real integrations, plus 14 frontend and 21 Go
cases. [Exact evidence and remaining limits](redjohn-github-actions-master-phase1.md).

## Remaining verification for later source changes

Later source snapshots require their own complete protected hosted x64/ARM64
Actions run. The completed earlier CI SHA does not verify newer code.
Native/browser RSS cannot be explained solely by
controller tracemalloc; allocation sites and retained measurement/cache size are
reported without claiming absence of every leak or a fabricated baseline gain.
The cooperative 2-GiB runtime/host admission budget is not presented as an OS
hard-memory limit; dedicated kernel cgroup/OOM E2E remains a separate test.
