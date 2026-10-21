# RedJohn browser workload measurements

The standalone runner uses the existing `AssessmentRuntime`, persistent
scheduler and private host-resource ledger on its own ephemeral HTTPS fixture.
It alternates Alice/Bob cookie contexts, verifies their server-side observation,
and performs explicit browser retests. It never accepts a remote target URL.

From the repository root, with the browser extra and Chromium already installed:

```sh
PYTHONPATH=RedJohn .venv/bin/python RedJohn/benchmarks/browser_soak.py \
  --output /tmp/redjohn-browser-soak --cycles 100 --warmup 10 --interval-seconds 5
```

Use a fresh output directory. Each cycle starts at least the selected interval
after the preceding cycle started; normal origin admission, request, job and
campaign limits remain active. The default pacing fits this fixture's normal
60-request origin window. A zero interval is a deliberate pressure workload:
blocked cycles stay blocked and `ok` is false if any crawl failed. There is no
override that turns rate-limit denial into a successful crawl.

Successful browser execution can still have `partial` coverage: this fixture's
automatic mutating POSTs remain blocked. `ok` checks the stated workload and
cleanup invariants, not complete assessment coverage or absence of memory leaks.

The JSON result contains per-cycle memory/process/FD/TCP-listener samples,
browser page/context/proxy cleanup counts, p50/p95 execution time, actual HTTP
requests, the host ledger after close, observer errors and source hashes. The
sampler has a three-second command deadline, bounded captured output and sample
count. Missing OS observation remains unavailable. Sampling itself opens short
lived descriptors; compare the per-cycle range and the workload phase before
interpreting descriptor growth. A live process-tree observation does not fully
track a descendant that has already reparented itself.

The full pytest source snapshot and this standalone runner have separate
verification records. The runner checks its own source and all imported
RedJohn source files before/after the workload. It does not change those sources
or mock scanner output. No Nuclei or optional scanner starts in this benchmark;
cache pressure, maximum queue/body/log load and a longer mixed scanner soak are
separate checks. Actual elapsed time is reported without claiming an old/new
speedup or vulnerability detection accuracy.

[Shared resources and OS limits](../docs/shared-resources-and-os-memory.md).
[Actual measurements and remaining boundaries](../../docs/redjohn-resource-runtime-verification.md).

## Mixed scheduler and limit-pressure workload

`mixed_soak.py` uses the same persistent queue for actual Chromium discovery,
the explicitly selected pinned httpx engine, and pinned Nuclei. Each cycle
alternates Alice/Bob and positive/fixed controls, reconciles httpx's actual
response into inventory, then scans that observed surface. Resubmitting the
same Nuclei job must produce no new request. Engines are selected and run
sequentially, with normal origin rate admission and no network-policy bypass.

```sh
PYTHONPATH=RedJohn .venv/bin/python RedJohn/benchmarks/mixed_soak.py \
  --output /tmp/redjohn-mixed-soak \
  --nuclei-lock RedJohn/.tools/nuclei/3.11.1/fixture-lock.json \
  --httpx-receipt RedJohn/.tools/httpx/1.12.0/receipt.json \
  --cycles 120 --warmup 10 --interval-seconds 10 --minimum-seconds 1200
```

Use this long command on a properly provisioned Linux CI runner. Local debug
may select two cycles and zero minimum duration; it is not a long-soak result.
Both the cycle count and minimum active duration must be met. More paced cycles
run if the selected duration has not elapsed; the duration is not filled with
idle waiting. The entire runner has a maximum 65-minute deadline and at most
1000 cycles. Invalid values are rejected, never silently reduced.

Separate, explicitly synthetic pressure checks drive the actual production
supervisor to its 512-KiB stdout/stderr caps and the actual proxy to its 8-MiB
wire cap and one byte beyond it. This is real process/socket enforcement proof,
not scanner detection evidence. Another connection observes the full 128-item
SQLite queue; overflow is rejected, dedup works while full, and those artificial
jobs are cancelled before execution. The same runtime cache is repeatedly
filled past its 8-MiB serialized-byte budget and oversized inserts/retest bypass
are verified. None of these quotas are relaxed for the benchmark.

The JSON result retains measured execution/queue-wait times, per-cycle RSS,
process/FD/listener observations, bounded observer samples, controller-only
tracemalloc allocation sites, actual request accounting, pinned engine hashes,
positive/fixed findings and cleanup checks. It records failure evidence before
propagating a workload error. RSS includes native children and may double-count
shared pages; tracemalloc excludes those children. A successful bounded workload
does not establish the absence of every memory leak. There is no fabricated
old/new baseline, model token saving, cloud/provider call, or original RCE proof.

GitHub Actions runs a short mixed workload on push/PR. Its manual inputs select
the minimum cycle count and minimum active duration; the fixed pacing is ten
seconds and one warmup cycle is excluded from latency percentiles. The strict
summary rejects absent/failed/wrong-commit soak evidence. Artifacts include the
JSON and command log on failure, with the existing job-owned cgroup/AppArmor
cleanup unchanged in strength.

A push whose commit message contains `[redjohn-long-soak]` selects at least
120 cycles and 1200 seconds of active mixed workload on both native runners.
This provides a reviewable, commit-bound long-run trigger through an ordinary
authorized push, without requiring separate workflow-dispatch credentials.
The marker only increases workload; it does not change security checks, scopes,
tool pins, limits or the strict result gate. PR events retain the short workload
unless manually dispatched with explicit inputs. Every report records the
selected duration and actual elapsed time; a marker itself is not success.
