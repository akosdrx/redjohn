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
