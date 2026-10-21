# Controller memory attribution

The historical `fc1f70dceffa23db653e3bd24d40e27aa7947b21` result remains
unchanged: cold-controller private memory to post-cleanup/GC/tracer-stop/one-call
glibc trim was +44,724,224 bytes x64 and +50,884,608 bytes ARM64. This was an
instrumented benchmark, not an uninstrumented production-controller leak test.
Almost all the increase already existed after the first real cycle: from that
checkpoint to the final trimmed observation, private memory changed by
-3,985,408 / +1,155,072 bytes. Active warm cache and closed-runtime checkpoints
are different states; this is not a universal leak-free claim.

## Controlled evidence already completed

[Attribution run 39536117198](https://github.com/akosdrx/redjohn/actions/runs/39536117198)
completed successfully on Ubuntu 24.04 x64 / CPython 3.13.16 and ARM64 / CPython
3.12.3 at `0b978b8baf5511d4e75709b10787e8b06dab426f`. All 821 frozen source
hashes and 63 indexed artifact files per platform were independently checked.
Each fresh owner used the unchanged 2 GiB kernel budget, 4 GiB shared aggregate,
zero swap, owner PID limit 512, owner group OOM, capability drop and read-only
cgroup/proc guard. The independent evidence supervisor stayed outside the owner.

Each mixed case executes two actual HTTPS Chromium → inventory → httpx → Nuclei
scheduler cycles against the owned TLS fixture, with positive/fixed controls,
request-budget agreement and process/FD/listener cleanup. Import-only, TLS and
synthetic pressure controls are not scanner detections or mock scanner proof.

| Cold to final trimmed private bytes | x64 | ARM64 |
|---|---:|---:|
| Idle measuring control | 344,064 | -53,248 |
| Playwright import only | 4,141,056 | 4,390,912 |
| TLS fixture only | 3,792,896 | 3,272,704 |
| Synthetic limit pressure only | 647,168 | 798,720 |
| Real mixed work, legacy snapshots + tracing | 30,187,520 | 39,219,200 |
| Same work, compact summaries + tracing | 25,198,592 | 30,191,616 |
| Same work, tracing not requested | 13,201,408 | 12,431,360 |

The snapshot change reduced private memory by 4,988,928 / 9,027,584 bytes in
these matched short runs. Current CPython arena counts fell from 76 to 71 / 76
to 68. Live allocated small-block bytes were nearly unchanged: legacy to compact
62,029,632 → 61,939,392 / 61,034,592 → 60,936,608. Legacy versus untraced current
arenas were 76 versus 62 / 76 versus 60. These are allocator reservations and
live/free blocks, not resident-page counts to be added to RSS.

The controller loaded 67 additional modules; 56 were reproduced by importing
the Playwright API alone. Source cache retention was 2,614,139 / 2,601,100 bytes
above baseline. This counter sums `sys.getsizeof` for cached Python source-line
strings, including string-object overhead; it excludes cache list/dict overhead
and is not an encoded source-file byte count. Mapped cryptography private pages grew 2,629,632 / 2,170,880 bytes.
The same extra modules/source-cache counts appeared in all three mixed cases.
No named GC-tracked AssessmentRuntime, BrowserDiscoveryService, Playwright
Connection, Browser, BrowserContext or Page remained after diagnostic GC.
This probe does not enumerate every opaque native allocation. Global import/API
singletons remain intentionally available. None of these counters or separate
controls is summed into an invented byte-exact causal decomposition.

## Change and tradeoff

The benchmark previously retained a complete warmup `tracemalloc.Snapshot`
through the entire workload and built complete traceback-statistic maps for
summaries. Compact mode retains numeric size/count pairs per allocation site,
releasing the complete snapshot immediately. Public-API streaming avoids the
stdlib grouping's cache of complete stack keys. Tests compare every allocation
site and positive/negative count delta with actual stdlib snapshot statistics.

The profiler still costs memory and CPU. Reported two-cycle `elapsed_seconds` were
35.475 / 35.549 seconds legacy, 67.993 / 56.696 compact, and 7.655 / 6.987
without allocation tracing. These times exclude final report serialization and
post-event-loop allocator probing; the owner receipt and CI command duration
record the complete external envelope. The runs without allocation tracing still
contain mapping/object/process observers, so they are not uninstrumented
production measurements. This diagnostic runs only in the benchmark, not the
RedJohn runtime.
Natural cleanup is recorded before GC, tracer stop and the explicitly labelled
one-call trim. No allocator policy or protection is changed in normal runtime.
Supplemental controller counters do not change historical observation fields.

The original allocation-group classifier matched the checkout directory name
`/redjohn/` before the benchmark directory. It therefore mislabeled benchmark
and other checkout allocations as `redjohn_runtime`. Classification now uses
explicit source roots, with a regression using the hosted checkout path. The
historical grouped field is not evidence of product-code retention. The CI
summary also enforces supplemental counters and released component types when
the actual soak command requests controller diagnostics.

The long acceptance gate must complete on its own new commit before this short
experiment is called long E2E verification. It requires all project checks and
120 cycles / 1200 seconds with compact tracing, plus separate hosted legacy and
untraced long controls. Missing counters, skipped capabilities, retained component
objects, nonzero OOM counters or unverified cleanup fail the gate.

## Commands

```bash
# Full project checks and compact long soak on both hosted architectures.
gh workflow run redjohn-ubuntu.yml -R akosdrx/redjohn \
  --ref codex/redjohn-controller-memory \
  -f soak_cycles=120 -f soak_minimum_seconds=1200

# Separate actual long attribution controls; distinct concurrency group.
gh workflow run redjohn-ubuntu.yml -R akosdrx/redjohn \
  --ref codex/redjohn-controller-memory \
  -f controller_profile_only=true -f controller_profile_long=true

# Targeted local contracts only; this is not Linux/kernel E2E.
.venv/bin/python -m pytest tests/test_soak_memory_profile.py \
  tests/test_soak_fault_contracts.py -q
```

GitHub logs, JUnit, exact source hashes, Python/tool versions, mapping categories,
allocator counters and owner/cleanup receipts are preserved even on failure.
Only numeric memory counters and Python source locations are retained; no heap
values, authentication bodies, process arguments or environment are captured by
the controller diagnostics. The existing CI command logger uses fixed fixture
commands only. No active tests, user configurations or existing integrations
were removed. Local Git HEAD/index and private MCP configuration are untouched.

Allocator semantics: [CPython memory management](https://docs.python.org/3.13/c-api/memory.html),
[tracemalloc](https://docs.python.org/3.13/library/tracemalloc.html), and
[glibc allocation statistics](https://sourceware.org/glibc/manual/latest/html_node/Statistics-of-Malloc.html).
