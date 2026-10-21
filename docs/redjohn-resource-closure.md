# RedJohn environment and complete-workload memory verification

This change keeps RedJohn's identity, operator configurations, active tests and
existing integrations. The previous completed baseline is source
`3cc92d20ee37fe54663dc7c25a73aeb802f98ef1`,
[run 39505094482](https://github.com/akosdrx/redjohn/actions/runs/39505094482).
Its 120-cycle x64/ARM64 soak and 454 real integrations per architecture remain
valid historical evidence. It did not impose a whole-workload kernel memory cap.

## Python environment

The old local environment mixed this checkout with editable `redjohnrenew`
packages and packaging-only tools. The clean profile installs this checkout's
`browser` and `graphql` extras plus pytest, pytest-asyncio, mypy and Ruff, using
the existing exact CI versions as constraints. PyInstaller belongs to the
separate `packaging` dependency group. Other projects are not edited or removed.

Run from the repository root with a trusted base Python 3.12/3.13 executable:

```sh
.venv/bin/python RedJohn/scripts/prepare-python-environment.py inventory \
  --report /absolute/private/environment-before.json
.venv/bin/python RedJohn/scripts/prepare-python-environment.py prepare \
  --destination /absolute/new-environment \
  --python /absolute/base-python \
  --report /absolute/private/environment-candidate.json
/absolute/new-environment/bin/redjohn --help
```

Preparation refuses an existing destination. Verification requires `pip check`,
the current checkout's RedJohn import, environment-local SDK/browser/MCP imports
and no foreign editable project. Reports contain local package identities and
sizes, never credential values or authenticated dependency URLs. No package's
internal files are selectively deleted. The original environment remains until
the candidate checks and active-process review have passed. Final installation
uses its real destination path, preserving entry-point shebang correctness.

Initial actual candidate: 13,896 to 8,534 Python files, 5,362 fewer (38.59%).
Apparent regular-file bytes: 644,633,202 to 582,709,994 before subsequent smoke
imports/cache writes. All retained distribution versions are unchanged. Forty-eight
old distributions are absent and three build-helper distributions are newly
present. File counts describe the environment itself, not a hidden or symlinked
project view. The final `.venv` was freshly reinstalled at its original path,
not moved from the candidate. It contains **8,534 Python files**, versus 13,896;
the complete project folder now has **8,971**, versus the initial 14,326, while
new implementation/regression files were added. Final pre-smoke apparent bytes:
582,298,172; after the selected smoke/import checks: 582,952,015. Allocated sizes
reported by `du -sh` are 698 MiB before and 609 MiB after (rounded).
The previous environment is preserved at
`/Users/akosdrx/.local/share/redjohn/environment-backups/rjkali-20261021T000525Z`.
The backup deliberately still consumes disk; reduced active-environment size
does not claim those rollback bytes have been freed.

No process references or open environment files were observed immediately before
the swap. The final environment passed imports, `pip check`, CLI help and all
42 selected contract/local-HTTP/real-HTTPS cases (10.28 s). The clean candidate
also passed strict mypy over all 250 production modules. To restore, first ensure
no process is using `.venv`, then move the clean environment aside and put the
backup back at its original path:

```sh
mv .venv /absolute/new-unused-clean-environment-backup
mv /Users/akosdrx/.local/share/redjohn/environment-backups/rjkali-20261021T000525Z .venv
.venv/bin/python -m pip check
```

The archived environment's entry-point scripts still name its original `.venv`
path; restore that path before using its command-line tools. No `redjohnrenew`
source or that project's own environment was deleted.

The separate tools-only packaging environment is
`/Users/akosdrx/.local/share/redjohn/packaging-environments/rjkali-pyinstaller-6.22.3`.
Its `pip check` passed and `python -m PyInstaller --version` returned `6.22.3`.
It contains seven distributions and 1,945 Python files, outside this checkout;
23,020,228 apparent bytes / 35,291,136 allocated bytes. It does not yet contain
the application's runtime dependencies and no complete app freeze was tested.
Install the reviewed application manifest and build dependencies in that
packaging environment before a future app freeze; do not copy site-packages
from the development environment.

The 48 absent distributions are accounted for as follows. Absence from the new
resolved dependency closure does not claim that another project can run without
them; that project's files and environment are untouched.

| Reason | Exact old distributions absent from the active environment |
|---|---|
| Foreign editable checkout, not this RedJohn manifest | `redjohn-cli 0.1.0`, `redjohn-core 0.1.0`, `redjohn-tui 0.1.0`, `strix-agent 1.7.0` |
| Packaging-only tools, now in the separate packaging profile | `pyinstaller 6.22.3`, `pyinstaller-hooks-contrib 2026.8`, `altgraph 0.17.5`, `macholib 1.16.4` |
| Not required by the current runtime/browser/GraphQL/test dependency closure | `aiosqlite 0.22.1`, `alembic 1.20.0`, `annotated-doc 0.0.5`, `anthropic 1.13.0`, `docstring_parser 0.18.0`, `fastapi 0.143.0`, `httpcore2 2.13.1`, `httpx2 2.13.1`, `jsonpatch 1.35`, `jsonpointer 3.2.1`, `langchain-core 1.6.10`, `langchain-protocol 0.0.19`, `langgraph 1.2.2`, `langgraph-checkpoint 4.2.0`, `langgraph-checkpoint-sqlite 3.1.1`, `langgraph-prebuilt 1.1.0`, `langgraph-sdk 0.3.15`, `langsmith 0.14.7`, `linkify-it-py 2.2.0`, `Mako 1.4.3`, `mcp-types 2.3.0`, `mdit-py-plugins 0.6.1`, `opentelemetry-api 1.45.1`, `openviking-sdk 0.1.14`, `orjson 3.13.0`, `ormsgpack 1.12.2`, `platformdirs 4.13.0`, `psutil 7.2.2`, `python-json-logger 4.2.0`, `requests-toolbelt 1.0.0`, `setuptools 84.0.0`, `shellingham 1.5.4`, `SQLAlchemy 2.1.4`, `sqlite-vec 0.1.9`, `textual 8.2.8`, `truststore 0.10.4`, `typer 0.27.3`, `uuid_utils 0.17.1`, `xxhash 4.0.1`, `zstandard 0.25.0` |

All retained distribution versions are unchanged. The three additions are
`editables 0.5`, `hatchling 1.27.0` and its `trove-classifiers 2026.9.21.13`
build dependency. LiteLLM, OpenAI/Agents SDK, MCP, Playwright, Google Auth and
Boto3 remain. Actual LiteLLM Anthropic/Bedrock/Gemini handler imports succeeded
without the old direct Anthropic SDK. This verifies imports and dependency
resolution, not live access to every provider.

Actual candidate checks: 41 MCP/cache/GraphQL contract/local-HTTP cases passed,
then one real HTTPS Chromium/inventory/Nuclei process-restart E2E passed in
9.25 seconds. These are targeted macOS checks, not Linux cgroup proof or a full
local regression. The first candidate failed before editable installation because
the pinned build backend required `editables`; the installer now explicitly
pins that build helper. The failed install did not replace the old environment.

## Whole-workload Linux boundary

The existing pre-exec owner now encloses the complete mixed workload: fresh
controller, TLS fixture, cache/queue/body/log pressure, Chromium/Node and serial
httpx/Nuclei descendants. The owner limit is 2 GiB, its shared aggregate pool
4 GiB, owner PID limit 512, swap zero. Owner `memory.oom.group=1` keeps a selected
owner's descendants together; aggregate `memory.oom.group=0` does not request
an atomic kill of the entire pool. It does not guarantee sibling-owner survival:
the kernel can select one or more owner groups under aggregate pressure.
These are kernel controls, separate
from cooperative admission and sampled RSS.

The bounded evidence supervisor stays outside the workload and reports its own
peak RSS. The ordinary host-user ledger's `os_hard_limit: false` remains truthful
about that ledger; the separate kernel owner/aggregate receipt provides the
actual hard-limit proof. No unrelated host process, external daemon or remote
worker is claimed inside the boundary. Missing delegation, attestation or
namespace capability blocks required execution; host security is not relaxed.

The CI gate requires exact kernel controls, namespace attestation, no OOM in a
normal soak, removed owner cgroup and verified process cleanup. The receipt's
digest is bound to the commit-bound command record. Existing and added actual
kernel controls cover OOM/setsid, aggregate ownership, cancellation, timeout,
owner death, startup failure and missing delegation separately from mock tests.
The deliberate fault-injection limits are 64/96/128 MiB; they exercise real
kernel OOM and group ownership without claiming a 4 GiB exhaustion stress test.
The 512-PID ceiling is read back from the kernel; PID exhaustion was not tested.

## Memory diagnosis and timing

The prior 85–86 MB process-tree RSS increase is an observation, not a demonstrated
leak. The new benchmark reports bounded per-phase/per-process measurements,
Linux PSS/private memory where available, kernel counters, controller allocation
changes, cache bytes before/after close and separately labelled GC diagnostics.
Exact workload-loop start/end/duration and pacing are recorded independently of
setup/cleanup elapsed time. RSS, PSS, Python tracing and kernel charging are
different quantities and must not be substituted for each other.

Process roles use only the executable basename read from `/proc/PID/exe`, with
PID/start identity rechecks; denied/unavailable reads explicitly fall back to
the comm name. No executable path, argv or environment is exported. This avoids
misclassifying a Node `MainThread` or Chromium `headless_shell` as a generic
descendant when the executable identity is readable. Permission-denied scanner
PSS remains unavailable rather than being reported as zero.

After natural cleanup, diagnostic GC and tracer shutdown, a separate bounded
glibc `malloc_trim(0)` probe records explicit controller RSS/PSS/private and
kernel observations immediately before/after its one call. Library/symbol
initialization precedes the explicit before measurement. The tenth checkpoint
reuses the actual after observation. An unavailable probe is blocked evidence;
a return of zero or one is valid without requiring any RSS drop. This is a
controller allocator diagnostic, not a change to production allocator policy
or to cleanup acceptance. A measured drop localizes reclaimable allocator
pages; it does not by itself prove universal leak freedom or explain every byte.

A reproducible retained-cache issue was found: closing a still-referenced
SmartCache kept its stored values. The original real pressure payload retained
6,291,462 serialized bytes in three entries, versus zero after the fix without
forcing GC. Serialized payload bytes are not an equal RSS reduction.
Clearing closed cache storage must
preserve existing in-flight ownership and late-publication fences. This explains
a measured subset, not the complete historic RSS increase. The completed long
run below records the remaining attribution boundary without a universal
leak-free claim.

## Live model and wider capability boundaries

The existing terminal/IPC/SQLite test is genuine terminal integration and remains
active. It does not claim a model-driven scan. A separate manually dispatched
live-model test requires explicit provider/model configuration and a CI secret;
no local key is automatically uploaded. Missing model access is blocked evidence,
never successful LLM coverage. Product provider integrations remain intact.

WPScan's approved offline HTML observation and the real two-advisory Trivy SBOM
fixture are complete within [their documented scope](redjohn-artifact-runtime.md).
Full WordPress assessment/license closure, full official Trivy feed/additional
formats, authenticated/mutating target MCP, attested remote/Docker target
execution and public OAST/DNS/IPv6 proof remain separate limitations. Live
cloud/Kubernetes and the original RCE fixture remain operator-deferred.

## Launch and repeat commands

From this repository root, use the freshly installed environment:

```sh
.venv/bin/redjohn --help
.venv/bin/python -m pip check
PYTHONPATH=RedJohn .venv/bin/python RedJohn/scripts/update-capability-matrix.py --check
```

Repeat the complete hosted matrix, including the long window, without a local
VM regression:

```sh
gh workflow run redjohn-ubuntu.yml --repo akosdrx/redjohn \
  --ref codex/redjohn-resource-closure \
  -f soak_cycles=120 -f soak_minimum_seconds=1200
```

The workflow invokes the existing `memory_exec` pre-exec boundary with explicit
`--memory-budget-mib 2048 --aggregate-budget-mib 4096` before starting the fresh
benchmark controller. Existing operator defaults are not silently rewritten.
Use the [separate live-model invocation](redjohn-live-model-e2e.md) only after
an explicit model and dedicated CI credential have been configured. The
packaging tools have a separate interpreter:

```sh
/Users/akosdrx/.local/share/redjohn/packaging-environments/rjkali-pyinstaller-6.22.3/bin/python -m pip check
/Users/akosdrx/.local/share/redjohn/packaging-environments/rjkali-pyinstaller-6.22.3/bin/python -m PyInstaller --version
```

## Changed files

The runtime implementation changes 32 source/test/documentation paths relative
to the preserved preceding evidence commit. Three additional catalogue paths
are documentation-generation metadata only. Existing active tests are retained.

```text
.github/scripts/ci.py
.github/scripts/linux-tests.sh
.github/scripts/live-model-e2e.py
.github/scripts/live-model-gateway.py
.github/scripts/live-model-linux.sh
.github/scripts/native-summary.py
.github/tests/test_ci.py
.github/tests/test_live_model_harness.py
.github/tests/test_native_ci.py
.github/workflows/redjohn-live-model.yml
.github/workflows/redjohn-ubuntu.yml
RedJohn/benchmarks/memory_profile.py
RedJohn/benchmarks/mixed_soak.py
RedJohn/pyproject.toml
RedJohn/redjohn/assessment/cache.py
RedJohn/redjohn/assessment/memory_exec.py
RedJohn/redjohn/assessment/memory_pool.py
RedJohn/redjohn/assessment/os_memory.py
RedJohn/redjohn/config/settings.py
RedJohn/redjohn/core/inputs.py
RedJohn/redjohn/core/runner.py
RedJohn/scripts/prepare-python-environment.py
RedJohn/scripts/update-capability-matrix.py
RedJohn/tests/test_assessment_resource_control.py
RedJohn/tests/test_mcp_target_contracts.py
RedJohn/tests/test_model_output_budget.py
RedJohn/tests/test_owned_memory_live.py
RedJohn/tests/test_soak_fault_contracts.py
RedJohn/tests/test_soak_memory_profile.py
docs/redjohn-capabilities.json
docs/redjohn-capabilities.md
docs/redjohn-completion-status.md
docs/redjohn-live-model-e2e.md
docs/redjohn-requirements.md
docs/redjohn-resource-closure.md
```

## Completed hosted verification — source fc1f70dc

The [complete Ubuntu run 39526474772](https://github.com/akosdrx/redjohn/actions/runs/39526474772)
finished with `conclusion: success` for both required jobs on exact source
`fc1f70dceffa23db653e3bd24d40e27aa7947b21`.
[The tested workflow](https://github.com/akosdrx/redjohn/blob/fc1f70dceffa23db653e3bd24d40e27aa7947b21/.github/workflows/redjohn-ubuntu.yml)
ran on GitHub-hosted Ubuntu 24.04, x64/Python 3.13.16 and ARM64/Python 3.12.3.
Images: x64 `20261012.334.1`, ARM64 `20261018.154.1`;
kernels: x64 `Linux-6.17.0-1022-azure-x86_64-with-glibc2.39`, ARM64 `Linux-7.0.0-1017-azure-aarch64-with-glibc2.39`.

| Platform | Python regression | Real integration | Frontend | Go race-tested | Failed / errors / skipped |
|---|---:|---:|---:|---:|---|
| x64 | 1585 | 456 | 14 | 21 | 0 / 0 / 0 |
| ARM64 | 1585 | 456 | 14 | 21 | 0 / 0 / 0 |

Each Python regression total includes **208 explicitly labelled mock contracts**
and 1,377 unit/contract/mixed cases. Frontend includes eight unit/contracts and
six fetch doubles; frontend/Go JUnit does not itself classify evidence, so the
CI classification is recorded separately. All 456 integration cases have the
actual `real_integration` JUnit property. Three active Darwin-only cases are
listed as platform-not-applicable, not successful Linux tests or hidden skips.
All 1,558/454/14/21 historical baseline testcase identities remain present;
27 regression and two integration cases were added. The intermediate 1,576-case
regression selection also remains entirely present, with nine additions.

The separate [native run 39526474747](https://github.com/akosdrx/redjohn/actions/runs/39526474747)
passed 1,585 regressions and 26 actual native cases per architecture. The separate
[artifact run 39526474754](https://github.com/akosdrx/redjohn/actions/runs/39526474754)
passed 11 actual WPScan/SBOM cases plus three strict orphan-recovery repetitions
per architecture. These overlap cases from the full suite; do not add them as
unique new coverage. No active test file or case was removed.

Both complete soaks met all **16 invariants**, zero normal owner/pool OOM events,
zero residual reservations, baseline process/FD/listener counts, closed browser
pages/contexts/proxy connections, and verified owner/process/cgroup/AppArmor
cleanup. Each used owner **2,147,483,648 B**, aggregate **4,294,967,296 B**, swap
zero, owner `memory.oom.group=1` and pids 512. The aggregate OOM group is zero
and pids limit 4096. No host namespace protection was disabled. The ten required
actual kernel fault/inheritance controls and all eleven artifact-owner receipts
were independently checked in the full artifacts.

| Measurement | x64 | ARM64 |
|---|---:|---:|
| Completed cycles | 120 | 120 |
| Scheduled jobs | 360 | 360 |
| Actual requests / durable budget usage | 720 | 720 |
| Explicit workload loop (s) | 1200.156791 | 1200.326945 |
| Pacing within loop (s) | 892.324768 | 788.795085 |
| Loop excluding pacing (s) | 307.832023 | 411.531860 |
| Runtime setup outside loop (s) | 0.389367 | 0.566574 |
| Complete benchmark including setup/cleanup/diagnostics (s) | 1209.547936 | 1214.219902 |
| Actual owner kernel peak (B) | 402,726,912 | 339,881,984 |
| Actual aggregate kernel peak (B) | 402,739,200 | 339,894,272 |
| Outside evidence supervisor peak RSS (B) | 20,914,176 | 19,410,944 |
| Retained / total captured profile samples | 561 / 2240 | 482 / 1921 |
| Natural process-tree RSS before (B) | 112,537,600 | 111,570,944 |
| Natural process-tree RSS after cleanup, before GC (B) | 212,385,792 | 196,771,840 |
| Natural process-tree RSS increase (B) | 99,848,192 | 85,200,896 |
| Cache serialized payload before close (B) | 6,291,462 | 6,291,462 |
| Cache serialized payload after close (B) | 0 | 0 |
| Controller RSS immediately before allocator trim (B) | 209,244,160 | 194,699,264 |
| Controller PSS immediately before allocator trim (B) | 197,582,848 | 185,591,808 |
| Controller private immediately before allocator trim (B) | 194,658,304 | 182,886,400 |
| Controller RSS immediately after allocator trim (B) | 160,382,976 | 163,971,072 |
| Controller PSS immediately after allocator trim (B) | 148,721,664 | 154,863,616 |
| Controller private immediately after allocator trim (B) | 145,797,120 | 152,158,208 |
| RSS/PSS/private decrease during actual trim (B) | 48,861,184 | 30,728,192 |
| Controller RSS after trim minus initial profile (B) | 47,792,128 | 52,195,328 |

Each loop had 60 positive and 60 fixed cycles, running actual headless Chromium
→ inventory → httpx → Nuclei jobs serially against owned loopback TLS fixtures.
The loop timestamps exclude runtime setup; pacing is explicitly inside the
1,200-second window. Synthetic queue/cache/log/body pressure exercises actual
bounded implementations; it is not additional scanner detection evidence.

The real glibc **2.39** diagnostic returned 1 on both architectures (one call
only; x64 0.003069321 s, ARM64 0.007458833 s). Its explicit pre/post observations
prove **48,861,184 B / 30,728,192 B** of reclaimable controller allocator residency
in these runs. This does not fully attribute the historical 85–86 MB observation.
After trim, controller RSS remains **47,792,128 B / 52,195,328 B** above its initial
profile; that residual is not fully attributed. Cache payload release, live
Python bytes, tracer metadata, observer JSON and allocator/RSS changes are
separate quantities, not an additive causal decomposition. No universal
leak-free claim or automatic production `malloc_trim` policy is made.

All named roles (controller, Chromium, Node, httpx and Nuclei) were actually
observed with the new executable-identity classifier. Role peaks below are
sampled at different times and cannot be summed into a concurrent peak.

| Role | x64 peak RSS / PSS / private (B) | ARM64 peak RSS / PSS / private (B) |
|---|---|---|
| controller | 210,829,312 / 199,168,000 / 196,243,456 | 195,772,416 / 186,664,960 / 183,959,552 |
| node | 126,210,048 / 122,424,320 / 121,970,688 | 138,006,528 / 135,433,216 / 134,750,208 |
| chromium | 474,460,160 / 189,258,752 / 91,017,216 | 502,267,904 / 198,086,656 / 104,009,728 |
| httpx | 211,013,632 / 211,005,440 / 211,005,440 | 190,676,992 / 190,668,800 / 190,668,800 |
| nuclei | 171,859,968 / 171,851,776 / 171,851,776 | 105,480,192 / unavailable / unavailable |

Chromium peaks comprise seven processes. ARM64 Nuclei's highest RSS sample used
an explicit comm fallback and had unavailable PSS/private; a different complete,
executable-identified sample recorded RSS 105,037,824 B
and PSS/private 105,029,632 B. Those lower-sample values are not substituted for
missing peak values. Some transient descendant reads also disappeared or denied
smaps; these observations stay explicit, never zero-memory results.

Each final artifact has **813 verified source hashes and 377 verified indexed
files**, independently checked against the frozen manifest. Source hashes,
JUnit, commands/build logs, `*-versions.json`, `tool-receipts`, resource time
series, kernel receipts and cleanup evidence are retained by Actions even on
failure. Build/scanner version pins and provenance were rechecked; core versions
include Playwright 1.58.0 / Chromium 145.0.7632.0, Nuclei 3.11.1, httpx 1.12.0,
frontend-build Node 22.14.0 and Go 1.25.1. The browser-driver Node is supplied
by the separately pinned Playwright package, not inferred to have the frontend
Node version.

| Final artifact | GitHub artifact ID | Verified ZIP SHA-256 |
|---|---:|---|
| x64 | 12315600630 | `b136fe2e2d68670c0cdfadd519c727fc77184728faca871c0707a56b1d65db1a` |
| ARM64 | 12315381746 | `6df84cebf8a3a6f9ee5937a2dca9d9f12dad81dc0a18651513f072f1a4b0e01d` |

The [separate model capability run 39526571218](https://github.com/akosdrx/redjohn/actions/runs/39526571218)
is **blocked**, not successful real model E2E. Both platforms lack an explicit
model and dedicated repository secret; each preflight JUnit has one error,
zero failures and zero skipped cases. No real model, CLI/TUI model scan or scanner
installation ran in that job. The normal full workflow's skipped optional
model job is likewise not model proof. See the [exact access and harness boundary](redjohn-live-model-e2e.md).

The correct GitHub user was reverified as `akosdrx`. Local Git HEAD
`115c7958232f1be5b34fe95159b21b86e85af06f`, index SHA-256
`95c507103b42959002663306e132127a1c2fbc4b0d3c04b4c2b97283ad8419db`
and private MCP configuration SHA-256
`37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570`
remain unchanged. Source was published to the separate
`codex/redjohn-resource-closure` branch with a non-force expected-head lease;
813 Git blob identities/modes and secret patterns were checked before upload.
Final measurement documentation is a documentation-only successor; these results
belong to source `fc1f70dc`, never silently to a later SHA.

## Intermediate diagnostic evidence

The first complete workload-bound run,
[`39520343037`](https://github.com/akosdrx/redjohn/actions/runs/39520343037),
completed successfully on both architectures at
`fefc3bf9d9e3dc0451f8f4d97cf91e630dc63747`. Its nine-checkpoint profile exposed
additional measurement limits: natural post-cleanup controller RSS still rose
about 86 MB on ARM64, GC did not lower it, stopping the tracer lowered it by
1,028,096 bytes, and comm-only role classification missed Chromium/Node names.
The cache release is proven; the remaining controller-resident memory is not
fully attributed by that run. These findings prompted the executable-identity
and allocator-diagnostic follow-up. The new ten-checkpoint source received its
own completed hosted validation above; no intermediate result is silently
reassigned to that source.

One intermediate source, `3d7cf156b7889f643aacabbf384a25d5e21dbcae`, had an x64
[regression failure](https://github.com/akosdrx/redjohn/actions/runs/39519351016):
1,573 passed / one failed; ARM64 had 1,574 passed. Its 26 actual native cases
passed on both architectures. The failing existing MCP deadline test used a
dispatch wall-clock threshold that could include delayed event-loop callbacks.
The corrected test retains the real overall deadline and asserts the actual
remaining timeout passed to `asyncio.wait_for`, including preparation time.
Two controls prove that an intentionally delayed callback still gets the proper
reduced budget and that resetting the budget is rejected. Production scheduling
and isolation were not relaxed. The superseded long run was cancelled before
soak completion, not counted as successful. The corrected fast
[native](https://github.com/akosdrx/redjohn/actions/runs/39520342993) and
[artifact](https://github.com/akosdrx/redjohn/actions/runs/39520342988) runs have
completed successfully on both architectures at
`fefc3bf9d9e3dc0451f8f4d97cf91e630dc63747`.
