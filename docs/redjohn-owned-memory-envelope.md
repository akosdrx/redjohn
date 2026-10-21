# Owned local Linux memory envelope

`python -m redjohn.assessment.memory_exec` starts the complete existing RedJohn
CLI/TUI command in a fresh owned Linux cgroup before the owner allocates its
application state. Local Chromium, SDK Shell, native scanner and stdio MCP
descendants inherit that group. The durable Scheduler, policy checks, queues,
resource admission and cancellation paths remain the existing implementations.
There is no second job queue and no automatic replay after OOM.

This is an **opt-in inherited-local-process guarantee**, not a universal host
budget or side-effect confinement. Default cooperative admission remains
available. `ResourceGovernor.snapshot()` and assessment reports now expose
actual kernel fence telemetry independently of the cooperative ledger, including
when the outer launcher is used without an `os_memory` assessment field.

## Requirements and startup

The operator must provide an owned, private cgroup-v2 delegation with the memory
and pids controllers enabled. The implementation does not run sudo, change
host-wide controls or adopt an unknown group. Bubblewrap and unprivileged user
and mount namespaces are also required. A missing prerequisite blocks the
requested profile; it never falls back to a software memory estimate.

From `RedJohn/`, a lightweight launch example is:

```sh
../.venv/bin/python -m redjohn.assessment.memory_exec \
  --delegated-root /sys/fs/cgroup/OPERATOR_DELEGATED_ROOT \
  --memory-budget-mib 1024 \
  --aggregate-budget-mib 4096 \
  --receipt "$HOME/.redjohn/memory-evidence/launch.json" \
  -- redjohn --help
```

Replace the trailing command with the existing scan arguments. For the actual
SDK path, select `REDJOHN_RUNTIME_BACKEND=local`; Docker and custom SDK backend
ownership is not attested by descendant inheritance. CLI and TUI stdin/stdout
remain inherited. The default owner deadline is 3600 seconds, configurable up to
86400. SIGINT, SIGTERM, timeout and normal completion all clean the owned group.
The receipt directory must be private and the receipt must not be a symlink.

An existing dedicated assessment config may opt into the same parent pool:

```json
{
  "os_memory": {
    "delegated_root": "/sys/fs/cgroup/OPERATOR_DELEGATED_ROOT",
    "aggregate_memory_budget_bytes": 4294967296,
    "pool_state_directory": "/ABSOLUTE/PRIVATE/memory-pools"
  }
}
```

Its owner budget remains `resources.total_memory_budget`. A matching inline
assessment borrows the actual existing fence. An already contained owner cannot
start a fresh boundary elsewhere. The SDK runner now checks an explicitly
requested inline profile before model or sandbox startup, rather than first
starting an uncontained SDK session and rejecting it later.

Borrowing rechecks the actual current kernel state: zero inheritable, permitted,
effective and ambient capabilities, no new privileges, a private single-UID
mapping, read-only cgroupfs, and absence of inherited cgroupfs descriptors.
All directory descriptors are also rejected, including handles on a different
device that could traverse an original mount with `openat`. The pre-exec bootstrap
applies the same descriptor exclusion; ordinary pipe/PTY descriptors remain valid.
Write-open probes (without writing) must fail for owner limits, migration
controls, and their aliases through the bounded actual ancestor `/proc/root`
chain. Matching membership, correct limits or an environment marker alone do not
grant inline startup authority. The borrowed boundary records this independent
current-state proof.

## Kernel controls and ownership

Each owner has `memory.max`, `memory.swap.max=0`, `memory.oom.group=1` and a bounded
`pids.max`. The shared parent `redjohn-aggregate-v1` has its own aggregate memory
and pids caps; parent OOM selects an owned leaf rather than killing the outside
supervisor. An OOM in an owner leaf kills the complete group, including detached
`setsid` descendants. Cleanup uses the existing inode/UID-attested cgroup fence,
waits for the subtree to empty, and only then releases/removes that fence.

The private parent contract is serialized by a bounded file lock and pins the
delegation inode, parent inode, memory cap and pids cap. Concurrent owners must
use the same contract. A later caller cannot reset a live/idle parent's budget.
Unknown groups, symlinked contracts, changed identities or readback mismatches
block admission. The empty parent and its private contract persist between runs;
changing the policy requires an operator-managed, drained profile change.

The owner also starts in a private user/mount namespace with zero capabilities
and no new privileges. Its cgroup filesystem is read-only. Startup independently
checks that opening its own memory control for writing fails and that the
supervisor's `/proc/PID/root` cannot expose a writable alias. These checks run
before the application exec, and a bounded, regular, schema-checked private
attestation distinguishes startup failure from a real owner exit. Host PID
identities remain usable by the shared ledger. The working directory and device
semantics are retained; real PTY input/output and a workspace Python build are
tested. Access relying on supplementary groups is not established by these
fixtures and must be checked for an operator's chosen namespace profile.

## Reproduced evidence

The focused Ubuntu ARM64 fixture uses its own copied source and private
delegations. `test_owned_memory_live.py` contains six actual cases:

1. Two detached children individually allocate below the owner cap, while their
   sum exceeds it. The kernel OOM kills the complete owner tree. An unrelated
   control process remains alive.
2. Two independent owners remain below their individual 96 MiB caps but exceed
   the common 128 MiB cap. The aggregate kernel peak reaches exactly
   **134217728 bytes** and one owned leaf is killed. A different requested parent
   budget is rejected without changing the existing cap.
3. A deadline cleans an owner and its detached descendant.
4. SIGTERM performs the same verified cleanup.
5. Real headless Chromium, an actual SDK session, a stateful confined MCP target
   process and a native worker overlap in one 1 GiB owner fence. Kernel
   membership proves they share the fence; Chromium/MCP namespace and off-scope
   negative controls still hold. Matching inline borrowing and a nested-boundary
   escape negative are also checked.
6. A real inherited PTY preserves terminal input/output and the working directory.

Fault contracts are separate in `test_owned_memory_contracts.py`; they are not
kernel-integration evidence. The final selected kernel/contract set also reruns
the active pre-existing `test_os_memory_live.py` cases, including the real
Chromium–Nuclei restart/fixed control, CLI OOM evidence and orphan reclaim.
Mac fault/root-wiring coverage is a separate short slice. The Linux-only file is
platform-not-applicable on macOS, not a passing macOS integration.

The final focused copied-source run completed **27 passed, 0 failed, 0 skipped
in 16.08 seconds** on Ubuntu ARM64 (11 actual kernel/integration cases and 16
fault/contract cases). The separate macOS contract slice completed **61 passed,
0 failed, 0 skipped in 4.71 seconds**; it does not prove Linux kernel behavior.
Strict mypy passed all eight changed production modules for both Linux and Darwin,
and Ruff/format checks passed all twelve changed Python files. The overlapping
Chromium/SDK/MCP/native case recorded a **373493760-byte owner kernel peak** under
its 1073741824-byte hard cap, with zero OOM events and verified final cleanup.
The separate test-controller cgroup peaked at 167555072 bytes, had no OOM and was
removed after `populated=0`. These measurements are distinct from the shared
ledger's sampled summed RSS.

The receipt records exact copied-source hashes. Central `runtime.py` and
`configuration.py` subsequently received coordinated Nmap composition changes;
the isolated memory probe therefore does not claim to have tested that final
combined source tree. The hosted matrix must test its frozen commit.

After the independent preflight review, the guard refresh completed **39 passed,
0 failed, 0 skipped in 14.16 seconds** on the same copied Ubuntu ARM64 fixture
(12 actual integrations and 27 contracts). A new actual negative control manually
enters a correctly limited owned cgroup, proves its control is writable without
changing it, and is rejected by inline preflight. Genuine wrapped inline borrowing
and all existing actual cases still pass. The refreshed macOS contract slice
completed **72 passed in 4.92 seconds**. Both strict mypy platforms (eight modules)
and Ruff/format (twelve Python files) pass. The separate test-controller peak was
161480704 bytes, with zero OOM events and verified `populated=0` before removal.
The earlier receipts remain preserved; the new receipt is in `guard-refresh/`.

The final directory-descriptor refresh completed **40 passed, 0 failed, 0 skipped
in 16.39 seconds** (the same 12 actual integrations, plus 28 contracts), and
**73 macOS contracts passed in 5.29 seconds**. Within the existing actual inline
negative case, a directory handle blocks borrowing; closing it restores
eligibility in the genuine wrapper. Its tested directory control alias was
read-only, so this is not a claimed reproduced original-root escape. A separate
diagnostic supplying a directory as stdin stopped during CPython initialization
before application exec and is retained as a diagnostic, not passing E2E evidence.
The final controller peak was 164196352 bytes, with zero OOM and `populated=0`
before removal. Final receipts are under `directory-refresh/`.

## Limits of the evidence

- Cgroup charged memory, cooperative reserved bytes and sampled summed RSS are
  different measurements. Shared/file-backed pages may already be charged
  elsewhere; summed RSS can count shared mappings repeatedly. These checks do
  not attribute all native/allocator RSS or prove zero transient kernel overshoot.
- The small receipt/cleanup supervisor stays outside the owner and parent data
  budgets so it can save OOM evidence. Its own process high-water RSS is reported
  separately. This is not a hard limit on every process involved in launching.
- Existing IPC/filesystem access is retained. Work launched by systemd-user,
  D-Bus, cron, another daemon or arbitrary RPC may run outside descendant
  inheritance. Docker daemon containers, remote MCP workers and external model
  servers are also outside this guarantee. Known Docker/custom SDK backends are
  blocked under the profile; no universal external-workload isolation is claimed.
- Abrupt supervisor death may leave a bounded owned fence requiring the existing
  outside host reaper. A private owner cannot write the read-only cgroup controls
  to reclaim another owner's fence; unknown ownership remains quarantined.
- Native macOS aggregate kernel enforcement remains unavailable in this
  implementation. Per-process virtual-address limits or private memorystatus
  privileges are not equivalent to the Linux aggregate physical-memory charge
  boundary. No private API or relaxed substitute is used.
- These short controlled probes do not replace the required GitHub-hosted
  x64/ARM64 full regression. A completed hosted run must provide the final commit
  SHA and platform totals; local source-hash receipts do not imply CI success.

Local debugging receipts, JUnit, logs, source hashes and component measurements
are saved under the git-ignored
`.ci-state/measurements/phase4-owned-memory/` directory.
