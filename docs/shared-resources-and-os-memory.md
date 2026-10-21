# RedJohn shared admission and Linux memory containment

`AssessmentRuntime` joins a private host-user resource ledger by default.
Independent campaign databases therefore share worker, browser, page and context
reservations. Existing campaign schemas, identities, evidence and native tools
remain in place. Standalone `ResourceGovernor` callers can pass a `HostResourcePool`;
the older interactive CLI/TUI path still needs full migration to this service.

The ledger is `~/.redjohn/resources/host.sqlite3`, overridden with an absolute
`REDJOHN_RESOURCE_POOL_PATH`. Use one path for participating controllers. Tests
use their own ledger. The extra SQLite file coordinates independent campaign
databases; it stores capacity and process/fence identities, not sessions or
evidence. No additional database server or orchestrator starts.

The initial host policy reserves at most four workers, one browser, four pages
and four contexts under a 4 GiB admission budget. These are configurable defaults,
not a measurement-based recommendation for every machine. Each campaign also
retains its narrower `ResourceEnvelope`. Admission adds measured process-forest
RSS and outstanding estimates. Overlapping trees are deduplicated by PID;
shared physical pages can still be counted more than once. The supervising CLI
outside a contained child is included in that child's host admission accounting.
Idle controllers/caches and legacy runtimes still require the complete shared
lifecycle migration described in the [completion ledger](redjohn-completion-status.md).

From the repository root:

```sh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment resources
PYTHONPATH=. .venv/bin/python -m redjohn.assessment resources \
  --policy examples/host-resources.json
PYTHONPATH=. .venv/bin/python -m redjohn.assessment resources --recover
```

The policy file is bounded to 4 KiB. Updates require an idle ledger and are
atomic. Existing clients reread the policy at their next reservation. The ledger
is owner-only, has a bounded lease count and database page limit, and rejects
symlink/non-private storage. A lost owner never expires solely because of a TTL
or a wall-clock jump. Process-owning claims require a confirmed dead owner and
their attested Linux cgroup fence: the group is killed, verified empty and removed
first. Unknown or legacy claims without that fence stay quarantined; `--recover`
does not forget them. An observation failure never proves death.

The native HTTP observation/header, session-refresh and OAST protocol adapters
only use their controller's threads and sockets. Both the trusted capability and
its adapter explicitly mark these worker reservations `owner_process_only`.
For an unfenced reservation with that classification, confirmed owner-process
death is sufficient: its threads and sockets cannot survive it. Admission can
reclaim that slot automatically, allowing another campaign to run. A job or
model cannot supply this classification. Browser, page, context and scanner
claims cannot use it. Existing rows migrate with the conservative value `false`.
Fenced reservations still require verified group cleanup. Reclaiming capacity
does not resolve a network outcome or authorize replay of an uncertain request;
the persistent OAST crash control still retains its unknown poll outcome and
does not duplicate the target send.

Temporary host contention can enter durable `retry_wait` under existing attempt,
retry and campaign deadline budgets. The scheduler requires an idempotent job
and unchanged persistent request-admission count. It holds no resource lease
while waiting. Mutating or already admitted work does not get replay permission
from a capacity error. Host contention neither opens nor resets a target circuit.
If the budget is exhausted, the blocked result and attempt history remain visible.

Actual OS enforcement is requested by adding this to an approved run config:

```json
{
  "resources": {
    "total_memory_budget": 2147483648
  },
  "os_memory": {
    "delegated_root": "/sys/fs/cgroup/redjohn-owned-assessments",
    "pids_max": 512
  }
}
```

Merge these fields into the existing policy/seeds/locks/TLS/vault configuration.
The administrator must already delegate a private cgroup v2 subtree with memory
and pids controllers. The supervising process needs permission to migrate its
child within that delegation. RedJohn never obtains root or relaxes host-wide
controls to repair missing delegation. On macOS or unavailable delegation the
requested OS mode returns `blocked_os_memory_limit_unavailable`; there is no
cooperative fallback for that request.

The supervisor creates a private child cgroup, verifies `memory.max`, disables
swap for that group, enables group OOM handling and sets `pids.max`. A small
bootstrap joins before exec of a fresh Python controller. This ordering matters:
moving an already allocated process would not transfer its previous memory
charges. Chromium, Node and scanner descendants inherit the kernel boundary.
The child still runs the ordinary persistent scheduler and existing adapters.
Membership claims are checked and never silently downgraded to uncontained work.

The test lab uses an administrator-created `launcher` child of the delegated
root. A root shell moves itself there, then drops to the test user's UID/GID
with `setpriv` before Python starts. The original user's HOME, executable path
and Playwright cache are passed explicitly. This is lab setup, not product-side
privilege escalation. The owned Ubuntu VM's unprivileged namespace setting is
recorded separately; host macOS settings are unchanged.

For an already delegated production service, the ordinary command remains:

```sh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/approved.json \
  --output /absolute/private/engagement --max-jobs 32 --wait-ready-seconds 65
```

`metrics.resources.host` reports shared admission. Its `os_hard_limit: false`
does not claim a host-wide OS ceiling. The separate
`metrics.resources.os_memory` reports the requested dedicated CLI's actual
kernel limit/current/peak/OOM counters. Kernel charging and sampled RSS are
different measurements. A whole-host cgroup ceiling and the legacy/cache
migration remain separate work.

On kernel OOM the supervisor verifies cleanup and returns `resource_exhausted`,
not an empty successful scan. Its kernel measurement is stored in the existing
quota-bound `rj_evidence` table with inconclusive coverage. If evidence storage
fails, the CLI exposes that failure separately. Existing job effects retain the
ordinary fenced reconciliation rules; a missing response never authorizes an
automatic resend.

The new tests are intentionally separated:

- `test_host_resources_contract.py`: synthetic policy, observation-fault and
  non-idempotent/already-admitted retry contracts.
- `test_host_resources_live.py`: actual process contention, real RSS and separate
  controller databases; these lease tests do not claim live scanner execution.
- `test_host_scheduler_live.py`: actual Chromium, independent CLI controllers,
  durable waiting/automatic resume, terminal denial and explicit retest.
- `test_os_memory_live.py`: actual kernel allocation/fork OOM, orphan cleanup,
  contained Chromium/inventory/Nuclei/restart/fixed control, startup OOM evidence,
  and explicit unsupported-platform/delegation handling.
- `test_resource_crash_recovery_live.py`: real killed owners, mixed unknown
  claims, and a real OAST process crash followed by another campaign's Chromium
  capture, all using the same ledger.
- `test_resource_owner_lifetime_contract.py`: synthetic observation failures,
  conservative legacy migration and rejected lifetime claims for process-owning
  resource classes.

```sh
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_host_resources_contract.py \
  tests/test_host_resources_live.py \
  tests/test_host_scheduler_live.py \
  tests/test_os_memory_live.py \
  tests/test_resource_crash_recovery_live.py \
  tests/test_resource_owner_lifetime_contract.py -q
```

Linux verification additionally sets `REDJOHN_TEST_CGROUP_ROOT` and
`REDJOHN_REQUIRE_OS_MEMORY=1`. Tests do not install engines or grant delegation.
`REDJOHN_OS_MEMORY_MEASUREMENTS` selects a directory for numeric lab results.
The contained HTTPS case needs the existing reviewed Nuclei fixture lock and
real Playwright Chromium. Without Linux delegation the kernel cases are explicitly
skipped, or fail when required. They are never counted as negative vulnerability tests.

Primary semantics: [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).
Actual measurements and full regression status belong in the
[resource verification report](archive/redjohn-resource-runtime-verification.md).
