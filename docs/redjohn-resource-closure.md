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
582,298,172. The previous environment is preserved at
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
owner's descendants together; aggregate `memory.oom.group=0` preserves other
owners instead of killing all campaigns. These are kernel controls, separate
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

## Memory diagnosis and timing

The prior 85–86 MB process-tree RSS increase is an observation, not a demonstrated
leak. The new benchmark reports bounded per-phase/per-process measurements,
Linux PSS/private memory where available, kernel counters, controller allocation
changes, cache bytes before/after close and separately labelled GC diagnostics.
Exact workload-loop start/end/duration and pacing are recorded independently of
setup/cleanup elapsed time. RSS, PSS, Python tracing and kernel charging are
different quantities and must not be substituted for each other.

A reproducible retained-cache issue was found: closing a still-referenced
SmartCache kept its stored values. The original real pressure payload retained
6,291,462 serialized bytes in three entries. Clearing closed cache storage must
preserve existing in-flight ownership and late-publication fences. This explains
a measured subset, not the complete historic RSS increase. The new long run
must establish the remaining attribution boundary without a universal leak-free
claim.

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

## New hosted results

Pending the new commit-bound completed x64/ARM64 run. A prepared workflow,
passing contract test or running job is not completion. Final source SHA, run
links, JUnit counts, resource metrics, artifact digests and blockers are added
only after retrieval and verification of actual results.
