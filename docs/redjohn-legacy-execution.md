# Legacy SDK execution: owned admission, outcomes and Linux Shell isolation

The root SDK runner and its child agents share the assessment ResourceGovernor.
Runs without a host assessment also participate in the existing host-wide
reservation pool. This change preserves RedJohn's tools and generic MCP support.
It does not create a second scanner queue: typed assessment work still uses the
existing persistent Scheduler.

## Admission and durable outcomes

`runtime/legacy_execution.py` keeps a size-bounded admission journal in the same
`.state/agents.db` database. Raw shell commands, MCP arguments, credentials and
provider responses are not persisted in this journal. A process lock prevents
two bridge owners using the same run concurrently. A new owner reconciles old
`running` rows to `inconclusive/coordinator_restart_unknown_outcome`; it never
automatically resends them.

Every selected MCP catalog/call has shared worker admission and a finite deadline.
Provider model requests acquire an in-process lease through SDK usage hooks;
the run-cycle finally path releases it even when a response fails or is cancelled.
Timeout/cancellation/cleanup failure have separate durable outcomes. An unproven
cleanup retains its reservation until an explicit successful retry.

An SDK `exec_command` result that yields a process ID retains its worker memory
reservation. Completion through `write_stdin`, cancellation, owner shutdown or a
maximum 600-second process deadline closes it. The deadline is bounded by the
engagement deadline too. The SDK currently exposes terminate-all for its Shell
bulkhead, so a Shell timeout terminates the run's other owned SDK PTY processes
as well. Target stdout cannot invent a process ID: only the SDK response header
before `Output:` is interpreted.

## MCP behavior and resource accounting

`list_mcps` is now an inert inventory operation. Search, schema or call connects
only the selected provider. No configured provider is started solely because it
appears in the inventory.

Pending requests are bounded by `queue_max_items` (default 32, maximum 128).
Persistent stdio server processes reserve one shared `context` slot and the
configured full `worker_memory_budget` for their lifetime, including idle time.
This pool is shared with browser contexts, so retained optional providers cannot
silently create their own unlimited process pool. Active calls additionally
consume a worker slot, with zero extra estimated bytes when the connection's
memory is already reserved. The server remains alive between calls; stateful
integrations are not disconnected after each invocation. Registry shutdown
awaits transport teardown before releasing the lifetime reservation.

MCP calls default to no automatic transport replay. A tool may already have
changed state when its connection disappears; the result is
`mcp_unknown_execution_outcome`, `coverage_effect=inconclusive`. An operator may
explicitly configure `idempotent_tools` for reviewed safe retries. Provider tool
annotations do not grant replay permission. SDK internal retries are disabled
so the supervisor owns the finite retry budget. Connection-closed and response
timeout MCP error codes are classified separately from protocol rejection.

## Local Linux Shell boundary

For a host-bound assessment, the existing RedJohn local SDK session attaches an
attested `LinuxEgressBoundary` at the SDK's common argv launch point. Both
one-shot and PTY commands, and their descendants, use the same namespace path.
There is no separate browser process. A `BrowserEgressProxy` applies origin/IP,
read-only request policy, current engagement policy, shared request budget and
upstream TLS verification. Direct worker sockets cannot reach the host network.

The namespace exposes the workspace and only explicit existing filesystem
grants, plus the reviewed interpreter/runtime mounts. Filesystem inspection and
local builds remain available. The inherited host HOME, provider/cloud credential
chain and ambient proxy environment are cleared. Only public ephemeral proxy CA
material is mounted for client trust; the signing key stays outside the worker.
Changing an environment proxy variable cannot restore direct networking.

Initialization is lazy at the first selected bound Shell command. A backend
without the namespace attachment hook, a missing bubblewrap/user namespace, or a
failed attestation produces `sdk_egress_enforcement_unavailable`, with a stable
cause reference. It does not execute the selected command through a fallback.
The Docker and macOS SDK backends do not yet expose this namespace attachment;
they are explicitly blocked for this bound Shell path. Unbound legacy SDK runs
keep their existing backend sandbox contract and gain shared resource ownership;
they are not reported as having the new assessed network boundary.

Generic remote MCP tools are still operator-configured integrations. A transport
connection allowance does not prove the remote provider's tool semantics obey an
assessment target policy. Typed remote-provider argument/action authorization
and corresponding live provider checks remain separate work; this patch does
not claim their completion.

## Reproduced verification

Focused macOS command from the repository root:

```sh
cd RedJohn
../.venv/bin/python -m pytest -q tests/test_legacy_execution.py \
  tests/test_mcp_configuration.py tests/test_runner_assessment_contract.py \
  tests/test_legacy_shell_boundary_live.py
../.venv/bin/ruff check redjohn/runtime/legacy_execution.py \
  redjohn/runtime/legacy_shell_boundary.py redjohn/runtime/local_backend.py \
  redjohn/assessment/browser_proxy.py redjohn/tools/mcp redjohn/core \
  redjohn/agents/factory.py
../.venv/bin/mypy redjohn --no-incremental
```

The focused bridge/MCP/root set produced **36 passed** in **7.16 seconds** before
the final Linux fixture run. The Linux-only case is skipped on macOS, rather than
claimed successful. Actual subprocess cases launch an owned local MCP stdio
server and SDK PTY processes, without cloud/model credentials. They prove one
effect after a commit-and-disconnect fault, cancellation cleanup with no effect,
same-PID state retention and idle memory reservation, plus yielded-process lease
retention and shutdown. Mock/contract cases remain separate assertions.

The single Linux Shell namespace test was then executed in a private copy in the
existing Ubuntu ARM64 guest, as UID 501, inside a fresh **1 GiB / swap 0** cgroup:
**1 passed in 2.12 seconds**, cgroup `memory.peak=154882048` bytes, final
`populated=0`. Its positive fixture performs an actual allowed HTTP request and
compiles a workspace Python file. Negative controls prove direct host socket
access blocked, a different actual network namespace, `CapEff=0`, an off-scope
origin denied and exactly one charged request. The temporary cgroup was removed
after collecting its result; the existing Colima runtime was preserved.

This short guest probe is debugging evidence, not the required protected
GitHub-hosted x64/ARM64 matrix. The hosted workflow must run
`tests/test_legacy_shell_boundary_live.py` with its normal strict capability gate
and retain its JUnit/metrics before this path can be called hosted-verified.
