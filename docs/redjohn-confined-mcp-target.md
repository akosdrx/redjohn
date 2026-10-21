# Confined local MCP target reads

`runtime/mcp_target.py` connects a reviewed local stdio MCP target tool to the
existing persistent Scheduler. Generic unbound MCP and provider metadata/account
contracts retain their previous behavior. Remote HTTP target execution remains
blocked: authorizing a service endpoint cannot attest that remote server's target
sockets, redirects or DNS.

## Supported execution path

The runner calls `LegacyExecution.bind_mcp_registry()` after binding the shared
ResourceGovernor. This host-only composition installs `mcp_target_read`; the
registry records an immutable aggregate contract digest and wrapper version
`redjohn-stdio-target-1`. Concrete reported MCP server name/version and schema
SHA256 are checked against the operator contract immediately before each call.
Explicit absolute launch files are hashed in bounded chunks, with at most sixteen
files and 64 MiB per file. A changed command/configuration/file or contract blocks
a queued job. These are controller checks, not model-provided permission flags.

The initial supported input is one **existing observed anonymous GET surface**,
one string URL argument and host-fixed values for every other argument. The call
must supply that `surface_id`; argument equality is checked against the selected
surface and fixed contract. `call_mcp` returns the durable job ID rather than
executing the target tool directly. Job options persist only the connection/tool
names and contract digest. No arbitrary body, live credentials or opaque argument
document is stored in the job.

Catalog access cannot start a target connection outside scheduled preparation.
`list_mcps` exposes reviewed target tool names without launching them. Operator
schema/version review uses the generic administration context before binding a
scan. A connection mixing provider and target effect contracts must use separate
explicit configurations for this initial target path; its target tool cannot
inherit the provider connection's unconfined launch.

The scheduler validates policy, actor and active inventory before `prepare()`.
Preparation has a heartbeat and shares the absolute job deadline with dispatch.
The selected connection starts under a shared worker admission and retains a full
`worker_memory_budget` context reservation for its complete stdio lifetime. The
in-process dispatcher separately reserves 64 MiB for bounded protocol parsing;
it does not double-reserve the server's full memory budget. This works with
`max_workers=1` and keeps the same stateful MCP process between completed calls.

## Enforced boundary

Only the existing **Linux local SDK backend** is supported for this target path.
`LegacyShellBoundary` reuses the actual attested Linux PID/network namespace and
policy proxy without changing the SDK session's Shell attachment. The workspace
and explicit runtime files remain available; runtime/source files are read-only
mounts. Host environment, provider secrets and ambient loader/proxy settings do
not enter the worker. Explicit operator environment values cannot override the
controller's proxy, trust, PATH/HOME or loader variables.

Every target request must match the currently active scheduled surface. Idle
sessions cannot continue target egress after a job completes. Direct sockets,
off-scope destinations and state-changing methods/routes are denied by the
existing kernel/proxy boundary. Anonymous requests also use a small header
allowlist: Cookie, Authorization, API-key and other unreviewed custom headers
cannot silently turn an anonymous surface into authenticated replay. HTTPS keeps
the ephemeral proxy trust anchor and strict upstream hostname/CA verification.

`tools/mcp/stdio_boundary.py` uses the installed MCP/Agents protocol types with
controller-owned process launch. It bounds each UTF-8 JSON-RPC line to **1 MiB**
before JSON parsing, including a stream that never sends a newline. Read/write
queues are rendezvous streams, not unbounded buffers. Startup cancellation keeps
the spawn task owned until a process handle or proven native exec failure is
received. Teardown is shielded and bounded, with TERM/KILL escalation. An
unconfirmed process retains its transport and shared reservation for retry.

Actual target dispatch disables transport replay even if the generic provider
configuration lists the tool as idempotent. Target jobs are non-idempotent for
restart accounting: a queued job can resume, while a delivered job with unknown
outcome cannot silently run again. Cancellation, timeout, protocol corruption,
tool rejection and blocked prerequisites remain distinct from a completed
negative observation. A completed target read records bounded evidence; it does
not manufacture a vulnerability finding.

## Reproduced checks

Actual Linux file: `tests/test_mcp_target_live.py`:

- Queued job survives complete owner/runtime close and reopen, then performs a
  real HTTPS MCP read through the persistent scheduler. A second job uses the
  same server PID/state. Direct sockets, off-scope requests, credential headers,
  Linux capabilities/network-namespace checks and later idle requests are tested.
- Cancellation and timeout are separate real cases. The fixture creates a
  `setsid` descendant; every captured OS PID is gone after namespace teardown.
- A server writes an oversized unterminated stdout frame. The result is
  failed/inconclusive, with one job attempt and one actual tool invocation; the
  coordinator remains usable and no target request is sent.

The first four-case run completed on Ubuntu ARM64 as UID 501 with Python 3.12.3:
**4 passed in 9.10 s**, fresh **1 GiB memory / swap 0**, cgroup
`memory.peak=162598912` bytes and final `populated=0`.

The later combined private-copy Linux probe included all four actual target
cases, eight target/scheduler fault contracts, four actual bounded-stdio
subprocess cases and seven Darwin-backend fault contracts:
**23 passed in 11.44 s**, `memory.peak=164012032` bytes, final `populated=0`.
The dedicated cgroup was removed after saving JUnit/logs. The existing Colima VM
and unrelated active data were retained. A first collection attempt reported the
test-only psutil dependency as missing; the tests now use the project's existing
native `/bin/ps`/procfs approach and no guest dependency was installed.

Receipts saved on the controller:

- `/tmp/redjohn-mcp-target-linux.junit.xml` and `.log` (four actual target cases)
- `/tmp/redjohn-mcp-target-final-linux.junit.xml` and `.log` (combined Linux probe)
- `/tmp/redjohn-fault-linux.junit.xml` and `.log` (separate frozen phase-two fix)

`test_mcp_target_contracts.py` is explicitly fault/contract coverage. It checks
missing PID/backend attachment, unsupported POST/auth/inferred input, heartbeat,
one-worker preparation/dispatch admission, a shared deadline, partial-context
cleanup and changed runtime bytes. `test_mcp_stdio_bounded_live.py` launches real
local processes for valid framing, oversized output, cancellation and native exec
failure. `test_docker_network_privileges.py` uses a fake Docker API and is not
Docker integration evidence.

The final focused macOS regression completed **73 passed in 20.44 s**. It
includes the existing actual Shell and provider MCP integrations, the seven
Darwin backend fault cases and the new target/transport/Docker contracts; the
Linux-only target namespace file was not selected. JUnit is saved at
`/tmp/redjohn-legacy-phase3-final.junit.xml`. Strict mypy passes all seventeen
owned source modules in both `--platform linux` and `--platform darwin` modes;
Ruff check and format check pass. The two warnings are upstream streamable HTTP
client deprecations from the actual provider endpoint tests.

These short guest probes are debugging evidence, not a replacement for the
required GitHub-hosted x64/ARM64 full regression. macOS cannot count the Linux-only
file as passing; it is platform-not-applicable there.

## Docker and remaining capabilities

The legacy Docker creation override now explicitly drops **NET_ADMIN and
NET_RAW**, including Docker's default NET_RAW capability. It preserves the
operator image ENTRYPOINT, existing source mounts, loopback port publication,
host-gateway behavior and resource/log configuration. The current installed
`openai-agents 0.19.4` Docker path-grant validation is also retained. Contract
tests verify the actual override's create arguments using a fake API.

This change does **not** make the existing Docker bridge an assessment egress
boundary. Bound Docker Shell and target MCP remain blocked. Existing running
containers cannot safely acquire the required network/PID/privilege contract by
adding an argv wrapper after creation. A complete implementation needs a
separate session-owned worker container with network disabled, all capabilities
dropped, no new privileges, bounded cgroup/PID limits and reviewed filesystem
mounts, plus a bounded authenticated controller relay over the Docker exec
transport. That relay needs a fresh per-session challenge, frame/connection
quotas and startup positive/negative probes inside the actual container. A Mac
controller must not interpret a VM kernel's SO_PEERCRED PID as a host PID.

The Mac Shell's verified Seatbelt network policy remains available, but generic
MCP fork/setsid process-tree lifetime cleanup is not yet attested on macOS;
`mcp_target_process_tree_boundary_unavailable` is explicit. Authenticated MCP
POST/JSON/form/multipart replay, session refresh and mutating target workflows
also require their own private replay/state bindings. Existing canonical browser,
Nuclei and specialist scheduler integrations retain those capabilities; this new
generic target path does not claim them by analogy.
