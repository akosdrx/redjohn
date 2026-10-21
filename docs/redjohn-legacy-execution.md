# Legacy SDK execution: owned admission, outcomes and local Shell isolation

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
The Docker SDK backend does not expose an attested attachment and remains
explicitly blocked for this bound Shell path. macOS uses the separate verified
Seatbelt backend below. Unbound legacy SDK runs
keep their existing backend sandbox contract and gain shared resource ownership;
they are not reported as having the new assessed network boundary.

Generic remote MCP tools are still operator-configured integrations. A transport
connection allowance does not prove the remote provider's tool semantics obey an
assessment target policy. The host-reviewed provider contracts below authorize
account/repository metadata and explicit provider workflows; generic MCP target
worker isolation remains a separate, explicitly blocked capability.

## Local macOS Shell boundary

The existing `RedJohnLocalSandboxSession` now attaches
`DarwinShellEgressBoundary` for an assessment-bound Shell. It retains the actual
installed SDK's workspace/filesystem profile and explicit operator path grants.
Controller-selected Python/tool runtime directories are read-only. The extra
Seatbelt rules deny networking and allow only outbound **IPv4 TCP to the exact
controller-owned loopback proxy port**. IPv6, UDP, other loopback addresses and
ports, Unix sockets, Mach/XPC, Apple events and foreign process inspection/signals
are denied. Descendant commands inherit the restrictions.

The environment is cleared **before** `sandbox-exec` launches, as well as inside
the command. Host provider tokens, Python/loader hooks, host HOME and ambient
proxy overrides are not passed to the process. Only the public proxy certificate
file is granted; its signing key stays outside the worker. HTTPS clients validate
that per-run certificate and the proxy still verifies the actual upstream CA and
hostname. No certificate-checking bypass or system trust-store modification is
used.

Before binding any selected command, a real subprocess under the exact composed
profile verifies the controller proxy is reachable, while another owned TCP
listener, another loopback address, IPv6 on the proxy port, UDP, an owned Unix
socket and a private controller canary are denied. A child process must also fail
direct TCP. This probe has a shared 64 MiB worker reservation, a ten-second
deadline and owned process-group cleanup; failed cleanup retains its reservation
and owner for retry. A failed/unavailable Seatbelt profile produces blocked
coverage before executing the requested command. Startup never falls back to
an unbound SDK command. The per-run command temporary directory, proxy assets
and probe artifacts are removed after owned-process cleanup.

This is macOS Seatbelt verification, **not** Linux namespace/cgroup verification.
`sandbox-exec` is the same deprecated Apple API the installed SDK already uses;
the runtime therefore checks the actual profile on each new boundary instead
of assuming another macOS release supports it. A missing executable or changed
kernel behavior blocks this capability. Docker/VM attachment, generic remote MCP
target isolation and cross-platform hard memory enforcement are separate gates.

## Reproduced verification

Focused macOS command from the repository root:

```sh
.venv/bin/python -m pytest -q tests/test_legacy_execution.py \
  tests/test_mcp_configuration.py tests/test_runner_assessment_contract.py \
  tests/test_legacy_shell_boundary_live.py
.venv/bin/ruff check redjohn/runtime/legacy_execution.py \
  redjohn/runtime/legacy_shell_boundary.py redjohn/runtime/local_backend.py \
  redjohn/assessment/browser_proxy.py redjohn/tools/mcp redjohn/core \
  redjohn/agents/factory.py
.venv/bin/mypy redjohn --no-incremental
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

## Host-approved provider semantics

Bound assessment runs now require a per-tool `tool_authorizations` contract in
the operator's MCP configuration. Unbound generic MCP usage remains compatible.
This is separate from configuring the service URL or bearer authentication:
permission to connect to an MCP endpoint does not authorize arbitrary repository,
account, workflow or assessment-target actions.

The contract pins the reported MCP server name/version and input-schema SHA256,
allowlists argument names, and fixes the account/repository/object context.
`get_mcp_tool_schema` returns the version and schema digest for host review. The
operator must review those values and semantics before adding a contract; the
model cannot create one through tool arguments. Calls validate the actual live
server immediately before dispatch, including after a transport reconnect.
Unexpected argument keys, changed context, changed schema or changed version do
not reach the underlying tool.

Supported contracts are `provider-read` and explicit `provider-mutate`. Mutation
requires a fixed context and workflow reference, an active-staging/isolated-lab
profile, and no automatic replay. A schema annotation cannot grant these rights.
`context_free=true` is an explicit host approval for public intelligence tools
that have no account context; it does not invent an assessment web target.

Example operator configuration fragment (replace metadata placeholders with the
reviewed result from the actual server):

```json
{
  "tool_authorizations": [{
    "tool": "read_repository",
    "effect": "provider-read",
    "server_name": "<reviewed server name>",
    "server_version": "<reviewed server version>",
    "schema_sha256": "<reviewed input schema digest>",
    "allowed_arguments": ["repository"],
    "fixed_arguments": {"repository": "operator-owned/project"}
  }]
}
```

No operator MCP file is rewritten or populated automatically. The active
regression reads an actual temporary operator JSON file and verifies its exact
bytes remain unchanged after all provider calls and failures.

Generic target contracts cannot silently inherit network authority from URL
arguments. Remote HTTP target execution remains blocked as
`mcp_remote_target_boundary_unavailable`; an unbound stdio target remains blocked
as `mcp_target_worker_boundary_not_attested`. The new host-bound Linux local path
submits reference-only `mcp_target_read` jobs to the existing persistent scheduler
and attests its actual PID/network namespace before dispatch. Its precise
supported inputs, live results and remaining Docker/macOS limitations are in
[Confined local MCP target reads](redjohn-confined-mcp-target.md). Target mutation
and authenticated/body replay remain separate explicit capabilities.

Phase-two verification:

```sh
.venv/bin/python -m pytest -q tests/test_mcp_authorization_live.py \
  tests/test_legacy_execution.py tests/test_mcp_configuration.py \
  tests/test_runner_assessment_contract.py
```

**47 passed in 13.56 seconds** on macOS, including actual stateful stdio provider
calls and an independent local HTTP MCP endpoint. The HTTP case proves approved
provider metadata works while assessment target egress is unavailable, a real
provider tool failure stays inconclusive, the controller remains alive, and the
next approved call recovers. Cross-repository calls do not reach the provider.
The run emitted two upstream SDK deprecation warnings for its streamable-HTTP
client alias; they did not represent a retry, assertion failure or skipped test.

The phase-two Shell fault contracts additionally prove that the absolute process
deadline includes the initial SDK yield and that a spawn interrupted before a
handle is returned retains its admission if terminate-all fails. Capacity becomes
available only after a successful cleanup retry. These are contract tests; the
separate real PTY and Linux namespace cases remain independently classified.

## macOS verification and fault contracts

The dedicated real macOS file is `tests/test_legacy_shell_darwin_live.py`:

- `test_real_macos_bound_shell_proxy_filesystem_and_descendants[http]`
- `test_real_macos_bound_shell_proxy_filesystem_and_descendants[https]`
- `test_real_macos_bound_shell_close_kills_worker_and_removes_proxy`

These **three actual SDK/Seatbelt cases passed in 4.18 seconds** on this macOS
ARM64 host with Python 3.13.16. The HTTP/HTTPS cases compile a workspace Python
file, validate the owned fixture response through the policy proxy, and verify
that direct sockets, proxy bypass, child direct sockets, off-scope requests,
controller file reads and inherited provider-secret environment access fail.
The cleanup case inspects the actual OS child PID, confirms it is gone, checks
the proxy port has closed, and verifies zero retained worker reservations or
proxy tasks. They are platform-not-applicable on Ubuntu, not Linux passes.

`tests/test_darwin_shell_boundary.py` is separately classified as fault/contract
coverage, not real Seatbelt evidence. It checks malformed proxy endpoint
rejection, missing backend fail-closed behavior, and interrupted probe cleanup
ownership: an unconfirmed child keeps its reservation and blocks new Shell
dispatch until cleanup succeeds. The next call cannot silently use an unbound
session. The final selected command also rechecks current policy after lazy
attestation, because that probe may yield while an operator stops the engagement.

Focused combined verification, retaining JUnit outside the source tree:

```sh
.venv/bin/python -m pytest -q tests/test_darwin_shell_boundary.py \
  tests/test_legacy_shell_darwin_live.py tests/test_mcp_authorization_live.py \
  tests/test_legacy_execution.py tests/test_mcp_configuration.py \
  tests/test_runner_assessment_contract.py \
  --junitxml=/tmp/redjohn-legacy-phase3.junit.xml
```

This focused command is not the full Python/frontend/Go or hosted x64/ARM64
regression. No Docker/VM backend attestation, external provider credentials, or
macOS hard cgroup-like memory enforcement is inferred from these results.

Final combined result on **macOS 27.0 ARM64, Python 3.13.16,
openai-agents 0.19.4**: **57 passed, 0 failed, 0 skipped in 16.29 seconds**.
The two warnings are the same upstream streamable-HTTP alias deprecations noted
above. The final JUnit records the three real macOS cases at 0.761, 0.719 and
0.503 seconds respectively; setup/interpreter collection overhead is separate.
Scoped Ruff/format checks passed, and strict mypy passed across the 14 changed
legacy-runtime/MCP modules. These are completed local focused checks, not a
replacement for the separately required hosted full matrix.
