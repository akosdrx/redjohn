# Remote HTTPS egress and authenticated Nuclei replay

This is the governed RedJohn assessment path. It preserves the existing Nuclei
adapter, persistent SQLite scheduler and RedJohn application. It does not migrate
the legacy interactive shell workflow into the new policy boundary.

## Enforcement boundary

`egress_mode="local-fixture"` continues to permit only explicitly allowed literal
loopback origins in `isolated-lab`. Remote execution uses `egress_mode="enforced"`
and requires all of the following:

- Linux with bubblewrap, working unprivileged user/network/mount/PID namespaces,
  and peer credentials available through `SO_PEERCRED`.
- Exact HTTPS origins and an explicit `allowed_ips` IP/CIDR allowlist. Discovery
  cannot expand either list. Loopback, link-local, multicast and unspecified
  destinations are rejected in remote mode.
- A controller-owned inspection proxy. The controller resolves the original
  hostname immediately before connecting, checks every returned address against
  the IP allowlist, and connects to an approved numeric address. TLS SNI,
  hostname validation and the HTTP authority retain the original hostname.
- Actual kernel attestation before launching a browser or scanner worker.
  Workers have an isolated network namespace with only loopback, no effective
  capabilities and `NoNewPrivs`. A private, permission-restricted Unix relay
  reaches exactly the selected controller proxy; it accepts only attested peers.

The policy string `enforced` alone does not grant execution. Direct
`policy.check_url()` still rejects remote execution without the boundary. Failed
attestation, unsupported macOS/Windows hosts or missing bubblewrap are blocked
capabilities, never successful scans. The trusted controller keeps its network
access to perform inspected upstream connections; this is not host-wide firewall
configuration or an OS memory limit.

The proxy decrypts CONNECT traffic and checks each HTTP/1.1 request before an
upstream connection. Its CA/hostname validation remains strict. Chromium trusts
only the ephemeral proxy key through a specific SPKI exception; RedJohn does not
change the system trust store or globally disable TLS verification. A configured
`tls.upstream_ca_file` adds an operator-provided upstream CA. There is no automatic
TLS downgrade, direct-connect fallback, proxy rotation or anonymous fallback.

Request budgets, origin/group/account rate windows, cooldowns, deadlines and job
leases remain in the existing SQLite state. Per-request admission applies before
network execution. The scheduler selects jobs serially and releases browser,
scanner, namespace, relay and lease resources during cleanup. Cancellation owns
only its own worker/process groups and must not interrupt another engagement.

Resource admission uses the larger of process-tree summed RSS and the worker's
controller cgroup `memory.current - inactive_file`. Raw current/inactive-file counters
remain in telemetry. Missing `memory.stat` permits no assumed cache subtraction;
the full current value is used. A system-wide root cgroup is not treated as this
engagement's memory. Run measurements in a dedicated systemd scope when other
build/download processes share the parent session. This admission calculation is
not a hard cgroup memory limit, and summed RSS may count shared pages repeatedly.

## Authenticated replay boundary

`AuthReplayVault` is a host-only credential provider. The scheduler stores actor,
tenant, session revision, policy revision and captured-request references; it does
not store the vault, cookie values or authentication headers in job options.

The original replay supports reviewed, body-free GET/HEAD requests to exact HTTPS
URLs. The [POST/session extension](post-refresh-replay.md) additionally supports
explicitly approved JSON/form/multipart bodies and durable refresh jobs. The existing read-only guard also rejects known state-changing routes and
query operations. URL spelling is not proof of arbitrary application semantics:
the operator must authorize the endpoint and template behavior. XML, generic
browser workflows, password guessing, account recovery and general cross-account
authorization testing remain outside this replay subset.

Vault-file rules are enforced by code: regular file, current OS owner, mode
`0600`, no symlink or extra hardlink, at most 256 KiB, version `1`, one to 64
entries. Each entry has exactly these fields:

| Field | Meaning |
|---|---|
| `engagement_id`, `owner_id`, `policy_revision` | Must match the active host-bound policy. |
| `actor_id`, `tenant_id`, `session_revision` | Exact identity context; `anonymous` cannot receive credentials. |
| `expires_at` | Finite future Unix timestamp, rechecked at authorization and request forwarding. |
| `origin` | Canonical HTTPS origin including its port, for example `https://app.example.test:443`. |
| `allowed_requests` | One to 128 exact `{url, method, request_ref}` records from observed traffic. |
| `headers` | Only `Authorization`, `X-API-Key` and `X-Auth-Token`; duplicate names are rejected. |
| `cookies` | Explicit `{name, value}` pairs; cookie syntax and the combined header budget are validated. |

At least one credential is required. A request needs one unambiguous matching
entry and an `observed` named-actor surface. The scheduler adapter also loads the
captured evidence and checks URL, method, actor, tenant, session revision and
whether the request was actually sent. An imported seed is not an authenticated
capture. Original path encoding, repeated parameters and query ordering remain
significant; only equivalent default-port authority spelling is normalized.

The proxy strips client credentials and injects the selected values only for the
bound request. Credentials are absent from scanner argv, templates and ordinary
evidence. Known credential values reflected by a target are redacted before raw
scanner evidence is stored. Redirects or another URL/method do not inherit the
binding. Expired or mismatched credentials stop the job without anonymous retry.

The CLI accepts an explicit `auth_vault_file` path. Authenticated browser discovery
also needs host-provided `AssessmentRuntime(actor_states=...)` with matching
identity/session wrappers. The CLI does not implement an interactive login wizard,
an implicit credential refresh or a public secret-upload API. Explicit
`session_refresh` jobs use a separately reviewed private provider. After rotation,
provide a fresh vault entry and session revision; old queued work must not silently
change identity. Keep credential files outside the repository and report output.

The additional [browser/body-token workflow](browser-post-body-tokens.md) captures
real Chromium POST bytes under exact private rules. Reviewed field bindings can
rotate body tokens, but new replay authority still requires a complete fresh
browser capture. Current-revision startup reconciliation and the fixed public
multipart header/body sentinels preserve durable job/template identities.

## Reproducible real tests

From the repository root on the prepared Linux host:

```bash
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_assessment_egress.py -q -s

REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_REMOTE_E2E_MEASUREMENTS=/tmp/redjohn-remote-auth-e2e.json \
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_remote_authenticated_pipeline.py -q -s
```

The remote test creates its own HTTPS service on an actual non-loopback local
interface, with an ephemeral CA and disposable credentials. It does not contact a
public assessment target. It exercises actual Chromium, observed authenticated
inventory, the pinned Nuclei engine and persistent close/reopen scheduler stages.
It checks candidate/fixed controls, deduplication, identity mismatch, expiry and
redirect boundaries. `REDJOHN_REQUIRE_REMOTE_E2E=1` converts a missing required
platform/dependency into a failure instead of a skipped capability.

The separate actual-engine authentication test also runs against a local HTTPS
fixture on supported development hosts:

```bash
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_nuclei_auth_live.py -q -s
```

Unit and mock tests are in `test_assessment_auth_replay.py`,
`test_hunt_nuclei.py`, `test_native_fixture_session.py` and
`test_nuclei_installer.py`. A fake scanner/download result is not actual Nuclei
evidence. A marker match remains a candidate; a complete fixed-control response
can establish `no_finding_observed` for that check, not a general safety or RCE
claim. Missing fixtures and capabilities remain explicit coverage gaps.

## Validation records and deployment limits

Historical local HTTP(S) measurements remain under `docs/measurements/`; their
platform, source snapshot and workload must be retained when comparing results.
The Linux validation target is the `redjohn-e2e` Ubuntu ARM64 VM with Python 3.12,
Chromium 145.0.7632.0 and Nuclei 3.11.1. The
[remote/auth validation record](../../docs/redjohn-remote-auth-verification.md)
reports the successful actual browser/inventory/authenticated Nuclei/restart chain
separately from namespace-only results. It retains the browser's partial scope
coverage and candidate-only marker status. Module presence or an older local TLS
test does not establish acceptance for another target or workload.

The prepared GitHub workflow belongs to `akosdrx/redjohn`. Authentication for that
repository was unavailable during preparation, so it has no current GitHub build
claim. Evidence from a different repository is not RedJohn CI acceptance. Linux VM
execution and GitHub execution are separate validation environments.

Unimplemented specialist adapters, production-wide hard RAM/cgroup limits,
unrestricted body replay, provider-refresh-token rotation, full legacy agent
policy migration and release-packaging acceptance remain separate requirements.
The original missing RCE fixture remains `not_reproduced_missing_fixture`.
