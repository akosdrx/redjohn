# Host-bound assessment in the existing CLI and TUI

The existing RedJohn runner now supplies the same caller-bound
`assessment_control` service to the root agent and its children. A bounded
host task consumes the existing SQLite assessment queue; it does not create
another queue or launch every configured scanner. CLI and TUI share the
configuration factory used by `redjohn assess run`.

## Starting and resuming

From the repository root, with the existing environment and reviewed tools:

```sh
# Interactive TUI, using an operator-owned assessment configuration.
PYTHONPATH=RedJohn .venv/bin/redjohn \
  --target https://owned.example \
  --assessment-config /absolute/path/approved-assessment.json

# Existing non-interactive CLI.
PYTHONPATH=RedJohn .venv/bin/redjohn --non-interactive \
  --target https://owned.example \
  --assessment-config /absolute/path/approved-assessment.json

# Restore the private per-run approval and the same durable queue.
PYTHONPATH=RedJohn .venv/bin/redjohn --resume RUN_NAME
```

Replace `owned.example` with a target you are authorized to assess. The
configuration uses the existing `assess run` JSON schema. Its origins must be
within the web/API origins selected in this scan. Remote HTTPS jobs require
explicit approved IP/CIDR ranges and the actual supported worker egress
boundary. TLS verification remains enabled. Authentication, body replay,
optional binaries and reviewed template locks retain their existing explicit
configuration requirements.

Without `--assessment-config`, explicit web/API targets establish a
`safe-production`, anonymous metadata-only engagement. Importing those targets
performs no DNS resolution or HTTP request and starts no browser or scanner.
It does not approve IP ranges. Job admission still rejects remote activity
without the required network configuration. A source-only scan does not invent
a web engagement or create an approval key.

## Authority and private state

Host arguments and an owner-approved configuration establish authority.
Model prompts, target content and submitted engagement IDs cannot replace it.
The configuration file must be owned by the current UID and not writable by
group or others. Existing permissions and user configuration are not rewritten.
Relative references to known private files are resolved from the original
working directory before the approval is saved.

The per-run `.state/assessment-host.json` snapshot is mode `0600`. Version 2
binds the configuration hash, caller, operator UID and resolved run directory
with HMAC-SHA256. Atomic replacement is followed by directory fsync. A snapshot
copied into another run directory is rejected. A missing signing key is an
explicit denial; verification never generates a replacement approval.

The default key is `~/.redjohn/assessment-approvals/host.key`, inside a private
directory. `REDJOHN_ASSESSMENT_APPROVAL_KEY` can select an absolute private key
path. The key is never prompt metadata or mounted into a source workspace.
An explicitly selected source root containing it is rejected.

The earlier development snapshot format (version 1) is not directory-bound.
It is rejected on automatic resume. Supply the original owner-approved
`--assessment-config` to reapprove that run and write version 2. This does not
delete the database, evidence or existing jobs.

Only reduced engagement/profile/revision/configuration-reference metadata enters
the prompt. The actual service and governor objects enter the SDK context.
Host control rejects a database policy change until an operator reapproves it;
the pump stops and the report records the blocked workflow. The existing
trusted control API's policy revision migration behavior remains available
outside this host binding.

Early setup failures close logging without creating a resumable agent graph.
Unreadable or invalid saved SDK topology is rejected without rewriting its
bytes. A valid resume preserves the SDK conversation in the same database
as the assessment queue.

## Bounded lifetime and reporting

The host pump runs at most 128 attempts by default, bounded further by queue
capacity, one hour and the persisted policy deadline. One job is claimed per
batch. Store registration resolves the default deadline before native,
browser and HTTP components are composed, so the Nuclei session uses the
same persisted policy. Coordinator lock contention waits without holding a
worker lease and
automatically continues when the lock is released. Shared host admission,
request budgets, durable retries and reviewed adapter constraints remain in
force.

`session_refresh`, `browser_post_capture` and mutating HTTP surfaces receive
non-idempotent job flags at API admission. Explicit unsafe retry flags are
rejected before enqueueing. The scheduler also rejects an unsafe persisted
refresh/capture job before its adapter runs.

On normal exit, the current job has a bounded grace period; unclaimed work
remains durable. User cancellation or deadline cancellation settles the
in-flight job without automatically replaying it. A full engagement cancel
stops the pump. Final reports retain separate execution, coverage and finding
states; a cancelled request with an uncertain result is not a negative scan.
The controller stop reason distinguishes cancellation from deadline exhaustion.

CLI and host reports now share capture/replay, reconciliation, performance and
resource metrics. Host reports also include controller status and the approved
and current policy revisions. The existing JSON/HTML assessment filenames are
preserved. A retained service object returns `engagement_runtime_closed` after
shutdown instead of querying a closed database.

A failed host start remains safely closeable without masking the startup
error. Component shutdown attempts all owned cleanup actions even when an
earlier optional component fails; chained failures remain visible.

## Current boundaries and verification

The real SDK-tool/host integration tests exercise owned HTTPS, Chromium,
inventory, reviewed Nuclei, durable reopen/deduplication, fixed controls,
in-flight cancellation/deadline and external-process coordinator contention.
No model is called by those tests.

Root wiring tests use model-loop and sandbox-startup doubles. The runner,
coordinator, SDK sessions, private files and service are real, including child
context inheritance, prompt override rejection and cleanup failures. These
contracts are not live CLI/TUI or model-provider E2E evidence.

The general MCP registry remains supported. Registration is now inert; a
connection starts on selected discovery/dispatch. This does not yet put every
legacy Shell/MCP operation into the assessment policy/resource boundary.
Readonly nested mounts protect control-plane writes on supported bind-mount
backends, but are not a general secret-read exclusion mechanism. Custom
non-bind workspace staging needs further control-plane exclusion work.

An inline host configuration requesting `os_memory` requires an already
contained Linux controller. The existing dedicated assessment CLI supports
pre-exec cgroup containment; the inline SDK runner does not silently relocate
an already allocated process. Missing containment is an explicit capability
block. Full legacy runtime/cache migration, provider fault coverage, final UI
E2E and the other master-prompt acceptance items remain tracked in
`docs/redjohn-completion-status.md` at the repository root.
