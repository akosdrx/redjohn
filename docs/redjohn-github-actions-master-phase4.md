# Phase 4 candidate and validation boundaries

This document preserves the historical Phase 4 candidate and its then-current
validation scope. The later WPScan observation and Trivy SBOM runtime slice now
has separate [completed hosted proof](redjohn-artifact-runtime-verification.md);
the exclusions and counts below describe this earlier candidate.

This candidate preserves the RedJohn application and existing active tests. It
adds the reviewed GraphQL/private workflow extension, selected v3 specialist
input replay, observed-open Nmap service adapter, cloud/Kubernetes preparation,
and opt-in owned Linux memory envelope. No live cloud account or cluster audit
is authorized or claimed. WPScan and the new Trivy SBOM work remain outside this
candidate until their separate source/dependency reviews and actual proof finish.

The current source is published only from a frozen explicit manifest after
comparing all agent-owned hashes, reviewing the root changes and scanning the
source allowlist for credential patterns. Pattern scanning is not a universal
secret guarantee. Generated local evidence, debug files, private configuration,
databases, `.tools`, dependencies and other active development slices are not
uploaded with the source. The local Git index/HEAD and private MCP configuration
are checked independently and remain untouched by publication.

## Hosted workflows

The [complete validation workflow](https://github.com/akosdrx/redjohn/blob/codex/redjohn-ubuntu-actions/.github/workflows/redjohn-ubuntu.yml)
retains native Ubuntu 24.04 x64/ARM64, exact Python/Node/Go/action pins, sequential
explicit optional-tool installation, dependency caches, finite job/command
deadlines, full Python/frontend/Go checks and actual owned-fixture integration.
It also checks the generated capability catalog against the current registry.
The long-soak marker requests at least 120 active cycles / 1200 seconds on each
platform. A run is successful only after all required stages, strict evidence
checks and cleanup finish.

The separate [native component workflow](https://github.com/akosdrx/redjohn/blob/codex/redjohn-ubuntu-actions/.github/workflows/redjohn-native-components.yml)
uses an independent concurrency group to provide faster native build/isolation
feedback while a long full matrix is still running. It requires exactly:

| Actual native selection | Cases |
| --- | ---: |
| Naabu/dnsx owned TCP/DNS fixtures | 8 |
| Nmap service identification and refusal/cancel controls | 4 |
| Isolated kube-bench version command, no audit | 1 |
| Owned/aggregate memory, writable-group rejection, signal/deadline/PTY | 6 |

All 19 must pass with no errors or skips. The one Chromium/SDK/MCP/native-memory
overlap case is explicitly outside this browser-free smoke scope and remains
mandatory in the complete workflow. Native smoke always records
`full_project_validated=false`; it does not prove the full application,
frontend/TUI, browser, provider or cloud audit.

Both workflows enter the job-owned enforcing AppArmor profile and run checks
after UID/capability drop. Global user-namespace restrictions remain enabled.
Capability failure is a blocked/failed run. No fallback disables the browser
sandbox, namespace isolation, cgroup controls or the shared resource ledger.
Owned cgroup/profile cleanup and commit-bound logs, JUnit, source/tool digests
and resource receipts are preserved even when earlier stages fail.

## Targeted evidence before hosted completion

The detailed documents keep native integrations, parser/fault contracts and
missing capabilities distinct:

- [V3 input replay](redjohn-extended-input-replay.md): 27 initial actual
  loopback selections, separate post-optimization JSON checks, four actual
  post-review XML/file TInjA controls, and failing/fixed parser regressions.
  Concurrent shared-pool admission blocks remain in the original failed receipt;
  only the affected cases were rerun after the other browser owner finished.
- [Authentication workflows](../RedJohn/docs/redjohn-browser-auth-workflows.md)
  and [GraphQL workflows](../RedJohn/docs/redjohn-graphql-workflows.md): real
  TLS/browser/Nuclei/CRUD/restart controls, FIFO rejection and conservative
  cancellation/one-use-input uncertainty handling.
- [Nmap](redjohn-nmap-service-profile.md): real source extraction/provenance and
  23 contracts; actual built engine and four native cases require hosted proof.
- [Owned Linux memory](redjohn-owned-memory-envelope.md): actual short ARM64
  kernel/Chromium/SDK/MCP/PTY checks and separately identified synthetic fault
  contracts; inherited directory/control descriptor rejection and inline guard
  proof. The supervisor and external daemon/remote work are outside the budget.
- [Cloud/Kubernetes preparation](../RedJohn/docs/redjohn-cloud-kubernetes-preparation.md):
  real local manifest persistence; native version proof remains separate from
  deferred account/node audit. Prowler's missing immutable dependency snapshot
  stays blocked.

These targeted measurements do not certify the final combined source or replace
the requested complete hosted matrix. Each actual run's artifacts identify its
executed commit SHA, source hashes and terminal status. Earlier completed
successful and failed candidates remain separately documented.
