# RedJohn Ubuntu validation in GitHub Actions

The full Ubuntu workload belongs to `.github/workflows/redjohn-ubuntu.yml`.
Push, pull request and manual `workflow_dispatch` events run the same matrix:

| Hosted runner | Architecture | Python | Reason |
|---|---|---|---|
| `ubuntu-24.04` | x64 | 3.13.16 | Reviewed Linux x64 Schemathesis wheel lock |
| `ubuntu-24.04-arm` | ARM64 | 3.12.3 | Reviewed Linux ARM64 Schemathesis wheel lock |

These are native GitHub-hosted VMs. There is no Colima, self-hosted runner,
emulation or Docker service in the workflow. GitHub documents support for
[ARM64 standard runners in private repositories](https://github.blog/changelog/2026-01-29-arm64-standard-runners-are-now-available-in-private-repositories/).
Account billing, quota and runner availability are still external capabilities.

The matrix uses Node 22.14.0, Go 1.25.1 and Playwright 1.58.0. Actions are pinned
to full upstream commit SHAs. `.github/requirements-ci.lock` pins the complete
Python dependency closure; `pip check` verifies it. npm uses `npm ci` with the
existing lockfile. Go uses the existing `go.mod`/`go.sum`. Download caches cover
pip, npm, Go modules/builds and the version-/architecture-specific Chromium
bundle. Reviewed scanner installers verify their existing source/archive,
license and executable checksums every run; scanner binaries are not uploaded
from the Mac and are not restored from an unchecked cache.

The workflow runs production Ruff, strict mypy, the complete current Python
test collection, TypeScript `tsc --noEmit`, the real Vite build, Go vet, race
tests, TUI build and the existing Hatchling wheel build hook. The frontend has
no separate JS test script in its current package; the real Viewer/Chromium
integration remains in the Python collection. The Go build is not presented
as an interactive TUI E2E.

`pytest_evidence.py` partitions the existing collection into disjoint
regression and reviewed native-integration suites. Assertions, test sources,
dependencies and application code are unchanged. JUnit properties distinguish
`real_integration`, `mock_contract` and `unit_contract_or_mixed`. Tests in the
last category can include local real components, but are not counted as native
scanner E2E. Native integration covers owned local HTTP/HTTPS applications,
positive/fixed controls, authenticated request formats, session refresh,
durable scheduler restarts, Chromium, Nuclei, ffuf, httpx, Katana, VulnX,
Arjun, sqlmap, Dalfox, TInjA, Schemathesis and the owned Interactsh receiver.
VulnX's additional public advisory API test is an external metadata dependency,
not a scan of an external target. A provider capability skip prevents full
acceptance and remains visible separately from a negative finding.

Linux setup creates only a uniquely named delegated cgroup subtree and an
owned fixture DNS alias. It restores exactly 35 hash-verified source documents
to the historical path used by the existing provenance regression inside the
disposable runner; the runtime skills remain English. No scanner executes as
root. The launcher drops to the original runner UID before the sampler and
tests start. The kernel namespace attestation, cgroup memory/swap/pids limits,
actual kernel OOM and process cleanup checks are mandatory. Missing
capabilities fail the capability gate.

Ubuntu's user-namespace restriction remains enabled (`=1`). A unique,
non-attached **enforcing** AppArmor profile scopes namespace permission to
this job's capability probe and integration descendants. A privileged launcher
enters it and immediately drops to the original runner UID/GID, with effective,
permitted and ambient host capabilities all zero. It never attaches to Python,
bwrap, Chromium or a writable executable path. The profile allows only seven
capabilities needed for UID/GID drop and namespace construction; DAC, private
mounts, network isolation, memory limits and Chromium's own sandbox still apply.
Every exec inherits the policy; policy/sysctl writes and profile changes are
denied. This policy deliberately covers the assessment subprocess tree, since
Chromium needs nested namespaces beneath bwrap's no-new-privs boundary.
It is not a general application deployment profile.

`apparmor_restrict_unprivileged_unconfined` is hardened to `1` so an ordinary
process cannot use `aa-exec` to gain the profile's namespace privileges.
Unprofiled `unshare`, unprivileged profile entry, profile escape and raw sockets
in a nested namespace are real negative controls. Chromium's `chrome://sandbox`
must show PID/network namespaces and seccomp; unsafe disabling flags are
rejected. No global restriction is disabled, no unconfined/complain policy or
setuid helper is installed, and TLS/egress checks remain intact. Only the
run/attempt/architecture-owned policy is removed after owned processes stop;
surviving profile processes prevent removal. Setup, policy SHA-256, negative
controls, browser status and cleanup are preserved as artifacts.

Each architecture has a 90-minute job timeout, per-command deadlines, bounded
Go build concurrency and a matrix concurrency of two. Existing runs are not
cancelled by a later push. `contents: read`, checkout without persisted Git
credentials and ordinary `pull_request` (not `pull_request_target`) keep
untrusted code away from repository write credentials. No provider credential
or public OAST account is required for controlled local targets.

Artifacts are uploaded with `always()` for 14 days and include separate Python
and Go JUnit, complete build/test logs, tool provenance/version receipts,
source hashes, external process-tree RSS samples, cgroup measurements,
cleanup evidence and the final strict summary. Both Python suites start in
separate fresh cgroups, so the Actions service and preceding compiler/download
page-cache charges are not misattributed to an assessment controller.
If namespace or sandboxed Chromium capability is absent, dependent cases are
explicit capability skips. Existing native loopback Nuclei and kernel-only
OOM/orphan tests still execute; no remote case changes its egress mode or
falls back to an uncontained worker. The strict gate rejects those skips.
The current Go source tree contains no `*_test.go` files; vet/build can pass
and `go test -race` can finish with zero test functions. This is recorded as
missing Go test coverage, not a successful Go unit suite.
The evidence index binds every
measurement/log by SHA-256 to the exact checked-out Git commit, run ID and
attempt. A missing JUnit, nonzero command, surviving owned process, skipped
mandatory case or missing runner boundary prevents a successful summary.
Hard cancellation/runner loss can prevent final upload; no workflow can
guarantee execution of cleanup after the VM is destroyed.

Manual command, from an authenticated `akosdrx` GitHub CLI session after this
workflow is present on the repository's default branch:

```sh
gh workflow run redjohn-ubuntu.yml --repo akosdrx/redjohn --ref BRANCH
gh run list --repo akosdrx/redjohn --workflow redjohn-ubuntu.yml
gh run watch RUN_ID --repo akosdrx/redjohn --exit-status
gh run download RUN_ID --repo akosdrx/redjohn --dir /tmp/redjohn-ci-results
```

Colima remains available for a short, selected reproduction after inspecting
an Actions failure. Do not run the full Ubuntu matrix locally as a hidden
substitute for missing Actions access. Preserve results of any active VM run
before stopping it or cleaning its fixture data.
