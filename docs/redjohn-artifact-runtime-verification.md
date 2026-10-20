# RedJohn offline artifact runtime verification — 2026-10-20

The public opt-in runtime now composes `wordpress_observe` and `trivy_sbom`
through the shared configuration, registry, durable scheduler, scanner admission
and cleanup guard. The RedJohn identity, user changes, active tests and existing
integrations are preserved. Neither optional engine starts at composition time.

## Completed actual native run

- Repository/account: `akosdrx/redjohn`, authenticated as `akosdrx`.
- Source SHA: `9f3a1a037b2f44bf1b503e2c796a0682f1ba146c`.
- Source tree: `d747f6276ef2f4184226f0080aca80eb0af29ddf`.
- [Offline artifact E2E, run 39498243803, attempt 1](https://github.com/akosdrx/redjohn/actions/runs/39498243803).
- [Workflow](../.github/workflows/redjohn-artifacts.yml); both GitHub-hosted Ubuntu 24.04 jobs concluded **success**.
- All 800 source hashes matched the frozen reviewed source. Both artifact ZIP SHA-256
  values and all 118 indexed evidence files per architecture were verified.

| Platform | Python | WPScan E2Es passed | SBOM E2Es passed | Kernel recovery repetitions passed | Failed / errors / skipped | Adapter E2E command duration |
|---|---|---:|---:|---:|---|---:|
| x64 / x86_64 | 3.13.16 | 4 | 7 | 3 | 0 / 0 / 0 | 25.859483 s |
| ARM64 / aarch64 | 3.12.3 | 4 | 7 | 3 | 0 / 0 / 0 | 24.608035 s |

These are eleven passing adapter **test scenarios** plus three executions of
the existing strict kernel recovery control; they are not fourteen positive
vulnerability findings. WPScan executes real Ruby/Nokogiri/Racc against approved positive,
generic and external-DTD HTML, then verifies durable restart. The fourth case
executes actual native health and proves a persisted cancellation prevents
observation. No WordPress database-backed version or vulnerability audit occurs.

The four SBOM matching scenarios execute actual Trivy against vulnerable/fixed
PyPI `requests` 2.20.0/2.31.0 and npm `semver` 7.5.1/7.5.2 declarations and verify
restart without rescanning. The selected records are CVE-2023-32681 and
CVE-2022-25883. A native-health cancellation prevents the SBOM scan. Two further
scenarios require missing/changed database input to produce **blocked coverage**,
not a successful negative. Those expected rejection controls pass as E2E tests.

The DB is a genuine schema-2 bbolt fixture built through the pinned official
trivy-db APIs and GHSA transformer. Its two upstream advisory records and
CC-BY-4.0 terms are content pinned. It is explicitly a controlled, lab-only DB;
its build time is not evidence of current aggregate advisory coverage.

## Measured resource and cleanup evidence

Each scenario starts a fresh, pre-exec owner under an actual 2,147,483,648-byte
cgroup-v2 memory limit. The owner has read-only cgroup control, zero capabilities
and NoNewPrivs. Native workers additionally use the existing deny-all network
namespace and immutable source/runtime snapshot. These limits were retained
throughout debugging; no global restriction or Chromium sandbox was disabled.

| Measurement | x64 | ARM64 |
|---|---:|---:|
| Maximum WPScan-scenario owner cgroup memory peak | 142,774,272 B | 137,105,408 B |
| Maximum SBOM-scenario owner cgroup memory peak | 260,120,576 B | 243,216,384 B |
| External command process-tree summed RSS peak | 307,388,416 B | 293,371,904 B |
| OOM kills in these artifact owners | 0 | 0 |
| Leftover descendants before safety cleanup | 0 | 0 |
| Job cgroup removed / owned AppArmor profile removed | yes / yes | yes / yes |
| Private WPScan runtime files / bytes | 157 / 66,704,935 | 157 / 66,482,068 |

The three additional recovery executions each use an actual 134,217,728-byte
owner limit. They independently observe the recorded owner PID/start identity
exit, require the orphan still to be live, then verify it dies before capacity
is returned. Their maximum owner peaks were 11,665,408 B on x64 and
11,657,216 B on ARM64. No assertion or kernel protection was relaxed.

Cgroup peak includes the owned process tree and kernel-accounted memory/cache.
The external RSS sum can count shared pages multiple times; it is not a hard
limit. These small controlled fixtures establish neither universal memory
bounds for arbitrary inputs nor long-term leak freedom.

Engine/runtime pins: WPScan source component 4.1.0 at
`f6169f00652c07feb45f57ff2a10e38949c28d56`; Ruby 3.3.12; Nokogiri 1.19.4;
Racc 1.8.1; RubyGems build/support 3.5.22; Trivy 0.76.0. Exact archives, binary,
source, license and installed native-library hashes/versions are in the committed
pin manifests and retained tool receipts. Only four pure RubyGems support
libraries are retained; automatic gem activation remains disabled.

| Evidence artifact | ID | ZIP SHA-256 |
|---|---:|---|
| x64 | 12297239983 | `5bf9b84bf77761d2229bdc764e4e29d9717e5b8a50673ca684543e364b88b8e4` |
| ARM64 | 12298773267 | `e8f226ace4fb2ca47c0af6c8de64ebd32c7b3ca987e20a4d5f128419410570d0` |

The `artifact-native-summary.json`, `integration.junit.xml`, `source.json`,
`evidence-index.json`, `os-memory/artifact-*.json`, build logs and tool receipts
are retained together. Missing/omitted/mocked/skipped native cases, absent owner
receipts or failed cleanup reject the required evidence gate.

## Completed full Ubuntu regression and integration run

The complete [Ubuntu validation run 39498243880, attempt 1](https://github.com/akosdrx/redjohn/actions/runs/39498243880)
finished with **success on both architectures** at the same source SHA
`9f3a1a037b2f44bf1b503e2c796a0682f1ba146c`. The final ZIP digests, all
800 source hashes and all 374 indexed evidence files per platform were checked.
Actual JUnit cases were counted independently of the workflow summary.

| Platform | Python regressions passed | Real integrations passed | Frontend passed | Go passed | Failed / errors / skipped |
|---|---:|---:|---:|---:|---|
| x64 / Python 3.13.16 | 1558 | 454 | 14 | 21 | 0 / 0 / 0 |
| ARM64 / Python 3.12.3 | 1558 | 454 | 14 | 21 | 0 / 0 / 0 |

The regression selection contains 1351 unit/contract/mixed cases and 207
explicitly labelled mock contracts. The frontend selection contains eight
unit/contract cases and six fetch-transport doubles. Those are not native E2Es.
The eleven artifact scenarios above are included in the 454 real integrations;
they must not be added again when counting distinct tests. Three active
Darwin-only shell cases are explicitly platform-inapplicable on Linux, not
executed, not passed and not silently counted as successful skips.

Ruff, strict mypy across 250 source files, CI evidence contracts, TypeScript,
frontend build, Go vet/race/build, Python wheel and wheel-license checks all
completed successfully. Actual Chromium–Nuclei/replay, the existing scanner
integrations, Linux namespace/cgroup controls and cleanup are in this full run.
The required native artifact gate confirmed every WPScan/SBOM case and actual
owner receipt. Both delegated cgroups and owned enforcing profiles were removed;
no leftover descendants were observed before the final safety cleanup.

| Full-run measurement | x64 | ARM64 |
|---|---:|---:|
| Actual integration command duration | 1877.552087 s | 1603.124992 s |
| Integration process-tree summed RSS peak | 1,532,350,464 B | 1,486,372,864 B |
| Maximum WPScan-scenario owner cgroup peak | 138,829,824 B | 135,389,184 B |
| Maximum SBOM-scenario owner cgroup peak | 261,984,256 B | 243,290,112 B |
| Mixed active cycles | 2 | 2 |
| Mixed active elapsed time | 19.281431 s | 16.866308 s |
| Mixed command wall time | 21.238804 s | 18.650119 s |
| Mixed process-tree summed RSS peak | 740,659,200 B | 766,812,160 B |
| Mixed resource samples | 101 | 88 |

The full push run used the existing default **two mixed cycles / zero minimum
active seconds**; all 15 resource/isolation checks were true. This is a short
controlled pressure check, not a new 120-cycle/20-minute soak. The older
`fd7c0d4` long-run evidence remains historical. RSS sums are observations, not
kernel hard limits; the artifact owner limits are independently attested above.

| Full-run evidence artifact | ID | ZIP SHA-256 |
|---|---:|---|
| x64 | 12301268328 | `d7126c7d2e9064b17160f2861cfac30b1458186f01e04d5e2f254db5c228b492` |
| arm64 | 12302351007 | `87a48f19448906b2d6715e56fec9b78298854c640aa0e71f23fc456f6078ea70` |

The previous [full run 39491165311, attempt 2](https://github.com/akosdrx/redjohn/actions/runs/39491165311)
was not successful: x64 had 453 passed / one failed integration while ARM64
passed 454. The existing orphan-recovery test had observed the launcher exit
before the actual ledger-owner PID finished exiting. The correction waits for
that exact PID/start identity to disappear, then preserves the original strict
live-orphan, lost-owner and reclaim assertions. The corrected test passed in
the full matrix and in three separate actual kernel repetitions per platform.
No production memory/resource protection was changed for that correction.

The separate [native component smoke run 39498243753](https://github.com/akosdrx/redjohn/actions/runs/39498243753)
also completed on the same source SHA: **1558 Python regressions and 24 native
scenarios per architecture, zero failure/error/skip**. Both ZIP digests, all
73 indexed evidence files per platform and actual JUnit counts were checked.
Its preparation scenario proves only the constrained kube-bench version command,
not a cluster audit. The limited smoke and artifact workflows continue to report
`full_project_validated: false`; full-project evidence comes from the complete
Ubuntu run above, within its selected test/fixture coverage.

Local targeted contracts remain separate evidence: 101 contracts passed before
the minimal RubyGems addition; the final focused WPScan/component/public-runtime
selection passed 76 tests. Twenty supervised copier process contracts and 30 CI
evidence contracts also passed. Synthetic scanner/DB/protocol cases are not
native E2E proof. No full local regression or Colima workload was substituted
for the hosted runs.

## Operator commands and remaining boundaries

See [runtime configuration and launch commands](redjohn-artifact-runtime.md),
[WordPress component constraints](redjohn-wpscan-observe-component.md), and the
[SBOM contract](../RedJohn/docs/redjohn-trivy-sbom.md). Both require independent
source-artifact grants and reviewed runtime/data pins. The WPScan component is
external operator material; no full WPScan CLI or commercial entitlement is
redistributed. Full WordPress database/API auditing and official aggregate Trivy
feed coverage are not established. Browser-produced WordPress-artifact ingestion,
SPDX/XML, Java and scoped npm SBOMs are outside these profiles.

Live cloud/Kubernetes and the original RCE fixture remain separately deferred
under the user's earlier scope decision. No missing capability is reported as
an absent vulnerability.

The local Git HEAD and index were preserved; the private MCP configuration hash
also remained unchanged. Publishing used a reviewed source allowlist, a secret
pattern scan, full Git blob/mode comparison and non-forced expected-head updates.
Generated installations, debug files, credentials and unrelated local files were
excluded. Existing source/test paths were not deleted.
Subsequent documentation-only publication records these completed results;
runtime, test and workflow blobs remain identical to the tested source SHA.

## Modified files

Compared with source `fd7c0d41df9204e57d8136194336bee2e2378a93`;
the four pre-existing documentation edits were retained. No baseline path was deleted.

- `.github/fixtures/trivy-sbom/main.go`
- `.github/scripts/artifact-evidence.py`
- `.github/scripts/ci.py`
- `.github/scripts/install-artifact-runtime.sh`
- `.github/scripts/install-sbom-database.py`
- `.github/scripts/linux-tests.sh`
- `.github/scripts/pytest_evidence.py`
- `.github/tests/test_artifact_evidence.py`
- `.github/workflows/redjohn-artifacts.yml`
- `.github/workflows/redjohn-ubuntu.yml`
- `RedJohn/docs/redjohn-trivy-sbom.md`
- `RedJohn/redjohn/assessment/artifact_tools.py`
- `RedJohn/redjohn/assessment/configuration.py`
- `RedJohn/redjohn/assessment/notices/trivy-sbom-provenance.json`
- `RedJohn/redjohn/assessment/registry.py`
- `RedJohn/redjohn/assessment/runtime.py`
- `RedJohn/redjohn/assessment/trivy_database.py`
- `RedJohn/redjohn/assessment/trivy_sbom.py`
- `RedJohn/redjohn/assessment/wpscan_component.py`
- `RedJohn/redjohn/assessment/wpscan_observe.py`
- `RedJohn/redjohn/assessment/wpscan_observe_bootstrap.rb`
- `RedJohn/redjohn/assessment/wpscan_runtime.py`
- `RedJohn/scripts/install-wpscan-observe.py`
- `RedJohn/scripts/update-capability-matrix.py`
- `RedJohn/scripts/wpscan-observe-runtime-pins.json`
- `RedJohn/tests/owned_artifact_execution.py`
- `RedJohn/tests/test_optional_artifact_runtime.py`
- `RedJohn/tests/test_os_memory_live.py`
- `RedJohn/tests/test_trivy_sbom_live.py`
- `RedJohn/tests/test_wpscan_observe_installer.py`
- `RedJohn/tests/test_wpscan_observe_live.py`
- `docs/redjohn-artifact-runtime-verification.md`
- `docs/redjohn-artifact-runtime.md`
- `docs/redjohn-capabilities.json`
- `docs/redjohn-capabilities.md`
- `docs/redjohn-completion-status.md`
- `docs/redjohn-github-actions-master-phase4.md`
- `docs/redjohn-github-actions-master-phase4-native.md`
- `docs/redjohn-owned-lab-component.md`
- `docs/redjohn-requirements.md`
- `docs/redjohn-wpscan-component-audit.md`
- `docs/redjohn-wpscan-observe-component.md`
