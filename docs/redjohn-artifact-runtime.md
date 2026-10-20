# Explicit offline artifact runtime integration

`trivy_sbom` and `wordpress_observe` are selectable through the shared public
configuration, capability registry and durable scheduler. Neither starts during
composition or discovery. Both consume an explicitly approved immutable source
artifact and the same scanner reservation/cleanup guard as existing adapters.
Use `source_jobs: [{"capability": "trivy_sbom"}]` or
`source_jobs: [{"capability": "wordpress_observe"}]` with the matching top-level
configuration object. Changed source/database/runtime pins change the durable
execution identity; reopening unchanged completed jobs does not rerun them.

## WordPress observation

The `wordpress_observe` object contains `component`, `artifact`, and `runtime`
(see `WPScanObserveConfig.to_mapping`). It requires an external operator-provided
WPScan 4.1.0 source component/license and pinned Ruby 3.3.12, Nokogiri 1.19.4 and
Racc 1.8.1 closure. The installer is an explicit own-systems-only external
component preparation step, not permission to redistribute the WPScan CLI or
use its commercial service. No full CLI, vulnerability database, enumeration,
credential attack, remote HTTP scan or verified WordPress version is claimed.
The input URL is provenance metadata, not network authority. Zero signatures
means no signature in this approved HTML artifact, not no WordPress on a site.

## SBOM matching

The `trivy_sbom` object contains `binary`, `source_root`, `files`, `database`;
see [SBOM contract](../RedJohn/docs/redjohn-trivy-sbom.md). It preserves the
existing `trivy_source` misconfiguration capability. Operator OCI snapshots
still require immutable declared reference, hash, byte limit, schema/freshness
and separately pinned data-source terms. Engine licensing is not feed licensing.

CI builds a **controlled two-advisory GHSA fixture database**, using official
trivy-db revision `cbebf2ecd6df42d36463844a45e689afee51c70f` and advisory-database
revision `c18aa0e82ff81450c9a57bdf5050f6a9d8193125` (CC-BY-4.0). This distinct
`origin: controlled_ghsa_fixture` accepts no official OCI publisher claim and is
restricted to `isolated-lab`. Build timestamps establish fixture lifetime, not
current advisory coverage. Actual Trivy 0.76.0 matches vulnerable/fixed
`requests` 2.20.0/2.31.0 and `semver` 7.5.1/7.5.2 CycloneDX declarations.
A match is a candidate, not installation or exploitability proof; no match is
limited to the two selected records. Official aggregate, images, SPDX/XML,
Java, scoped npm packages and arbitrary source trees remain outside this mode.

## Linux CI and commands

The Ubuntu validation workflow runs native x64 and ARM64. Installation is
sequential. Ruby build/health enters only the job-owned enforcing AppArmor
profile; every artifact E2E runs below a genuine pre-exec cgroup-v2 owner fence,
then the existing deny-all worker namespace/read-only snapshot. Missing required
engine, profile, namespace or delegation fails the required CI gate; no sandbox
or global restriction is disabled. Receipts, logs, JUnit and owner memory/cleanup
measurements are retained on failure too, tied to the Actions source commit.

CI-only preparation (after the normal pinned Trivy install):

```sh
python .github/scripts/install-sbom-database.py
sudo -E bash .github/scripts/linux-tests.sh "$(command -v python)" artifact-install
```

The second command requires the job-scoped profile/delegation setup. The full
workflow provides these. To launch an operator assessment after supplying
reviewed pins/grants, use the existing `redjohn assess run --config` interface;
consult `redjohn assess run --help` for required output/caller arguments.

`test_optional_artifact_runtime.py` and synthetic DB/engine contracts are local
unit/contract evidence, **not native E2E**. The four WPScan cases and four SBOM
cases are in the required real-integration selection. Native proof is pending
until the new x64/ARM64 Actions run completes; older runs explicitly excluded
WPScan and did not execute Trivy SBOM matching.
