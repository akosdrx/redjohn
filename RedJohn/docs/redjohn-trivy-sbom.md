# Offline declared-package SBOM advisory matching

The optional `trivy_sbom` implementation is a separate manual capability from
the existing `trivy_source` filesystem misconfiguration scan. It consumes one
explicitly approved CycloneDX JSON file and an operator-supplied immutable
Trivy vulnerability database snapshot. It never installs a dependency, downloads
a database, opens a registry, builds an image or executes source code.

Shared registry/runtime/configuration selection is implemented through the explicit
`trivy_sbom` configuration and `source_jobs` selector. CI prepares a separately
labelled controlled GHSA fixture database and executes real Trivy matching;
[the runtime guide](../../docs/redjohn-artifact-runtime.md) describes the scope and
current verification state. The official aggregate database is not downloaded
or licensed by this fixture. Existing misconfiguration behavior is preserved.

## Supported scope and truthful results

Input is a bounded subset of CycloneDX JSON1.5: one document, version1, 1–128
simple unscoped PyPI/npm `library` components with exact canonical name, version,
PURL and unique `bom-ref`. Optional dependency edges must reference those exact
components. PyPI aliases, scoped npm packages, qualifiers, nested components,
metadata/tool extensions, license claims, VEX/external references, attestations,
SPDX, XML, Java lookup, images and arbitrary source trees are explicitly
unsupported. Unsupported input is rejected before a native scan.

The pinned CycloneDX/PURL path groups these simple libraries as Trivy result
types `python-pkg` and `node-pkg`; lockfile `pip`/`npm` result assumptions are not
used. The exact pinned decoder, PURL mapping and type-definition source hashes
are recorded in the provenance notice. The scanner must return a complete package inventory matching every declared
component. Missing/partial inventory, unknown packages, unreviewed advisory
source IDs, malformed/duplicate findings, output truncation and native failures
cannot produce a successful negative result. Results are candidates for the
declared package/version only. They establish neither installed-package presence
nor exploitability. Successful matching records `coverage_status: partial`,
`sbom_scan_completed: true`, `package_installation_verified: false` and
`image_or_source_tree_scan: false`. A fixed control means the selected advisory
match disappeared for the reviewed fixture; it is not a clean bill for all
dependencies or the deployed application.

## Database, provenance and data terms

`TrivySBOMConfig.from_mapping` requires exactly `binary`, `source_root`, `files`
and `database`. The binary is the existing reviewed Trivy0.76.0 pin. `files`
contains exactly one relative `.json` path and SHA256. The source manifest digest
must already be in the current engagement's `allowed_source_artifacts`.

The `database` object requires:

```json
{
  "root": "/absolute/operator/trivy-db",
  "database_sha256": "<64 lowercase hex characters>",
  "database_bytes": 123456,
  "metadata_sha256": "<64 lowercase hex characters>",
  "provenance_file": "/absolute/operator/provenance.json",
  "provenance_sha256": "<64 lowercase hex characters>",
  "max_age_seconds": 86400
}
```

These are templates, not usable database pins. The root contains regular,
non-symlink `trivy.db` and `metadata.json`. Schema must be exactly2; metadata
`UpdatedAt` and `NextUpdate` must be explicit UTC timestamps. `NextUpdate` must
still be in the future; both database age and acquisition age must fit the
configured 60-second to seven-day maximum. Future timestamps beyond five
minutes are rejected. Freshness is checked before copying, after copying and
after scanning. There is no allow-stale fallback or automatic update.

The pinned provenance JSON has exactly these fields:

- `format: redjohn-trivy-db-provenance-v1`, `publisher: aquasecurity/trivy-db`;
- `oci_reference`: a declared `ghcr.io/aquasecurity/trivy-db@sha256:...` reference,
  `builder_revision`: a full40-character source revision;
- exact `database_sha256`, `database_bytes`, `metadata_sha256`, UTC `acquired_at`;
- `license_review`: `engine_license_sha256`, `database_builder_license_sha256`,
  `database_builder_notice_sha256`, and the boolean `operator_terms_reviewed: true`;
- `data_sources`: 1–16 objects with bounded unique `id`, HTTPS `url`, HTTPS
  `terms_url`, local relative `terms_file` and exact `terms_sha256`.

Every terms document is actually read and hashed, capped at64KiB each/256KiB
total, and copied into the private snapshot. IDs returned by Trivy must belong
to this reviewed set. The engine and database-builder Apache2.0 license/notice
pins are recorded in
`redjohn/assessment/notices/trivy-sbom-provenance.json`. Advisory feeds retain
their own terms. The operator's approval and content digests identify the
selected bytes; declared publisher/OCI metadata does not authenticate an official
publisher. Evidence therefore always records
`database_origin: operator_supplied_content_pins` and
`publisher_provenance_verified: false`. The database and terms are not uploaded
as public CI evidence or embedded in the RedJohn package.

## Limits and lifecycle

Configuration parsing and authority validation are pure: they check explicit
paths, hashes, versions, sizes and current policy without opening an operator
file. An existing file, readable path or reviewed manifest never becomes an
execution grant. A missing/malformed input is discovered only after normal
scheduler admission, during the bounded owned preparation operation.

The database is streamed in64KiB chunks into a fresh private snapshot, capped
at2GiB, with exact byte count, full SHA256 and before/after inode/size/mtime/ctime
checks. It is never read wholesale into controller RAM. The scheduled bulk-copy
path uses one fixed trusted Python child under the current attested Linux memory
owner. The same helper reads, hashes and parses the SBOM, streams the pinned
engine (at most256MiB), and reads/copies all metadata, provenance and terms.
No controller path reads the original inputs during composition, preparation,
normalization or after scanning. It independently checks UID, parent, exact cgroup/inode, read-only cgroup
filesystem, zero capability sets and NoNewPrivs, then installs a parent-death
signal. It has no network or command-dispatch operation. Missing actual owner
attestation blocks before spawning or creating the destination.

The supervisor records a pending spawn before its first await and applies an
absolute30-second deadline including Process delivery, then bounded TERM/KILL
and reap waits. Concurrent prepare calls cannot overwrite ownership. An
undelivered process handle yields typed quarantine with the pending task still
attached; a fixed late-delivery reaper stops that exact child once known. A
second cancellation joins the existing bounded cleanup instead of detaching it.
A signal failure does not establish
cleanup; an observed child exit is required. Scheduler heartbeats continue
while the child is copying or stalled. Cancellation uses the same cleanup.
An unreaped child retains its process handle, partial proof and private snapshot
paths and raises `TrivyCopyCleanupUnverified`. A real uninterruptible kernel
read may survive SIGKILL; that result is quarantined, never reported cleaned.
Generated directories are created and removed by the same fixed helper under a
separate bounded cleanup operation. Removal requires an exact private nonce
marker, owner/type/mode checks and descriptor-safe `rmtree`; an existing path
without that proof is retained. No parent event-loop thread removes an arbitrary
operator path. Process cleanup and complete resource cleanup are separate facts.
`resource_cleanup_verified()` remains false while a pending spawn, process,
drain, late reaper, prepared path, native worker, namespace or listener is owned.
The typed exception requests retention of the existing logical scheduler lease.
**That shared release guard is not wired yet:** evidence explicitly records
`reservation_retention_wired: false`, and the component remains unregistered.
No second worker lease is acquired for this helper.

The synchronous `DatabaseSnapshot.snapshot`, `read_metadata` and
`TrivySBOMConfig.read_packages` are worker/local-contract IO primitives. The
composed controller never calls them. A between-read deadline alone cannot
interrupt a kernel filesystem read; the actual scheduled fence is the helper's
absolute deadline plus verified termination or retained quarantine. After the
scan, freshness is checked against the helper-returned expiration bound and
owned package identity without reopening any original input.

The source snapshot is capped at256KiB for the SBOM. Existing binary/source
snapshot bounds, minimal environment, bounded output, native supervisor,
deny-all Linux namespace and attested read-only snapshot remain in force. DB
and terms copies sit below the same read-only snapshot. Trivy opens the DB in
read-only mode. Worker output remains capped at512KiB; no raw SBOM, DB or tool
stderr enters public findings. The fixed CLI selects only `sbom --scanners vuln`,
uses `--list-all-pkgs`, disables configuration loading, telemetry, version/VEX
and DB updates, and uses an in-memory analysis cache. The pinned SBOM command
has no `--parallel`; no filesystem misconfiguration switches are reused.

One adapter serializes its workspace lifecycle. Job execution requires the
current durable job owner/attempt/lease, exact spec/revision, active source asset
and current policy before and after the scan. A DB or terms change alters the
configuration revision. Restart deduplicates the same reviewed queued job;
discovery never grants a source permission. Selection must use the same
scheduler/resource governor when shared composition is wired.

The standalone queue API is explicit:

```python
from redjohn.assessment.trivy_sbom import TrivySBOMConfig, trivy_sbom_job

selected = TrivySBOMConfig.from_mapping(operator_document)
spec = trivy_sbom_job(selected, current_policy, assessment_store)
job_id = assessment_store.submit(current_policy, [spec])[0]
```

This does not start a scanner and does not bypass capability-registry admission.
The pending shared integration must register only this selected adapter and
retain the existing governor/namespace requirements.

## Evidence and remaining proof

Focused contracts run without a native engine or downloads:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_trivy_database_contract.py \
  RedJohn/tests/test_trivy_sbom_contract.py \
  RedJohn/tests/test_trivy_copy_process.py -q
```

The tests explicitly use synthetic non-bbolt DB bytes, synthetic terms and
synthetic engine replies. The process suite launches real small Python copy or
stalled children and verifies timeout, cancellation, concurrent heartbeat,
signal denial and confirmed reap. Its kernel-admission entrypoint is a test
double. Its unreaped-child case injects a failed wait proof around a real child;
it is not a real D-state test. Real local file/process IO and SQLite restart
checks do not turn those fixtures into native/advisory E2E evidence.
The next hosted proof must install the existing pinned Linux engine
sequentially, prepare a separately reviewed immutable official DB download with
receipts, and run owned declared positive/fixed package fixtures through the
real scheduler on Ubuntu x64/ARM64. It must verify the selected advisory,
complete inventory, deny-all/read-only attestations, restart, cancellation,
resource measurements and zero residual workers/snapshots. Missing official DB,
unsupported schema, expired metadata or missing kernel capability stays blocked.
No Mac/VM scanner run or external account/cluster access was performed for this slice.

## Reviewed public OCI metadata, not a downloaded database

At2026-10-18T18:46:51Z the official GHCR `2` tag resolved to the following
immutable manifest, which was requested again by digest and hash-checked:

```text
ghcr.io/aquasecurity/trivy-db@sha256:2b8946896faa75f514aec564d623a73e4832f2f93c7cb908abc7bfd63a99f377
manifest: 616 bytes, OCI image manifest schemaVersion2
artifactType: application/vnd.aquasec.trivy.config.v1+json
layer: sha256:a18a7c39f2688c7891fc85564cfb09d19d4b50c2e6c14f1df09cb29cbcf37101
compressed layer bytes: 134968710
layer mediaType: application/vnd.aquasec.trivy.db.layer.v1.tar+gzip
created annotation: 2026-10-18T18:39:41Z
```

Only manifest/token metadata was requested; no DB layer was downloaded. The
created annotation is not a database freshness proof. Internal metadata schema,
`UpdatedAt`, `NextUpdate`, uncompressed DB size/hash and actual advisory presence
remain unverified until a separately reviewed CI-only extraction. The OCI
manifest contains no binding to the reviewed builder source revision or a
verified publisher signature. Official namespace/TLS and content hashes must
not be presented as independent publisher attestation.

The reviewed builder source is
[trivy-db cbebf2e](https://github.com/aquasecurity/trivy-db/tree/cbebf2ecd6df42d36463844a45e689afee51c70f).
Its [publish workflow](https://github.com/aquasecurity/trivy-db/blob/cbebf2ecd6df42d36463844a45e689afee51c70f/.github/workflows/cron.yml)
uses the reviewed DB artifact/layer types. The pinned source defines the
advisory source ID `ghsa` for both reviewed PyPI and npm records. Builder code is
Apache2.0 with its pinned notice. The separately reviewed
[GitHub Advisory Database license](https://github.com/github/advisory-database/blob/c18aa0e82ff81450c9a57bdf5050f6a9d8193125/LICENSE.md)
is CC-BY-4.0; preserve source/license attribution and disclose transformations.
Those terms do not cover every other feed in the aggregated DB. Do not publish
the full DB as a CI artifact under a blanket engine-license assumption.
The full public aggregate's feed/terms closure has not been reviewed, so a real
official-aggregate native E2E remains blocked. A future independently built,
immutable GHSA-only schema2 fixture would need exact licensed advisory inputs,
builder pins and real engine execution, and must be labelled a controlled feed
fixture rather than validation of the full public DB.

Future real positive/fixed controls can assert these individual advisories:

| Ecosystem | Declared positive | Fixed control | Selected advisory |
| --- | --- | --- | --- |
| PyPI | requests 2.20.0 | requests 2.31.0 | [CVE-2023-32681 / GHSA-j8r2-6x86-q33q](https://github.com/github/advisory-database/blob/c18aa0e82ff81450c9a57bdf5050f6a9d8193125/advisories/github-reviewed/2023/05/GHSA-j8r2-6x86-q33q/GHSA-j8r2-6x86-q33q.json) |
| npm | semver 7.5.1 | semver 7.5.2 | [CVE-2022-25883 / GHSA-c2qf-rxjj-qqgw](https://github.com/github/advisory-database/blob/c18aa0e82ff81450c9a57bdf5050f6a9d8193125/advisories/github-reviewed/2023/06/GHSA-c2qf-rxjj-qqgw/GHSA-c2qf-rxjj-qqgw.json) |

These are reviewed source definitions, not executed Trivy results. The fixed
control asserts absence of the selected CVE only; other advisories may remain.

A future CI-only installer must GET the exact manifest with a64KiB cap, verify
its digest and exact single reviewed layer descriptor, stream only that pinned
layer with an exact compressed size/hash cap and a whole-operation deadline,
and safely extract only reviewed regular `trivy.db`/`metadata.json` members.
Never use `extractall`, allow links/devices/traversal/duplicates/sparse members,
follow an unreviewed mirror or convert an expired DB into a passing result.
Bound member count, decompressed DB bytes at2GiB and metadata at2KiB. Verify
schema/freshness/content pins after extraction and on cache hits. Keep pull
tokens in memory and do not forward authorization on blob redirects to another
host. Receipts must bind commit SHA, manifest/layer/DB/metadata/terms digests,
byte counts, UTC times and platform; no token or full DB belongs in public
artifacts. No installer or native official-feed E2E has been executed by this
preparatory slice.
