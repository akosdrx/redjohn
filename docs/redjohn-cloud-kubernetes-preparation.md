# Optional cloud and Kubernetes preparation

`cloud_prepare` and `kubernetes_prepare` are bounded preparatory capabilities.
They are separate from `cloud_assess` and `kubernetes_benchmark`, which remain
blocked. The owner has deferred live account and cluster access. Preparation
never reads an AWS credential chain, kubeconfig, node process table, Kubernetes
host filesystem, cloud metadata endpoint, live account, or cluster.

An immutable `source_artifact` is the approved **input manifest**. It describes
the requested preparation context; it is not a cloud target or node attestation.
The existing source-domain/digest policy grants permission only to read that
input and perform its reviewed preparation operation. Discovery, imported
account names, matching profile names and installed binaries grant no audit
authority. No invented HTTP URL is used to pass a cloud target through web scope.

## Verified upstream boundaries

The checked pins are:

| Tool | Version | Source commit | License |
| --- | --- | --- | --- |
| Prowler | 5.45.0 | `bffc8844c1c9a3666e37a2ada4ee05f62e1446b0` | Apache-2.0 |
| kube-bench | 0.16.0 | `5c6c22d51b926020e7414e1f1e051851d1a2feff` | Apache-2.0 |

Commit-pinned source/license hashes and reviewed release archive checksums are
in `redjohn/assessment/notices/preparation-provenance.json`. These are engine
and interface provenance, not an audit result or a redistribution claim for
every provider dataset/benchmark. Original upstream repositories and licenses:
[Prowler](https://github.com/prowler-cloud/prowler/tree/5.45.0),
[Prowler license](https://github.com/prowler-cloud/prowler/blob/5.45.0/LICENSE),
[kube-bench](https://github.com/aquasecurity/kube-bench/tree/v0.16.0),
[kube-bench license](https://github.com/aquasecurity/kube-bench/blob/v0.16.0/LICENSE).

The exact Prowler CLI can select AWS profiles, execute fixers and custom checks,
and upload findings. None of those operations is exposed here. Version-only
execution of Prowler is currently blocked with
`prowler_pinned_python_dependency_snapshot_unavailable`: its entry script alone
does not pin the Python interpreter, imports, dependency closure and data.
Other providers, assumed-role discovery and live credential handling are also
unsupported in this preparatory slice.

kube-bench runs audit shell commands from its benchmark YAML and inspects node
processes/configuration. A kubeconfig or cluster name does not provide a safe
remote-node benchmark mode. Preparation never executes benchmark YAML, arbitrary
shell, privileged container flags, host mounts, node detection, remediation or
Security Hub uploads. See its pinned [audit implementation](https://github.com/aquasecurity/kube-bench/blob/v0.16.0/check/check.go)
and [configuration documentation](https://github.com/aquasecurity/kube-bench/blob/v0.16.0/docs/controls.md).

## Explicit manifests and jobs

Prowler's reviewed input is a JSON object with exactly:

```json
{
  "version": 1,
  "tool": "prowler",
  "operation": "manifest_validate",
  "provider": "aws",
  "account_id": "000000000000",
  "profile": "owned-example-profile",
  "regions": ["us-east-1"],
  "checks": ["s3_bucket_public_access"],
  "live_authorization": "deferred"
}
```

The all-zero account is an example fixture, not an authorized real account.
Kubernetes preparation uses this separate exact schema:

```json
{
  "version": 1,
  "tool": "kube-bench",
  "operation": "manifest_validate",
  "cluster_id": "owned-example-cluster",
  "node_id": "owned-example-node",
  "benchmark": "1.12",
  "checks": ["1.1.1"],
  "live_authorization": "deferred"
}
```

Only `manifest_validate` and `version_only` operations are accepted. Manifests
are at most 16 KiB, with at most 32 checks and 16 AWS regions. Unknown keys,
credentials, endpoint/command overrides, fixers, duplicate JSON keys, implicit
providers and `live_authorization` values other than `deferred` are rejected.
The exact manifest bytes must match their reviewed SHA256 on configuration and
execution. Each path component is opened without following symlinks.

The assessment config uses top-level `prowler` and/or `kube_bench` objects:

```json
{
  "policy": {
    "engagement_id": "approved-preparation",
    "owner_id": "operator",
    "allowed_origins": [],
    "target_domains": ["source"],
    "allowed_source_artifacts": ["<actual manifest SHA256>"]
  },
  "kube_bench": {
    "manifest_file": "/absolute/reviewed/preparation.json",
    "manifest_sha256": "<actual manifest SHA256>"
  },
  "preparation_jobs": [{
    "capability": "kubernetes_prepare",
    "timeout_seconds": 20
  }]
}
```

The normal launcher is unchanged:

```sh
redjohn assess run --config /absolute/approved.json --output /absolute/run --max-jobs 1
```

Configuration validates bounded inputs before acquiring the host pool. Explicit
jobs enter the existing persistent scheduler, which resolves policy/version,
input asset, current lease/attempt and retirement fences. Composition and queue
insertion never launch either optional engine. Restart deduplicates the same
immutable job and evidence. A completed preparation result always has
`audit_executed: false`, `audit_coverage_status: blocked`, no findings and no
`no_finding_observed` claim.

## Native version preparation

The explicit installer downloads only a reviewed native kube-bench archive and
its verified license, writes a provenance receipt, and never runs the engine:

```sh
.venv/bin/python scripts/install-preparation-pinned.py --tool kube-bench
```

Reviewed native archives cover Linux x64/ARM64 and macOS ARM64. Other platforms
are blocked; existing destinations are preserved. Prowler installation is
explicitly unsupported until its complete immutable dependency snapshot is
available. Installation and a matching binary name do not prove a version probe.

To request the native version operation, select `version_only` in the manifest,
review its new digest grant, and add the install receipt's exact `binary`
object (`path`, `sha256`, `version`) to `kube_bench`. The adapter copies the engine
and manifest into the existing source snapshot, verifies the read-only snapshot
and deny-all Linux namespace, then executes only `kube-bench version`. Native
stdout/stderr are capped by the existing bounded worker and are never copied
into public evidence. Only verified version/digest/attestation metadata leaves
the runner. Timeout, cancellation, output limits, digest mismatch, network
attempt or missing kernel capability blocks preparation; there is no fallback
to an unrestricted process. Workspace, snapshot, worker and deny listener are
cleaned up. macOS can validate the input but cannot pass this native namespace
stage merely because its binary was downloaded.

## Evidence and remaining blocks

Focused tests:

```sh
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_preparation_tools_contract.py \
  tests/test_preparation_scheduler.py \
  tests/test_preparation_native.py -q
```

The contract file labels its provider rows as **mock imported data**. The
standalone OCSF and kube-bench JSON parsers retain only reviewed check IDs/status
counts, discard raw resource data, audit commands and secret-bearing text, and
always label summaries `imported_unverified_report`. A claimed account ID in a
report is not external identity attestation. kube-bench JSON itself does not
attest the cluster/node; WARN is manual coverage rather than a passing check.
Imported summaries never create verified findings or complete live coverage.

The scheduler tests use actual protected input files, SQLite, production
registry/scheduler and `ConfiguredAssessment` restart, while running no cloud
engine. The native test requires the actual pinned engine in the copied
deny-all Linux runner and checks that no audit occurred. Setting
`REDJOHN_REQUIRE_PREPARATION_E2E=1` makes a missing Linux installation/capability
fail rather than silently skip. There is no real Prowler cloud assessment or
kube-bench node/cluster benchmark evidence yet. Future live work needs explicit
owner authorization, genuine account/cluster identity and node/process/egress
attestations, complete immutable engine/dependency/benchmark manifests and
controlled real positive/fixed audit tests.
