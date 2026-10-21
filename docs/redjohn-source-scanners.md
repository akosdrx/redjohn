# Explicit offline source scanners

`semgrep_source` runs the native Semgrep Community Edition OCaml CLI 1.181.0.
`trivy_source` runs Trivy 0.76.0 filesystem misconfiguration checks. Both are
selected lazily through the existing persistent scheduler, resource governor,
fenced job leases, cancellation and evidence store. Runtime composition and
capability discovery do not start either engine.

Install explicitly on an Ubuntu x64/ARM64 test runner:

```sh
PYTHON=python bash scripts/install-source-scanners.sh
```

The installer checks embedded SHA-256 pins for official PyPI/release archives
and exact source-commit engine license files. It extracts Semgrep's native
binary under its reviewed `osemgrep` entry-point name plus the exact 26 bundled
ELF shared libraries from that official wheel. It installs no Python package.
The fixed native health and scan commands include `--experimental`: in the
pinned upstream [native dispatcher](https://github.com/semgrep/semgrep/blob/72d3525fe7e02f486428386078f192f8c4756804/src/osemgrep/cli_scan/Scan_subcommand.ml#L700),
the default scan maturity asks for the Python frontend, while experimental
maturity selects native execution. This dispatch setting changes none of the
namespace, source, rule or resource restrictions below.
Install receipts retain archive, binary, each library SHA/size, engine license,
version and source-commit identities. Bundled-library provenance is the pinned
upstream wheel; independent package version/license attestations are not
invented or claimed. No existing installation is overwritten.
The pins are in `scripts/source-scanner-pins.json`.

## Scope and configuration

A source artifact is a manifest of exact relative paths and content SHA-256
digests. `source_root` is an explicitly approved local directory; the scanner
receives an immutable private snapshot of the manifest, never that host root.
Every path component uses descriptor-relative `O_NOFOLLOW` access. Links,
special files, changed hashes, traversal, implicit ignore/config files and
unsupported fields are rejected. Limits are 1024 files, 1 MiB per file and
16 MiB total; the existing configuration-file loader separately caps JSON input
at 64 KiB.

The manifest digest is available as
`SourceToolConfig.from_mapping(tool, configuration).artifact_sha256`. Add this
exact digest to the policy's `allowed_source_artifacts` field. Discovery or
import alone cannot grant execution. Source-only policies use
`allowed_origins: []`; they require no invented URL, DNS resolution or HTTP
egress grant. Their surfaces have `url: ""`, `resource_kind: "source_artifact"`,
the real inventory asset reference and approved manifest digest. Old HTTP
surface keys, policy JSON/revisions and queued job IDs retain their identities.

The relevant configuration structure is:

```json
{
  "policy": {
    "engagement_id": "approved-source-review",
    "owner_id": "operator",
    "allowed_origins": [],
    "target_domains": ["source"],
    "allowed_source_artifacts": ["<exact manifest digest>"],
    "egress_mode": "unavailable"
  },
  "semgrep": {
    "binary": {"path": "/absolute/osemgrep", "version": "1.181.0", "sha256": "<receipt binary digest>"},
    "native_libraries": [{"name": "<each receipt native_libraries name>", "sha256": "<matching receipt digest>"}],
    "source_root": "/absolute/approved/source",
    "files": [{"path": "example.py", "sha256": "<exact file digest>"}],
    "rules_file": "/absolute/reviewed-rules.json",
    "rules_sha256": "<exact rules digest>"
  },
  "source_jobs": [{"capability": "semgrep_source", "timeout_seconds": 60}]
}
```

For Trivy, use the `trivy` configuration key and `trivy_source` capability,
version `0.76.0`, the installed `trivy` binary and no rules/library fields.
For Semgrep, copy **all** `name`/`sha256` pairs from the installation receipt
into `native_libraries`; byte counts stay in the receipt. The engine (at most
256 MiB) and libraries (at most 32 files, 16 MiB each and 32 MiB total) are
verified and copied into the private read-only snapshot before execution.
Later changes to the host installation cannot alter that running snapshot. Semgrep rules
are a locally pinned JSON object containing at most 32 rules. JSON is valid YAML
and avoids YAML tags/aliases, Jsonnet imports and remote registry configuration.
Rule extension/validator entry points, autofix, code builds, package resolution,
upload, telemetry, version checks and additional worker concurrency are excluded
from the fixed command profiles.

Execute with the existing assessment command:

```sh
.venv/bin/python -m redjohn assess run --config /absolute/source-config.json --output /absolute/run
```

The CLI uses the configured policy owner as its caller. The configuration and
runner are shared by CLI and host-bound assessment control.

## Actual execution boundaries

Linux kernel isolation is mandatory for these source workers, including local
fixtures. Each worker has attested user/mount/PID/network namespaces, loopback
only, dropped capabilities and a controller-owned relay which rejects every
network connection. There is no network-capable fallback. The private workspace
contains one valid short-lived public self-signed root for native TLS library
initialization, whose signer key is discarded and never written. No host/public
trust store is imported, no server certificate is issued, and deny-all kernel
egress and the rejecting controller remain mandatory. An empty trust file makes
the pinned native OCaml client fail before even its version command.
The source snapshot
is mounted read-only as a sibling of the writable temporary workspace. Before
executing an engine, a trusted supervised probe checks the actual worker's
`/proc/self/mountinfo` read-only flag and the separate writable workspace.
Missing namespace/bubblewrap/AppArmor capability blocks the job.

The supervisor verifies binary integrity, bounds stdout/stderr, enforces the job
deadline, applies the existing 1 MiB per-file creation limit and cleans up owned
process groups. The scanners use one worker/thread; Semgrep receives a 128 MiB
engine memory setting and the existing Go worker uses `GOMEMLIMIT=128MiB`.
Those engine settings are cooperative, not an OS hard-memory guarantee; the
shared governor and configured Linux cgroup remain the host resource boundary.

Output is normalized into candidate source findings with rule ID, relative
manifest path and line number. Evidence contains versions, hashes, manifest
revision, scanned-unit counts and timing, not raw source snippets or scanner
logs. Empty scans, parser errors, output truncation, timeout and attempted
offline dependency access cannot become successful clean scans. A static match
does not establish dynamic exploitability or confirmed impact.

## Verification commands and remaining mode limits

```sh
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_source_tools_contract.py \
  tests/test_source_scanner_installer.py -q

REDJOHN_REQUIRE_SOURCE_SCANNER_E2E=1 PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_source_tools_live.py -q
```

The four native integration cases run real installed Semgrep/Trivy engines on
owned positive/fixed source, verify the selected rule's presence/absence,
candidate-only status, zero HTTP requests, read-only mount attestation, cleanup,
and persisted deduplication after restart. Missing engines or isolation fail the
required CI invocation; an ordinary local run labels missing dependencies as
blocked skips. Installer/parser/archive tests are contract tests, not scanner
availability proof.

Current Trivy coverage is filesystem misconfiguration with embedded checks.
Vulnerability database scans, dependency advisories, image archives and SBOM
modes require additional explicitly pinned offline datasets and artifact
profiles; they are not silently substituted by misconfiguration results. Live
cloud/Kubernetes account access remains a separate operator-supplied capability.

Upstream references: [Semgrep CLI](https://docs.semgrep.dev/cli-reference),
[reviewed native entry-point dispatch](https://github.com/semgrep/semgrep/blob/v1.181.0/src/main/Main.ml),
[Semgrep license](https://github.com/semgrep/semgrep/blob/v1.181.0/LICENSE),
[Trivy filesystem CLI](https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/),
[Trivy source/license](https://github.com/aquasecurity/trivy/tree/v0.76.0).


Focused macOS verification on 2026-10-18: **106 passed, 4 blocked skips, 0
failed** in 6.25 seconds. This includes 26 source contracts, 7 synthetic installer
contracts, 49 existing scheduler/resource checks, 18 inventory contracts and 6
actual owned HTTP workflow integration cases. Eight assessment modules pass
strict mypy; all 11 touched Python files pass Ruff. The four source-native cases
were skipped because this machine has no reviewed Linux installation; they are
not scanner successes. Hosted x64/ARM64 execution is a separate required gate.
See `docs/measurements/master-completion-20261018/source-scanners/verification.json`
and `focused.junit.xml` for source hashes and exact classifications.
