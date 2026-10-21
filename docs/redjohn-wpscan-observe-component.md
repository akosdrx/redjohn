# Offline `wordpress_observe` runtime capability

Status: **public opt-in runtime/registry/scheduler integration implemented and actual hosted x64/ARM64 proof completed**. See [the verification record](redjohn-artifact-runtime-verification.md): four WPScan native scenarios passed on each architecture at source `9f3a1a037b2f44bf1b503e2c796a0682f1ba146c`. `wordpress_assess` remains unimplemented. The new adapter and job factory have file/SQLite regression coverage; four actual native cases ran successfully on hosted Ubuntu; a Mac without the required Linux owner/runtime remains unsupported for these native cases. No native Ruby/gem build or scanner execution occurred locally.

The separate frozen 35-package full-CLI audit still exits 2 for the missing `get_process_mem` license notice. That package is outside this narrow component's require closure; the full CLI is neither installed nor loaded.

## Source and license boundary

The exact operator-provided WPScan 4.1.0 file at commit `f6169f00652c07feb45f57ff2a10e38949c28d56` supplies only these inclusive ranges from `lib/wpscan/target/platform/wordpress.rb`:

| Lines | Purpose |
| --- | --- |
| 14 | Resource-path pattern |
| 16–17 | oEmbed/admin-AJAX patterns |
| 51–67 | `wordpress_from_meta_comments_or_scripts?` |

The complete source file, each range, concatenation and 930-byte wrapped component are independently SHA-256 pinned. No upstream WPScan method or license payload is committed in RedJohn. The private selected-job snapshot receives the separately supplied source fragment and unmodified exact license. `external_operator_component=true` and `operator_use=own-systems` or `pentest-toolkit` are mandatory. These declarations do not grant commercial/SaaS/product redistribution rights; commercial context is rejected.

The complete `require 'wpscan'`, Target/controller hierarchy, homepage/random-404 fetches, database version finders, API/updater, Ferrum and password paths are excluded. Only immutable operator-supplied HTML is inspected. A browser producer string cannot impersonate a committed capture; browser-artifact ingestion remains a separate missing capability.

## Execution and authority

`WPScanObserveConfig.from_mapping` accepts exactly `component`, `artifact`, `runtime`:

- `component`: absolute `source_file`, absolute `license_file`, `external_operator_component: true`, permitted `operator_use`.
- `artifact`: absolute `html_file`, exact `html_sha256`, provenance-only `page_url`, `producer: operator`.
- `runtime`: absolute `root`, absolute `manifest_file`, exact host-approved `manifest_sha256`.

The descriptor reader rejects symlinks, FIFOs, digest changes and oversize inputs. HTML is strict UTF-8, NUL-free and at most 256 KiB. Source, license, metadata URL, runtime manifest, wrapper and operator context contribute to configuration identity. No private HTML/source/path enters job options or public evidence.

`wordpress_observe_job(config, policy, store, timeout_seconds=30, retest_revision='')` requires the independent explicit `allowed_source_artifacts` HTML digest and `target_domains=['source']`. It records one deduplicated immutable INPUT manifest and typed source asset/surface with an empty URL. Inventory discovery or a web-origin grant cannot authorize execution. Jobs are idempotent, family `cms_observation`, capability `wordpress_observe`, and have no options. Reopening SQLite preserves job and INPUT identity.

`WPScanObserveAdapter(config, policy, store)` is a selected scanner using the existing shared Scheduler worker claim. It checks current policy, stop/deadline, asset/surface state, exact job specification, owner, attempt, live lease and cancellation before snapshot, every worker dispatch, health, observation and evidence. It has no private governor, shell input, dynamic command or additional HTTP controller. The public runtime/registry composes this adapter only from explicit `wordpress_observe` configuration. `source_jobs` selects the durable job. The actual native tests use this public composition; they do not inject a private registry entry. See [the runtime guide](redjohn-artifact-runtime.md) for the current proof boundary.

The runner reuses the real deny-all Linux user/network/mount namespace and read-only snapshot attestation. Every runtime file is bounded and hash checked into a private immutable sibling snapshot; only workspace/output is writable. Unsupported platform, pin/license mismatch, missing namespace or native health is `blocked`; malformed/incomplete output is `inconclusive`, never a scanner-negative. Timeout and cancel release the existing owned process/boundary/snapshot lifecycle.

The RedJohn-authored Ruby wrapper verifies the fixed selected component hash before evaluation; HTML is separate JSON data. It uses HTML4 NONET without DTDLOAD/NOENT/HUGE, never fetches links and limits URI/comment inspection and generator results. A launcher sets a 1 MiB file-size limit before Ruby initialization; this supplements the existing supervisor/cgroup, not substitutes for it.

## Runtime provenance and CI build

Ruby **3.3.12**, source commit `0581089df9f0af0fe6b64cb8167987c211100947`, is pinned to exact official Ubuntu 24.04 x64/ARM64 builder archives. Both actual archives were read-only audited: 2,522 materialized files each, 108,323,784 / 103,618,056 bytes, largest file below 20 MiB. Only two reviewed internal libruby aliases may materialize a regular target; traversal, other links, duplicate paths and decompression budgets remain strict. Exact COPYING/BSDL/LEGAL files match both the commit and SHA-verified official source archive. No signature verification or reproducible-binary claim is made.

The native runtime consists of Nokogiri **1.19.4**, Racc **1.8.1**, their required Ruby core/default features and receipted libraries. Nokogiri also requires the pure RubyGems **3.5.22** `version`, `requirement`, `platform` and `deprecate` helpers (revision `342d4542fdaaea847507a84a1ccef3a157fd03a4`, MIT/Ruby terms included). The wrapper loads only those helpers and `rbconfig`; `--disable-gems` remains active, without gem activation, discovery, updater or plugin loading. Nokogiri's packaged Gumbo recipe uses mini_portile2 **2.8.9** only at build time; it is not copied into the runtime. The fixed native build uses system libxml2/libxslt instead of downloading or building their nested source archives. The private output prunes unused Ruby/Gem code to the actual require closure. Every subsequent health/observation must load exactly that closure, with no full-platform dependencies.

The CI-only installer does not run on macOS. Its fixed build/inspection commands run in a deny-all network namespace, use only pinned local gem archives, at most two make jobs, finite timeouts, bounded files/logs and a dedicated process group killed on success/failure/timeout. It records Ruby revision, native versions, compiler/build package versions, actual linked OS package versions, all copied file hashes and full original copyright notices. Original Ruby/Nokogiri/Racc license digests are mandatory at runtime. These are host build receipts, not upstream signatures. Product namespace evidence remains the actual Scheduler E2E's responsibility.

From `RedJohn/`, after Ubuntu build dependencies and namespace capability are available:

```sh
python scripts/install-wpscan-observe.py --cache "$RUNNER_TEMP/wordpress-cache" --destination "$PWD/.tools/wordpress-observe/4.1.0" --logs "$ARTIFACTS/wordpress-build" --external-operator-component
REDJOHN_REQUIRE_ARTIFACT_E2E=1 REDJOHN_REQUIRE_WORDPRESS_OBSERVE_E2E=1 python -m pytest -q tests/test_wpscan_observe_live.py --junitxml="$ARTIFACTS/wordpress-live.junit.xml"
```

The test command also requires the existing delegated `REDJOHN_TEST_CGROUP_ROOT`
and enforcing profile; the hosted workflow sets and attests both. The required
flags make absent capabilities a failure rather than a successful skipped run.

Required build packages: gcc, make, pkg-config, binutils, libc6-dev, libxml2-dev, libxslt1-dev, zlib1g-dev. The installer performs no apt operation. CI caches only input archives, keyed by architecture, Ubuntu release, runtime pins and installer; every cache hit is content verified. The runtime is rebuilt and receipted against the current pinned bootstrap, not restored as a cached executable closure. Artifacts should include `.tools/wordpress-observe/4.1.0/{receipt,runtime-manifest}.json` and the requested logs directory, including failure logs. Do not cache a partially built destination as a valid install.

## Verified and remaining

Historical local preparation results: **65 passed, 0 failed, 4 blocked native skips**, 0.45 s. Payload/protocol fixtures and installer-process doubles are explicitly synthetic; SQLite, file-reader, archive-budget and lifecycle assertions use actual files/state. Both real Ruby archives plus all four selected gem archives passed the safe read-only extractor. Ruby/component syntax-only parsing is distinct from engine execution. Those historical measurements are under `docs/measurements/master-completion-20261018/wpscan-observe-component/`; the current hosted proof and artifact hashes are in [the verification record](redjohn-artifact-runtime-verification.md).

The actual positive-generator, generic-absence, external-DTD non-fetch and post-health cancellation cases all passed on hosted Ubuntu x64 and ARM64 at the source SHA above. They assert public runtime composition, shared worker admission, immutable namespace, zero HTTP requests, partial-only coverage, cleanup and SQLite restart deduplication. The adapter scenarios run under an actual 2 GiB pre-exec owner memory fence. A partial generator observation is never a database-confirmed version, deployment assurance, vulnerability finding or global clean result. Full WordPress assessment, authenticated WordPress replay, vulnerability API/database and browser artifact provenance remain outside this component.
