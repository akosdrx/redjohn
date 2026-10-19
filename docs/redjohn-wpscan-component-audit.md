# WPScan component supply-chain preparation

This slice audits public package bytes. **The WPScan runtime adapter remains
unimplemented and blocked; no WPScan, gem installer, native extension, Ferrum,
password check, updater or vulnerability API was executed.** It is separate from
phase 4's frozen Nmap/runtime source and from the hosted E2E results.

## Fixed identity and actual audit

The proposed component source is WPScan 4.1.0, upstream commit
`f6169f00652c07feb45f57ff2a10e38949c28d56`. The complete official Ruby-platform
`.gem` SHA-256 is
`fe467ff867116fe85ab3913297d6acbbbdac815b8e8d4590535564a91eada95e`.
Eleven inspected Ruby/entry-point files plus `LICENSE` are independently pinned;
the actual gem copies match that commit's inspected file bytes. This establishes
those file identities, not a reproducible build of the entire gem from Git.

`scripts/wpscan-component-pins.json` fixes all 35 declared transitive gem
versions, Ruby-platform archive URLs, SHA-256 values, license labels and exact
runtime requirements. Explicit `?platform=ruby` was necessary when reading the
official version API: its default selected Java variants for four packages.
Java/native platform alternatives and floating versions are rejected.

The audit read all 35 actual archives: **8,634,880 compressed bytes,
27,395,510 regular payload bytes**. Package identity, actual Ruby YAML metadata,
runtime dependency closure, Ruby requirements and the internal SHA-256 manifest
match the pins. A separate RubyGems requirement calculation found zero unsatisfied
constraints for target Ruby **3.3.12**. This mathematical check used the existing
RubyGems parser; it did not load a pinned gem or execute a scanner. The required
Ruby 3.3 runtime is not installed/verified by this work. Ubuntu 24.04's default
Ruby 3.2 cannot satisfy WPScan 4.1.0's `>= 3.3` requirement.

Five gems contain detached signature payloads. Their bytes are hashed in the
report; **no certificate chain or package signature was verified**. Official
archive digests over verified HTTPS provide the recorded provenance.

## Explicit blockers and incomplete coverage

- `get_process_mem` 1.0.0 provides only an MIT label in its README/gemspec; its
  archive has no full license notice. The exact upstream release commit
  `244e0d3ba5cd48d6929591fb4b189abf9685fec6` also has no dedicated license file.
  The auditor intentionally exits **2** with `missing_full_license_notice`.
  No generic MIT text or another release's notice was substituted.
- WPScan's actual `LICENSE` is 3,398 bytes, SHA-256
  `72eaecf9c3497bb34fb5722eba38a4b3b0ae39235c17378547101b8329b51008`.
  Its dual public-source/commercial terms distinguish own-system/pentest-toolkit
  use from commercial product redistribution and managed/SaaS use. This audit
  grants no commercial entitlement and does not bundle WPScan into RedJohn.
- Nine packages declare native extension build scripts: bigdecimal, ffi, fiddle,
  json, nokogiri, prism, racc, websocket-driver and yajl-ruby. Those scripts were
  recorded and never evaluated. Exact runtime/build dependencies, compilation,
  installed-file receipts and the resulting private read-only runtime still need
  hosted verification. Builds must not acquire floating dependencies.
- Nokogiri packages libxml2 2.13.9 and libxslt 1.1.43 compressed source archives.
  Their exact bytes/digests and existing license-notice files are recorded; nested
  source contents were not recursively reviewed or built. A mini_portile test
  archive is likewise recorded as unreviewed nested content.
- There is no WordPress positive/fixed engine E2E, namespace/proxy proof, scheduler
  job or supported authenticated WPScan replay in this slice. None is represented
  as a negative vulnerability result or successful integration.

## Bounded audit and reproduction

The new command uses no Ruby deserialization or shell/engine execution. Tagged
YAML is traversed as plain scalar/sequence/mapping nodes. It rejects duplicate
keys, cycles, excessive depth/node counts, path traversal, links, special files,
duplicate members, unreviewed archive members and digest mismatches. It extracts
no payload files. Archives are limited to 8 MiB, metadata to 256 KiB, one regular
file to 4 MiB, 1,024 files/16 MiB per gem and 64 MiB total regular payload. File
opens use `O_NOFOLLOW|O_NONBLOCK` and verify regular-file type before reading.

From the project directory:

```sh
python scripts/audit-wpscan-gems.py --cache /absolute/owned/gem-cache --download > audit.json
python scripts/audit-wpscan-gems.py --cache /absolute/owned/gem-cache > audit.json
python -m pytest -q tests/test_wpscan_gem_audit.py
```

`--download` fetches only the exact official pinned RubyGems archives with HTTPS;
redirects to other URLs are denied. Without it, auditing is offline. Exit 2 is the
expected current license block, not a successful WPScan run. The 30 synthetic
archive/parser/requirement contracts are separate from the actual 35-archive
measurement under
`docs/measurements/master-completion-20261018/wpscan-component-audit/`.

## Next isolated component boundary

The next review must trace the actual `require` closure for the inspected passive
WordPress detection component, rather than installing this whole declared CLI
closure. The existing full entry point loads process metrics and the application;
its core controller updates the database, and interactive authentication uses
Ferrum. These paths must not become a second browser or automatic platform.
A future small bootstrap may call only the reviewed passive detector using the
same RedJohn namespace, proxy, governor, scheduler and exact evidenced CMS scope.
It must maintain TLS verification, bounded GET-only requests and partial coverage
without the vulnerability API/database. This is a proposed boundary, not current
runtime support. Shared runtime/registry/configuration files are unchanged.

Primary sources: [WPScan exact source](https://github.com/wpscanteam/wpscan/tree/f6169f00652c07feb45f57ff2a10e38949c28d56),
[WPScan exact license](https://github.com/wpscanteam/wpscan/blob/f6169f00652c07feb45f57ff2a10e38949c28d56/LICENSE),
[official gem release](https://rubygems.org/gems/wpscan/versions/4.1.0),
[Ruby releases](https://www.ruby-lang.org/en/downloads/releases/),
[get_process_mem exact source](https://github.com/zombocom/get_process_mem/tree/244e0d3ba5cd48d6929591fb4b189abf9685fec6).
