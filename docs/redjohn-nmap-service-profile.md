# Explicit observed-open service identification

RedJohn's optional `nmap_services` adapter uses an independently installed,
content-pinned Nmap 7.992 engine. It identifies SSH/HTTP services on a currently
approved exact numeric IP/TCP port. It does not perform general port discovery,
OS/UDP scanning, NSE checks, password attempts or broad vendor/version matching.
No optional engine or browser starts during configuration/capability discovery.

## Authority and transport

A service job needs a `network_endpoint` inventory surface, independent network
CIDR/port grants and durable network budget, plus a recent completed native
Naabu-open evidence reference from the same engagement, policy and exact asset /
endpoint. Evidence import or a local relay's open port does not authorize a job.
The prerequisite expires after 300 seconds. Only active staging / isolated lab
profiles are supported initially. Retirement, scope changes, lease ownership,
attempt, cancellation and campaign deadline remain fenced at broker admission
and before response/probe forwarding.

The worker uses the existing attested Linux user/mount/PID/network namespace,
loopback only and dropped capabilities. A distinct raw service controller owns
the exact approved upstream. The authenticated Unix relay adds a private
per-job preamble only after the kernel peer / live control socket gate. The
worker never sees that nonce; another local TCP client cannot create upstream
proof without it. Existing relay users retain byte-identical behavior with the
new preamble option empty.

Nmap connects to the namespace's private local relay. Its local port-state report
is discarded. A normalized service needs actual bounded upstream response bytes,
a digest and a matching independently observed SSH/HTTP response prefix. A
closed upstream after a previous open observation is inconclusive, never a
false "open" result. Raw banners/body snippets and the private preamble are not
stored in evidence. Service/protocol labels are observations; SSH protocol 2.0
is not reported as a product release.

The RedJohn-authored probe database has only NULL/banner recognition and the
fixed `GET / HTTP/1.0\r\n\r\n` request. Its content SHA256 is part of the adapter
revision and immutable evidence. System/user `nmap-service-probes`, arbitrary
payload files and extra CLI flags are not accepted. Workers receive an exact
private read-only binary/data snapshot and a writable temporary workspace.
Version health requires the exact actual engine version and a build without
Lua: Nmap's version detection can otherwise invoke version-category NSE scripts
even without a user-supplied `--script` flag.

The fixed worker profile bounds parallelism/rate, retries and host duration.
The controller permits two active streams, eight actual upstream attempts,
minimum 100ms admission spacing, five seconds per stream, one fixed read-only
probe per stream, 64KiB per upstream response and 128KiB total response bytes.
Every upstream connection and forwarded fixed HTTP probe consumes a separate
unit of the existing durable network budget. The independent HTTP counter
remains unchanged. Existing 1MiB file creation limit, bounded native output,
shared memory admission and cancellation apply.

## Configuration

After an explicitly selected native Naabu job has completed, obtain its
`naabu_network` evidence reference and configure the service job:

```json
{
  "nmap": {
    "binary": {"path": "/absolute/nmap", "version": "7.992", "sha256": "<exact binary SHA256>"},
    "external_operator_install": true,
    "license_sha256": "9d9a9a763c0e6145172cfe7d8483e23b38ce60b6c79a82e4894242917bdae6d3"
  },
  "service_jobs": [{
    "address": "127.0.0.1", "port": "9000",
    "open_evidence_ref": "<current native Naabu evidence ref>",
    "timeout_seconds": 20
  }]
}
```

The existing policy must independently permit this address/port, select target
`network`, use active-staging/isolated-lab and grant a positive
`network_request_budget`. Configuration accepts at most 64 service jobs;
timeouts are 1–30 seconds. Job IDs/restart deduplication use the existing durable
scheduler. The operator explicitly supplies the prior evidence reference; no
planner silently promotes imported/discovered metadata into execution authority.

## Engine provenance and license boundary

The reviewed source commit is
[`0ee561663c1d7d2d4e708cd414dccfd3d9df30d9`](https://github.com/nmap/nmap/tree/0ee561663c1d7d2d4e708cd414dccfd3d9df30d9).
The actual source macros are major `7`, minor `992`, special `""`, producing
`7.992`; the git tag alone is not used as a native version claim. The source
archive SHA256 is
`4d43d8cad701d13da94610bc956d3df5c146c43820f74fac103ca8b847067172`.
The official nmap.org archive failed TLS certificate validation during research;
no TLS bypass was used. The pinned official GitHub source archive uses verified
HTTPS instead.

Nmap uses [NPSL 0.95](https://github.com/nmap/nmap/blob/0ee561663c1d7d2d4e708cd414dccfd3d9df30d9/LICENSE),
with product integration/redistribution conditions; it is not plain MIT/GPL.
`external_operator_install` identifies this integration mode and does not
establish a commercial/OEM entitlement. RedJohn does not embed an upstream
binary or its full probe database. Product/SaaS redistribution needs an
applicable license determination rather than an invented permission.

The explicit CI-owned fixture build is:

```sh
python RedJohn/scripts/install-service-scanners.py nmap --owned-fixture-build
```

It checks the exact source and license hashes, safely extracts regular files
under finite member/size limits, builds with two make jobs and finite
configure/build timeouts, kills a timed-out owned build process group, and
publishes a complete installation atomically. Lua/NSE, Ncat, Nping, Zenmap and
OpenSSL are excluded. The actual built version / excluded-feature output,
compiler/make versions, linked OS library hashes and probe-data hash are saved
in its receipt. It refuses existing installations. This build is only for owned
CI fixtures; ordinary runtime startup never downloads, builds or installs it.
A locally computed built-binary hash proves the specific build input/output
identity, not a reproducible upstream binary or independent signature.

## Verification and current limits

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_service_tools_contract.py \
  RedJohn/tests/test_service_egress_contract.py \
  RedJohn/tests/test_service_scanner_installer.py -q

REDJOHN_REQUIRE_SERVICE_SCANNER_E2E=1 PYTHONPATH=RedJohn python -m pytest \
  RedJohn/tests/test_service_tools_live.py -q
```

The contracts distinguish actual owned sockets/SQLite/helper cleanup from
synthetic native metadata/XML/attestation replies. Four separate real-engine
cases require installed Naabu and a no-NSE Nmap: SSH, HTTP, closed upstream after
a real open observation, and cancellation of an actual service probe. They also
check persisted restart deduplication and owned process/broker/payload cleanup.
A missing Linux engine/isolation fails required CI mode and is explicitly
blocked/skipped in an ordinary macOS run.

At implementation handoff, 23 focused contracts pass and these four native
cases remain blocked locally pending the actual hosted build/run. A real pinned
source archive safe-extraction check passed with 2761 members, 65,783,972 regular
bytes, largest member 5,368,132 bytes and no links; no engine was built or run on
macOS. The corresponding measurement receipts keep this separate from native
integration proof.

All completed service results retain `coverage_status: partial`: only this
narrow SSH/HTTP profile was assessed. A valid no-match is not global safety.
TLS service recognition, the general upstream probe database, NSE, OS/UDP scans
and commercial packaging are outside the initial implemented profile.
