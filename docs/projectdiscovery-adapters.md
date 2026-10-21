# Optional httpx, Katana and VulnX adapters

RedJohn now exposes `httpx_probe`, `katana_discover` and `vulnx_intelligence`
through its existing durable SQLite scheduler and `assessment_control` API.
They require explicit host configuration. Registration, health checks and
planning do not execute or install them. CLI seeds keep their existing default
capabilities; configuring a tool does not automatically queue it. Configured
httpx/Katana can be selected by the deterministic planner for observed inputs.
VulnX queries require explicit jobs and approved public CVE IDs.

The reviewed official releases are:

| Tool | Version | Source commit | CLI license |
|---|---|---|---|
| [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx/releases/tag/v1.12.0) | 1.12.0 | `4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8` | MIT |
| [Katana](https://github.com/projectdiscovery/katana/releases/tag/v1.8.0) | 1.8.0 | `35267ac5c8ff1db9694a319d0eb466ed97b0969f` | MIT |
| [VulnX](https://github.com/projectdiscovery/vulnx/releases/tag/v2.0.2) | 2.0.2 | `76410ddde266b7103673813e14a79dbad13b4beb` | MIT |

These are CLI license checks. Optional fingerprint databases, cloud-provider
data, API entitlements and redistribution terms are separate. RedJohn retains
bounded provider metadata and content digests, not upstream PoC/template bodies.
It uses host-observed product headers for technology observations; it does not
adopt the CLI's fingerprint catalog or treat its guesses as affected versions.
No Strix/HexStrike source or second CVEMap engine is imported. Existing native
NVD/OSV/KEV/EPSS tools, authenticated Nuclei replay and MCP support remain.

Run from the repository root, explicitly preparing only the tools you select:

```sh
.venv/bin/python scripts/install-projectdiscovery-pinned.py httpx
.venv/bin/python scripts/install-projectdiscovery-pinned.py katana
.venv/bin/python scripts/install-projectdiscovery-pinned.py vulnx
PYTHONPATH=. .venv/bin/python -m redjohn.assessment health
```

The installer verifies embedded archive pins, official checksum-file and license
digests, extracts only one bounded executable, refuses an existing destination
and records a receipt under `.tools/<tool>/<version>/receipt.json`.
It never runs an upstream install script. This is checksum verification, not an
independent release signature. ARM64 binaries were executed during verification;
AMD64 archive pins are recorded but are not a claim of AMD64 E2E testing.

Copy `examples/assessment-projectdiscovery.json` to a private operator config.
Replace the example target/IP pins and binary paths/digests using the receipts.
Approve the service IPs for `https://api.projectdiscovery.io` separately as
`vulnx.api_ips`; runtime checks every DNS answer and connects numerically with
the original TLS hostname. A changed provider address fails closed. Target
discovery never authorizes new targets. The provider is never inserted into the
engagement's active target allowlist.

```sh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/path/to/operator-config.json \
  --output /absolute/path/to/assessment --max-jobs 16
```

Only host-owned keys are accepted. There is no free-form argv, output path,
external config, dashboard upload, automatic update, auth import or shell option.
Both discovery adapters accept one anonymous GET with an explicit URL path
(`/` for origin probes). Commas are rejected because upstream input flags can
interpret them as multiple targets/files. POST/body/session replay remains in
the existing browser-capture/Nuclei path. All adapter jobs share scheduler leases,
deadlines, cancellation, the resource governor and persisted request/cooldown
limits. QoS-only rate/timeout changes do not repeat completed work; explicit
`retest_revision` does. Unknown crash outcomes are not an exactly-once promise.

Origin case/default-port spelling is reconciled without changing path/query
bytes, repeated parameters, parameter order or an explicit empty query. If a
pinned engine rewrites the seed URI (for example, decoding an encoded `/` in
the path), admission rejects it before forwarding and reports `unsupported`.
There is no automatic switch to an unsafe HTTP mode to hide this limitation.

| Bound | Implementation |
|---|---|
| Optional workers | One selected job at a time; idle Chromium closes before scanner admission |
| httpx | Exact supplied URL only; one GET, no protocol fallback, redirects, favicon/TLS/domain probes |
| Katana | Standard mode, depth 1–3, pages 1–32, one fetcher/input; no forms, headless/hybrid, path climbing or knowledge-base downloads |
| Discovery traffic | Rate 1–10/s, request timeout 1–15 s, at most one admitted request per exact URL per attempt, 64 KiB wire limit |
| Worker output | 512 KiB per stdout/stderr channel; bounded supervisor terminates overflow and descendants |
| Go runtime | `GOMAXPROCS=1`, soft `GOMEMLIMIT=128MiB`, empty private HOME/XDG; host credentials are excluded |
| VulnX | 1–8 approved CVE IDs; fixed `id` command, one provider request per ID, 1 MiB wire limit; retries cannot bypass admission |
| Intelligence cache | Existing SQLite, max 128 metadata records/engagement, 8 KiB each, TTL 1–86400 s; fresh records survive controller restart |

The Go memory limit is soft. Controller admission/watchdog measurements are real,
but this does not add an OS hard RAM cap or a host-wide multi-database governor.
Remote workers require an attested Linux user/mount/PID/network namespace and
the private proxy relay. Missing kernel support, bubblewrap or namespace rights
returns `blocked`; macOS cannot replace this boundary with a proxy flag.
Only explicitly isolated literal-loopback lab fixtures may use local mode.

VulnX's worker talks to an exact local gateway path. The host maps only approved
GET CVE paths to the configured HTTPS provider, checks scope and budget, then
verifies the upstream certificate and hostname. This also works around the
reviewed macOS binary's inability to trust the ephemeral interception CA via
`SSL_CERT_FILE`, without changing the system trust store. A configured API key
is read from an owner-only, regular, single-link `0600` JSON file containing
`{"api_key":"..."}`. It is injected only by the host for approved provider paths;
the CLI, argv, child environment, evidence and public reports do not receive it.
The public provider always uses system trust roots, independent of a private
target's lab CA. Only an explicitly isolated provider fixture inherits the lab CA.
Anonymous provider queries are supported; 401/403/429/provider errors remain
availability/coverage gaps, never evidence that an asset has no vulnerabilities.

Katana 1.8.0 has two reviewed behaviors relevant to this integration:

* [`-ob` mutates the response body before the standard parser](https://github.com/projectdiscovery/katana/blob/35267ac5c8ff1db9694a319d0eb466ed97b0969f/pkg/output/output.go).
  RedJohn uses serialization field exclusion instead, preserving JS extraction.
* Its pinned [`utils v0.11.6` proxy detector](https://github.com/projectdiscovery/utils/blob/v0.11.6/proxy/burp.go)
  requests `http://burpsuite/`. That exact optional startup probe is rejected
  before DNS/admission/connection and counted separately. No scope exception is
  granted. Other rejected/incomplete target requests make coverage inconclusive.

Standard Katana does not execute JavaScript. Its regex does not extract every JS
URL form: the active E2E proves `/api/js-only` discovery and records the unfetched
single-segment `/js-only` limitation. Playwright remains mandatory for executed
SPA/browser coverage. Hitting the page budget returns `partial`, not complete
asset coverage. Redirects are observed without following them. Compressed or
oversized responses, invalid TLS, output mismatches, rate limits and missing
capabilities cannot become clean negative results.

Only complete host-observed responses reconciled with scanner output enter
observed inventory. Raw secret-bearing CLI JSON is not persisted. CVE records
carry source, fetched time, provider timestamp/content digest, version and TTL.
Asset applicability stays `unknown` without validated asset versions and affected
ranges. Intelligence never creates a dynamic finding. Explicit retest bypasses
its cache; changing the freshness limit also changes the cache identity.

```sh
# Contract tests: fixture inputs/metadata; no external CLI execution.
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_projectdiscovery_contract.py -q

# Real binaries + Chromium + existing pinned Nuclei; no implicit installation.
PYTHONPATH=. REDJOHN_REQUIRE_PD_E2E=1 .venv/bin/python -m pytest \
  tests/test_projectdiscovery_live.py -q -s
```

Linux E2E requires `REDJOHN_REQUIRE_REMOTE_E2E=1`, real bubblewrap/user namespaces,
iproute2, Chromium and the existing reviewed Nuclei fixture lock. The public
VulnX case calls the real service with one public CVE ID, without an API key or
private asset upload. A provider outage is recorded as a blocked service check,
distinct from the real-binary controlled-protocol fixture. See the dated
verification report for actual counts, measurements and remaining blockers.
