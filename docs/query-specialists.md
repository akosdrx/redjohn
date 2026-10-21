# Optional query specialists

RedJohn runs Arjun 2.2.7, sqlmap 1.10.10 and Dalfox 3.2.4 as explicitly selected
durable jobs. Registration/health never starts or installs them. Existing
Chromium, Nuclei, authenticated POST replay, session refresh, MCP and other
adapters retain their execution paths.

| Capability | Supported input | Result |
|---|---|---|
| `arjun_parameters` | Observed anonymous GET endpoint without an existing query; 2–16 approved names | Parameter candidates; generated input surfaces stay inferred until observed |
| `sqlmap_validate` | Completed browser-observed GET; one selected query parameter; reviewed SQLi hint; optional existing private actor vault | Boolean-based scanner candidate, never database/shell access or an automatically confirmed impact |
| `dalfox_validate` | Completed anonymous GET capture; selected query parameter and reviewed XSS hint | Scanner candidate; one harmless host-generated nonce payload |
| `browser_xss_confirmation` | Successful committed Dalfox parent and its private host-owned continuation record | Real target-delivered nonce alert plus benign control can promote the existing candidate to `confirmed_weakness` |

Only `active-staging` and `isolated-lab` are accepted. These capabilities are
absent from the automatic per-URL planner. A captured request reference is
checked against method, exact URL, actor, tenant, session, engagement, policy,
sent flag and completed response status. GET reconstruction preserves the
encoded path and query; this is **not byte-exact original-header capture**.
POST/JSON/form/multipart mutation, duplicate occurrences of the selected name,
authenticated Dalfox/browser confirmation, stored XSS and general DOM-only XSS
are unsupported here. Existing Nuclei POST replay remains available.

## Execution and limits

The existing SQLite scheduler owns claims, attempts, leases, heartbeat,
cross-process exclusion, deadlines and cancellation. One selected worker runs
at a time. Dalfox confirmation uses a small additive `rj_specialist_followup`
outbox: only a successful committed parent releases work. A crash between queue
insertion and acknowledgement is reconciled by the stable job key. Failed or
cancelled parents cannot release a confirmation. A separate browser proof is
validated inside the fenced finish transaction before promoting the existing
finding; a scanner's `confirmed` field alone has no authority.

Python tools run in separate `python -I -S -B` processes from verified private
source/dependency snapshots. No packages are installed/imported into the
controller's environment. Arjun's private `db/special.json` snapshot is replaced
with `{}` to prevent its unconditional built-in wordlist expansion; upstream
source code stays unchanged. Every name sent must be approved or match the
pinned engine's six-character random stability-control form. Response-derived
extra names are denied. This data derivation is part of adapter revision v1.

Workers see an HTTP alias for one endpoint and no session credentials. The
host rewrites it before scope, DNS, admission, credentials and sockets, then
performs numeric IP pinning, SNI/hostname and certificate-chain verification.
Arjun's upstream `verify=False` never disables host-side upstream validation.
Dalfox's default insecure mode is explicitly set to false. Its HEAD preflight
is allowed only on the exact benign request. Every unselected encoded query
pair and its order must remain identical; unsupported engine rewrites fail.
Authenticated sqlmap receives credentials only at the host proxy after the
original vault binding and current session revision are rechecked per request.

Remote jobs require the existing attested Linux network namespace. Missing
kernel support fails closed. `local-fixture` is limited to literal loopback
targets in `isolated-lab`; it is not a macOS remote-network substitute.

- One CLI thread/worker; 1–10 requests/s, per-request timeout 1–10 seconds;
  host admission cap 8–128 requests/job (default 96), plus the shared campaign
  budget and persistent origin cooldown. Jobs default to 60 seconds via the
  selected-job CLI; the existing campaign deadline remains authoritative.
- Immediate process stop after redirect, 401/403/429/503, unapproved mutation,
  exhausted admission or unsupported response encoding. Interrupted streams
  are marked unavailable, never interpreted as an empty scanner result.
- 64 KiB proxy response wire cap; non-identity compressed responses are denied
  before reaching a decompressor. stdout and stderr are drained independently,
  at most 512 KiB each. POSIX `RLIMIT_FSIZE` is 1 MiB/file and core dumps are
  disabled for these workers. The shared resource governor samples the process
  tree. RAM admission is cooperative, not an OS hard memory limit.
- No arbitrary argv, configs, paths, plugins, payload catalogs, updates,
  passive sources, OAST, dashboard uploads, shell, DB dump or file access flags.
  sqlmap is level 1/risk 1/boolean-only with a fixed reviewed test filter.
- Complete framing, non-denied host requests and version-specific output
  schemas are required for a completed negative. Dalfox exit code 1 is accepted
  only with a valid complete finding report. Invalid JSON, incomplete metadata,
  failed requests, TLS errors, timeout and missing engines are coverage gaps.
- Raw scanner streams, request headers and tokens are not written to ordinary
  evidence. Version/digest, byte counts/hashes, status, request counts and
  bounded normalized evidence are retained. Workspaces and processes are
  reaped on success, error, timeout and cancellation.

## Install and run

From the repository root, explicitly install only the selected engines:

```sh
.venv/bin/python scripts/install-specialists-pinned.py arjun
.venv/bin/python scripts/install-specialists-pinned.py sqlmap
.venv/bin/python scripts/install-specialists-pinned.py dalfox
PYTHONPATH=. .venv/bin/python -m redjohn.assessment health
```

The installer verifies reviewed archive/dependency hashes, executes no upstream
install scripts, refuses overwrite, and writes `.tools/<tool>/<version>/install-receipt.json`.
Installation alone is not live verification. Copy its `path`, `sha256`, `version`
into the corresponding configuration's `binary` object. Python tools use sealed
tar bundles, not an arbitrary PATH script or the host's site packages.

Start from `examples/assessment-query-specialists.json`, replace the scope,
policy, pins and recorded surface references. Run browser discovery first using
the existing seed capabilities. Select an observed GET surface from the store;
derive its selected-input surface with `dataclasses.replace(input_location="query",
input_name="id")`, preserving the capture reference. For sqlmap/Dalfox record a
reviewed hint with `AssessmentStore.evidence_put` containing `signal` (`sqli` or
`xss`), `request_ref`, and `input_name`. This explicit hypothesis is not a claim
that an automatic hint detector ran. The adapter verifies that evidence belongs
to the same engagement and recorded input.

Selected jobs use this restricted shape:

```json
{"surface_id":"existing-surface-id", "capability":"sqlmap_validate",
 "hint_ref":"existing-32-hex-evidence-ref", "timeout_seconds":60}
```

Arjun does not accept a hint or per-job wordlist; names live in reviewed host
configuration. Retests require a new `retest_revision`. Rate/transport timeout
changes alone do not rescan a completed job.

```sh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/path/approved-engagement.json \
  --output /absolute/path/redjohn-run --max-jobs 16
# Resume with the same config and output. Pending browser confirmation survives.
```

For named sqlmap actors, configure `auth_vault_file` with the existing private
vault schema. Expired credentials block without an anonymous fallback. Session
refresh and Nuclei's automatic fresh-capture replay keep their existing durable
workflow; new specialist hypotheses must reference the fresh observation.

## Reproduce validation

```sh
PYTHONPATH=. REDJOHN_TELEMETRY=0 REDJOHN_REQUIRE_SPECIALIST_E2E=1 \
  .venv/bin/python -m pytest tests/test_specialists_contract.py \
  tests/test_specialists_live.py -q -s
```

On Linux, add `REDJOHN_REQUIRE_REMOTE_E2E=1` to make unavailable kernel tests
fail instead of skip. Test binaries must already be installed; tests never
install them. `REDJOHN_SPECIALIST_MEASUREMENTS=/absolute/path/results.json`
emits separate loopback/non-loopback positive/fixed measurements.
The live suite uses real Chromium, real CLIs, an owned HTTPS server and actual
SQLite SELECT evaluation. Unit/schema tests are a separate file. It covers
restart/dedup, fixed controls, host-only authenticated replay/expiry, real CLI
process restart, cancellation, timeout, wrong CA/digest, 429 and redirects.

See `redjohn-specialists-verification.md` for the actual run results
and machine-readable evidence. No production target, other DBMS, stored/DOM
workflow or original missing RCE fixture is certified by these controls.

## Sources and licensing

Source/dependency/archive pins and license metadata are in
`scripts/specialist-pins.json`. Reviewed upstreams:

- [Arjun 2.2.7](https://github.com/s0md3v/Arjun/tree/1b11c3574e1e173b47990e7d914f0c183986ec32):
  LICENSE is AGPL-3.0; setup.py contains conflicting GPLv3 metadata. Retain the
  license file and this discrepancy. Dependencies include requests Apache-2.0,
  urllib3/charset-normalizer/ratelimit MIT, certifi MPL-2.0, idna BSD-3-Clause,
  and dicttoxml GPL-2.0 (full texts remain in the installed snapshot).
- [sqlmap 1.10.10](https://github.com/sqlmapproject/sqlmap/tree/65b6e7b4acb13a736614a1ab73b0908476f3c24a):
  [GPL-2.0-or-later with upstream clarifications/exceptions](https://github.com/sqlmapproject/sqlmap/blob/65b6e7b4acb13a736614a1ab73b0908476f3c24a/LICENSE).
  Upstream explicitly includes executing sqlmap and parsing its output in its
  interpretation of derived works, and offers an alternative commercial
  license. Independent-process execution does not establish a licensing
  exemption. Proprietary redistribution/packaging is **not cleared** here.
- [Dalfox 3.2.4](https://github.com/hahwul/dalfox/tree/da19527f9c82d8525e911ca3669fc456daeb50f2):
  MIT, Rust release binaries; no hidden Chromium pool. RedJohn owns actual
  browser confirmation separately.

No upstream implementation is copied into RedJohn source or its core package.
Optional operator-owned installs retain upstream notices; the RedJohn project's
existing license metadata and branding are unchanged. No Strix/HexStrike
component is introduced in this stage.
