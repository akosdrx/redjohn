# Bounded ffuf discovery and assessment Web View

`ffuf_discover` is an optional RedJohn scheduler adapter, not an independently
started scanner platform. It runs only with explicit host configuration and
an `active-staging` or `isolated-lab` engagement. Existing RedJohn tools, Nuclei,
MCP support and user settings remain in place.

The reviewed engine is [ffuf 2.1.0](https://github.com/ffuf/ffuf/releases/tag/v2.1.0),
commit `7a2756a8f367c69c261544ae83d52e86b1ca52d0`, MIT. The installer checks embedded
archive, official checksums-file and license digests, extracts only the executable,
uses exclusive destination creation and records a receipt. These checks are not
an independently verified release signature. No Strix/HexStrike code is imported.
No engine installation or update occurs during application startup, health checks,
planning or job execution. An existing installation is never overwritten.

```sh
# Explicit dependency preparation; skip this if the reviewed version is installed.
.venv/bin/python RedJohn/scripts/install-ffuf-pinned.py
.venv/bin/redjohn assess health
```

The managed receipt is `RedJohn/.tools/ffuf/2.1.0/receipt.json`. Configure its
absolute executable path and `binary_sha256`; do not confuse installation
presence, configuration readiness, verified binary execution and live evidence.
`health` deliberately does not claim live verification or launch the executable.

Configuration example: [assessment-ffuf.json](../examples/assessment-ffuf.json).
Replace the example scope, IP and binary path/digest with reviewed operator values.
The example is not authorization to contact any external target.

```sh
PYTHONPATH=RedJohn .venv/bin/redjohn assess run \
  --config /absolute/path/to/approved-config.json \
  --output redjohn_runs/approved-assessment --max-jobs 8
# Same configuration/output resumes the persistent queue without repeated requests.
PYTHONPATH=RedJohn .venv/bin/redjohn view \
  --assessment-dir redjohn_runs/approved-assessment --no-open
```

The private host configuration is named `ffuf` and contains `binary` (path,
version, SHA-256), `paths` (1–64 unique approved relative paths), optional
`rate_limit` (1–10 requests/second) and `request_timeout` (1–15 seconds).
Jobs may select a `path_subset` from that list. Arbitrary arguments, external
wordlists, configuration files, bodies, headers, mutations, vhost/query fuzzing,
authenticated replay, recursion, calibration and redirect following are unsupported.
A base URL must end in `/` and have no query or fragment. Traversal, encodings,
flags, empty path segments and known state-changing read routes are rejected.
Unknown application effects still require operator review of the approved paths.

The scheduler owns the scanner lease and closes idle Chromium before scanner
admission. Concurrency is one; stdout/stderr are drained concurrently with a
128 KiB cap per channel, process-group supervision, deadlines and cancellation.
The inspected host proxy enforces exact approved URLs, one send per URL/attempt,
shared persistent request budget/cooldown, fresh DNS/IP scope and verified upstream
TLS. Remote execution additionally requires a live, attested Linux network/PID/
mount/user namespace and private relay. macOS remote execution fails closed;
only explicit loopback lab fixtures run without the Linux boundary.

The upstream ffuf transport disables its own certificate verification. It is
therefore never the TLS security boundary: the host proxy verifies the actual
upstream CA/SAN/SNI and the remote worker cannot bypass that proxy. This adapter
also rejects compressed responses before forwarding any response header to ffuf,
which prevents ffuf's unbounded gzip/brotli/deflate decoding. This is an unsupported
response format, not a negative test. Wire responses are bounded to 1 MiB.

Every JSON result must agree with a complete proxy-observed response. Only 2xx/
3xx endpoints are added as observed inventory; 404 controls remain evidence.
Redirect destinations are not followed or authorized. Discovery emits no findings.
401/403/429/503, incomplete responses, schema errors, bad TLS, budget exhaustion,
missing binaries/locks and cancellation never become clean negative results.
Cancellation retains references to already committed evidence and discards finding
claims. The same protection applies to other scheduler adapters.

Job identity includes the pinned engine and approved paths. Changing only the
rate/request timeout does not repeat a completed test. An explicit retest revision
or meaningful input/tool/policy change is needed. Inventory, job state, evidence,
cooldown and request charges survive coordinator restarts. Network side effects
are not promised exactly once.

The assessment Web View reads at most 1 MiB of the public report, exposes up to
100 visible job/finding rows and keeps candidate counts separate from legacy
confirmed-vulnerability records. It reads no credential vault, raw evidence or
private SQLite state. Existing legacy run records take precedence. The view is
a snapshot: resume with the CLI and reload for a new report. Mutation endpoints
are disabled for its entire server lifetime, even if the report disappears.
This is not a live scheduler dashboard or a migration of the legacy agent/TUI
execution boundary. The TUI now displays the actual registered skill count;
registration is not a claim of live scanner coverage.

```sh
# Tests never install a fake or real engine automatically.
PYTHONPATH=RedJohn REDJOHN_REQUIRE_FFUF_E2E=1 .venv/bin/python -m pytest \
  RedJohn/tests/test_ffuf_contract.py RedJohn/tests/test_ffuf_live.py \
  RedJohn/tests/test_ffuf_cli_live.py RedJohn/tests/test_viewer_assessment.py -q
# On a prepared Linux runner, require actual non-loopback HTTPS/kernel egress too.
PYTHONPATH=RedJohn REDJOHN_REQUIRE_REMOTE_E2E=1 REDJOHN_REQUIRE_FFUF_E2E=1 \
  .venv/bin/python -m pytest RedJohn/tests -q
```

The live tests execute actual Chromium, ffuf and Nuclei against owned local
HTTPS fixtures, reopen the coordinator/store between stages, preserve captured
inventory provenance, run marker/fixed controls, and verify that resubmission and
QoS changes add no duplicate traffic. Real error cases cover TLS, gzip, 429,
budget exhaustion, binary tampering, cancellation and timeout. Contract/parser
fixtures are separate from those live executions. The harmless Nuclei marker
checks the pipeline, not RCE detection. Original RCE remains
`not_reproduced_missing_fixture`.

Current measurements, remaining capabilities, images and preservation evidence:
[verification report](../../docs/redjohn-ffuf-verification.md).
