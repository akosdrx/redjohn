# Selected TInjA, Schemathesis and Interactsh jobs

These adapters extend the existing RedJohn controller. Optional tools are lazy:
configuration/health inspection never starts a scanner, receiver or browser.
Only selected jobs run, through the persistent SQLite scheduler and its shared
request/rate/resource budgets. Existing browser, Nuclei, session and MCP paths remain.

The current [authenticated POST/session extension](authenticated-schema-oast.md) adds
private JSON/form/multipart selected fields and automatic fresh-session children.
The GET profiles and pinned versions below remain available.

## Implemented profiles

| Capability | Actual implementation | Required input | Verdict boundary |
|---|---|---|---|
| `tinja_validate` | TInjA 1.2.0 native CLI | Successful capture, selected GET or reviewed private POST field, reviewed `ssti` hint | Scanner candidate; template evaluation is not RCE |
| `schemathesis_validate` | Schemathesis 4.31.1 CLI, isolated pinned wheels | Successful capture, one bounded integer GET/POST input projection, pinned OpenAPI subset, reviewed `schema` hint | Response conformance candidate; no exploitability claim |
| `oast_correlate` | RedJohn host implementation of the Interactsh 1.4.1 protocol | Captured GET or approved named POST text input, reviewed `oast_http` hint, separately approved owned receiver | One target delivery, encrypted callback correlation; candidate only |
| `oast_poll` | Controller-generated durable continuation | Committed parent/outbox, same allocation/policy/surface and private session | Bounded late polling; no target redelivery |

No job is created automatically for every discovered URL. A hint is an operator
reviewed hypothesis, not independent vulnerability proof. Its JSON is exactly
`{"signal":"ssti|schema|oast_http","request_ref":"...","input_name":"..."}`;
choose one signal, never the literal pipe-separated string. Submit its existing
evidence ID as `options.hint_ref` or the selected CLI job's `hint_ref`.
Re-recording a hint under another evidence ID does not authorize repeat traffic.
Tool/profile/session/surface revisions and explicit retest still affect identity.

## Request and runtime enforcement

TInjA and Schemathesis see an HTTP alias for one selected endpoint. The host
rewrites it before authorization, credentials, DNS or connect, pins all DNS
answers, connects numerically and verifies upstream TLS hostname and chain.
TInjA's own insecure TLS defaults cannot disable this HTTPS validation.
Alias-only workers are denied direct CONNECT tunnels before admission or
credential handling, including tunnels to an otherwise in-scope destination.
Workers on remote targets require the existing attested Linux network namespace;
missing kernel support fails closed. The macOS loopback fixture profile is a
distinct isolated-lab exception and proves no remote kernel containment.

The host rejects unselected parameters/paths/methods, raw-key canonicalization,
extra query pairs, encoded responses, redirects, auth challenges and rate limits.
TInjA uses the attributed finite 71-item expression/syntax/context catalogue and
its bounded controls. Arbitrary file, shell or import probes are not accepted.
GET baselines are benign. Named GETs use exact private credential bindings;
reviewed named POSTs use the private selected-field bridge documented in the extension.
Actual detection controls use sandboxed Jinja versus escaped rendering. Other
template engines, TInjA CSTI and arbitrary unreviewed body mutation remain unverified.
JSONL output is not evidence of JSON request-body support.

Schemathesis accepts a bounded local OpenAPI 3.0.3 JSON subset: one GET operation or reviewed POST projection,
one required integer input with range inside 0..100, and flat JSON
response properties. Refs (including local files), links, alternate servers,
callbacks, security providers, plugins and extra operations are rejected.
The request profile is positive fuzzing only, 4–16 examples, one worker, fixed
seed, no shrinking/retries/stateful execution and no persistent upstream cache.
Two unconditional upstream preflight probes leave the selected operation and
send control characters. The version-checked private wrapper marks them **SKIP**;
their absence is not successful coverage. Actual generation, HTTP transport and
conformance checks remain upstream. GraphQL and mutating/CRUD workflows are unsupported.

Each worker has a finite deadline and process-group TERM/KILL cleanup. Per job:
8–128 requests, 1–10 requests/s plus the engagement's persistent limiter,
1–10 s HTTP timeout, two proxy connections, 64 KiB response wire limit,
512 KiB stdout/stderr each, 1 MiB file-size rlimit and disabled core dumps.
The Python bundle is at most 128 MiB / 8192 files for Schemathesis; the existing
Arjun/sqlmap 64 MiB / 4096 bounds remain. RAM admission and sampling are cooperative,
not a universal OS hard memory limit. Policies, jobs and finite artifact quotas
continue to apply to the controller and every phase.

## Interactsh lifecycle

The trusted host client uses the same numeric/TLS-enforcing proxy for its exact
receiver API requests and its single reviewed target GET or approved private POST. It does not launch an
untrusted CLI process. Receiver origin/IP authorization is separate from active
target scope. No default public service is selected, no file hosting/ASN lookup,
upload or external identity enrichment runs. The optional official server is
explicit test/owned infrastructure and is never started by the product adapter.

Registration, target-dispatch reservation and draining polls are checkpointed.
The server encrypts events with RSA-OAEP/SHA-256 and AES-256-CTR; even empty poll
responses must decrypt the correct session key. Match exact full ID, nonce path,
protocol and timestamp window. Store only bounded correlation metadata/evidence,
not raw callback bodies or receiver credentials. A callback alone proves neither
code execution, file access, nor the identity of its sender.

Keys/tokens stay in 0600 files under a 0700 host directory. Limits are 64 private
allocations, 16 events, 2–16 polls and a 3–60 s observation window. The SQLite
outbox only releases a child after successful parent commit; a stable key handles
enqueue-before-ack recovery. Normal restart resumes polling without redelivery.
After acknowledged deregistration, private key/receiver secret are retired;
a metadata tombstone prevents reallocation. Failed/uncertain sessions retain
their private state for operator reconciliation, within the allocation bound.
The existing scheduler deliberately does not replay expired leases, even for GET.
An interrupted draining poll therefore stays inconclusive, never a clean negative.

DNS delegation, internet callback reachability, IPv6 callback paths and additional
protocols are not established by the owned HTTP receiver test. Automatic Nuclei
OAST binding, XML and file-part mutation remain unsupported. Reviewed authenticated
POST text inputs use the existing private capture/vault contract.

## Installation and use

From the repository root, explicitly install only the wanted engines:

```sh
.venv/bin/python scripts/install-schema-oast-pinned.py tinja
.venv/bin/python scripts/install-schema-oast-pinned.py schemathesis
# Only for owned receiver infrastructure / the real receiver E2E:
.venv/bin/python scripts/install-schema-oast-pinned.py interactsh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment health
```

The installer verifies upstream asset/wheel/license hashes, retains license texts
and refuses overwrite. It does not pip-install into RedJohn or run upstream install
scripts. Schemathesis locks include platform and Python minor: macOS ARM64/3.13,
Linux ARM64/3.12 and a prepared Linux AMD64/3.13 CI lock. A lock's existence is not
live platform proof. See the actual verification report for tested platforms.

Start with approved Chromium discovery into the same output workspace, then choose
an observed input and record the reviewed hint through the host store API. Populate
the version/digest fields from each local install receipt. The configuration
example has empty seeds/jobs deliberately; it sends no requests by itself.

```sh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/path/approved-schema-oast.json \
  --output /absolute/path/engagement --max-jobs 16 --wait-ready-seconds 65
```

`--wait-ready-seconds` is optional, defaults to zero and is bounded to 120 seconds.
It lets the running controller execute future ready jobs with no worker lease held
while sleeping; `--max-jobs`, campaign deadlines and cancellation still apply.
Queue entries survive a zero-wait exit or an exhausted batch/wait budget. Resume
with the same approved configuration/output. Do not call a pending window negative.

```sh
PYTHONPATH=. REDJOHN_REQUIRE_SCHEMA_OAST_E2E=1 \
  .venv/bin/python -m pytest tests/test_schema_oast_contract.py \
  tests/test_schema_oast_live.py -q -s -p no:cacheprovider
```

## Provenance

The pin file records commits, asset/source/license hashes and each Schemathesis
dependency wheel/version/license. No Strix/HexStrike code is added by this change.
The TInjA catalogue is a necessary attributed Apache-2.0 data component; its full
license is retained under `assessment/notices/`.

- [TInjA 1.2.0 source](https://github.com/Hackmanit/TInjA/tree/a434f525798cdc942427b22894608a5d9181037b): Apache-2.0.
- [Schemathesis 4.31.1 source](https://github.com/schemathesis/schemathesis/tree/76b10a59d248eaf578df82841edb48c8e25a2e44): MIT; dependency licenses remain in the bundle/lock.
- [Interactsh 1.4.1 source](https://github.com/projectdiscovery/interactsh/tree/a5b78b2f1d990cd18c85cc422f0e651cf204c464): MIT; host protocol implementation verified against the official receiver.
- [Official Schemathesis CLI reference](https://schemathesis.readthedocs.io/en/stable/reference/cli/).

The earlier sqlmap redistribution/licensing boundary is unchanged; this document
does not grant commercial redistribution clearance for the complete product.
