# Explicit v3 body replay

Per-request `body_contract_version: 3` adds vendor JSON (`application/*+json`),
XML (`application/xml`, `text/xml`, `application/*+xml`) and a closed set of
character encodings: UTF-8, ISO-8859-1, Windows-1250/1252 and UTF-16 with an
explicit byte order or BOM. The original Content-Type, body bytes and BOM are
retained. Conflicting declarations, invalid sequences and unsupported codecs
fail closed. The existing v1/v2 contracts retain their original authority.

This is private operator configuration. A target response/header does not
upgrade a request to v3. Automatic browser capture requires an explicit v3 rule
for the exact approved URL, named actor, tenant and session revision. Replay
still requires successful durable capture, current policy/session and reviewed
Nuclei template authority. Bodies and credentials stay in the private vault;
workers receive the existing public host-body marker.

## Token bindings

Existing JSON pointers and repeated-field `occurrence` selectors work with the
approved codec. Only the selected wire span changes. Form percent-encoding uses
the approved charset. Multipart text parts use their own charset, falling back
to the enclosing approved charset independently for every part. Binary uploads
remain byte-exact.

New v3 binding locations are:

* `xml`: exact wire-prefix element path such as `/soap:Envelope/soap:Body/request/token`,
  or an attribute such as `/request/@csrf`. No XPath expression runs. Only
  contiguous text, a single CDATA value, or a selected attribute is mutable.
* `multipart_file`: an explicitly selected text file part, with an explicit
  text/JSON/XML MIME type. Binary and unspecified file types are rejected.
  The filename, headers, BOM and other parts remain unchanged.

XML has a 64 KiB body limit, 64-element depth, 4096-node and 128-attribute limits.
DTD declarations, entity definitions and external entity loading are forbidden.
Namespace declarations cannot be token selectors. XML escaping matches the
selected text/attribute context; CDATA terminators and unrepresentable refreshed
characters are rejected without changing the approved encoding.

Rotation revokes the old request reference and sets `fresh-capture-required`.
It grants no replay permission until a new successful browser capture matches
the expected bytes. v3 capture cannot be silently downgraded to a legacy body
contract. No arbitrary XPath, stylesheet, decoder plugin or target-supplied
selector is evaluated.

## Verification boundary

The focused local command exercises real parsers and exact byte substitutions,
plus the existing owned TLS/proxy fault tests and the pre-existing actual Nuclei
multipart regression. It does not prove the new v3 scanner chain or Linux
namespace behavior:

```sh
cd RedJohn
../.venv/bin/python -m pytest -q tests/test_wire_encoding_xml.py \
  tests/test_extended_wire_replay_contract.py tests/test_replay_body_contract.py \
  tests/test_mime_replay_contract.py tests/test_body_token_refresh.py \
  tests/test_browser_post_capture.py -k 'not actual_chromium'
```

Observed result: **170 passed, 0 failed, 0 skipped, 1 deselected, 9.43 s**.
The deselected case requires the actual Chromium run, rather than being counted
as a successful contract. Strict mypy over the eight changed production modules
and their Ruff checks pass. The receipt records their source hashes separately.
Known reflected private text is also masked in its approved wire encoding,
including UTF-16 NUL-interleaved, Base64 and percent-encoded forms; trusted
numeric/boolean engine protocol fields retain their original types.

`tests/test_extended_wire_replay_live.py` adds two actual Linux E2E variants:
UTF-16 vendor JSON and ISO-8859-1 XML. Both use the existing real Chromium,
private capture, Nuclei, session-refresh and independent CLI restart lifecycle
with positive/fixed/redirect controls and exact request accounting. These tests
are included in the hosted integration suite; they are **pending hosted
execution**, not passed based on the local parser tests.

The first completed hosted candidate (`1ba82ce568c12fdda1468a47c6e08056fd5942df`,
[run 39147621368](https://github.com/akosdrx/redjohn/actions/runs/39147621368))
blocked both variants before scanner admission. A targeted native Ubuntu ARM64
reproduction identified `template_contract_error`: the public Nuclei marker
template still used the old MIME regular expression. The fix validates bounded
v3 JSON/XML/form marker MIME syntax while retaining private binding/version,
exact MIME/charset and per-request proxy checks. Multipart templates retain
their existing fixed public-boundary subset.

With only the corrected `nuclei.py` overlaid into a separate frozen source copy,
both actual variants passed in **53.73 seconds**. Each completed 17 independent
CLI stages, 19 observed requests equalling 19 persisted requests, six positive
candidates, one refresh from revision 7 to 8, new capture and replay, and zero
fixed-control findings, duplicate-restart requests or credential-trap requests.
Each variant recorded 34 namespace attestations with no capabilities, no new
privileges and loopback-only networking. The owned 1 GiB/swap-zero cgroup peaked
at **410,849,280 bytes**, with zero OOM events and no populated processes after
cleanup. The sampled summed RSS is a different measurement and double-counts
shared pages; it is not the cgroup peak.

These are real, targeted Linux ARM64 results, not a completed corrected hosted
x64/ARM64 matrix. Before/after JUnit, metrics and hashes are retained separately
under `docs/measurements/master-completion-20261018/extended-wire/`.

Selected specialist input mutation for these new XML/codec/file profiles is a
separate capability boundary. Existing TInjA/Schemathesis/OAST UTF-8 POST support
continues to work; this change does not claim unverified extended profiles for
those engines.
