# MIME replay and persistent CLI restart

RedJohn keeps the original Content-Type header and approved body bytes private
on the host. MIME interpretation never canonicalizes an authenticated request
on the wire. Existing integrations and legacy approval files remain compatible.

## Versioned request body interpretation

The private vault root still uses `"version": 2`. An individual approved POST
may additionally use `"body_contract_version": 2`. Omission or value `1` retains
the original strict validator. Do not confuse these two version fields.

Body contract 2 supports the following equivalent MIME representations:

- Case-insensitive JSON, URL-encoded form and multipart media types.
- Case-insensitive parameter names and UTF-8 charset values, optional whitespace,
  and quoted parameter values. Chromium's real
  `application/x-www-form-urlencoded;charset=UTF-8` is accepted.
- Quoted multipart boundaries, including permitted MIME boundary characters.
  Part Content-Type parameters are parsed; text parts remain UTF-8 and file
  parts remain opaque bytes.

Automatic Chromium POST capture first tries the legacy validator. A supported
MIME representation that needs the new interpretation is explicitly recorded
with body contract 2 in its private approval. SDK callers can request it with
`capture_authenticated_request(..., body_contract_version=2)`.

Each MIME header is bounded to 256 ASCII bytes and eight unique parameters.
Duplicate parameters, ambiguous syntax, unsupported main parameters, CR/LF and
non-UTF-8 text encodings are rejected with a precise contract error. This change
does not transcode ISO-8859-1/UTF-16 bodies or add XML/vendor JSON mutation.
The existing body, part, selector, response and scheduler budgets still apply.

Public Nuclei templates retain the existing canonical JSON/form Content-Type
or the existing `REDJOHN_HOST_REPLAY_BOUNDARY_V1` multipart placeholder. The
private body contract 2 binding checks semantic compatibility and restores the
exact approved target header and bytes on the host. No body or credential is
added to public templates or native worker arguments.

Session refresh rotates only explicitly reviewed body-token spans. It preserves
the body contract marker and original MIME header. Fresh capture may use a new
multipart boundary; matching compares the corresponding part bytes and keeps
unselected fields, uploads and token bindings intact. New captured body digests
flow through the existing durable outbox and scheduler identities.

## Restart and absolute deadlines

An engagement deadline is an absolute wall-clock authorization boundary. Host
sleep or VM clock synchronization can advance wall time while a guest's measured
monotonic test duration changes little. An apparently short restart can therefore
occur after authorization has expired.

The CLI keeps exit code 2 and `"error": "policy_denied"`, and adds a safe
allowlisted `"reason"`, for example `"campaign_deadline_exceeded"`. Arbitrary
exception text is never published. An expired restart neither replays POSTs nor
changes completed jobs or silently extends authorization. An operator must review
the authorization and use the existing new policy revision process when further
work is authorized.

For TInjA/Schemathesis recovery, a complete trusted 401 now fences subsequent
admission immediately, before the asynchronous native-worker stop executes.
This prevents another queued native request from becoming an incomplete admitted
request during shutdown. Truncated responses, TLS errors, missing responses,
403/challenges and unverified effects retain their existing recovery restrictions.

## Run and verify

From the repository root, using the existing pinned installations and private
approved configuration:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/approved.json \
  --output /absolute/private/engagement --max-jobs 32 --wait-ready-seconds 65

PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_mime_replay_contract.py \
  RedJohn/tests/test_restart_deadline.py \
  RedJohn/tests/test_mime_replay_live.py -q -s

cd RedJohn
../.venv/bin/mypy redjohn
```

Set `REDJOHN_NUCLEI_LOCK` to the actual fixture lock and require real tools with
`REDJOHN_REQUIRE_SCHEMA_OAST_E2E=1`. On Linux,
`REDJOHN_REQUIRE_REMOTE_E2E=1` requires the attested kernel boundary. macOS can
exercise the owned loopback HTTPS lab but cannot attest Linux namespaces.

`test_mime_replay_contract.py` and the three CLI allowlist cases are synthetic
contract controls. The live MIME cases use actual Chromium, HTTPS targets,
pinned native engines and official Interactsh receiver I/O. The deadline case
executes the original complete multi-process Chromium/Nuclei lifecycle and adds
one extra child whose Python wall clock advances by 600 seconds. This deliberate
clock injection is identified in measurements; it does not mock browser, TLS,
Nuclei, scheduler state or HTTP responses and does not change the host clock.

MIME syntax references:
[RFC 9110 section 8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1),
[RFC 7578 section 4.1](https://www.rfc-editor.org/rfc/rfc7578.html#section-4.1),
and [RFC 8259 section 8.1](https://www.rfc-editor.org/rfc/rfc8259.html#section-8.1).
