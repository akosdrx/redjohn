# Reviewed specialist input in v3 captured bodies

The private replay proxy can mutate one explicitly reviewed input for TInjA,
Schemathesis or the owned Interactsh correlation path in an approved v3 body.
This extends the existing UTF-8 JSON/form/multipart behavior to the bounded
vendor-JSON, XML, charset and text-file profiles described in
[the wire-body contract](redjohn-extended-wire-replay.md).

`Surface.input_occurrence` is optional. Omitting it preserves historical surface
and persisted job identities and requires an unambiguous selected field.
Explicit zero selects the first occurrence; another integer selects that exact
occurrence. The range is 0..127. It does not authorize a new URL, actor, method,
body, session or mutation profile.

XML occurrence counting includes matching self-closing, non-leaf and split-text
elements. Selecting an unsupported element is rejected; it never shifts the
selector to a later sibling. An omitted selector remains ambiguous when more
than one matching element exists. Protected empty values also reserve their
insertion point: an empty CSRF/session token cannot become a scanner input.

JSON selection preserves the original codec, BOM, whitespace and every
unselected occurrence. XML uses an exact element/attribute wire path, without
executing XPath, and escapes text, attribute or CDATA replacements in context.
Form encoding uses the approved charset. A `multipart_file` input requires v3
and an explicitly typed text/JSON/XML file part; its filename, headers, BOM and
other binary parts remain unchanged. Multipart delimiter injection, invalid
encoding, oversized output, ambiguous selection and overlap with a protected
session token are rejected before target transmission. The complete resulting
body is revalidated against the existing framing and 64 KiB limits.

Public adapter routing may use the base MIME `multipart/form-data`. Only the
private captured Content-Type with its actual boundary authorizes materializing
the POST. The worker still sees the existing public GET carrier; private body
bytes, cookies and body tokens remain with the trusted proxy.

The durable workflow forwards the reviewed occurrence selector. Session refresh
revokes the old binding, rotates the protected body token, schedules a new real
browser capture and then schedules the current-session specialist job in the
same running scheduler. A stale capture grants no replay permission. XML
Schemathesis projection supports only the reviewed two-level root/property or
root/attribute form; arbitrary XML schemas and XPath are unsupported.

## Actual checks and their scope

`tests/test_extended_input_replay_contract.py` contains byte-exact parser and
admission contracts; it is not a native scanner integration. An earlier focused
combined contract selection passed **68 cases in 0.17 seconds**. Existing
body-token/capture/replay compatibility checks also passed **134 cases in
16.60 seconds**. These commands did not run a full local regression.

An independent review then reproduced seven failing empty-protected-token/XML
occurrence regressions. After the narrow collision/counting fix, the selected
input plus wire/XML compatibility selection passed **146 cases in 1.02 seconds**.
Original failing and corrected JUnit/logs remain separate. These are parser and
private-binding contracts, not seven native scanner integrations.

The corrected collision/XML implementation also passed four actual loopback
TInjA cases (XML and multipart text file, positive/fixed) in **14.17 seconds**.
The other final-source profiles remain part of the mandatory hosted matrix;
earlier successful selections are not silently relabelled as that full run.

`tests/test_extended_input_replay_live.py` uses actual Chromium, the pinned
TInjA 1.2.0 / Schemathesis 4.31.1 engines and the pinned Interactsh 1.4.1
receiver, real owned TLS services, private capture and persistent SQLite jobs.
Only the owned fixture and reviewed operator configuration are adapted to the
three test profiles. Native engine output and browser capture are not mocked.
No model/provider conversation is exercised.

Completed targeted macOS loopback results before the final JSON offset
optimization:

| Selection | Passed | Failed | Skipped | Time |
| --- | ---: | ---: | ---: | ---: |
| Vendor JSON UTF-16 and XML Latin-1, three tools, positive/fixed | 12 | 0 | 0 | 45.41 s |
| UTF-16 multipart text file, three tools, positive/fixed | 6 | 0 | 0 | 23.57 s |
| Three profiles and tools, refresh/recapture without restart | 9 | 0 | 0 | 52.76 s |

The first multipart run failed six cases at admission because a public routing
check incorrectly required the private boundary. The correction separates that
public routing check from unchanged private framing validation. The original
failed JUnit/log is retained beside the corrected result.

After reducing JSON byte-offset work to the selected occurrence, a six-case
JSON recheck passed four cases; two browser jobs were blocked before sending
with `host_resource_busy` during concurrent development checks. Those blocked
jobs are recorded as failed validation cases, not negative findings or scanner
successes. No resource limit or shared reservation was disabled or cleared.
After the overlapping browser checks ended, only those two affected cases were
rerun: **2 passed in 12.43 seconds**, with the same shared pool and limits. The
original failed receipt remains separate. This verifies all six JSON cases on
the final selected-offset implementation; the earlier XML/file results remain
separately identified rather than being presented as a full final-source run.

The complete file defines 45 cases, including remote-interface namespace cases.
These local loopback runs do not prove Linux isolation or the final hosted
x64/ARM64 matrix. The full Actions integration selection includes this file and
requires real capabilities. Live cloud/Kubernetes account access remains
deferred by the owner and is unrelated to these owned TLS fixtures.

Example focused commands from `` (dependencies and pinned tools must
already be installed):

```sh
.venv/bin/python -m pytest -q tests/test_extended_input_replay_contract.py
.venv/bin/python -m pytest -q tests/test_extended_input_replay_live.py \
  -k 'loopback and not multipart'
.venv/bin/python -m pytest -q tests/test_extended_input_replay_live.py \
  -k 'loopback and multipart'
.venv/bin/python -m pytest -q tests/test_extended_input_replay_live.py \
  -k refresh_recapture
```

JUnit, diagnostic logs, per-profile request/session metrics and source hashes
are retained under
`docs/measurements/master-completion-20261018/extended-input/`. That generated
evidence directory is excluded from source publication; Actions preserves its
own commit-bound evidence as artifacts even on failure.
