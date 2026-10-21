# RedJohn HTTP(S) browser transport verification

Verified 2026-10-17 in the existing RedJohn checkout. This document covers the
browser transport and independent proxy guard. The durable scheduler and actual
Nuclei engine have separate end-to-end evidence in the main verification report.
No browser, proxy transport, or TLS server was mocked in the tests below.

The final combined run adds two real idle HTTP/TLS connection regressions:
17 browser/proxy cases passed as part of 230 successful Python tests. The
empty speculative client close is harmless; incomplete upstream response
framing still prevents the completed-response callback. Current combined
evidence: [HTTPS/Nuclei verification](redjohn-https-nuclei-verification.md).

## Implementation and trust boundary

- `redjohn/assessment/browser_tls.py`: `BrowserTLSConfig(upstream_ca_file=None)`
  uses the default verified TLS client context. An explicit PEM CA file may be
  supplied for an owned local fixture. Certificate-chain and IP/hostname checks
  remain enabled. The TLS minimum is TLS 1.2; ALPN is HTTP/1.1.
- `BrowserEgressProxy` terminates CONNECT with its own ephemeral CA/leaf chain,
  inspects the decrypted HTTP/1.1 request, checks the engagement policy and
  shared read-only request guard, then obtains persistent request admission
  before opening the actual upstream connection. Every connection carries at
  most one application request. HTTP redirects obtain their own admission.
- Chromium receives exactly the generated leaf key's SPKI SHA-256 pin through
  `--ignore-certificate-errors-spki-list`. `ignore_https_errors=False` remains
  set. There is no global certificate-ignore flag and no system/keychain trust
  import. An actual Chromium negative test proves another ephemeral key is
  rejected with `ERR_CERT_AUTHORITY_INVALID` and zero upstream HTTP requests.
- The temporary certificate directory is mode 0700, its certificate and private
  leaf key are mode 0600, and close removes the directory. No CA signing key is
  persisted. The identity lives only for this browser/proxy lifecycle.
- The proxy independently rejects mismatched CONNECT/Host authorities,
  absolute HTTPS request targets, duplicate request headers, body-bearing read
  requests, unsafe methods, known state-changing read routes, and upgrades.
  It strips hop-by-hop and proxy credentials before forwarding. Actor cookies
  and authorization reach the permitted origin but never enter its response
  metadata callback or persistent browser inventory.
- Response headers are bounded to 16 KiB, total wire response to 8 MiB by
  default, concurrent proxy connections to 16, and connection lifecycle to
  10 seconds. Bodies stream in chunks of at most 64 KiB. Content-Length and
  chunked framing must complete correctly; truncated/oversized responses have
  no complete-response callback. The callback includes only URL, status,
  Content-Type, and Retry-After. These limits are enforced code paths.
- Browser cancellation closes the actual context, joins its outstanding
  Playwright channel operation with a cleanup deadline, and releases context,
  page, browser, and proxy resources. Cancellation is not a negative scan result.

The current authorization boundary still permits only explicit literal-loopback
local labs. Remote targets remain blocked while independently enforced remote
worker egress is unavailable. The proxy is not an OS network namespace or a
raw-socket containment mechanism. It is intentionally HTTP/1.1 only, blocks
WebSockets, does not execute unsafe browser form submissions, and does not
capture response bodies as inventory evidence. Chunk extensions are rejected
rather than silently accepted. These limits are capability boundaries, not
negative vulnerability results.

## Reproduction

From `/Users/akosdrx/Documents/rjkali/RedJohn`:

```sh
.venv/bin/python -m pytest tests/test_assessment_browser.py tests/test_assessment_browser_https.py tests/test_assessment_browser_proxy_https.py -q -s
.venv/bin/python -m ruff check redjohn/assessment/browser.py redjohn/assessment/browser_proxy.py redjohn/assessment/browser_tls.py tests/test_assessment_browser.py tests/test_assessment_browser_https.py tests/test_assessment_browser_proxy_https.py
.venv/bin/python -m mypy redjohn/assessment/browser_tls.py redjohn/assessment/browser_proxy.py redjohn/assessment/browser.py --follow-imports=silent
```

The browser extra is pinned to Playwright 1.58.0. The actual executable identified
itself as Chromium **145.0.7632.6**, with the Chromium sandbox enabled and no
no-sandbox fallback. The fixture uses ephemeral certificates and a dynamic port
on 127.0.0.1; no remote service or external LLM is involved.

## Executed results

**15 passed in 15.20 s**, zero skips, plus Ruff and targeted strict mypy passed.
The run includes:

| Actual test | Result |
|---|---|
| Existing HTTP SPA/fetch/XHR discovery, actors, POST blocking, limits, redirect, cancellation, crash | 5 passed |
| HTTPS SPA discovery, secure actor cookies, request admission, cleanup | Passed |
| HTTPS upstream self-signed certificate, trusted-chain wrong IP SAN, unrelated CA | All denied; zero application HTTP requests reached upstream |
| HTTPS redirect to unauthorized HTTP `localhost` | Denied; `/forbidden` received zero requests |
| HTTPS readiness cancellation | Context/page closed; no unobserved channel exception |
| Independent TLS proxy Host mismatch/body/duplicate header/POST/absolute target/stateful GET | Denied before admission or actual upstream request |
| Independent proxy request budget | Two attempted requests produced one admitted and one actual upstream GET |
| Chromium wrong SPKI | Certificate rejection; zero forwarded requests |
| Response truncated Content-Length, missing terminal chunk, oversized body | Zero complete callbacks; proxy limit failure recorded |

Measured HTTPS fixture run:

```json
{
  "chromium_version": "145.0.7632.6",
  "durations_seconds": [0.340633, 0.297628],
  "model_calls": 0,
  "process_count_before": 2,
  "process_count_during": 6,
  "process_count_after": 2,
  "process_tree_rss_bytes": 434192384,
  "requests": 9
}
```

The two successful actor cycles sent 8 GET requests. The third budget test
admitted one additional GET and denied subsequent requests. Exactly 9 requests
were admitted and exactly 9 reached the TLS fixture. `/api/me` received secure
actor cookies in order `alice`, `bob`. Three contexts/pages were created and
closed; the ephemeral proxy directory no longer existed after service close.
The RSS value is one process-tree sample (about 414.08 MiB), not a claimed peak
or leak proof; summed RSS can count shared pages more than once. The existing
HTTP five-cycle test sent 25 requests and returned from six processes to the
original two after cleanup.

## API integration

```python
from redjohn.assessment.browser import BrowserDiscoveryService
from redjohn.assessment.browser_tls import BrowserTLSConfig

tls = BrowserTLSConfig(upstream_ca_file=fixture.ca_file)
service = BrowserDiscoveryService(policy, governor, tls_config=tls,
                                  request_admission=persistent_admission)
```

The proxy can also be used without launching Chromium:

```python
from redjohn.assessment.browser_proxy import BrowserEgressProxy

proxy = BrowserEgressProxy(policy, tls_config=tls,
                          request_admission=persistent_admission,
                          on_response=record_complete_response)
await proxy.start()
# Pass proxy.url to the separately governed scanner worker.
await proxy.close()
```

The complete-response observer executes only after a bounded, correctly framed
response has been forwarded. A scanner result still requires its own template,
engine, evidence, error, and coverage validation.

References checked during implementation: Python
[stream TLS upgrade API](https://docs.python.org/3/library/asyncio-stream.html#asyncio.StreamWriter.start_tls)
and cryptography's [X.509 tutorial](https://cryptography.io/en/latest/x509/tutorial/).
The decisive certificate-pin evidence is the installed Chromium positive and
wrong-pin negative execution above.
