# Authenticated POST replay and durable session refresh

The optional [continuous replay workflow](continuous-refresh-replay.md) continues
successful refresh, real fresh browser capture and explicitly selected Nuclei
replay in the same running scheduler. Manual replay examples below remain valid.

The current [Chromium capture/body-token workflow](browser-post-body-tokens.md)
adds private automatic browser approval, current-revision startup jobs and
reviewed field-token rotation. The trusted-host HTTPX capture SDK below remains
available; its earlier measurements are a separate workload.

RedJohn reuses its existing pinned Nuclei adapter and persistent SQLite scheduler.
Authenticated replay supports exact observed GET/HEAD requests and an explicitly
approved POST subset: JSON, URL-encoded forms and multipart forms/uploads, with a
64 KiB request-body ceiling. POST requires `active-staging` or `isolated-lab`, a
named actor, exact `allowed_replay_urls`, a private version-2 vault and verified
sent-request evidence. General login/MFA/password-reset automation remains a
separate missing capability.

The existing Linux namespace boundary remains mandatory for remote Chromium and
Nuclei workers. The trusted host proxy validates every decrypted request, connects
to an approved numeric IP with the original TLS hostname, and verifies upstream
CA and hostname. Body replay does not expand the origin/IP policy or permit
redirects, dynamic templates, fuzzing, arbitrary scanner arguments or shell access.

## Capture and private approval

The trusted-host SDK helper `capture_authenticated_request` sends one reviewed
POST using the exact private body and authentication headers. This is a real
request with application side effects; use designated test objects and cleanup.
The caller supplies the body and headers from a private source, outside the
repository and worker workspace:

```python
from redjohn.assessment.capture import capture_authenticated_request
from redjohn.assessment.models import JobSpec, Surface

surface = Surface(
    approved_url,
    method="POST",
    content_type="application/json",
    actor_id="alice",
    tenant_id="tenant-a",
    session_revision="7",
)
observed = await capture_authenticated_request(
    runtime.policy, store, surface,
    body=private_body_bytes,
    headers=private_auth_headers,
    tls_config=reviewed_tls_config,
    rate_limits=runtime.rate_limits,
)
```

Capture preserves JSON whitespace/order, duplicate form parameters, percent
encoding, multipart boundary/part order and upload bytes. The validator checks
finite, bounded JSON; strict form encoding; and a bounded multipart subset with
at most 32 parts, 4 KiB part headers and a 1–70 character reviewed boundary.
XML, raw HTTP bodies, nested multipart and unknown formats are unsupported.
The exact wire bytes are never reconstructed from parsed values.

`rj_request_capture` durably reserves the request by engagement, policy revision
and surface/body identity. Only its fenced owner can atomically admit one request
and charge the shared SQLite budget. A completed reservation returns its existing
observed surface after restart, with zero new network traffic. Concurrent capture
is blocked. A lost/expired reservation or uncertain response cannot be resent
automatically. Only request metadata and a body SHA-256 enter inventory/evidence;
the body, upload contents and credentials remain private.

Approve the resulting `request_ref` and body digest in a private vault. Version 1
GET/HEAD vaults remain compatible. Version 2 adds these fields to a POST request
inside an otherwise unchanged identity entry:

```json
{
  "url": "https://authorized.example:443/submit",
  "method": "POST",
  "request_ref": "<actual-capture-evidence-reference>",
  "content_type": "application/json",
  "body_base64": "<base64 of the exact private bytes>",
  "body_sha256": "<SHA-256 of those bytes>",
  "replay_safety": "operator-approved"
}
```

The enclosing file is `{"version": 2, "entries": [...]}`. Every entry retains
engagement/owner/policy/actor/tenant/session revision, expiry, canonical HTTPS
origin, `allowed_requests`, authentication headers and cookies, as documented in
[authenticated replay](nuclei-auth-replay.md). The current user must own the
regular, single-link `0600` file; symlinks and files over 256 KiB are rejected.
`auth_vault_file` configures this host-only source. Credentials, CSRF headers and
body values reflected by a target are redacted before scanner evidence persists.
Classification uses bounded original scanner output only in host memory. The
persisted JSONL masks reflected string values while retaining public schema
keys and typed protocol numbers/flags; redaction cannot erase candidate counts
or turn an inconclusive run into a completed negative. Known JSON scalar values
and ordinary URL/base64/HTML-escaped reflections are included. This is bounded
known-value masking, not a claim to detect arbitrary target-side encryption or
custom transformations.

## Reviewed template and scheduler contract

A POST template must be individually reviewed and locked with
`effect="authenticated-replay"`; it cannot allow `safe-production`. Its HTTP
request uses the exact approved Content-Type and the public body sentinel:

```yaml
http:
  - method: POST
    path:
      - "{{RootURL}}/submit"
    headers:
      Content-Type: application/json
    body: REDJOHN_HOST_REPLAY_BODY_V1
```

The actual template also needs its reviewed ID/info/matchers and the engine and
complete bundle locks. For multipart, the additional exact public Content-Type sentinel
`multipart/form-data; boundary=REDJOHN_HOST_REPLAY_BOUNDARY_V1` permits a fresh
Chromium boundary while retaining the same reviewed bundle. The scanner sees only
public sentinels. The proxy
accepts that exact reviewed request and replaces the sentinel with the approved
private bytes in host memory. Arbitrary template body substitution is denied.
The original upload/body never enters template files, worker mounts, argv or job
options.

For per-request `body_contract_version: 2`, public templates keep the canonical
JSON/form Content-Type shown above or the existing multipart sentinel. The host
checks semantic MIME compatibility and restores the exact private header, body
and token bytes. See [MIME replay and restart](mime-replay-and-restart.md); the
private vault root remains version 2 independently of this body marker.

After private-vault approval, queue the observed surface explicitly:

```python
surface_id = store.upsert_surface(runtime.policy.engagement_id, observed)
spec = JobSpec(
    surface_id, "known_vulnerability", "nuclei_scan",
    policy_revision=runtime.policy.revision,
    idempotent=False,
    **runtime.registry.execution_versions("nuclei_scan"),
)
store.submit(runtime.policy, [spec])
await runtime.scheduler.run_batch(max_jobs=1)
```

Both submission and execution reject a POST replay incorrectly marked
idempotent. The controller checks exact observed URL/method, actor/tenant,
session/policy revision, request reference, body hash and actual sent-request
metadata before any engine I/O. A valid empty scanner result requires a complete
expected 2xx response and a healthy parser/proxy; 401/403/429, redirect, TLS error,
truncation or missing capability is not a completed negative result. Matches stay
candidate findings.

## Explicit session refresh

Configure a private `refresh_provider_file` together with `auth_vault_file`.
`allowed_refresh_urls` separately authorizes exact HTTPS POST refresh endpoints;
it does not authorize ordinary scanner POST replay. Queue `session_refresh` with
`idempotent=False`, empty options, the current policy revision and the actor's
current session revision. Refresh may use a scoped observed surface or an
explicit operator-approved seed; it never invents an observed POST capture.

The provider configuration, response schema and 30-second/64-KiB transport bounds
are in [durable session refresh](session-refresh.md). The provider's own refresh
credential remains private. A successful response rotates approved authentication
and CSRF headers/cookies and atomically advances the numeric revision, for example
`7` to `8`, using SQLite CAS and fenced job ownership.

Successful refresh invalidates the current runtime's actual cache entries for the
old engagement/actor/tenant/session revision and fences late cache publication.
The result reports `cache_invalidated`; unrelated actor/revision entries remain.
This is a per-runtime cache. Other processes rely on durable session-state fences
and revision-scoped keys rather than a claimed global cache invalidation.

Existing revision-7 jobs and captures retain revision 7 and become blocked.
New revision-8 POST work requires a real fresh capture and explicit private-vault
request approval. No queued job, old evidence or private body is silently
relabelled. Refresh itself has no anonymous fallback or automatic retry.

Embedded authentication/CSRF values can now rotate only through explicit private
`body_tokens` field bindings. New body approval remains pending until a real
fresh Chromium capture confirms it under a reviewed automatic-approval rule.
Unbound bytes/uploads are preserved; only valid multipart boundary framing may
change. The schemas, limits and startup flow are in the
[browser/body-token workflow](browser-post-body-tokens.md). Provider refresh-token
rotation and cross-origin credential fan-out remain unsupported.

A lost response, cancellation after admission, worker loss or a crash between
private-vault replacement and SQLite commit is an uncertain outcome. Reconcile
server/private state and issue a newly reviewed policy revision and matching
configuration; do not restart the same mutating request as though it were safe.

## Reproduction and verification boundaries

Current source, commands, measured results and remaining blocks are recorded in
the [POST/session verification report](archive/redjohn-post-refresh-verification.md).
The [standalone actual-engine measurement](measurements/post-refresh-nuclei-live.json)
and [Linux persistent-chain measurement](measurements/post-refresh-linux/post-refresh-e2e.json)
describe separate workloads; historical GET/HEAD numbers must not be relabelled
as POST/refresh measurements. The newer actual Chromium POST/body-token chain
has [its own report](archive/redjohn-browser-token-verification.md).

From the repository root, after the explicit pinned engine/browser prerequisites:

```bash
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_post_policy_and_proxy.py \
  tests/test_assessment_session_refresh.py \
  tests/test_capture_reservations.py -q

PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_nuclei_post_live.py -q -s

REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_POST_REFRESH_MEASUREMENTS=/tmp/redjohn-post-refresh.json \
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_post_refresh_pipeline.py -q -s
```

Unit/mock checks, real loopback HTTPS engine/provider tests and the Linux
non-loopback host capture–persistent scheduler–Nuclei–refresh chain are
separate evidence. This older POST chain uses the trusted-host capture SDK;
`test_browser_token_pipeline.py` separately exercises actual Chromium POST capture
and body-token refresh.
The mandatory remote flag turns missing Linux/bubblewrap or Nuclei prerequisites
for the POST chain into a test failure. The tests use owned,
disposable HTTPS services; they do not establish behavior on an unrelated public
application, full CVE coverage, MFA automation or the original RCE fixture.
