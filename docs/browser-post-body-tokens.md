# Chromium POST capture and reviewed body-token refresh

For automatic refresh → fresh capture → selected scanner replay inside the
already running scheduler, enable the explicit
[continuous replay mapping](continuous-refresh-replay.md). The startup-only
configuration described below remains compatible.

`browser_post_capture` runs real headless Playwright/Chromium. Application
JavaScript, `fetch`, `FormData` and browser form requests produce the POST bytes;
the trusted inspection proxy reserves, validates, forwards and confirms them.
This differs from the earlier trusted-host HTTPX capture SDK. The normal
`browser_discover` capability keeps its read-only behavior.

Automatic approval requires an explicit private rule for each actor, tenant,
revision, exact POST URL and media type. A generic page, discovered endpoint,
imported surface, HTTP 200 from an unrelated request or browser metadata is not
capture authority. The Linux remote path still requires attested Chromium/Nuclei
worker namespaces, exact HTTPS origin/IP scope and strict upstream TLS.

## Public engagement configuration

The assessment configuration accepts these three private-file references:

```json
{
  "policy": {
    "engagement_id": "approved-assessment",
    "owner_id": "operator",
    "revision": "1",
    "profile": "active-staging",
    "egress_mode": "enforced",
    "allowed_origins": ["https://authorized.example:443"],
    "allowed_ips": ["203.0.113.10/32"],
    "allowed_replay_urls": ["https://authorized.example:443/submit"],
    "allowed_refresh_urls": ["https://authorized.example:443/session/refresh"],
    "actor_ids": ["anonymous", "alice"]
  },
  "auth_vault_file": "/absolute/private/replay-vault.json",
  "browser_capture_file": "/absolute/private/browser-capture.json",
  "refresh_provider_file": "/absolute/private/refresh-provider.json",
  "seeds": []
}
```

Replace the example domain/IP with explicitly authorized infrastructure. Add the
reviewed `nuclei_lock` when scanner replay is needed; browser capture alone does
not install or start Nuclei. An owned literal-loopback lab instead uses
`egress_mode="local-fixture"` and `profile="isolated-lab"`.

All three private files must be current-user-owned, single-link regular files
with mode `0600`, at most 256 KiB and no final symlink. Keep them outside the
repository, reports and worker mounts, in an owner-only directory. The public
CLI configuration is limited to 64 KiB and contains references, not credentials
or bodies.

Initialize the vault with current actor/tenant credentials, a numeric session
revision and a reviewed GET start anchor, using the compatible v1/v2 entry
schema in [authenticated replay](nuclei-auth-replay.md). The anchor is operator
configuration; it does not prove an observed POST. A CLI rule using `current`
needs an unambiguous current vault revision or a ready persisted session state.
An empty vault does not establish the actor's identity. The lower-level SDK can
use explicitly supplied browser storage state; this is not a login wizard.

## Private browser rules

The rule file has exactly `version: 1` and a `rules` array, with at most 64 rules.
Each rule requires the fields below; `start_url` and `body_tokens` are optional.
The example expiry is illustrative: supply a future UNIX timestamp when creating
or reviewing the private file.

```json
{
  "version": 1,
  "rules": [{
    "engagement_id": "approved-assessment",
    "owner_id": "operator",
    "actor_id": "alice",
    "tenant_id": "tenant-a",
    "policy_revision": "1",
    "session_revision": "current",
    "url": "https://authorized.example:443/submit",
    "content_type": "application/json",
    "expires_at": 1799999999,
    "automatic_approval": true,
    "start_url": "https://authorized.example:443/start",
    "body_tokens": [{
      "location": "json",
      "selector": "/csrf",
      "occurrence": 0,
      "source": {"kind": "header", "name": "X-CSRF-Token"}
    }]
  }]
}
```

Each POST must match exactly one active rule for its identity, URL and media type.
The rule media type is exactly `application/json`,
`application/x-www-form-urlencoded` or `multipart/form-data`, without a browser
boundary. The captured request retains its actual validated Content-Type,
including UTF-8 charset or multipart boundary. `start_url` must be a scoped
read-only GET on the POST rule's origin. A numeric rule revision fixes that
revision; `current` explicitly permits resolving the ready durable/current-vault
revision on each coordinator startup. It does not extend rule expiry or scope.

Supported MIME spelling/charset/boundary variants are retained with explicit
per-request `body_contract_version: 2`; legacy approvals keep their original
interpretation. See [MIME replay and restart](mime-replay-and-restart.md) for the
separate vault/body version fields and canonical public Nuclei placeholders.

Startup reconciles each configured start/identity/revision into one durable,
non-idempotent `browser_post_capture` job. Reopening the same coordinator output
directory deduplicates completed work. After successful refresh from 7 to 8, the
next coordinator startup queues the revision-8 capture without editing old jobs.
The optional continuous workflow also queues it in the current scheduler batch.
The public report lists `automatic_browser_capture_jobs`. An unconfigured capability is `blocked_configuration`; missing or invalid
configured files stop initialization or the affected job with a configuration/auth
error. Neither is a negative browser assessment.

The browser context's proxy uses current origin-bound vault headers/cookies,
including refreshed credentials. It does not rewrite persistent browser
`storage_state`. Rules permit application-generated POSTs; the controller does
not invent arbitrary clicks, login/MFA flows or account-control actions.

## Observation and automatic private approval

Before forwarding, the proxy validates the body and exact rule, reserves
`rj_request_capture`, and atomically charges the request budget with fenced
admission. A fully framed 2xx response is required before storing observed
request metadata and updating the private v2 vault. The evidence contains
actor/tenant/revision, URL/method, media type, body length/SHA-256 and transport
completion, never raw bodies, credentials or upload bytes.

The private vault receives the exact browser request bytes and real evidence
reference under the reviewed automatic-approval rule. Failed, redirected,
truncated, expired, mismatched or lost responses do not approve replay. A
reservation after unknown delivery is blocked/uncertain and cannot cause an
automatic resend. A successful capture is transport evidence, not proof of full
application workflow semantics or a confirmed vulnerability.

Captured surfaces can then be selected for the existing reviewed Nuclei scheduler
path. Startup creates capture jobs; it does not silently select scanner templates
or queue arbitrary scanners. Use the explicit job example in
[POST replay](post-refresh-replay.md) with the real observed surface and current
engine/bundle versions.

## Reviewed token bindings

A private v2 POST request may include the same `body_tokens` declarations as its
capture rule. These are explicit field selectors, not heuristic secret search:

| Location | Selector | Replacement |
|---|---|---|
| `json` | RFC 6901 JSON Pointer, such as `/csrf` or `/items/0/token` | Only the selected JSON string literal |
| `form` | Decoded field name | Only the selected encoded value |
| `multipart` | Text-part field name | Only that part's payload; uploads cannot be selected |

`occurrence` is an explicit zero-based duplicate occurrence, 0–127. Unselected
JSON whitespace/escaping, duplicate fields, form encoding/order, multipart part
headers/order and upload bytes remain unchanged. JSON bindings accept string
values only. A bare form key without `=` cannot be a token field.

A binding source has exactly `kind` (`header`, `cookie` or `response`) and `name`.
Header names compare without case; cookie and response names compare exactly.
`header` consumes the complete refreshed header value, including a Bearer prefix
if present. There is no automatic Bearer stripping. A bare access token can use
an explicitly named `response` source.

The refresh provider's backward-compatible response remains
`headers`, `cookies`, `expires_at`, with one optional field:

```json
{
  "headers": {"Authorization": "Bearer <new-session>", "X-CSRF-Token": "<new-csrf>"},
  "cookies": [{"name": "csrf_cookie", "value": "<new-cookie-token>"}],
  "expires_at": 1799999999,
  "body_tokens": {"access_token": "<new-bare-token>"}
}
```

The real expiry must satisfy the existing future/24-hour refresh bound. For the
last value, declare `source={"kind":"response","name":"access_token"}`. The
optional map is private host transport data; token values never enter summaries
or SQLite. The private provider request schema remains unchanged in
[session refresh](session-refresh.md).

Refresh updates only declared fields, recalculates body SHA-256 and marks each
bound request `replay_safety="fresh-capture-required"` with a pending reference.
Old capture approval cannot authorize the new body or revision. The next actual
Chromium capture must match the pending JSON/form bytes exactly. For multipart,
only valid boundary framing may differ: part headers, order, token values and
upload bytes must still match exactly. A complete 2xx browser response then
replaces pending input with actual bytes/hash/reference in the private vault.
No synthetic capture or manual relabelling supplies this proof.

## Stable reviewed multipart template

Legacy approvals can use a reviewed POST template with their exact private
Content-Type. For body contract 2, keep the canonical public JSON/form header or
use this exact public multipart header together with the existing body marker:

```yaml
headers:
  Content-Type: multipart/form-data; boundary=REDJOHN_HOST_REPLAY_BOUNDARY_V1
body: REDJOHN_HOST_REPLAY_BODY_V1
```

Only a valid private multipart binding may accept that header. The trusted proxy
injects the actual private Content-Type/boundary and bytes. Other boundary
wildcards, arbitrary template bodies and media-type substitutions remain denied.
The same reviewed bundle can therefore survive a fresh Chromium boundary; old
queued engine/template versions are not rewritten.

## Bounds and recovery

Bodies remain limited to 64 KiB. Browser capture accepts at most 16 POST capture
attempts per job by default; capture responses have an 80 KiB wire bound and must
complete valid framing. Existing browser page/context/frontier/deadline/resource
limits still apply. Form parsing allows 128 fields; multipart allows 32 parts,
4 KiB part headers and a simple 1–70 character boundary.

Each request has at most 16 token bindings; a refresh resolves at most 16 unique
sources and 16 KiB of source values, with 4096 bytes per nonempty value. Control
characters, CRLF/NUL, overlapping selectors, unknown sources and multipart
boundary injection are rejected. JSON token parsing is bounded to depth 64 and
4096 nodes; pointers are at most 512 UTF-8 bytes, and form/multipart selector
names are bounded ASCII references of at most 128 characters.

Private file locking, inode/mtime/size CAS, durable leases and current identity
checks preserve concurrent operator changes. Vault replacement and SQLite commit
remain two operations; a crash gap is uncertain and requires reconciliation and
a newly reviewed policy revision/configuration. No unknown mutating outcome is
retried automatically. Successful refresh invalidates the actual runtime cache
for the old identity/revision; other processes rely on durable state fencing.

Provider refresh-token rotation from responses, arbitrary OAuth discovery,
generic login/logout/MFA/password-reset automation, cross-origin credential
fan-out, arbitrary binary-field replacement, numeric JSON token coercion and
unsupported body formats remain outside this implementation.

## Commands and evidence

With reviewed private files and the existing dependencies prepared:

```bash
# Startup reconciliation and actual Chromium capture; no SDK body recipe:
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/assessment.json \
  --output /absolute/redjohn-runs/approved-assessment --max-jobs 1

# New actual Linux Chromium/body-token/Nuclei/refresh chain:
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_BROWSER_TOKEN_MEASUREMENTS=/tmp/redjohn-browser-token.json \
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_browser_token_pipeline.py -q -s

# Body-token units, actual HTTPS rotation and actual-engine multipart controls:
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_body_token_refresh.py -q
```

A refresh is still an explicit `session_refresh` non-idempotent job. Use a numeric
current revision for its surface/seed; `current` is a private browser-rule
selector, not a substitute for a refresh job's fenced revision. Resume the same
output directory afterward to reconcile the new browser-capture revision.

The [current verification report](archive/redjohn-browser-token-verification.md)
records actual Chromium, engine, restart, body-token, fixed-control and privacy
results. The earlier HTTPX capture and GET/HEAD measurements remain separate
historical workloads. Missing Linux namespaces, Chromium, engine, credentials,
private rules or fixtures are capability blocks, not completed negative results.
