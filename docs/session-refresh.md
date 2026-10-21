# Durable authenticated session refresh

Refresh is an explicitly queued `session_refresh` capability. It uses one
non-idempotent scheduler job, an exact operator-approved HTTPS POST endpoint,
and private host-owned credential files. Browser discovery and Nuclei replay
do not invoke refresh implicitly and never fall back to anonymous requests.

The engagement must use `active-staging` or `isolated-lab`, authorize the actor,
and list the exact endpoint in `allowed_refresh_urls`. This authorization is
separate from ordinary authenticated POST replay (`allowed_replay_urls`).

## Private configuration

Configure `auth_vault_file` and `refresh_provider_file` in the assessment CLI
configuration. Each file must be a regular, single-link file owned by the current
user with mode `0600`; symlinks and oversized files are rejected. Neither file
belongs in source control or the worker workspace.

The provider file contains this schema; replace placeholders locally:

```json
{
  "version": 1,
  "providers": [{
    "engagement_id": "authorized-assessment",
    "owner_id": "operator",
    "actor_id": "alice",
    "tenant_id": "tenant-a",
    "policy_revision": "1",
    "refresh_url": "https://authorized.example:443/session/refresh",
    "headers": {"Authorization": "Bearer <private-refresh-credential>"},
    "body_base64": "<base64 of the exact approved refresh request bytes>",
    "content_type": "application/json"
  }]
}
```

The refresh body may be JSON or `application/x-www-form-urlencoded`. It is
bounded to 64 KiB. Allowed host-injected headers are `Authorization`, `X-API-Key`,
`X-Auth-Token`, `X-CSRF-Token`, `X-XSRF-Token`, and `Cookie`, with an aggregate
8 KiB value budget. The exact body and headers are injected by the trusted proxy;
they are never placed in SQLite jobs, scanner arguments, templates or evidence.

The reviewed endpoint must return HTTP 200, uncompressed `application/json`,
and these required fields; the optional `body_tokens` map is described below:

```json
{
  "headers": {"Authorization": "Bearer <new-session-credential>"},
  "cookies": [{"name": "session", "value": "<new-cookie>"}],
  "expires_at": 1792250000
}
```

The example expiry is illustrative. A real expiry must be in the future and no
more than 24 hours away. Response bytes are limited to 64 KiB. Redirects are
rejected without following them; TLS chain and hostname verification remain
mandatory. The request deadline is at most 30 seconds and never extends the
engagement deadline. Refresh 429/503 responses update the same persistent
origin/account/endpoint rate limiter as the other scheduler adapters.

## Queue and revision behavior

Queue a `JobSpec` with `capability="session_refresh"`, `family="session"`,
`idempotent=False`, empty `options`, the current policy revision, and a scoped
surface identifying the actor, tenant and current session revision. An explicit
operator-approved seed is permitted for refresh; it does not prove POST capture. The original
surface URL need not be the refresh endpoint: the separately reviewed provider
configuration selects that endpoint.

Refresh revisions are decimal positive integers. A successful refresh advances
`7` to `8` with a fenced SQLite compare-and-swap. Older queued replay jobs keep
revision `7` and are blocked before I/O. New authenticated POST work needs a
fresh observed capture for revision `8`; refresh never manufactures observation
evidence or rewrites pending jobs.

The provider receives one request. Concurrent refreshes for the same old identity
are deduplicated across processes and coordinator restarts. The host also holds
a private-vault file lock, rechecks identity after acquiring it, and uses an
inode/mtime/size compare-and-swap before an atomic `0600` vault replacement.
Concurrent manual vault edits are preserved and produce an uncertain outcome.
An expired session can be refreshed; its old credential cannot authorize replay.

After a successful refresh, the runtime invalidates its actual `SmartCache`
entries matching the old engagement, actor, tenant and session revision. The
invalidation also fences late in-flight cache publications. The result reports
the removed-entry count; unrelated actor/revision entries remain. This cache is
per runtime, not a global cross-process cache. Other processes still enforce the
durable session-state fence, and new revision keys cannot serve the old context.

## Failure and reconciliation

Missing/invalid private configuration, identity mismatch and an existing
rate-limit cooldown are blocked before reserving a refresh or sending traffic.
A reserved refresh that fails leaves the identity blocked; timeout,
cancellation after admission, worker loss, malformed/oversized success response,
or a stale commit leaves an uncertain outcome. The scheduler never resends such
a refresh automatically. Old credentials cannot silently resume replay.

Private vault replacement and SQLite commit are two durable operations. A crash
between them is deliberately not reported as success. Reconcile the server and
private credential state explicitly, then issue a newly reviewed engagement
policy revision and matching private vault/provider configuration. The original
uncertain job remains evidence of the unknown delivery; it is not rewritten.

Authentication and CSRF headers/cookies rotate as before. Private POST requests
can now declare exact `body_tokens` bindings to refreshed header/cookie values or
an optional response `body_tokens` map. Only selected JSON string/form/text-part
values change; other bytes and uploads remain intact. The new body/SHA becomes
`fresh-capture-required`, never scanner authority. An explicitly configured real
Chromium capture must confirm the new bytes before automatic private approval.
There is no heuristic substitution. The full schema and strict multipart-boundary
rule are in [browser capture/body-token refresh](browser-post-body-tokens.md).

Rotation of a provider's own one-use refresh token, general login/MFA automation
and cross-origin credential fan-out remain unsupported. Those need an explicitly
reviewed provider integration.

## Verification boundary

`tests/test_assessment_session_refresh.py` contains durable SQLite CAS/fencing
unit tests and real verified HTTPS integration tests. The HTTPS cases cover
active and expired sessions, one-request rotation, redirects, response quotas,
malformed responses, timeouts, persistent Retry-After, certificate rejection,
and preservation of concurrent operator changes. They use an owned loopback
HTTPS server; they are not evidence of a public remote assessment.

The earlier Linux POST/refresh pipeline test runs the trusted-host HTTPX capture
SDK. The new `test_browser_token_pipeline.py` uses actual headless Chromium POSTs,
persistent scheduler/independent CLI processes, body-token refresh and the pinned
Nuclei binary against an owned non-loopback HTTPS fixture. The
[current verification report](archive/redjohn-browser-token-verification.md)
keeps those workloads and capability blocks separate.
