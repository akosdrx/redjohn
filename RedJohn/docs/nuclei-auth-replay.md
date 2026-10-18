# Authenticated Nuclei replay

This page documents the compatible version-1 GET/HEAD vault. The current
[POST/body and explicit refresh workflow](post-refresh-replay.md) adds private
version-2 body approval, durable capture reservations and explicit refresh jobs.
The current [Chromium capture/body-token extension](browser-post-body-tokens.md)
adds explicit automatic private approval and selected field-token rotation.

Authenticated scans use the existing pinned Nuclei engine, reviewed HTTP
templates, persistent job identities and host-owned HTTPS proxy. The scanner
receives no credentials in its command line, environment, templates or worker
files. The proxy injects credentials in host memory immediately before the
exact approved request is forwarded.

The host loads an explicitly configured credential vault with
`AuthReplayVault.from_file(path, policy)`. The input must be a regular file owned
by the current user, with mode `0600`, one hard link, no final symlink and at most
256 KiB. It is the operator's private credential source, not a generated scanner
temporary file. Existing host credential providers may instead call
`from_mapping`; job options cannot supply vault contents.

The JSON schema is version 1 with an `entries` array. Every entry requires:

```json
{
  "version": 1,
  "entries": [{
    "engagement_id": "approved-engagement",
    "owner_id": "operator",
    "policy_revision": "1",
    "actor_id": "alice",
    "tenant_id": "tenant-a",
    "session_revision": "7",
    "expires_at": 1792300000,
    "origin": "https://approved.example:443",
    "allowed_requests": [{
      "url": "https://approved.example/api/me",
      "method": "GET",
      "request_ref": "existing-captured-evidence-reference"
    }],
    "headers": {"Authorization": "Bearer REPLACE-IN-PRIVATE-VAULT"},
    "cookies": [{"name": "session", "value": "REPLACE-IN-PRIVATE-VAULT"}]
  }]
}
```

The example expiry is illustrative; expired vaults are rejected. An entry may
use headers, cookies, or both. Only `Authorization`, `X-API-Key` and
`X-Auth-Token` are accepted as authentication headers. Header injection,
arbitrary headers, cleartext HTTP credentials, empty credentials and malformed
cookies are denied. Browser local-storage tokens are not automatically guessed
or extracted into headers.

`vault.authorize(surface)` requires a named actor and an observed surface with
an exact captured request reference. Actor, tenant, session revision, policy
revision, URL, method and reference must match. Query order and percent encoding
remain part of the exact URL; authority casing and an implicit HTTPS port 443
are normalized when comparing the actual proxy request. The surrounding pipeline validates that the
reference belongs to the engagement's captured evidence. The vault deliberately
cannot promote imported or inferred endpoints to observed requests.

The resulting private binding supplies `rewrite_headers(url, method, headers)`
to the host proxy and `auth_replay=binding` to `NucleiAdapter`. Incoming scanner
authentication headers and cookies are replaced. Any different URL or method,
including a redirect destination on the same origin, is denied. The reviewed
template's entire request list is checked against this binding before the scan
process starts. Expiry is checked again for each proxy request.

Only `binding.metadata()` is suitable for persistence. Known credential values,
their URL encoding and base64 encoding are removed from scanner output before
the raw evidence sink runs, including reflected credential values. The normal
evidence redactor remains active. No automatic authentication refresh or
credential substitution occurs after expiry, a 401 or a 403.

`test_nuclei_auth_live.py` uses the actual installed Nuclei binary, a real local
HTTPS server and strict upstream certificate verification. It distinguishes
anonymous 401 (blocked), the correct named actor's marker (candidate), an
authenticated fixed control (completed with no finding), a redirect
(inconclusive, no replay), and expired credentials (blocked before any target
request). Wrong actor, tenant and revision are also denied before target I/O.
This is separate from schema/permission boundary tests and from remote kernel
egress verification.

Reproduce from the repository root:

```sh
.venv/bin/python -m pytest RedJohn/tests/test_assessment_auth_replay.py -q
REDJOHN_AUTH_E2E_MEASUREMENTS=docs/measurements/authenticated-nuclei-live.json \
  .venv/bin/python -m pytest RedJohn/tests/test_nuclei_auth_live.py -q
```

No download occurs in these tests. A missing binary or reviewed lock is reported
as a missing test capability. The default lock selects only RedJohn's harmless
fixture marker; it does not load the community template collection.
