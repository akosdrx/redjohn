# Bounded automatic session recovery

RedJohn can detect a completed authenticated 401 or known private-credential
expiry and continue refresh → fresh Chromium capture → selected Nuclei replay
inside the already running persistent scheduler. Enable it explicitly within
the existing reviewed [continuous workflow](continuous-refresh-replay.md):

```json
{
  "continuous_replay": {
    "version": 1,
    "rules": [{
      "actor_id": "alice",
      "tenant_id": "tenant-a",
      "url": "https://authorized.example:443/submit",
      "content_type": "application/json",
      "template_id": "reviewed-submit-check"
    }],
    "session_recovery": {"max_refreshes": 1, "cooldown_seconds": 0}
  }
}
```

This is a configuration fragment. The existing exact policy scope, replay and
refresh endpoint permissions, private vault, browser capture rules, provider
file and pinned reviewed Nuclei lock remain required. Recovery also requires an
exact reviewed private GET start anchor for the same actor/tenant/revision.
No refresh job needs to be manually submitted for the supported failure path.

`max_refreshes` is an integer from 1 to 3; `cooldown_seconds` is an integer from
0 to 3600. Both fields are required when opting in. Booleans, extra keys and
invalid bounds are rejected. Without this option, existing explicit-refresh
and continuous replay configurations keep their behavior.

## Signals and authority

The browser's trusted inspection proxy reports a 401 only after the complete,
bounded response framing has been validated. Only the exact current reviewed GET start requests
and POST routes count; an unrelated background resource's 401 cannot spend the
session recovery budget. Playwright response metadata, a status line, truncated
body or lost connection alone is insufficient. Failed/incomplete POST capture
never becomes approval. A completely received POST 401 retains the old failed
capture reservation and cannot be resent under its old revision.

The browser adapter can detect expired private credentials before starting
Chromium. Preflight expiry checks consider only bindings for the selected start
and its reviewed POST routes; unrelated endpoint/origin expiry cannot spend
this recovery budget. Nuclei can detect an expired private replay binding before starting
the scanner. These precise expiry signals remain distinct from malformed files,
missing credentials, expired capture approval, superseded sessions and unknown
execution. A 403/challenge, redirect or generic transport/parser error does not
request automatic refresh.

Every admitted signal carries host-generated proof bound to the parent actor,
tenant and revision. The failed parent remains failed/blocked with its original
evidence. Recovery schedules a separate non-idempotent refresh from the reviewed
GET anchor; it does not retry or relabel the old POST. After successful refresh,
the existing flow captures the new real browser bytes and validates their
private approval before any selected Nuclei replay.

## Durable limits and failure handling

The auth-failure outbox event commits atomically with parent completion.
`rj_auth_recovery_budget` and `rj_auth_recovery_job` persist admission counts,
cooldown timestamps and one canonical refresh per identity/from-revision.
Admission, budget charge, child queue entry and event acknowledgement are one
SQLite transaction. Queue/storage failure rolls all of them back.

The automatic budget is per engagement, actor, tenant and policy revision, and
spans session revision changes and controller restarts. Simultaneous failures
for the same generation coalesce without extra charges. A late revision-7
failure cannot refresh an already ready revision 8. An existing explicitly
submitted refresh may be reused; it is not an additional automatic refresh.
Manual refresh authorization remains a separate explicit operation.

`auth_recovery_budget_exhausted`, `auth_recovery_cooldown_active` and uncertain or
terminal prior-refresh states remain visible blocked continuations. Pending
cooldown is reconsidered at a later scheduler reconciliation; the bounded batch
does not sleep indefinitely or become a background daemon. A failed, lost or
uncertain mutating refresh is not automatically retried. The existing request,
deadline, queue, resource and capture-rule expiry limits still apply.

Reports expose `metrics.continuous_replay.session_recovery`, exact aggregate
counts, bounded identity rows, refresh job identifiers and safe error codes.
They never include private headers, cookies or bodies. Historical 401 parents
remain coverage gaps even when the new revision succeeds; CLI exit status can
therefore remain nonzero. Inspect the individual recovery and new replay jobs
instead of treating the exit code as a negative vulnerability result.

## Run and verify

Using a reviewed configuration from the repository root:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/assessment.json \
  --output /absolute/private/assessment-output --max-jobs 32
```

Real Linux E2E, using the existing pinned engine, Chromium and working namespace
isolation:

```sh
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_AUTOMATIC_SESSION_MEASUREMENTS=/tmp/redjohn-automatic-session.json \
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_automatic_session_recovery_pipeline.py -q -s
```

Cases cover browser GET/POST 401, scanner 401, expired browser/scanner private
credentials, repeated 401 after refresh, and a truncated 401 body. The positive
paths use real JSON/form/multipart captures and actual reviewed Nuclei workers.
The rejecting cases prove blocked behavior, not successful negative scans.
Synthetic adapter, workflow and transactional fault tests remain separate files.
macOS cannot provide the required remote Linux kernel boundary; the real remote
test reports that missing capability rather than substituting a mock.

This is explicit provider-based recovery for the same named identity. General
login/MFA/password-reset, OAuth discovery, provider refresh-token rotation and
heuristic body-token extraction remain unsupported. No anonymous fallback,
scope expansion, CAPTCHA bypass or template update is introduced.
