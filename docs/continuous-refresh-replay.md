# Continuous session refresh, browser capture and reviewed replay

For bounded automatic detection of session expiry/401, enable the optional
[`session_recovery` configuration](automatic-session-recovery.md). The explicit
refresh workflow below remains available.

The existing assessment runtime can continue a reviewed authentication workflow
in the same scheduler batch. Add `continuous_replay` to an otherwise configured
assessment, alongside `auth_vault_file`, `browser_capture_file` and `nuclei_lock`:

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
    }]
  }
}
```

This is an additional configuration fragment, not a complete runnable policy.
Use the existing [private capture rules](browser-post-body-tokens.md),
[provider schema](session-refresh.md) and reviewed engine/template lock. Each
mapping selects an exact named actor, tenant, POST URL, base media type and
template ID already in that lock. The supported media types are JSON,
URL-encoded form and multipart form. At most 64 rules are accepted. A mapping
does not grant scope, POST, credential or template permissions by itself.

The caller still explicitly submits the non-idempotent `session_refresh` job.
For the CLI, this can be an explicitly configured seed at the reviewed GET start
anchor, bound to the current numeric revision:

```json
{
  "seeds": [{
    "url": "https://authorized.example:443/start",
    "actor_id": "alice",
    "tenant_id": "tenant-a",
    "session_revision": "7",
    "capabilities": ["session_refresh"]
  }]
}
```

The provider still supplies the separate exact authorized refresh POST endpoint.
Keep a completed seed unchanged when resuming; it deduplicates instead of
requesting another refresh.

With the option above enabled, a successful refresh creates a durable follow-up
event. The already running scheduler resolves the current session and queues a
new non-idempotent Chromium capture. Only an individually complete 2xx capture from a successful browser job, with
matching sent-request evidence and current private approval can queue the
selected Nuclei replay. No operator submission or process restart is needed
between those steps. Embedded body tokens retain their explicit bindings;
refresh alone cannot approve a rewritten body.

Without `continuous_replay`, existing startup capture and explicitly submitted
scanner workflows retain their behavior. Optional workers remain lazy and run
under the existing shared resource/request limits. Automatic continuation does
not submit another refresh or introduce a general login/MFA workflow.

Before admitting a non-browser job, the sequential scheduler closes retained
idle browser workers and releases their leases. The chain therefore also works
with `resources.max_workers=1`; scanner admission does not depend on an unused
second worker slot. A propagated close failure blocks scanner launch with
`browser_idle_cleanup_failed`.

## Persistence and execution bounds

`rj_followup_event` is an additive SQLite table. A successful parent job and its
follow-up event commit together. Child-job submission and acknowledgement of
that event also commit together. Reconciliation runs under the coordinator's
existing cross-process lock before claiming work and after finishing each job.
Deterministic child keys include the real surface, session/body identity,
selected template and pinned engine/bundle versions. Existing jobs and evidence
are never rewritten to the new revision.

`--max-jobs` counts every executed parent and child. For one start page producing
three approved POSTs, refresh + capture + three selected replays require five
available slots. If the batch stops at a smaller limit, newly queued jobs remain
durable for the next batch; the scheduler does not exceed the requested limit.
A completed refresh can therefore remain succeeded while its continuation is
pending or blocked.

Queue pressure or a follow-up validation failure cannot turn a successful
mutating parent into a retry. The pending event retains a stable error code for
inspection and later reconciliation. Uncertain refresh delivery, failed or
incomplete POST capture, stale evidence, expired approval, unsupported input and missing
workers are coverage gaps. They never become an empty successful scan. The
existing private-vault/SQLite uncertain-commit boundary still requires explicit
operator reconciliation; automatic continuation does not resolve unknown effects.

The CLI report records `metrics.continuous_replay`, including queued identifiers,
pending events and bounded errors. Follow-up errors make the configured CLI exit
nonzero. Pending work caused solely by the batch limit is not a negative result
and is not counted as an executed scan. A successful browser job may retain
`partial` aggregate coverage, for example after an out-of-scope background request
is blocked. This does not approve any incomplete request: only individually
proven complete 2xx POSTs may continue, and the aggregate gap remains visible.
If an expected configured start produces no approved POST, its event remains
blocked with `continuous_replay_capture_missing`; an empty capture is not a
negative scanner result.

## Start and verify

From the repository root, using an existing reviewed private configuration:

```sh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/assessment.json \
  --output /absolute/private/assessment-output --max-jobs 16
```

The Linux E2E uses an owned non-loopback HTTPS fixture, real headless Chromium,
the actual pinned Nuclei binary and attested network namespaces:

```sh
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_CONTINUOUS_REFRESH_MEASUREMENTS=/tmp/redjohn-continuous-refresh.json \
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_continuous_refresh_pipeline.py -q -s
```

The strict flag makes missing Linux isolation or runtime dependencies fail the
verification instead of silently skipping. On macOS, the remote-kernel test is
explicitly blocked/skipped; local contract tests are a separate test group.
Positive marker matches remain candidate findings. Fixed controls returning no
match establish only those executed checks, not a general vulnerability guarantee.
