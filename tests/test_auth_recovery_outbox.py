"""Persistent auth recovery admission/fault tests; no live scanner is simulated as proof."""

import sqlite3
import time
from dataclasses import replace

import pytest

from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.store import AssessmentStore, CapacityExceeded


@pytest.fixture
def state(tmp_path):
    store = AssessmentStore(tmp_path / "agents.db", queue_max_items=4)
    policy = store.register(
        EngagementPolicy(
            "auth-recovery-outbox",
            "operator",
            ("https://127.0.0.1:8443",),
            actor_ids=("anonymous", "alice", "bob"),
            profile="isolated-lab",
            egress_mode="local-fixture",
        )
    )
    try:
        yield store, policy
    finally:
        store.close()


def anchor(store, policy, *, actor="alice", tenant="primary", revision="7"):
    return store.upsert_surface(
        policy.engagement_id,
        Surface(
            policy.allowed_origins[0] + "/app",
            actor_id=actor,
            tenant_id=tenant,
            session_revision=revision,
            source="imported",
            workflow_state="approved_seed",
        ),
    )


def refresh_spec(surface):
    return JobSpec(
        surface, "authentication", "session_refresh", idempotent=False, timeout_seconds=45
    )


def auth_failure(
    store,
    policy,
    *,
    capability="browser_post_capture",
    code="authentication_expired",
    actor="alice",
    tenant="primary",
    revision="7",
    retest="",
    patch=None,
    execution="failed",
    coverage="blocked",
    retry_after=None,
):
    surface = anchor(store, policy, actor=actor, tenant=tenant, revision=revision)
    marker = {
        "admitted": True,
        "actor_id": actor,
        "tenant_id": tenant,
        "session_revision": revision,
        "signal": "http_401" if code == "authentication_expired" else "credential_expired",
    }
    if code == "authentication_expired":
        marker.update(status=401, response_complete=True)
    if patch is not None:
        marker.update(patch)
    parent_id = store.submit(
        policy,
        [
            JobSpec(
                surface,
                "discovery",
                capability,
                idempotent=False,
                retest_revision=retest,
                priority=9,
            )
        ],
    )[0]
    parent = store.claim(policy, "worker")
    assert parent["id"] == parent_id
    result = AdapterResult(
        execution,
        coverage,
        {"auth_recovery": marker},
        error=error_record(code, category="auth", coverage_effect="blocked"),
    )
    assert store.finish(parent, result, retry_after=retry_after)
    event = next((x for x in store.pending_followups(policy) if x["job_id"] == parent_id), None)
    return parent_id, surface, event


@pytest.mark.parametrize(
    ("capability", "code"),
    [
        ("browser_post_capture", "authentication_expired"),
        ("nuclei_scan", "authentication_expired"),
        ("browser_post_capture", "browser_capture_credentials_expired"),
        ("nuclei_scan", "auth_replay_expired"),
    ],
)
def test_admitted_auth_signal_has_durable_event_preserving_failed_parent(state, capability, code):
    store, policy = state
    parent_id, surface, event = auth_failure(store, policy, capability=capability, code=code)
    assert event["kind"] == "auth_failure"
    assert event["result"]["execution_status"] == "failed"
    with pytest.raises(PolicyDenied, match="auth_recovery_admission_required"):
        store.complete_followup(policy, event["id"], [refresh_spec(surface)])
    other = AssessmentStore(store.path)
    try:
        assert other.pending_followups(policy) == [event]
        ids = other.complete_auth_recovery(
            policy, event["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
        )
        assert len(ids) == 1
        assert (
            other.complete_auth_recovery(
                policy, event["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
            )
            == ids
        )
        rows = {row["id"]: row for row in store.jobs(policy.engagement_id)}
        assert (rows[parent_id]["execution_status"], rows[parent_id]["coverage_status"]) == (
            "failed",
            "blocked",
        )
        assert rows[ids[0]]["capability"] == "session_refresh"
        assert rows[ids[0]]["spec"]["idempotent"] is False
        assert store.recovery_status(policy)["refreshes_used"] == 1
        assert not store.pending_followups(policy)
    finally:
        other.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"patch": {"admitted": False}},
        {"patch": {"admitted": 1}},
        {"patch": {"response_complete": False}},
        {"patch": {"status": 403}},
        {"patch": {"status": "401"}},
        {"patch": {"signal": "html_login_page"}},
        {"patch": {"actor_id": "bob"}},
        {"patch": {"tenant_id": "other"}},
        {"patch": {"session_revision": "8"}},
        {"actor": "anonymous"},
        {"execution": "timed_out"},
        {"execution": "succeeded"},
        {"coverage": "inconclusive"},
        {"code": "authentication_denied"},
        {"code": "auth_replay_expired"},
        {"capability": "http_observe"},
        {"retry_after": 1},
    ],
)
def test_untrusted_403_unknown_or_unconfigured_signal_never_creates_recovery(state, kwargs):
    store, policy = state
    _, _, event = auth_failure(store, policy, **kwargs)
    assert event is None
    assert store.recovery_status(policy)["refreshes_used"] == 0


def test_same_revision_failures_coalesce_to_one_refresh_and_one_budget_charge(state):
    store, policy = state
    _, surface, first = auth_failure(store, policy)
    _, _, second = auth_failure(store, policy, capability="nuclei_scan")
    ids = store.complete_auth_recovery(
        policy, first["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=3600
    )
    assert (
        store.complete_auth_recovery(
            policy, second["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=3600
        )
        == ids
    )
    assert store.recovery_status(policy)["refreshes_used"] == 1
    assert (
        len(
            [
                row
                for row in store.jobs(policy.engagement_id)
                if row["capability"] == "session_refresh"
            ]
        )
        == 1
    )


def test_inflight_same_revision_signal_coalesces_without_second_refresh(state):
    store, policy = state
    _, surface, first = auth_failure(store, policy)
    _, _, second = auth_failure(store, policy, capability="nuclei_scan")
    ids = store.complete_auth_recovery(
        policy, first["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
    )
    job = store.claim(policy, "refresh-worker")
    assert job["id"] == ids[0]
    store.begin_session_refresh(policy, job, store.surface(policy.engagement_id, surface))
    assert (
        store.complete_auth_recovery(
            policy, second["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
        )
        == ids
    )
    assert store.recovery_status(policy)["refreshes_used"] == 1


def test_late_old_failure_is_acknowledged_without_old_anchor_or_refreshing_new_session(state):
    store, policy = state
    _, _, event = auth_failure(store, policy)
    store.db.execute(
        "INSERT INTO rj_session_state VALUES(?,?,?,?,?,'ready',NULL,?)",
        (policy.engagement_id, "alice", "primary", policy.revision, "8", time.time()),
    )
    assert (
        store.complete_auth_recovery(
            policy,
            event["id"],
            refresh_spec("missing-old-anchor"),
            max_refreshes=1,
            cooldown_seconds=0,
        )
        == []
    )
    assert not store.pending_followups(policy)
    assert len(store.jobs(policy.engagement_id)) == 1
    assert store.recovery_status(policy)["refreshes_used"] == 0


@pytest.mark.parametrize("status", ["uncertain", "blocked", "refreshing"])
def test_nonready_session_remains_blocked_and_event_pending(state, status):
    store, policy = state
    _, surface, event = auth_failure(store, policy)
    store.db.execute(
        "INSERT INTO rj_session_state VALUES(?,?,?,?,?,?,NULL,?)",
        (policy.engagement_id, "alice", "primary", policy.revision, "7", status, time.time()),
    )
    with pytest.raises(PolicyDenied, match="auth_recovery_session_" + status):
        store.complete_auth_recovery(
            policy, event["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
        )
    assert store.pending_followups(policy) == [event]
    assert store.recovery_status(policy)["refreshes_used"] == 0


def test_budget_and_cooldown_persist_across_store_reopen_and_new_revisions(state):
    store, policy = state
    _, surface, first = auth_failure(store, policy)
    store.complete_auth_recovery(
        policy, first["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
    )
    # Deterministic successful-refresh fixture state; no HTTP is asserted here.
    refresh_job = store.claim(policy, "fixture-refresh-worker")
    store.finish(refresh_job, AdapterResult("succeeded", "completed"))
    store.db.execute("UPDATE rj_session_state SET revision='8'")
    _, surface8, second = auth_failure(store, policy, revision="8")
    reopened = AssessmentStore(store.path)
    try:
        with pytest.raises(PolicyDenied, match="auth_recovery_budget_exhausted"):
            reopened.complete_auth_recovery(
                policy, second["id"], refresh_spec(surface8), max_refreshes=1, cooldown_seconds=0
            )
        with pytest.raises(PolicyDenied, match="auth_recovery_cooldown_active"):
            reopened.complete_auth_recovery(
                policy, second["id"], refresh_spec(surface8), max_refreshes=2, cooldown_seconds=3600
            )
        assert reopened.recovery_status(policy)["refreshes_used"] == 1
        reopened.db.execute("UPDATE rj_auth_recovery_budget SET last_queued_at=last_queued_at-3601")
        assert (
            len(
                reopened.complete_auth_recovery(
                    policy,
                    second["id"],
                    refresh_spec(surface8),
                    max_refreshes=2,
                    cooldown_seconds=3600,
                )
            )
            == 1
        )
        assert reopened.recovery_status(policy)["refreshes_used"] == 2
    finally:
        reopened.close()


def test_capacity_or_storage_failure_rolls_back_budget_child_and_ack(state):
    store, policy = state
    _, surface, event = auth_failure(store, policy)
    store.submit(
        policy,
        [JobSpec(surface, "other", "headers_audit", retest_revision=str(n)) for n in range(4)],
    )
    with pytest.raises(CapacityExceeded):
        store.complete_auth_recovery(
            policy, event["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
        )
    assert store.recovery_status(policy)["refreshes_used"] == 0
    assert store.pending_followups(policy) == [event]
    job = store.claim(policy, "worker")
    store.finish(job, AdapterResult("succeeded", "completed"))
    store.db.execute(
        "CREATE TRIGGER deny_recovery BEFORE INSERT ON rj_auth_recovery_budget "
        "BEGIN SELECT RAISE(ABORT,'injected_recovery_write_failure'); END"
    )
    before = store.jobs(policy.engagement_id)
    with pytest.raises(sqlite3.IntegrityError, match="injected_recovery_write_failure"):
        store.complete_auth_recovery(
            policy, event["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
        )
    assert store.jobs(policy.engagement_id) == before
    assert store.recovery_status(policy)["refreshes_used"] == 0
    assert store.pending_followups(policy) == [event]


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_refreshes": 0},
        {"max_refreshes": 4},
        {"max_refreshes": True},
        {"cooldown_seconds": -1},
        {"cooldown_seconds": 3601},
        {"cooldown_seconds": 1.5},
    ],
)
def test_invalid_recovery_limits_are_rejected(state, overrides):
    store, policy = state
    _, surface, event = auth_failure(store, policy)
    kwargs = {"max_refreshes": 1, "cooldown_seconds": 0, **overrides}
    with pytest.raises(ValueError, match="auth_recovery_invalid_"):
        store.complete_auth_recovery(policy, event["id"], refresh_spec(surface), **kwargs)


@pytest.mark.parametrize(
    "change",
    [
        {"idempotent": True},
        {"capability": "nuclei_scan"},
        {"retest_revision": "again"},
        {"options": {"retry": True}},
        {"tool_version": "different"},
    ],
)
def test_refresh_spec_cannot_widen_or_force_duplicate_recovery(state, change):
    store, policy = state
    _, surface, event = auth_failure(store, policy)
    with pytest.raises(PolicyDenied, match=r"auth_recovery_(invalid|noncanonical)_refresh_job"):
        store.complete_auth_recovery(
            policy,
            event["id"],
            replace(refresh_spec(surface), **change),
            max_refreshes=1,
            cooldown_seconds=0,
        )
    assert store.recovery_status(policy)["refreshes_used"] == 0


def test_old_completion_only_database_migrates_without_rewriting_events(tmp_path):
    path = tmp_path / "legacy.db"
    store = AssessmentStore(path)
    store.db.execute("ALTER TABLE rj_followup_event DROP COLUMN kind")
    store.close()
    reopened = AssessmentStore(path)
    try:
        assert "kind" in {
            row["name"] for row in reopened.db.execute("PRAGMA table_info(rj_followup_event)")
        }
        assert reopened.db.execute("SELECT count(*) FROM rj_followup_event").fetchone()[0] == 0
    finally:
        reopened.close()


@pytest.mark.parametrize("inactive", ["stopped", "expired"])
def test_inactive_engagement_cannot_admit_recovery(state, inactive):
    store, policy = state
    _, surface, event = auth_failure(store, policy)
    if inactive == "stopped":
        store.cancel(policy.engagement_id)
    else:
        policy = store.register(replace(policy, revision="2", deadline=time.time() - 1))
        # Old-revision events remain inaccessible under the new policy.
    with pytest.raises(PolicyDenied, match=r"(policy_inactive|event_access_denied)"):
        store.complete_auth_recovery(
            policy, event["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
        )
    assert store.recovery_status(policy)["refreshes_used"] == 0


@pytest.mark.parametrize("revision", ["0", "current", "0007"])
def test_non_numeric_or_noncanonical_session_revision_cannot_refresh(state, revision):
    store, policy = state
    _, surface, event = auth_failure(store, policy, revision=revision)
    with pytest.raises(PolicyDenied, match="session_refresh_numeric_revision_required"):
        store.complete_auth_recovery(
            policy, event["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
        )
    assert store.recovery_status(policy)["refreshes_used"] == 0


def test_refresh_seed_must_match_exact_failed_identity(state):
    store, policy = state
    _, _, event = auth_failure(store, policy)
    other_surface = anchor(store, policy, actor="bob")
    with pytest.raises(PolicyDenied, match="auth_recovery_invalid_refresh_job"):
        store.complete_auth_recovery(
            policy, event["id"], refresh_spec(other_surface), max_refreshes=1, cooldown_seconds=0
        )
    assert store.recovery_status(policy)["refreshes_used"] == 0


def test_terminal_canonical_refresh_is_not_automatically_resent(state):
    store, policy = state
    _, surface, first = auth_failure(store, policy)
    _, _, second = auth_failure(store, policy, capability="nuclei_scan")
    store.complete_auth_recovery(
        policy, first["id"], refresh_spec(surface), max_refreshes=1, cooldown_seconds=0
    )
    refresh = store.claim(policy, "lost-worker", lease_seconds=-1)
    assert refresh["capability"] == "session_refresh"
    store.recover_expired(policy)
    with pytest.raises(PolicyDenied, match="auth_recovery_prior_refresh_terminal"):
        store.complete_auth_recovery(
            policy, second["id"], refresh_spec(surface), max_refreshes=3, cooldown_seconds=0
        )
    assert store.recovery_status(policy)["refreshes_used"] == 1
    assert store.claim(policy, "worker") is None


def test_recovery_status_uses_exact_totals_with_a_bounded_public_page(state):
    store, policy = state
    store.db.executemany(
        "INSERT INTO rj_auth_recovery_budget VALUES(?,?,?,?,?,?)",
        [
            (policy.engagement_id, "alice", f"tenant-{n:03}", policy.revision, 1, 0)
            for n in range(65)
        ],
    )
    result = store.recovery_status(policy)
    assert result["refreshes_used"] == 65
    assert len(result["identities"]) == 64
    assert result["identities_truncated"] is True
