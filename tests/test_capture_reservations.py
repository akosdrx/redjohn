"""Unit verification of durable POST capture reservations; no network doubles claim E2E."""

from __future__ import annotations

import hashlib
import time
from dataclasses import replace

import pytest

from redjohn.assessment.models import Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.store import AssessmentStore, CapacityExceeded


def configured(tmp_path, **limits):
    store = AssessmentStore(tmp_path / "agents.db", **limits)
    policy = store.register(
        EngagementPolicy(
            "capture-reservation",
            "owner",
            ("https://127.0.0.1:8443",),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice"),
            allowed_replay_urls=("https://127.0.0.1:8443/submit",),
            request_budget=3,
        )
    )
    surface = Surface(
        "https://127.0.0.1:8443/submit",
        method="POST",
        actor_id="alice",
        tenant_id="a",
        session_revision="7",
        content_type="application/json",
        body_sha256=hashlib.sha256(b'{"private":"never-persist-body"}').hexdigest(),
    )
    return store, policy, surface


def evidence_surface(store, policy, surface, **changes):
    metadata = {
        "url": surface.url,
        "method": "POST",
        "actor_id": surface.actor_id,
        "tenant_id": surface.tenant_id,
        "session_revision": surface.session_revision,
        "policy_revision": policy.revision,
        "engagement_id": policy.engagement_id,
        "body_sha256": surface.body_sha256,
        "sent": True,
        "response_complete": True,
        "status": 200,
        **changes,
    }
    reference = store.evidence_put(
        policy.engagement_id, metadata, kind="authenticated_request_metadata"
    )
    return replace(surface, source="observed", request_ref=reference)


def test_capture_success_restart_dedup_and_atomic_budget(tmp_path):
    store, policy, surface = configured(tmp_path)
    reservation = store.reserve_capture(policy, surface, timeout_seconds=15)
    assert reservation["completed_surface_id"] is None
    second = AssessmentStore(store.path)
    with pytest.raises(PolicyDenied, match="capture_in_progress"):
        second.reserve_capture(policy, surface, timeout_seconds=15)
    assert not second.mark_capture_admitted(policy, reservation["key"], "wrong-owner")
    assert store.mark_capture_admitted(policy, reservation["key"], reservation["owner"])
    assert not second.mark_capture_admitted(policy, reservation["key"], reservation["owner"])
    assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 1
    observed = evidence_surface(store, policy, surface)
    assert store.finish_capture(policy, reservation["key"], reservation["owner"], observed)
    store.close()
    recovered = second.reserve_capture(policy, surface, timeout_seconds=15)
    assert recovered["completed_surface_id"]
    assert second.surface(policy.engagement_id, recovered["completed_surface_id"]) == observed
    assert second.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 1
    second.fail_capture(policy, reservation["key"], reservation["owner"], "late_cancel")
    assert second.db.execute("SELECT state FROM rj_request_capture").fetchone()[0] == "succeeded"
    assert "never-persist-body" not in "\n".join(second.db.iterdump())
    second.close()


@pytest.mark.parametrize("admitted", [False, True])
def test_capture_failure_fails_closed_and_never_reserves_again(tmp_path, admitted):
    store, policy, surface = configured(tmp_path)
    reservation = store.reserve_capture(policy, surface, timeout_seconds=15)
    if admitted:
        assert store.mark_capture_admitted(policy, reservation["key"], reservation["owner"])
    store.fail_capture(policy, reservation["key"], reservation["owner"], "capture_test_failure")
    state = "uncertain" if admitted else "blocked"
    assert store.db.execute("SELECT state FROM rj_request_capture").fetchone()[0] == state
    with pytest.raises(PolicyDenied, match="capture_" + state):
        store.reserve_capture(policy, surface, timeout_seconds=15)
    assert not store.mark_capture_admitted(policy, reservation["key"], reservation["owner"])
    store.close()


def test_expired_capture_reservation_persists_unknown_after_exception_and_restart(tmp_path):
    store, policy, surface = configured(tmp_path)
    reservation = store.reserve_capture(policy, surface, timeout_seconds=1)
    store.db.execute("UPDATE rj_request_capture SET lease_until=?", (time.time() - 1,))
    assert not store.mark_capture_admitted(policy, reservation["key"], reservation["owner"])
    with pytest.raises(PolicyDenied, match="capture_outcome_uncertain"):
        store.reserve_capture(policy, surface, timeout_seconds=1)
    path = store.path
    store.close()
    reopened = AssessmentStore(path)
    assert reopened.db.execute("SELECT state FROM rj_request_capture").fetchone()[0] == "uncertain"
    with pytest.raises(PolicyDenied, match="capture_uncertain"):
        reopened.reserve_capture(policy, surface, timeout_seconds=1)
    reopened.close()


@pytest.mark.parametrize(
    "change",
    [
        {"sent": False},
        {"response_complete": False},
        {"status": 302},
        {"status": 401},
        {"body_sha256": "0" * 64},
        {"session_revision": "8"},
        {"actor_id": "other"},
        {"policy_revision": "other"},
    ],
)
def test_capture_finish_requires_exact_verified_evidence(tmp_path, change):
    store, policy, surface = configured(tmp_path)
    reservation = store.reserve_capture(policy, surface, timeout_seconds=15)
    assert store.mark_capture_admitted(policy, reservation["key"], reservation["owner"])
    observed = evidence_surface(store, policy, surface, **change)
    assert not store.finish_capture(policy, reservation["key"], reservation["owner"], observed)
    assert store.surfaces(policy.engagement_id) == []
    store.close()


def test_capture_policy_stop_revision_and_owner_fences(tmp_path):
    store, policy, surface = configured(tmp_path)
    reservation = store.reserve_capture(policy, surface, timeout_seconds=15)
    assert not store.mark_capture_admitted(
        replace(policy, request_budget=100), reservation["key"], reservation["owner"]
    )
    store.db.execute("UPDATE rj_engagement SET stopped=1")
    assert not store.mark_capture_admitted(policy, reservation["key"], reservation["owner"])
    with pytest.raises(PolicyDenied):
        store.reserve_capture(policy, surface, timeout_seconds=15)
    store.close()


def test_capture_budget_failure_is_atomic_and_active_capacity_bounded(tmp_path):
    store, policy, surface = configured(tmp_path, queue_max_items=1)
    reservation = store.reserve_capture(policy, surface, timeout_seconds=15)
    with pytest.raises(CapacityExceeded, match="capture_capacity"):
        store.reserve_capture(policy, replace(surface, body_sha256="0" * 64), timeout_seconds=15)
    store.db.execute("UPDATE rj_engagement SET requests_used=?", (policy.request_budget,))
    with pytest.raises(CapacityExceeded, match="request_budget"):
        store.mark_capture_admitted(policy, reservation["key"], reservation["owner"])
    assert store.db.execute("SELECT admitted FROM rj_request_capture").fetchone()[0] == 0
    assert (
        store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0]
        == policy.request_budget
    )
    store.close()


@pytest.mark.parametrize(
    "changes,timeout",
    [
        ({"actor_id": "anonymous"}, 15),
        ({"method": "GET"}, 15),
        ({"body_sha256": ""}, 15),
        ({}, 0),
        ({}, 16),
        ({}, float("inf")),
    ],
)
def test_capture_invalid_reservation_zero_state(tmp_path, changes, timeout):
    store, policy, surface = configured(tmp_path)
    with pytest.raises(PolicyDenied):
        store.reserve_capture(policy, replace(surface, **changes), timeout_seconds=timeout)
    assert store.db.execute("SELECT count(*) FROM rj_request_capture").fetchone()[0] == 0
    store.close()
