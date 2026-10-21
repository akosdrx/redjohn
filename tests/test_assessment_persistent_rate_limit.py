"""Actual SQLite reopen/concurrent-connection checks, without network doubles."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from email.utils import format_datetime

import pytest

from redjohn.assessment.persistent_rate_limit import PersistentRateLimitDetector
from redjohn.assessment.store import AssessmentStore


ORIGIN = "https://127.0.0.1:12345"


def test_window_budget_survives_store_reopen_and_expires_in_utc(tmp_path):
    now = [1_800_000_000.0]
    database = tmp_path / "agents.db"
    store = AssessmentStore(database)
    detector = PersistentRateLimitDetector(
        store, "eng", requests_per_window=2, window_seconds=20, wall_clock=lambda: now[0]
    )
    assert detector.admit(ORIGIN)
    assert detector.admit(ORIGIN)
    assert not detector.admit(ORIGIN)
    assert detector.remaining(ORIGIN) == 20
    store.close()
    now[0] += 7
    reopened = AssessmentStore(database)
    try:
        restored = PersistentRateLimitDetector(
            reopened, "eng", requests_per_window=2, window_seconds=20, wall_clock=lambda: now[0]
        )
        assert restored.remaining(ORIGIN) == 13
        assert not restored.admit(ORIGIN)
        now[0] += 13
        assert restored.remaining(ORIGIN) == 0
        assert restored.admit(ORIGIN)
        rows = reopened.db.execute("SELECT * FROM rj_rate_limit").fetchall()
        assert len(rows) == 3 and all(row["requests"] == 1 for row in rows)
    finally:
        reopened.close()


@pytest.mark.parametrize("use_http_date", [False, True])
def test_retry_after_cooldown_survives_new_sqlite_connection(tmp_path, use_http_date):
    now = [1_800_000_000.0]
    database = tmp_path / "agents.db"
    store = AssessmentStore(database)
    detector = PersistentRateLimitDetector(store, "eng", wall_clock=lambda: now[0])
    retry_after = (
        format_datetime(datetime.fromtimestamp(now[0] + 60, UTC), usegmt=True)
        if use_http_date
        else "60"
    )
    observation = detector.observe(ORIGIN, 429, {"Retry-After": retry_after}, account="alice")
    assert observation.limited and observation.retry_after == 60
    store.close()
    now[0] += 5
    reopened = AssessmentStore(database)
    try:
        restored = PersistentRateLimitDetector(reopened, "eng", wall_clock=lambda: now[0])
        assert restored.remaining(ORIGIN, account="alice") == 55
        # The origin scope prevents switching accounts or endpoint groups.
        assert not restored.admit(ORIGIN, account="bob", endpoint_group="different")
        now[0] += 55
        assert restored.admit(ORIGIN, account="alice")
    finally:
        reopened.close()


def test_two_connections_cannot_both_admit_budget_one(tmp_path):
    database = tmp_path / "agents.db"
    stores = [AssessmentStore(database), AssessmentStore(database)]
    detectors = [
        PersistentRateLimitDetector(store, "eng", requests_per_window=1) for store in stores
    ]
    barrier = threading.Barrier(2)

    def admit(detector):
        barrier.wait(timeout=5)
        return detector.admit(ORIGIN, account="alice", endpoint_group="api")

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(admit, detectors))
        assert sorted(outcomes) == [False, True]
        rows = stores[0].db.execute("SELECT * FROM rj_rate_limit").fetchall()
        assert len(rows) == 3
        assert all(row["requests"] == 1 for row in rows)
    finally:
        for store in stores:
            store.close()


def test_capacity_uses_persisted_global_cooldown_without_active_scope_eviction(tmp_path):
    now = [1_800_000_000.0]
    database = tmp_path / "agents.db"
    store = AssessmentStore(database)
    detector = PersistentRateLimitDetector(
        store, "eng", max_scopes=3, default_cooldown=5, wall_clock=lambda: now[0]
    )
    assert detector.admit(ORIGIN)
    assert not detector.admit("https://127.0.0.1:23456")
    assert store.db.execute("SELECT COUNT(*) FROM rj_rate_limit").fetchone()[0] == 4
    store.close()
    reopened = AssessmentStore(database)
    try:
        restored = PersistentRateLimitDetector(
            reopened, "eng", max_scopes=3, default_cooldown=5, wall_clock=lambda: now[0]
        )
        assert restored.remaining(ORIGIN) == 5
        assert not restored.admit(ORIGIN)
        now[0] += 60
        assert restored.admit("https://127.0.0.1:23456")
        assert reopened.db.execute("SELECT COUNT(*) FROM rj_rate_limit").fetchone()[0] == 3
    finally:
        reopened.close()


def test_engagements_are_isolated_and_403_is_not_a_rate_limit(tmp_path):
    store = AssessmentStore(tmp_path / "agents.db")
    try:
        limited = PersistentRateLimitDetector(store, "one", requests_per_window=1)
        other = PersistentRateLimitDetector(store, "two", requests_per_window=1)
        assert limited.admit(ORIGIN)
        assert not limited.admit(ORIGIN)
        assert other.admit(ORIGIN)
        observation = other.observe(ORIGIN, 403)
        assert not observation.limited
        assert observation.classification == "permission_or_challenge"
        assert observation.retry_after == 0
    finally:
        store.close()


@pytest.mark.parametrize(
    "options",
    [
        {"requests_per_window": 0},
        {"max_scopes": 2049},
        {"max_scopes": 2},
        {"window_seconds": float("nan")},
        {"default_cooldown": float("inf")},
    ],
)
def test_invalid_persistent_limiter_budgets_are_rejected(tmp_path, options):
    store = AssessmentStore(tmp_path / "agents.db")
    try:
        with pytest.raises(ValueError, match="invalid_persistent_rate_limit_budgets"):
            PersistentRateLimitDetector(store, "eng", **options)
    finally:
        store.close()
