"""Outbox fault/recovery tests with fake workers; these are not live integrations."""

import fcntl
import json
import os
import sqlite3
from dataclasses import replace

import pytest

from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.resources import ProcessTreeMemory, ResourceEnvelope, ResourceGovernor
from redjohn.assessment.scheduler import Scheduler
from redjohn.assessment.store import AssessmentStore, CapacityExceeded


@pytest.fixture
def state(tmp_path):
    store = AssessmentStore(tmp_path / "agents.db", queue_max_items=4)
    policy = store.register(
        EngagementPolicy(
            "continuous-outbox",
            "operator",
            ("https://127.0.0.1:8443",),
            profile="isolated-lab",
            egress_mode="local-fixture",
        )
    )
    surface = store.upsert_surface(
        policy.engagement_id, Surface(policy.allowed_origins[0] + "/app")
    )
    try:
        yield store, policy, surface
    finally:
        store.close()


def submit_parent(store, policy, surface, capability="session_refresh", *, revision=""):
    return store.submit(
        policy,
        [
            JobSpec(
                surface,
                "discovery" if capability == "browser_post_capture" else "session",
                capability,
                idempotent=False,
                policy_revision=policy.revision,
                retest_revision=revision,
            )
        ],
    )[0]


def finish_parent(store, policy, surface, capability="session_refresh", *, revision=""):
    parent_id = submit_parent(store, policy, surface, capability, revision=revision)
    parent = store.claim(policy, "worker")
    assert parent["id"] == parent_id
    assert store.finish(parent, AdapterResult("succeeded", "completed", {"revision": "8"}))
    return parent_id, store.pending_followups(policy)[-1]


@pytest.mark.parametrize("capability", ["session_refresh", "browser_post_capture"])
def test_success_outbox_survives_store_reopen_and_ack_is_atomic_and_idempotent(state, capability):
    store, policy, surface = state
    parent_id, event = finish_parent(store, policy, surface, capability)
    assert (event["job_id"], event["capability"], event["result"]["summary"]["revision"]) == (
        parent_id,
        capability,
        "8",
    )
    with pytest.raises(PolicyDenied, match="followup_access_denied"):
        store.complete_followup(policy, "unknown", [])
    reopened = AssessmentStore(store.path, queue_max_items=4)
    try:
        assert reopened.pending_followups(policy) == [event]
        child = JobSpec(surface, "configuration", "headers_audit")
        child_ids = reopened.complete_followup(policy, event["id"], [child])
        assert len(child_ids) == 1
        # A crash after commit, before the caller sees IDs, cannot publish more work.
        assert (
            reopened.complete_followup(
                policy, event["id"], [replace(child, retest_revision="different")]
            )
            == child_ids
        )
        assert not store.pending_followups(policy)
        assert store.followup_status(policy) == {"pending_events": 0, "errors": []}
        assert len(store.jobs(policy.engagement_id)) == 2
    finally:
        reopened.close()


def test_followup_queue_full_rolls_back_every_child_without_changing_parent(state):
    store, policy, surface = state
    parent_id, event = finish_parent(store, policy, surface)
    base = JobSpec(surface, "configuration", "headers_audit")
    store.submit(policy, [replace(base, retest_revision=str(index)) for index in range(3)])
    before = store.jobs(policy.engagement_id)
    with pytest.raises(CapacityExceeded, match="queue_capacity_exhausted"):
        store.complete_followup(
            policy,
            event["id"],
            [replace(base, retest_revision="child-1"), replace(base, retest_revision="child-2")],
        )
    assert store.jobs(policy.engagement_id) == before
    assert store.pending_followups(policy) == [event]
    store.record_followup_error(policy, event["id"], "queue_capacity_exhausted")
    store.record_followup_error(policy, event["id"], "queue_capacity_exhausted")
    assert store.followup_status(policy) == {
        "pending_events": 1,
        "errors": [
            {
                "event_id": event["id"],
                "code": "queue_capacity_exhausted",
                "coverage_status": "blocked",
            }
        ],
    }
    assert (
        store.db.execute(
            "SELECT count(*) FROM rj_audit WHERE action='followup_blocked'"
        ).fetchone()[0]
        == 1
    )
    parent = next(row for row in store.jobs(policy.engagement_id) if row["id"] == parent_id)
    assert (parent["execution_status"], parent["coverage_status"]) == ("succeeded", "completed")
    # Capacity returns when an unrelated job completes; the same parent intent is used.
    other = store.claim(policy, "worker")
    store.finish(other, AdapterResult("succeeded", "completed"))
    assert (
        len(
            store.complete_followup(
                policy,
                event["id"],
                [
                    replace(base, retest_revision="child-1"),
                    replace(base, retest_revision="child-2"),
                ],
            )
        )
        == 2
    )


@pytest.mark.parametrize(
    ("capability", "result", "retry_after"),
    [
        ("session_refresh", AdapterResult("failed", "inconclusive"), None),
        ("session_refresh", AdapterResult("timed_out", "inconclusive"), None),
        ("session_refresh", AdapterResult("succeeded", "partial"), None),
        ("browser_post_capture", AdapterResult("failed", "inconclusive"), None),
        ("browser_post_capture", AdapterResult("succeeded", "inconclusive"), None),
        (
            "browser_post_capture",
            AdapterResult("succeeded", "partial", error=error_record("unknown_capture_outcome")),
            None,
        ),
        (
            "session_refresh",
            AdapterResult("succeeded", "completed", error=error_record("fault")),
            None,
        ),
        ("session_refresh", AdapterResult("succeeded", "completed"), 1),
        ("http_observe", AdapterResult("succeeded", "completed"), None),
    ],
)
def test_only_unambiguous_supported_successes_create_followup_intent(
    state, capability, result, retry_after
):
    store, policy, surface = state
    submit_parent(store, policy, surface, capability)
    parent = store.claim(policy, "worker")
    assert store.finish(parent, result, retry_after=retry_after)
    assert not store.pending_followups(policy)


def test_partial_browser_event_preserves_parent_gap_and_requires_consumer_proof(state):
    store, policy, surface = state
    parent_id = submit_parent(store, policy, surface, "browser_post_capture")
    parent = store.claim(policy, "worker")
    assert store.finish(
        parent,
        AdapterResult("succeeded", "partial", {"blocked_reasons": ["browser_scope_denied"]}),
    )
    event = store.pending_followups(policy)[0]
    assert event["job_id"] == parent_id
    assert event["result"]["coverage_status"] == "partial"
    assert event["result"]["summary"]["blocked_reasons"] == ["browser_scope_denied"]
    assert store.jobs(policy.engagement_id)[0]["coverage_status"] == "partial"
    # An event only invites proof validation; it never admits any replay itself.
    assert store.claim(policy, "worker") is None
    assert store.followup_status(policy)["pending_events"] == 1


def test_cancelled_or_expired_parent_never_creates_outbox_or_auto_resends(state):
    store, policy, surface = state
    parent_id = submit_parent(store, policy, surface)
    parent = store.claim(policy, "lost-worker", lease_seconds=-1)
    assert store.recover_expired(policy) == 1
    assert not store.finish(parent, AdapterResult("succeeded", "completed"))
    assert not store.pending_followups(policy)
    assert store.claim(policy, "new-worker") is None
    assert (
        next(row for row in store.jobs(policy.engagement_id) if row["id"] == parent_id)["result"][
            "error"
        ]["code"]
        == "unknown_execution_outcome"
    )
    submit_parent(store, policy, surface, revision="cancelled")
    parent = store.claim(policy, "worker")
    store.cancel(policy.engagement_id, parent["id"])
    assert store.finish(parent, AdapterResult("succeeded", "completed"))
    assert not store.pending_followups(policy)


def test_parent_finish_and_outbox_insert_are_one_sqlite_transaction(state):
    store, policy, surface = state
    submit_parent(store, policy, surface)
    parent = store.claim(policy, "worker")
    store.db.execute(
        "CREATE TRIGGER deny_outbox BEFORE INSERT ON rj_followup_event "
        "BEGIN SELECT RAISE(ABORT, 'injected_outbox_write_failure'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected_outbox_write_failure"):
        store.finish(parent, AdapterResult("succeeded", "completed"))
    assert store.jobs(policy.engagement_id)[0]["execution_status"] == "running"
    assert not store.pending_followups(policy)
    store.db.execute("DROP TRIGGER deny_outbox")
    assert store.finish(parent, AdapterResult("succeeded", "completed"))
    assert len(store.pending_followups(policy)) == 1


def test_pending_events_are_paged_and_policy_owner_isolated(state):
    store, policy, surface = state
    for index in range(3):
        finish_parent(store, policy, surface, revision=str(index))
    first = store.pending_followups(policy, limit=2)
    second = store.pending_followups(policy, limit=2, after=first[-1]["id"])
    assert len(first) == 2 and len(second) == 1
    assert len({event["id"] for event in first + second}) == 3
    assert store.followup_status(policy)["pending_events"] == 3
    with pytest.raises(ValueError, match="invalid_followup_page_limit"):
        store.pending_followups(policy, limit=65)
    with pytest.raises(PolicyDenied, match="engagement_access_denied"):
        store.pending_followups(replace(policy, owner_id="other"))
    with pytest.raises(ValueError, match="invalid_followup_error_code"):
        store.record_followup_error(policy, first[0]["id"], "Authorization: secret")
    other = store.register(replace(policy, engagement_id="other"))
    assert not store.pending_followups(other)
    with pytest.raises(PolicyDenied, match="followup_access_denied"):
        store.complete_followup(other, first[0]["id"], [])
    current = store.register(replace(policy, revision="2"))
    assert not store.pending_followups(current)
    with pytest.raises(PolicyDenied, match="stale_policy_revision"):
        store.complete_followup(policy, first[0]["id"], [])


class FakeWorker:
    """Scheduler ordering/fault injection only; no browser or Nuclei subprocess."""

    def __init__(self, order):
        self.order = order

    async def run(self, _job, _surface, spec):
        self.order.append(spec.capability)
        return AdapterResult("succeeded", "completed")

    async def cleanup(self):
        pass

    async def cancel(self):
        pass


def scheduler_for(store, policy, order, reconcile):
    worker = FakeWorker(order)
    return Scheduler(
        store,
        policy,
        ResourceGovernor(),
        CapabilityRegistry(session_refresh_configured=True, browser_post_capture_configured=True),
        {
            "session_refresh": worker,
            "browser_post_capture": worker,
            "headers_audit": worker,
        },
        reconcile=reconcile,
    )


async def test_one_running_scheduler_executes_new_children_and_honors_max_jobs(state):
    store, policy, surface = state
    submit_parent(store, policy, surface)
    order = []

    def reconcile():
        # Reconciliation must run while cross-process coordinator exclusion is held.
        descriptor = os.open(
            store.path.with_name(store.path.name + ".assessment.lock"), os.O_WRONLY
        )
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        for event in store.pending_followups(policy):
            capability = (
                "browser_post_capture"
                if event["capability"] == "session_refresh"
                else "headers_audit"
            )
            store.complete_followup(
                policy,
                event["id"],
                [JobSpec(surface, "discovery", capability, idempotent=False)],
            )

    scheduler = scheduler_for(store, policy, order, reconcile)
    assert len(await scheduler.run_batch(max_jobs=2)) == 2
    assert order == ["session_refresh", "browser_post_capture"]
    queued = [
        row for row in store.jobs(policy.engagement_id) if row["execution_status"] == "queued"
    ]
    assert [row["capability"] for row in queued] == ["headers_audit"]
    assert not store.pending_followups(policy)
    assert len(await scheduler.run_batch(max_jobs=2)) == 1
    assert order == ["session_refresh", "browser_post_capture", "headers_audit"]


async def test_reconciler_failure_preserves_success_and_recovery_never_reruns_parent(state):
    store, policy, surface = state
    parent_id = submit_parent(store, policy, surface)
    order = []

    def fail_after_finish():
        if store.pending_followups(policy):
            raise RuntimeError("credential must never enter audit")

    scheduler = scheduler_for(store, policy, order, fail_after_finish)
    assert await scheduler.run_batch(max_jobs=1) == [parent_id]
    assert order == ["session_refresh"]
    assert scheduler.metrics["followup_errors"] == 1
    row = store.jobs(policy.engagement_id)[0]
    assert (row["execution_status"], row["coverage_status"]) == ("succeeded", "completed")
    assert len(store.pending_followups(policy)) == 1
    audits = store.db.execute(
        "SELECT payload FROM rj_audit WHERE action='followup_blocked'"
    ).fetchall()
    assert json.loads(audits[0][0])["code"] == "workflow_reconciliation_error"
    assert "credential" not in audits[0][0]

    def recover():
        for event in store.pending_followups(policy):
            store.complete_followup(
                policy, event["id"], [JobSpec(surface, "audit", "headers_audit")]
            )

    replacement = scheduler_for(store, policy, order, recover)
    assert len(await replacement.run_batch(max_jobs=2)) == 1
    assert order == ["session_refresh", "headers_audit"]
    assert not store.pending_followups(policy)


class RetainedBrowserWorker(FakeWorker):
    """Model Chromium's retained worker lease; this does not launch a browser."""

    def __init__(self, order, governor, *, fail_first_close=False):
        super().__init__(order)
        self.governor = governor
        self.lease = None
        self.close_calls = 0
        self.fail_first_close = fail_first_close

    async def run(self, job, surface, spec):
        self.lease = self.governor.acquire("browser")
        return await super().run(job, surface, spec)

    async def close_idle(self):
        self.close_calls += 1
        if self.lease is not None:
            if self.fail_first_close:
                self.fail_first_close = False
                raise RuntimeError("private cleanup details")
            self.order.append("browser_closed")
            self.lease.release()
            self.lease = None


class ExclusiveScannerWorker(FakeWorker):
    """Assert actual governor admission follows browser lease release."""

    def __init__(self, order, governor, browser):
        super().__init__(order)
        self.governor, self.browser = governor, browser

    async def run(self, job, surface, spec):
        assert self.browser.lease is None
        assert self.browser.close_calls == 1  # duplicate adapter registration is deduplicated
        assert self.governor.snapshot()["active"] == {"scanner": 1}
        return await super().run(job, surface, spec)


@pytest.mark.parametrize("close_fails", [False, True])
async def test_browser_to_scanner_releases_single_worker_capacity_before_admission(
    state, close_fails
):
    store, policy, surface = state
    governor = ResourceGovernor(
        ResourceEnvelope(max_workers=1),
        memory_reader=lambda: ProcessTreeMemory(1, 0, 1, 0),
    )
    order = []
    browser = RetainedBrowserWorker(order, governor, fail_first_close=close_fails)
    scanner = ExclusiveScannerWorker(order, governor, browser)
    registry = CapabilityRegistry()
    scheduler = Scheduler(
        store,
        policy,
        governor,
        registry,
        {
            "browser_discover": browser,
            "browser_post_capture": browser,
            "nuclei_scan": scanner,
        },
    )
    store.submit(
        policy,
        [
            JobSpec(surface, "discovery", "browser_discover", priority=5),
            JobSpec(surface, "known_vulnerability", "nuclei_scan", priority=4),
        ],
    )
    assert len(await scheduler.run_batch(max_jobs=2)) == 2
    rows = {row["capability"]: row for row in store.jobs(policy.engagement_id)}
    assert rows["browser_discover"]["execution_status"] == "succeeded"
    assert governor.snapshot()["active"] == {}
    assert governor.denied == 0
    if close_fails:
        assert order == ["browser_discover", "browser_closed"]
        row = rows["nuclei_scan"]
        assert (row["execution_status"], row["coverage_status"]) == ("failed", "blocked")
        assert row["result"]["error"]["code"] == "browser_idle_cleanup_failed"
        assert "private" not in json.dumps(row["result"])
    else:
        assert order == ["browser_discover", "browser_closed", "nuclei_scan"]
        assert rows["nuclei_scan"]["execution_status"] == "succeeded"
