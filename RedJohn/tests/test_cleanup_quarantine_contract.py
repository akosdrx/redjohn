"""Synthetic lifecycle faults with real local SQLite; no scanner/kernel proof."""

from __future__ import annotations

import pytest

from redjohn.assessment import host_resources
from redjohn.assessment.host_resources import HostResourcePool
from redjohn.assessment.models import JobSpec
from redjohn.assessment.resources import ResourceAdmissionError, ResourceGovernor
from tests.test_assessment_scheduler import FakeWorker, make_scheduler, state  # noqa: F401


def test_unverified_cleanup_retains_existing_capacity_across_pool_clients(tmp_path):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    first = ResourceGovernor(host_pool=pool)
    second = ResourceGovernor(host_pool=HostResourcePool(pool.path))
    reaped = False
    lease = first.acquire("scanner", 1024, cleanup_guard=lambda: reaped)
    with pytest.raises(ResourceAdmissionError, match="resource_cleanup_unverified"):
        lease.release()
    assert not lease.released
    assert first.snapshot()["active"] == {"scanner": 1}
    assert first.snapshot()["cleanup_quarantined"] == 1
    assert pool.snapshot()["reserved_bytes"] == 1024
    assert pool.snapshot()["cleanup_quarantined"] == 1
    assert pool.snapshot()["admission_blocked"] is True
    assert pool.recover() == 0  # A live owner cannot expire its unresolved child.
    with pytest.raises(ResourceAdmissionError, match="cleanup_unverified"):
        second.acquire()
    with pytest.raises(ResourceAdmissionError, match="resource_leases_still_active"):
        first.close()
    assert first.recover_cleanup() == 0
    reaped = True
    assert first.recover_cleanup() == 1
    assert lease.released and pool.snapshot()["active"] == {}
    with second.acquire():
        assert pool.snapshot()["active"] == {"worker": 1}
    lease.release()  # Already released leases remain idempotent.
    first.close()
    second.close()


@pytest.mark.parametrize("outcome", [1, None, "yes", RuntimeError("unavailable")])
def test_cleanup_proof_requires_exact_true_and_exceptions_retain_lease(outcome):
    def verify():
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    governor = ResourceGovernor()
    lease = governor.acquire(cleanup_guard=verify)
    with pytest.raises(ResourceAdmissionError, match="resource_cleanup_unverified"):
        lease.release()
    with pytest.raises(ResourceAdmissionError, match="resource_cleanup_unverified"):
        governor.acquire()
    assert not lease.released and governor.snapshot()["active"] == {"worker": 1}


def test_unverified_cleanup_cannot_reuse_owner_only_death_recovery(tmp_path, monkeypatch):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    governor = ResourceGovernor(host_pool=pool)
    lease = governor.acquire(owner_process_only=True, cleanup_guard=lambda: False)
    with pytest.raises(ResourceAdmissionError, match="resource_cleanup_unverified"):
        lease.release()
    # A failed cleanup explicitly contradicts the old in-process-only lifetime
    # assumption. It must not reclaim this row after a controller observation.
    monkeypatch.setattr(host_resources, "process_identity", lambda _pid: "other-start")
    monkeypatch.setattr(host_resources, "_confirmed_dead", lambda *_args: True)
    assert pool.recover() == 0
    assert pool.snapshot()["active"] == {"worker": 1}
    assert pool.snapshot()["admission_blocked"] is True


def test_failed_quarantine_write_cannot_enable_later_owner_death_reclaim(tmp_path, monkeypatch):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    governor = ResourceGovernor(host_pool=pool)
    lease = governor.acquire(owner_process_only=True, cleanup_guard=lambda: False)

    def unavailable(*_args):
        raise ResourceAdmissionError("synthetic_host_store_unavailable")

    monkeypatch.setattr(pool, "quarantine", unavailable)
    with pytest.raises(ResourceAdmissionError, match="synthetic_host_store_unavailable"):
        lease.release()
    assert not lease.released and governor.snapshot()["cleanup_quarantined"] == 1
    monkeypatch.setattr(host_resources, "process_identity", lambda _pid: "other-start")
    monkeypatch.setattr(host_resources, "_confirmed_dead", lambda *_args: True)
    assert pool.recover() == 0
    assert pool.snapshot()["active"] == {"worker": 1}
    assert pool.snapshot()["recovery"] == "requires_verified_os_fence"


async def test_scheduler_never_publishes_success_after_unreaped_owned_work(state):  # noqa: F811
    store, policy, surface = state

    class UnreapedWorker(FakeWorker):
        reaped = False

        def resource_cleanup_verified(self):
            return self.reaped

        async def cleanup(self):
            self.cleaned += 1
            if not self.reaped:
                raise RuntimeError("synthetic child remains alive")

    worker = UnreapedWorker()
    scheduler = make_scheduler(store, policy, worker)
    job = store.submit(policy, [JobSpec(surface, "test", "http_observe")])[0]
    assert await scheduler.run_batch(max_jobs=1) == [job]
    row = store.jobs(policy.engagement_id)[0]
    assert row["execution_status"] == "resource_exhausted"
    assert row["result"]["error"]["category"] == "resource"
    assert worker.calls == 1 and worker.cleaned == 1
    assert store.findings(policy.engagement_id) == []
    assert scheduler.governor.snapshot()["cleanup_quarantined"] == 1
    assert scheduler.governor.recover_cleanup() == 0
    worker.reaped = True
    assert scheduler.governor.recover_cleanup() == 1
    scheduler.governor.close()
