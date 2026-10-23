"""Synthetic policy/error contracts, distinct from actual process/kernel E2E."""

from __future__ import annotations

import json
import sqlite3

import pytest

from redjohn.assessment import host_resources, os_memory
from redjohn.assessment.cli import main
from redjohn.assessment.host_resources import HostResourceLimits, HostResourcePool
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceAdmissionError, ResourceGovernor
from redjohn.assessment.store import AssessmentStore
from tests.test_assessment_scheduler import FakeWorker, make_scheduler


def test_policy_update_is_atomic_idle_only_and_old_clients_recheck_it(tmp_path):
    path = tmp_path / "host.sqlite3"
    pool = HostResourcePool(path)
    old_client = HostResourcePool(path)
    first, second = ResourceGovernor(host_pool=pool), ResourceGovernor(host_pool=old_client)
    lease = first.acquire()
    try:
        with pytest.raises(ResourceAdmissionError, match="host_resource_policy_busy"):
            pool.configure(HostResourceLimits(max_workers=1, max_browsers=1))
    finally:
        lease.release()
    pool.configure(HostResourceLimits(max_workers=1, max_browsers=1))
    with (
        first.acquire(),
        pytest.raises(ResourceAdmissionError, match="host_worker_capacity_exhausted"),
    ):
        second.acquire()
    assert old_client.snapshot()["limits"]["max_workers"] == 1


def test_missing_identity_observation_is_not_proof_that_a_live_owner_died(tmp_path, monkeypatch):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    governor = ResourceGovernor(host_pool=pool)
    lease = governor.acquire()
    with monkeypatch.context() as fault:
        fault.setattr(host_resources, "process_identity", lambda _pid: None)
        assert pool.recover() == 0
        assert pool.snapshot()["admission_blocked"] is True
    assert pool.snapshot()["active"] == {"worker": 1}
    lease.release()


def test_corrupt_host_policy_never_grants_capacity(tmp_path):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    with sqlite3.connect(pool.path) as db:
        db.execute("UPDATE metadata SET value='{}' WHERE key='policy'")
    governor = ResourceGovernor(host_pool=pool)
    with pytest.raises(ResourceAdmissionError, match="host_resource_policy_invalid"):
        governor.acquire()


def test_existing_symlink_target_is_preserved(tmp_path):
    target = tmp_path / "keep.txt"
    target.write_text("preserve me")
    link = tmp_path / "host.sqlite3"
    link.symlink_to(target)
    with pytest.raises(OSError):
        HostResourcePool(link)
    assert target.read_text() == "preserve me"


def test_operator_cli_configures_and_reports_actual_host_policy(tmp_path, capsys):
    pool, policy = tmp_path / "host.sqlite3", tmp_path / "policy.json"
    policy.write_text(json.dumps({"max_workers": 1}))
    assert main(["resources", "--pool", str(pool), "--policy", str(policy)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["product"] == "RedJohn"
    assert result["resources"]["limits"]["max_workers"] == 1
    assert main(["resources", "--pool", str(pool), "--recover"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["recovered_leases"] == 0
    assert result["resources"]["active"] == {}


def test_unverifiable_claimed_os_fence_never_falls_back_to_uncontained_execution(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("REDJOHN_CONTAINED_GROUP", "/sys/fs/cgroup/redjohn-" + "0" * 32)
    monkeypatch.setattr(os_memory, "current_memory_fence", lambda: None)
    monkeypatch.setattr(host_resources, "current_memory_fence", lambda: None)
    with pytest.raises(
        os_memory.MemoryLimitUnavailableError, match="os_memory_membership_not_enforced"
    ):
        os_memory.LinuxMemoryBoundary.current(
            {"delegated_root": "/sys/fs/cgroup/owned"}, 64 * 1024**2
        )
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    with pytest.raises(ResourceAdmissionError, match="host_memory_measurement_unavailable"):
        ResourceGovernor(host_pool=pool).acquire()
    assert pool.snapshot()["active"] == {}


@pytest.mark.parametrize("idempotent,admitted", [(False, False), (True, True)])
async def test_capacity_wait_never_repeats_mutating_or_already_admitted_work(
    tmp_path,
    idempotent,
    admitted,
):
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(
        EngagementPolicy(
            "synthetic-capacity",
            "operator",
            ("http://127.0.0.1:9",),
            profile="isolated-lab",
            egress_mode="local-fixture",
            max_attempts=2,
        )
    )
    surface = store.upsert_surface(policy.engagement_id, Surface("http://127.0.0.1:9/"))
    job = store.submit(policy, [JobSpec(surface, "test", "http_observe", idempotent=idempotent)])[0]

    class DeniedWorker(FakeWorker):
        async def run(self, *_args):
            self.calls += 1
            if admitted:
                store.consume_requests(policy)
            raise ResourceAdmissionError("host_worker_capacity_exhausted")

    worker = DeniedWorker()
    try:
        scheduler = make_scheduler(store, policy, worker)
        await scheduler.run_batch(max_jobs=2)
        row = next(row for row in store.jobs(policy.engagement_id) if row["id"] == job)
        assert row["execution_status"] == "resource_exhausted"
        assert row["attempt"] == 1
        assert worker.calls == 1 and worker.cleaned == 1
        assert scheduler.metrics["retries"] == 0
        assert store.findings(policy.engagement_id) == []
    finally:
        store.close()
