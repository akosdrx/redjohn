"""Actual controllers/processes and SQLite admission; no fake memory samples.

These are resource integration tests. Browser/scanner E2E checks are separately
identified; acquiring a lease alone does not establish a live engine run.
"""

from __future__ import annotations

import asyncio
import json
import sys

import pytest

from redjohn.assessment.host_resources import HostResourceLimits, HostResourcePool
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import (
    MIB,
    ResourceAdmissionError,
    ResourceEnvelope,
    ResourceGovernor,
)
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore


_LEASE_CHILD = """
import json,sys
from redjohn.assessment.host_resources import HostResourcePool
from redjohn.assessment.resources import ResourceGovernor,ResourceAdmissionError
pool=HostResourcePool(sys.argv[1])
governor=ResourceGovernor(host_pool=pool)
try:
    lease=governor.acquire('worker',1024*1024)
except ResourceAdmissionError as exc:
    print(json.dumps({'granted':False,'reason':str(exc)}),flush=True)
else:
    print(json.dumps({'granted':True}),flush=True)
    sys.stdin.readline()
    lease.release()
    governor.close()
"""


async def _lease_child(path):
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        _LEASE_CHILD,
        str(path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert child.stdout is not None
    result = json.loads(await asyncio.wait_for(child.stdout.readline(), 10))
    return child, result


@pytest.mark.asyncio
async def test_two_campaign_databases_share_browser_capacity(tmp_path, monkeypatch):
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "host" / "resources.sqlite3"))
    stores, runtimes, leases = [], [], []
    try:
        for name in ("one", "two"):
            store = AssessmentStore(tmp_path / name / "agents.db")
            stores.append(store)
            policy = EngagementPolicy(
                engagement_id=name,
                owner_id="operator",
                allowed_origins=("http://127.0.0.1:9",),
                profile="isolated-lab",
                egress_mode="local-fixture",
            )
            runtimes.append(
                AssessmentRuntime(
                    store,
                    policy,
                    caller="operator",
                    envelope=ResourceEnvelope(total_memory_budget=2048 * MIB),
                )
            )
        leases.append(runtimes[0].governor.acquire("browser", MIB))
        with pytest.raises(ResourceAdmissionError, match=r"host.*browser.*capacity"):
            leases.append(runtimes[1].governor.acquire("browser", MIB))
        leases.pop().release()
        leases.append(runtimes[1].governor.acquire("browser", MIB))
    finally:
        for lease in leases:
            lease.release()
        for runtime in runtimes:
            await runtime.close()
        for store in stores:
            store.close()


@pytest.mark.asyncio
async def test_actual_eight_processes_contend_for_two_worker_slots(tmp_path):
    pool = HostResourcePool(tmp_path / "host.sqlite3", HostResourceLimits(max_workers=2))
    children = []
    try:
        children = await asyncio.gather(*[_lease_child(pool.path) for _ in range(8)])
        assert sum(result["granted"] for _, result in children) == 2
        assert pool.snapshot()["active"] == {"worker": 2}
        assert all(
            result.get("reason") == "host_worker_capacity_exhausted"
            for _, result in children
            if not result["granted"]
        )
    finally:
        for child, _ in children:
            if child.returncode is None and child.stdin is not None:
                child.stdin.write(b"release\n")
                await child.stdin.drain()
                child.stdin.close()
            await asyncio.wait_for(child.wait(), 10)
            assert child.returncode == 0
    assert pool.snapshot()["active"] == {}


@pytest.mark.asyncio
async def test_actual_owner_crash_without_os_fence_quarantines_capacity(tmp_path):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    child, result = await _lease_child(pool.path)
    assert result["granted"]
    child.kill()
    await asyncio.wait_for(child.wait(), 5)
    governor = ResourceGovernor(host_pool=pool)
    with pytest.raises(ResourceAdmissionError, match="host_owner_lost_requires_recovery"):
        governor.acquire("worker", MIB)
    snapshot = pool.snapshot()
    assert snapshot["lost_owners"] == 1
    assert snapshot["reserved_bytes"] == MIB
    assert snapshot["admission_blocked"] is True
    assert governor.snapshot()["active"] == {}


def test_actual_rss_blocks_an_undersized_host_budget(tmp_path):
    pool = HostResourcePool(tmp_path / "host.sqlite3", HostResourceLimits(memory_budget_bytes=MIB))
    governor = ResourceGovernor(host_pool=pool)
    with pytest.raises(ResourceAdmissionError, match="host_memory_reservation_exhausted"):
        governor.acquire("worker", 0)
    assert pool.snapshot()["active"] == {}
