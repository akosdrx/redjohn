"""Synthetic spawn faults; real leases, no native namespace execution."""

from __future__ import annotations

import asyncio

import pytest

from redjohn.assessment.lab_worker import LabWorker
from redjohn.assessment.resources import ResourceAdmissionError, ResourceGovernor


@pytest.mark.parametrize("cancel", [False, True])
async def test_pending_spawn_keeps_original_reservation_until_late_child_reaped(
    tmp_path, monkeypatch, cancel
):
    started, deliver = asyncio.Event(), asyncio.Event()

    class Process:
        pid = 123456789
        returncode = None
        stdout = asyncio.StreamReader()
        stderr = asyncio.StreamReader()

        async def wait(self):
            self.returncode = 0
            return 0

    process = Process()

    async def launch(*_args, **_kwargs):
        started.set()
        await deliver.wait()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", launch)
    monkeypatch.setattr("redjohn.assessment.lab_worker.os.killpg", lambda *_args: None)
    worker = LabWorker(tmp_path, memory_config={}, owner_budget=1024**3)
    governor = ResourceGovernor()
    lease = governor.acquire(cleanup_guard=worker.resource_cleanup_verified)
    operation = asyncio.create_task(worker._execute(["fixed-test-command"], tmp_path, timeout=0.02))
    await started.wait()
    if cancel:
        operation.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else TimeoutError):
        await operation
    async with asyncio.timeout(1):
        with pytest.raises(ResourceAdmissionError, match="delivery_cleanup_unverified"):
            await worker.cleanup()
    with pytest.raises(ResourceAdmissionError, match="cleanup_unverified"):
        lease.release()
    assert governor.snapshot()["active"] == {"worker": 1}
    assert governor.recover_cleanup() == 0
    deliver.set()
    assert worker._late_reaper is not None
    await asyncio.wait_for(worker._late_reaper, 1)
    assert process.returncode == 0 and worker.resource_cleanup_verified() is True
    assert governor.recover_cleanup() == 1
    assert governor.snapshot()["active"] == {}
    governor.close()


async def test_unreaped_child_keeps_guard_and_exact_lease(tmp_path, monkeypatch):
    class Process:
        pid = 123456789
        returncode = None

        async def wait(self):
            await asyncio.Event().wait()

    monkeypatch.setattr("redjohn.assessment.lab_worker.os.killpg", lambda *_args: None)
    worker = LabWorker(tmp_path, memory_config={}, owner_budget=1024**3)
    worker.process = Process()
    worker._cleanup_verified = False
    governor = ResourceGovernor()
    lease = governor.acquire(cleanup_guard=worker.resource_cleanup_verified)
    async with asyncio.timeout(3):
        with pytest.raises(ResourceAdmissionError, match="reap_unverified"):
            await worker.cleanup()
    with pytest.raises(ResourceAdmissionError, match="cleanup_unverified"):
        lease.release()
    assert governor.snapshot()["cleanup_quarantined"] == 1
    assert not lease.released and worker.process is not None
