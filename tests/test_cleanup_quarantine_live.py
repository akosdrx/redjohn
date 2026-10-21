"""Actual small owned Python process and SQLite lifecycle; no scanner or OS-limit claim."""

from __future__ import annotations

import asyncio
import sys

import pytest

from redjohn.assessment.host_resources import HostResourcePool
from redjohn.assessment.resources import ResourceAdmissionError, ResourceGovernor


async def test_actual_owned_process_retains_shared_capacity_until_wait_confirms_exit(tmp_path):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    governor = ResourceGovernor(host_pool=pool)
    other = ResourceGovernor(host_pool=HostResourcePool(pool.path))
    process = None
    cleanup_verified = False
    lease = governor.acquire("scanner", 32 * 1024**2, cleanup_guard=lambda: cleanup_verified)
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-S",
            "-c",
            "import time; print('owned-ready',flush=True); time.sleep(30)",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        assert process.stdout is not None
        assert await asyncio.wait_for(process.stdout.readline(), 5) == b"owned-ready\n"
        assert process.returncode is None
        with pytest.raises(ResourceAdmissionError, match="resource_cleanup_unverified"):
            lease.release()
        assert pool.snapshot()["active"] == {"scanner": 1}
        assert pool.recover() == 0
        with pytest.raises(ResourceAdmissionError, match="host_cleanup_unverified"):
            other.acquire()
        assert governor.recover_cleanup() == 0
        process.terminate()
        await asyncio.wait_for(process.wait(), 5)
        cleanup_verified = True
        assert governor.recover_cleanup() == 1
        assert pool.snapshot()["active"] == {}
        with other.acquire():
            assert pool.snapshot()["active"] == {"worker": 1}
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await asyncio.wait_for(process.wait(), 5)
        cleanup_verified = process is not None and process.returncode is not None
        governor.recover_cleanup()
        lease.release()
        governor.close()
        other.close()
