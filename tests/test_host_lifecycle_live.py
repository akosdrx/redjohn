"""Actual HTTPS, SDK control, durable queue and OS-lock lifecycle checks.

No model or simulated worker is used. Delays are imposed by the owned HTTPS
fixture; the contention test holds the same scheduler lock in another process.
"""

import asyncio
import sys
import threading
import time

import pytest

from redjohn.assessment.host import HostAssessment, HostControllerLimits
from redjohn.assessment.tls_fixture import TLSFixtureServer
from tests.test_host_assessment_live import config_for, invoke, wait_job


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
async def test_actual_inflight_https_job_is_settled_and_released(tmp_path, monkeypatch, stop):
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "host.sqlite3"))
    entered, release = threading.Event(), threading.Event()

    def delay_response(_request):
        entered.set()
        release.wait(timeout=5)

    with TLSFixtureServer() as fixture:
        fixture._get_observer = delay_response
        fixture.server.handle_error = lambda *_args: None  # expected peer close on cancellation
        config = config_for(fixture, capability="http_observe")
        limits = HostControllerLimits(max_jobs=4, max_seconds=0.75 if stop == "deadline" else 10)
        try:
            async with HostAssessment(
                config, tmp_path / "run", caller="operator", limits=limits
            ) as host:
                assert await asyncio.to_thread(entered.wait, 3), (
                    "actual HTTPS request did not arrive"
                )
                started = time.monotonic()
                if stop == "cancel":
                    cancelled = await invoke(host.control, "jobs_cancel")
                    assert cancelled["result"]["cancel_requested"] == 1
                await asyncio.wait_for(host._task, timeout=3)
                assert time.monotonic() - started < 3
                expected = "engagement_cancelled" if stop == "cancel" else "deadline_exhausted"
                assert host.status()["stop_reason"] == expected
                jobs = host.configured.store.jobs(host.configured.policy.engagement_id)
                assert len(jobs) == 1
                assert jobs[0]["execution_status"] == "cancelled"
                assert jobs[0]["coverage_status"] == "partial"
                assert host.configured.runtime.governor.snapshot()["active"] == {}
                assert host.configured.store.request_usage(host.configured.policy) == 1
        finally:
            release.set()


async def test_actual_external_coordinator_lock_waits_then_resumes_without_restart(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "host.sqlite3"))
    output = tmp_path / "run"
    state = output / ".state"
    state.mkdir(parents=True)
    lock_path = state / "agents.db.assessment.lock"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import fcntl,os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT,0o600); "
        "fcntl.flock(fd,fcntl.LOCK_EX); print('locked',flush=True); "
        "sys.stdin.buffer.read(1); os.close(fd)",
        str(lock_path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    try:
        assert await asyncio.wait_for(process.stdout.readline(), 5) == b"locked\n"
        with TLSFixtureServer() as fixture:
            config = config_for(fixture, capability="http_observe")
            async with HostAssessment(
                config,
                output,
                caller="operator",
                limits=HostControllerLimits(max_jobs=2, max_seconds=15),
            ) as host:
                until = time.monotonic() + 3
                while not host.status()["coordinator_contention"] and time.monotonic() < until:
                    await asyncio.sleep(0.02)
                assert host.status()["coordinator_contention"] > 0
                assert host.configured.runtime.governor.snapshot()["active"] == {}
                assert sum(fixture.counts.values()) == 0
                process.stdin.write(b"x")
                await process.stdin.drain()
                assert await asyncio.wait_for(process.wait(), 3) == 0
                jobs = await wait_job(host.control, "http_observe")
                assert jobs[0]["execution_status"] == "succeeded"
                assert sum(fixture.counts.values()) == 1
                assert host.configured.runtime.governor.snapshot()["active"] == {}
    finally:
        if process.returncode is None:
            process.kill()
            await asyncio.wait_for(process.wait(), timeout=3)
