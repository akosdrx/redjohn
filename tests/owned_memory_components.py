"""Real Linux child fixture for simultaneous Chromium, SDK MCP and native argv."""

from __future__ import annotations

import asyncio
import json
import os
import py_compile
import sys
from pathlib import Path

from redjohn.assessment.browser import BrowserDiscoveryService, BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.fixture import FixtureServer
from redjohn.assessment.os_memory import (
    LinuxMemoryBoundary,
    MemoryLimitUnavailableError,
    active_memory_measurement,
    current_memory_fence,
)
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.tls_fixture import TLSFixtureServer
from tests.remote_https_fixture import RemoteHTTPSFixture, fixture_host
from tests.test_mcp_target_live import _owned, _result, _reviewed_config, _server_source


def _check_owner_fence(root: Path) -> None:
    borrowed = LinuxMemoryBoundary.current(json.loads(sys.argv[3]), 1024**3)
    assert borrowed is not None
    with borrowed:
        assert borrowed.snapshot()["aggregate"]["memory_max_bytes"] == 1536 * 1024**2
    try:
        LinuxMemoryBoundary({"delegated_root": str(root)}, 64 * 1024**2).__enter__()
    except MemoryLimitUnavailableError as exc:
        assert str(exc) == "contained_owner_must_reuse_existing_memory_fence"
    else:
        raise AssertionError("a nested controller escaped the inherited memory fence")


def _workspace(root: Path):
    root.mkdir()
    workspace = root / "workspace"
    workspace.mkdir()
    build = workspace / "owned_build.py"
    build.write_text("VALUE = 42\n")
    assert Path(py_compile.compile(str(build), doraise=True)).is_file()
    source, _events = _server_source(workspace)
    return workspace, source


async def run(root: Path, report: Path) -> None:
    _check_owner_fence(root)
    workspace, source = _workspace(root)
    host = fixture_host()
    with (
        TLSFixtureServer() as fixture,
        FixtureServer() as outside,
        RemoteHTTPSFixture(host, root / "tls") as browser_fixture,
    ):
        config = await _reviewed_config(source, outside)
        async with _owned(root, fixture, config, workspace) as owner:
            # Explicit software admission differs from the independently
            # enforced 1GiB kernel budget; neither substitutes for the other.
            owner.runtime.governor.envelope = ResourceEnvelope(
                total_memory_budget=2 * 1024**3, max_workers=2
            )
            job = await owner.submit("/api/me")
            await owner.runtime.scheduler.run_batch(max_jobs=1)
            data, _row = _result(owner, job)
            assert data["blocked"] and data["offscope"] == 403
            entry = owner.registry.get("owned")
            mcp_pid = entry.session._bound_transports[0]._process.pid
            policy = EngagementPolicy(
                "owned-memory-browser",
                "operator",
                (browser_fixture.origin,),
                allowed_ips=(host + "/32",),
                profile="isolated-lab",
                egress_mode="enforced",
            )
            browser = BrowserDiscoveryService(
                policy,
                owner.runtime.governor,
                BrowserLimits(max_pages=1, max_requests=3, observation_window_ms=100),
                tls_config=BrowserTLSConfig(upstream_ca_file=browser_fixture.ca_file),
                egress_workspace=root / "browser",
            )
            worker, lease = None, None
            try:
                result = await browser.discover(
                    [browser_fixture.origin + "/"], actor_id="anonymous", session_revision="1"
                )
                assert result.execution_status == "succeeded", result.failures
                assert result.observations and browser._egress.attestations
                lease = owner.runtime.governor.acquire("worker", 16 * 1024**2)
                worker = await asyncio.create_subprocess_exec(
                    *browser._egress.wrap_argv(
                        [
                            sys.executable,
                            "-c",
                            (
                                "import time;data=bytearray(8*1024*1024);"
                                "print('ready',flush=True);time.sleep(30)"
                            ),
                        ]
                    ),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                line = await asyncio.wait_for(worker.stdout.readline(), 5)
                assert line.strip() == b"ready"
                group = Path(current_memory_fence()[0])
                members = set(map(int, (group / "cgroup.procs").read_text().split()))
                browser_pids = {item["pid"] for item in browser._egress.attestations} & members
                assert browser_pids
                pids = {os.getpid(), mcp_pid, worker.pid} | browser_pids
                assert pids <= members
                measurement = active_memory_measurement()
                assert measurement["enforced"] is True
                assert measurement["memory_max_bytes"] == 1024**3
                ledger = owner.runtime.governor.snapshot()
                assert ledger["active"]["browser"] == 1
                assert ledger["active"]["worker"] == 1
                assert ledger["active"]["context"] == 1
                value = {
                    "pids": sorted(pids),
                    "kernel": measurement,
                    "software_ledger": ledger,
                    "software_admission_budget_bytes": 2 * 1024**3,
                    "owned_file_write_and_python_build": True,
                    "chromium_version": browser._browser.version,
                    "mcp_namespace_negative_controls": True,
                    "matching_inline_boundary_reused": True,
                    "nested_boundary_escape_denied": True,
                    "browser_namespace_attestations": list(browser._egress.attestations),
                }
            finally:
                if worker is not None and worker.returncode is None:
                    worker.terminate()
                    await asyncio.wait_for(worker.communicate(), 5)
                if lease is not None:
                    lease.release()
                await browser.close()
        report.write_text(json.dumps(value))


if __name__ == "__main__":
    asyncio.run(run(Path(sys.argv[1]), Path(sys.argv[2])))
