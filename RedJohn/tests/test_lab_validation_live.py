"""Actual Linux public generated-regression E2E; intended for hosted CI.

Missing kernel capabilities are blocked/failing in required jobs, never mocked.
This restricted header fixture does not reproduce the original RCE.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import sys
import uuid
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(
    platform.system() != "Linux", reason="Linux kernel profile required"
)


@pytest.mark.parametrize("scenario", ["positive", "slow", "oversized", "cancel"])
async def test_actual_owned_header_regression_namespace_limits_restart_and_control(
    tmp_path, scenario
):
    configured = os.environ.get("REDJOHN_TEST_CGROUP_ROOT")
    if not configured:
        reason = "blocked_missing_capability: private delegated cgroup required"
        if os.environ.get("REDJOHN_REQUIRE_OS_MEMORY") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    delegated = Path(configured) / ("lab-regression-" + uuid.uuid4().hex)
    delegated.mkdir()
    (delegated / "cgroup.subtree_control").write_text("+memory +pids")
    config = {
        "delegated_root": str(delegated),
        "aggregate_memory_budget_bytes": 1536 * 1024**2,
        "pool_state_directory": str(tmp_path / "pool"),
    }
    receipt = tmp_path / "receipt.json"
    command = [
        sys.executable,
        "-m",
        "redjohn.assessment.memory_exec",
        "--delegated-root",
        str(delegated),
        "--memory-budget-mib",
        "1024",
        "--aggregate-budget-mib",
        "1536",
        "--pool-state-directory",
        str(tmp_path / "pool"),
        "--receipt",
        str(receipt),
        "--timeout-seconds",
        "45",
        "--",
        sys.executable,
        "-m",
        "tests.owned_lab_driver",
        str(tmp_path / "run"),
        json.dumps(config),
        scenario,
    ]
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 55)
        if process.returncode != 0:
            pytest.fail(
                f"stdout:\n{stdout.decode(errors='replace')}\n"
                f"stderr:\n{stderr.decode(errors='replace')}",
                pytrace=False,
            )
        result = json.loads((tmp_path / "run/result.json").read_text())
        hard = json.loads(receipt.read_text())
        assert hard["process_cleanup_verified"] is True
        assert hard["os_memory"]["owner_namespace"]["verified"] is True
        assert hard["os_memory"]["oom_kills"] == 0
        assert result["model_calls"] == 0 and result["duplicate_resume_requests"] == 0
        if directory := os.environ.get("REDJOHN_OS_MEMORY_MEASUREMENTS"):
            target = Path(directory)
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            (target / ("owned-lab-" + scenario + ".json")).write_text(
                json.dumps({"result": result, "kernel": hard}, indent=2)
            )
    finally:
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 3)
            except TimeoutError:
                process.kill()
                await process.wait()
        leaked = "populated 1" in (delegated / "cgroup.events").read_text()
        if leaked:
            (delegated / "cgroup.kill").write_text("1")
            async with asyncio.timeout(3):
                while "populated 1" in (delegated / "cgroup.events").read_text():
                    await asyncio.sleep(0.01)
        for group in [p for p in delegated.iterdir() if p.is_dir()]:
            for leaf in [p for p in group.iterdir() if p.is_dir()]:
                leaf.rmdir()
            group.rmdir()
        delegated.rmdir()
        assert not leaked, "owned lab fixture required emergency descendant cleanup"
