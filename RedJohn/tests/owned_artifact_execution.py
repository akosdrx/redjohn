"""Hosted-Linux native test supervisor with an attested, immutable owner fence."""

import asyncio
import json
import os
import platform
import sys
import uuid
from pathlib import Path

import pytest


async def supervise_owned_test(request, tmp_path):
    if os.environ.get("REDJOHN_ARTIFACT_TEST_OWNER") == request.node.nodeid:
        return False
    configured = os.environ.get("REDJOHN_TEST_CGROUP_ROOT")
    if platform.system() != "Linux" or not configured:
        reason = "blocked_missing_capability: delegated Linux memory owner required"
        if os.environ.get("REDJOHN_REQUIRE_ARTIFACT_E2E") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    root = Path(configured) / ("artifact-" + uuid.uuid4().hex)
    root.mkdir()
    (root / "cgroup.subtree_control").write_text("+memory +pids")
    receipt = tmp_path / "owner.json"
    environment = dict(os.environ, REDJOHN_ARTIFACT_TEST_OWNER=request.node.nodeid)
    process = None
    leaked = False
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "redjohn.assessment.memory_exec",
            "--delegated-root",
            str(root),
            "--memory-budget-mib",
            "2048",
            "--aggregate-budget-mib",
            "2304",
            "--pool-state-directory",
            str(tmp_path / "pool"),
            "--receipt",
            str(receipt),
            "--timeout-seconds",
            "150",
            "--",
            sys.executable,
            "-m",
            "pytest",
            request.node.nodeid,
            "-q",
            "-s",
            "-p",
            "no:cacheprovider",
            "--basetemp=" + str(tmp_path / "child"),
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 165)
        assert process.returncode == 0, (
            stdout.decode(errors="replace")[-24000:],
            stderr.decode(errors="replace")[-12000:],
        )
        hard = json.loads(receipt.read_text())
        assert hard["process_cleanup_verified"] is True
        assert hard["os_memory"]["owner_namespace"]["verified"] is True
        assert hard["os_memory"]["oom_kills"] == 0
        if directory := os.environ.get("REDJOHN_OS_MEMORY_MEASUREMENTS"):
            target = Path(directory)
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            import hashlib

            name = hashlib.sha256(request.node.nodeid.encode()).hexdigest()[:16]
            (target / ("artifact-" + name + ".json")).write_text(
                json.dumps({"nodeid": request.node.nodeid, "kernel": hard}, indent=2)
            )
    finally:
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 3)
            except TimeoutError:
                process.kill()
                await process.wait()
        leaked = "populated 1" in (root / "cgroup.events").read_text()
        if leaked:
            (root / "cgroup.kill").write_text("1")
            async with asyncio.timeout(3):
                while "populated 1" in (root / "cgroup.events").read_text():
                    await asyncio.sleep(0.01)
        for group in [p for p in root.iterdir() if p.is_dir()]:
            for leaf in [p for p in group.iterdir() if p.is_dir()]:
                leaf.rmdir()
            group.rmdir()
        root.rmdir()
        assert not leaked, "native artifact test required emergency descendant cleanup"
    return True
