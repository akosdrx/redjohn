"""Real Linux kernel limits, owner-death recovery and Chromium/Nuclei CLI E2E.

An administrator must delegate a private cgroup subtree before running these
tests. They never grant root privileges or change host-wide kernel settings.
Missing delegation is a capability gap; REQUIRE_OS_MEMORY makes that a failure.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import signal
import sys
from pathlib import Path

import pytest

from redjohn.assessment.host_resources import HostResourcePool, process_identity
from redjohn.assessment.https_verification import https_demo
from redjohn.assessment.os_memory import LinuxMemoryBoundary, MemoryLimitUnavailableError
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import MIB, ResourceGovernor
from redjohn.assessment.store import AssessmentStore
from tests.test_nuclei_live import DEFAULT_LOCK, existing_live_lock


@pytest.fixture
def delegated_root():
    path = os.environ.get("REDJOHN_TEST_CGROUP_ROOT")
    if platform.system() != "Linux" or not path:
        reason = "blocked_missing_capability: delegated Linux cgroup v2 subtree required"
        if os.environ.get("REDJOHN_REQUIRE_OS_MEMORY") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    return Path(path)


def _save(name, value):
    if directory := os.environ.get("REDJOHN_OS_MEMORY_MEASUREMENTS"):
        target = Path(directory)
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        (target / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


@pytest.mark.parametrize("descendant", [False, True])
async def test_actual_kernel_memory_max_kills_oversized_tree(delegated_root, descendant):
    allocate = "data=[bytearray(1024*1024) for _ in range(256)]; print(len(data))"
    command = allocate
    if descendant:
        command = (
            "import subprocess,sys; subprocess.run([sys.executable,'-c',"
            + repr(allocate)
            + "],check=True)"
        )
    with LinuxMemoryBoundary({"delegated_root": str(delegated_root)}, 64 * MIB) as boundary:
        group = boundary.group
        process = await asyncio.create_subprocess_exec(
            *boundary.wrap_argv([sys.executable, "-c", command]),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await asyncio.wait_for(process.communicate(), 15)
        measured = boundary.snapshot()
        assert process.returncode == -signal.SIGKILL
        assert stdout == b""
        assert measured["memory_max_bytes"] == 64 * MIB
        assert measured["swap_max_bytes"] == 0
        assert measured["oom_kills"] >= 1
        assert measured["memory_peak_bytes"] > 0
        _save("oom-descendant" if descendant else "oom-controller", measured)
    assert group is not None and not group.exists()


async def test_actual_orphan_is_killed_before_crashed_owner_capacity_is_reclaimed(
    delegated_root,
    tmp_path,
):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    command = """
import json,subprocess,sys
from redjohn.assessment.host_resources import HostResourcePool
from redjohn.assessment.resources import ResourceGovernor
governor=ResourceGovernor(host_pool=HostResourcePool(sys.argv[1]))
lease=governor.acquire('worker',1024*1024)
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],
    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(json.dumps({'child_pid':child.pid}),flush=True)
sys.stdin.readline()
"""
    with LinuxMemoryBoundary({"delegated_root": str(delegated_root)}, 128 * MIB) as boundary:
        group = boundary.group
        process = await asyncio.create_subprocess_exec(
            *boundary.wrap_argv([sys.executable, "-c", command, str(pool.path)]),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert process.stdout is not None
        data = json.loads(await asyncio.wait_for(process.stdout.readline(), 10))
        orphan = data["child_pid"]
        identity = process_identity(orphan)
        assert identity is not None
        process.kill()
        await asyncio.wait_for(process.wait(), 5)
        assert process_identity(orphan) == identity
        before = pool.snapshot()
        assert before["lost_owners"] == 1
        governor = ResourceGovernor(host_pool=pool)
        with governor.acquire("worker", MIB):
            assert process_identity(orphan) != identity
            assert group is not None and not group.exists()
            assert pool.snapshot()["lost_owners"] == 0
        governor.close()
        after = pool.snapshot()
        assert after["active"] == {}
        _save("owner-crash-recovery", {"before": before, "after": after, "orphan_stopped": True})


async def test_actual_contained_https_chromium_inventory_nuclei_restart_and_fixed_control(
    delegated_root,
    tmp_path,
    monkeypatch,
):
    lock = existing_live_lock()
    lock_path = Path(os.environ.get("REDJOHN_NUCLEI_LOCK", str(DEFAULT_LOCK)))
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "host.sqlite3"))
    metrics = await https_demo(
        tmp_path / "run",
        lock_path,
        os_memory={"delegated_root": str(delegated_root)},
    )
    assert metrics["nuclei_binary_sha256"] == lock.binary_sha256
    assert metrics["restart_duplicate_requests"] == 0
    assert metrics["initial_candidates"] == 1
    assert metrics["fixed_control_new_findings"] == 0
    resources = metrics["resource_state_after_final_job"]
    assert resources["host"]["active"] == {}
    assert resources["os_memory"]["enforced"] is True
    assert resources["os_memory"]["memory_max_bytes"] == 2048 * MIB
    assert resources["os_memory"]["oom_kills"] == 0
    assert not list(delegated_root.glob("redjohn-*"))
    _save("chromium-nuclei-cli-e2e", metrics)


async def test_actual_cli_oom_persists_resource_failure_without_a_negative_scan(
    delegated_root,
    tmp_path,
):
    existing_live_lock()
    lock_path = Path(os.environ.get("REDJOHN_NUCLEI_LOCK", str(DEFAULT_LOCK)))
    policy = EngagementPolicy(
        "oom-before-job",
        "operator",
        ("http://127.0.0.1:9",),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )
    config = {
        "policy": policy.to_dict(),
        "seeds": [],
        "nuclei_lock": json.loads(lock_path.read_text()),
        "os_memory": {"delegated_root": str(delegated_root)},
        "resources": {
            "total_memory_budget": 32 * MIB,
            "worker_memory_budget": 8 * MIB,
            "cache_max_bytes": MIB,
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "redjohn.assessment",
        "run",
        "--config",
        str(path),
        "--output",
        str(tmp_path / "run"),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _stderr = await asyncio.wait_for(process.communicate(), 20)
    assert process.returncode == 2
    result = json.loads(stdout)
    assert result["error"] == "resource_exhausted"
    assert result["reason"] == "os_memory_limit_exceeded"
    assert result["resources"]["oom_kills"] > 0
    assert result["evidence_ref"] and result["evidence_error"] is None
    store = AssessmentStore(tmp_path / "run/.state/agents.db")
    try:
        evidence = store.evidence_get(policy.engagement_id, result["evidence_ref"])
        value = json.loads(evidence["excerpt"])
        assert value["execution_status"] == "resource_exhausted"
        assert value["coverage_status"] == "inconclusive"
        assert value["process_cleanup_verified"] is True
        assert store.jobs(policy.engagement_id) == []
        assert store.findings(policy.engagement_id) == []
    finally:
        store.close()
    assert not list(delegated_root.glob("redjohn-*"))
    _save("cli-oom", result)


def test_unavailable_os_memory_is_explicit_and_never_a_cooperative_fallback(tmp_path):
    with (
        pytest.raises(MemoryLimitUnavailableError),
        LinuxMemoryBoundary({"delegated_root": str(tmp_path / "not-cgroup")}, 64 * MIB),
    ):
        pytest.fail("Unavailable OS enforcement was silently accepted")
