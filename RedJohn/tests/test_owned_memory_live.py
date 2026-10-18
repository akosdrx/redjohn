"""Actual owned Linux aggregate OOM/timeout/cancellation, never a sampled cap."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import pty
import signal
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from redjohn.assessment.host_resources import process_identity
from redjohn.assessment.os_memory import LinuxMemoryBoundary, MemoryLimitUnavailableError
from redjohn.assessment.resources import MIB


pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="Linux kernel cgroup required")
_CONTROLLERS: dict[Path, list[asyncio.subprocess.Process]] = {}


@pytest.fixture
async def private_delegation():
    configured = os.environ.get("REDJOHN_TEST_CGROUP_ROOT")
    if not configured:
        reason = "blocked_missing_capability: delegated cgroup root required"
        if os.environ.get("REDJOHN_REQUIRE_OS_MEMORY") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    group = Path(configured) / ("owned-memory-fixture-" + uuid.uuid4().hex)
    group.mkdir()
    (group / "cgroup.subtree_control").write_text("+memory +pids")
    _CONTROLLERS[group] = []
    try:
        yield group
    finally:
        for process in _CONTROLLERS.pop(group):
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 3)
                except TimeoutError:
                    process.kill()
                    await asyncio.wait_for(process.wait(), 3)
        # These groups belong only to this fixture; unrelated delegations stay intact.
        leaked = "populated 1" in (group / "cgroup.events").read_text()
        if leaked:
            (group / "cgroup.kill").write_text("1")
            async with asyncio.timeout(3):
                while "populated 1" in (group / "cgroup.events").read_text():
                    await asyncio.sleep(0.01)
        children = [path for path in group.iterdir() if path.is_dir()]
        for path in children:
            for leaf in path.iterdir():
                if leaf.is_dir():
                    leaf.rmdir()
            path.rmdir()
        group.rmdir()
        assert not leaked, "owned fixture had to reap an unexpectedly surviving descendant"


async def _start(root, *arguments, **options):
    process = await asyncio.create_subprocess_exec(*arguments, **options)
    _CONTROLLERS[root].append(process)
    return process


def _argv(root, state, receipt, command, *, owner=96, aggregate=128, timeout=10):
    return [
        sys.executable,
        "-m",
        "redjohn.assessment.memory_exec",
        "--delegated-root",
        str(root),
        "--memory-budget-mib",
        str(owner),
        "--aggregate-budget-mib",
        str(aggregate),
        "--pool-state-directory",
        str(state),
        "--receipt",
        str(receipt),
        "--timeout-seconds",
        str(timeout),
        "--",
        sys.executable,
        "-c",
        command,
    ]


async def _ready(path):
    async with asyncio.timeout(10):
        while not path.is_file():
            await asyncio.sleep(0.01)


def _save(name, value):
    if directory := os.environ.get("REDJOHN_OS_MEMORY_MEASUREMENTS"):
        target = Path(directory)
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        (target / ("owned-" + name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


async def test_actual_manually_entered_writable_group_cannot_authorize_inline_profile(
    private_delegation,
):
    with LinuxMemoryBoundary({"delegated_root": str(private_delegation)}, 96 * MIB) as boundary:
        group = boundary.group
        command = (
            "import json,os;from pathlib import Path;"
            "from redjohn.assessment.os_memory import "
            "require_inline_memory_boundary,MemoryLimitUnavailableError;"
            f"group=Path({str(group)!r});"
            "(group/'cgroup.procs').write_text(str(os.getpid()));"
            "fd=os.open(group/'memory.max',os.O_WRONLY);os.close(fd);"
            f"config={ {'os_memory': {'delegated_root': str(private_delegation)}}!r};"
            "\ntry: require_inline_memory_boundary(config,96*1024**2)\n"
            "except MemoryLimitUnavailableError as exc: "
            "print(json.dumps({'blocked':str(exc),'writable_control':True}),flush=True)\n"
            "else: raise AssertionError('unwrapped writable group authorized SDK startup')"
        )
        process = await _start(
            private_delegation,
            sys.executable,
            "-c",
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode == 0, (stdout, stderr)
        result = json.loads(stdout)
        assert result == {"blocked": "os_memory_owner_guard_unverified", "writable_control": True}
        assert (group / "memory.max").read_text().strip() == str(96 * MIB)
        assert "populated 0" in (group / "cgroup.events").read_text()
        directory_command = (
            "import json,os;from pathlib import Path;"
            "from redjohn.assessment.os_memory import "
            "require_inline_memory_boundary,MemoryLimitUnavailableError;"
            "directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY);"
            f"path={str(group / 'memory.max').lstrip('/')!r};"
            "\ntry: fd=os.open(path,os.O_WRONLY,dir_fd=directory)\n"
            "except OSError: alias_writable=False\n"
            "else: os.close(fd);alias_writable=True\n"
            f"config={ {'os_memory': {'delegated_root': str(private_delegation)}}!r}\n"
            "try: require_inline_memory_boundary(config,96*1024**2)\n"
            "except MemoryLimitUnavailableError as exc: blocked=str(exc)\n"
            "else: raise AssertionError('directory descriptor authorized inline startup')\n"
            "finally: os.close(directory)\n"
            "require_inline_memory_boundary(config,96*1024**2);"
            "print(json.dumps({'blocked':blocked,'directory_alias_writable':alias_writable,"
            "'accepted_after_close':True}),flush=True)"
        )
        # The genuine wrapper has no inherited directory handles. A subsequently
        # opened directory still requires explicit rejection at inline borrowing;
        # closing it restores eligibility without changing the kernel boundary.
        wrapped = await _start(
            private_delegation,
            *boundary.wrap_argv([sys.executable, "-c", directory_command]),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(wrapped.communicate(), 10)
        assert wrapped.returncode == 0, (stdout, stderr)
        directory_result = json.loads(stdout)
        assert directory_result["blocked"] == "os_memory_owner_guard_unverified"
        assert directory_result["accepted_after_close"] is True
        assert directory_result["directory_alias_writable"] is False
        assert (group / "memory.max").read_text().strip() == str(96 * MIB)
        assert "populated 0" in (group / "cgroup.events").read_text()
        _save("unwrapped-inline-blocked", {"raw": result, "directory_fd": directory_result})


async def test_actual_owner_and_setsid_children_share_one_kernel_memory_budget(
    private_delegation, tmp_path
):
    marker, gate = tmp_path / "pids.json", tmp_path / "go"
    worker = (
        "import pathlib,time; p=pathlib.Path("
        + repr(str(gate))
        + ");\nwhile not p.exists(): time.sleep(.01)\n"
        "data=bytearray(48*1024*1024);time.sleep(60)"
    )
    command = (
        "import os,sys,json,pathlib,subprocess,time; "
        f"children=[subprocess.Popen([sys.executable,'-c',{worker!r}],start_new_session=True) "
        "for _ in range(2)];"
        f"pathlib.Path({str(marker)!r}).write_text("
        "json.dumps([os.getpid(),*[p.pid for p in children]]));"
        f"pathlib.Path({str(gate)!r}).touch();time.sleep(60)"
    )
    receipt = tmp_path / "receipt.json"
    outside = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"])
    try:
        identity = process_identity(outside.pid)
        process = await _start(
            private_delegation,
            *_argv(
                private_delegation,
                tmp_path / "state",
                receipt,
                command,
                owner=64,
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
        assert process.returncode == 2, (stdout, stderr)
        result = json.loads(receipt.read_text())
        measured = result["os_memory"]
        assert result["outcome"] == "resource_exhausted"
        assert result["process_cleanup_verified"] is True
        assert measured["memory_max_bytes"] == 64 * MIB
        assert measured["oom_kills"] >= 1 and measured["swap_max_bytes"] == 0
        guard = measured["owner_namespace"]
        assert guard["verified"] and guard["capabilities_zero"]
        assert guard["direct_control_open_denied"] and guard["supervisor_proc_root_open_denied"]
        assert 0 < measured["memory_peak_bytes"] <= 80 * MIB
        assert all(process_identity(pid) is None for pid in json.loads(marker.read_text()))
        assert process_identity(outside.pid) == identity
        assert not list((private_delegation / "redjohn-aggregate-v1").glob("redjohn-*"))
        _save("summed-oom", result)
    finally:
        outside.terminate()
        await asyncio.to_thread(outside.wait, 5)


async def test_actual_two_owners_share_immutable_aggregate_kernel_budget(
    private_delegation, tmp_path
):
    gate = tmp_path / "go"
    processes, receipts, markers = [], [], []
    for index in range(2):
        marker = tmp_path / f"ready-{index}"
        markers.append(marker)
        receipt = tmp_path / f"receipt-{index}.json"
        receipts.append(receipt)
        command = (
            "import pathlib,time;"
            f"pathlib.Path({str(marker)!r}).touch();p=pathlib.Path({str(gate)!r});\n"
            "while not p.exists(): time.sleep(.01)\n"
            "data=bytearray(60*1024*1024);time.sleep(1)"
        )
        processes.append(
            await _start(
                private_delegation,
                *_argv(private_delegation, tmp_path / "state", receipt, command),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        )
    await asyncio.gather(*(_ready(path) for path in markers))
    gate.touch()
    outputs = await asyncio.wait_for(
        asyncio.gather(*(process.communicate() for process in processes)), 20
    )
    results = [json.loads(path.read_text()) for path in receipts]
    assert all(process.returncode in {0, 2} for process in processes), outputs
    assert any(result["outcome"] == "resource_exhausted" for result in results)
    for result in results:
        measured = result["os_memory"]
        assert result["process_cleanup_verified"] is True
        assert measured["memory_max_bytes"] == 96 * MIB
        assert measured["aggregate"]["memory_max_bytes"] == 128 * MIB
        assert measured["aggregate"]["swap_max_bytes"] == 0
        assert 0 < measured["aggregate"]["memory_peak_bytes"] <= 144 * MIB
    pool = private_delegation / "redjohn-aggregate-v1"
    assert not list(pool.glob("redjohn-*"))
    with (
        pytest.raises(MemoryLimitUnavailableError, match="aggregate_memory_contract_mismatch"),
        LinuxMemoryBoundary(
            {
                "delegated_root": str(private_delegation),
                "aggregate_memory_budget_bytes": 256 * MIB,
                "pool_state_directory": str(tmp_path / "state"),
            },
            96 * MIB,
        ),
    ):
        pytest.fail("a later owner replaced the shared host budget")
    assert (pool / "memory.max").read_text().strip() == str(128 * MIB)
    _save("two-owner-oom", {"owners": results})


@pytest.mark.parametrize("cancel", [False, True])
async def test_actual_supervisor_deadline_or_signal_cleans_setsid_descendant(
    private_delegation, tmp_path, cancel
):
    marker = tmp_path / "pids.json"
    receipt = tmp_path / "receipt.json"
    command = (
        "import os,sys,subprocess,json,pathlib,time;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
        "start_new_session=True);"
        f"pathlib.Path({str(marker)!r}).write_text(json.dumps([os.getpid(),child.pid]));"
        "time.sleep(60)"
    )
    process = await _start(
        private_delegation,
        *_argv(
            private_delegation,
            tmp_path / "state",
            receipt,
            command,
            timeout=10 if cancel else 0.5,
        ),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await _ready(marker)
    if cancel:
        process.send_signal(signal.SIGTERM)
    stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
    assert process.returncode == (143 if cancel else 2), (stdout, stderr)
    result = json.loads(receipt.read_text())
    assert result["outcome"] == ("cancelled" if cancel else "timed_out")
    assert result["process_cleanup_verified"] is True
    assert result["os_memory"]["oom_kills"] == 0
    assert all(process_identity(pid) is None for pid in json.loads(marker.read_text()))
    _save("cancel" if cancel else "deadline", result)


async def test_actual_browser_sdk_mcp_and_native_worker_inherit_the_owner_hard_fence(
    private_delegation, tmp_path
):
    """Real Chromium, stateful target MCP and native argv overlap in one fence."""
    report, receipt = tmp_path / "components.json", tmp_path / "receipt.json"
    inline_config = json.dumps(
        {
            "delegated_root": str(private_delegation),
            "aggregate_memory_budget_bytes": 1536 * MIB,
            "pool_state_directory": str(tmp_path / "state"),
        }
    )
    command = (
        "import sys,runpy;"
        f"sys.argv=['owned-memory-components',{str(tmp_path / 'components')!r},"
        f"{str(report)!r},{inline_config!r}];"
        "runpy.run_module('tests.owned_memory_components',run_name='__main__')"
    )
    process = await _start(
        private_delegation,
        *_argv(
            private_delegation,
            tmp_path / "state",
            receipt,
            command,
            owner=1024,
            aggregate=1536,
            timeout=45,
        ),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), 55)
    assert len(stdout) <= 65536 and len(stderr) <= 65536
    (tmp_path / "owner.stderr.log").write_bytes(stderr)
    if process.returncode != 0:
        pytest.fail(stderr.decode(errors="replace"), pytrace=False)
    value, outcome = json.loads(report.read_text()), json.loads(receipt.read_text())
    assert outcome["outcome"] == "owner_exited"
    assert outcome["process_cleanup_verified"] is True
    assert outcome["os_memory"]["oom_kills"] == 0
    assert all(process_identity(pid) is None for pid in value["pids"])
    assert all(
        item["effective_capabilities"] == "0" and item["no_new_privileges"]
        for item in value["browser_namespace_attestations"]
    )
    _save("actual-browser-mcp-native", {"components": value, "supervisor": outcome})


async def test_actual_owner_preserves_inherited_terminal_io(private_delegation, tmp_path):
    master, slave = pty.openpty()
    receipt = tmp_path / "receipt.json"
    command = (
        "import os,sys;assert os.isatty(0) and os.isatty(1);"
        f"assert os.getcwd()=={str(Path.cwd())!r};"
        "value=sys.stdin.readline().strip();assert value=='redjohn-owned-tty';"
        "print('tty-preserved:'+value,flush=True)"
    )
    try:
        process = await _start(
            private_delegation,
            *_argv(private_delegation, tmp_path / "state", receipt, command),
            stdin=slave,
            stdout=slave,
            stderr=asyncio.subprocess.PIPE,
        )
        os.close(slave)
        slave = -1
        os.write(master, b"redjohn-owned-tty\n")
        _stdout, stderr = await asyncio.wait_for(process.communicate(), 15)
        assert process.returncode == 0, stderr
        os.set_blocking(master, False)
        assert b"tty-preserved:redjohn-owned-tty" in os.read(master, 4096)
        result = json.loads(receipt.read_text())
        assert result["os_memory"]["owner_namespace"]["verified"] is True
        assert result["process_cleanup_verified"] is True
        _save("terminal", result)
    finally:
        os.close(master)
        if slave != -1:
            os.close(slave)
