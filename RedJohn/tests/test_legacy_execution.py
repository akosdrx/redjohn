"""SDK bridge contracts and real owned stdio/PTY subprocess regressions.

The MCP and PTY tests launch actual local processes. They do not claim live
cloud/provider credentials or prove an additional OS network boundary.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import sys
import time
from types import SimpleNamespace

import pytest
from agents.sandbox.capabilities.tools.shell_tool import ExecCommandTool, WriteStdinTool
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.unix_local import UnixLocalSandboxClient
from agents.tool_context import ToolContext

from redjohn.agents.factory import _wrap_exec_command, _wrap_write_stdin
from redjohn.assessment.resources import (
    ProcessTreeMemory,
    ResourceAdmissionError,
    ResourceEnvelope,
    ResourceGovernor,
)
from redjohn.runtime.legacy_execution import LegacyExecution
from redjohn.tools.mcp import McpConnectionConfig, McpConnectionRequest, McpRegistry
from redjohn.tools.mcp.agent_tools import call_mcp, list_mcps


def governor(**limits):
    return ResourceGovernor(
        ResourceEnvelope(**limits),
        memory_reader=lambda: ProcessTreeMemory(os.getpid(), 1024, 1, 0),
    )


def context(registry=None, owner=None):
    return ToolContext(
        context={"mcp_registry": registry, "legacy_execution": owner},
        tool_name="call_mcp",
        tool_call_id="owned-test",
        tool_arguments="{}",
    )


async def test_shared_admission_deadline_and_cleanup_are_durable(tmp_path):
    pool = governor(max_workers=1)
    owner = LegacyExecution(tmp_path / "agents.db", pool, max_history=2)
    ready, cleaned = asyncio.Event(), []

    async def slow():
        ready.set()
        await asyncio.sleep(10)

    async def cleanup():
        cleaned.append(True)

    task = asyncio.create_task(owner.run("secret-free-label", slow, timeout=0.05, cleanup=cleanup))
    await ready.wait()
    with pytest.raises(ResourceAdmissionError):
        pool.acquire("scanner")
    with pytest.raises(TimeoutError):
        await task
    assert cleaned == [True]
    assert pool.snapshot()["active"] == {}
    assert owner.db.execute("SELECT status,error_code FROM rj_legacy_execution").fetchall() == [
        ("timed_out", "legacy_operation_timeout")
    ]
    for _ in range(3):
        await owner.run("private-not-persisted", lambda: asyncio.sleep(0))
    assert owner.db.execute("SELECT COUNT(*) FROM rj_legacy_execution").fetchone()[0] == 2
    assert b"private-not-persisted" not in (tmp_path / "agents.db").read_bytes()
    await owner.close()
    pool.close()


async def test_owner_collision_restart_and_model_failure_release(tmp_path):
    path = tmp_path / "agents.db"
    pool = governor(max_workers=1)
    owner = LegacyExecution(path, pool)
    with pytest.raises(ResourceAdmissionError, match="already_running"):
        LegacyExecution(path, pool)
    owner.model_start("root")
    with pytest.raises(ResourceAdmissionError):
        pool.acquire("browser")
    owner.model_end("root")
    assert pool.snapshot()["active"] == {}
    owner.db.execute(
        "INSERT INTO rj_legacy_execution VALUES('old','dead','sdk','digest',0,NULL,'running','')"
    )
    await owner.close()
    resumed = LegacyExecution(path, pool)
    assert resumed.db.execute("SELECT status,error_code FROM rj_legacy_execution").fetchall() == [
        ("inconclusive", "coordinator_restart_unknown_outcome")
    ]
    await resumed.close()
    pool.close()


async def test_inventory_does_not_launch_any_optional_server():
    registry = McpRegistry()
    for name in ("one", "two", "three"):
        registry.register(
            McpConnectionRequest(
                config=McpConnectionConfig(
                    name=name, transport="stdio", command="must-not-start-redjohn-test"
                )
            )
        )
    result = await list_mcps.on_invoke_tool(context(registry), "{}")
    assert [row["state"] for row in result["connections"]] == ["configured"] * 3
    assert all(registry.get(name).session is None for name in registry.names())
    await registry.close()


def real_registry(tmp_path):
    server = tmp_path / "owned_server.py"
    events = tmp_path / "events.json"
    server.write_text(
        "import asyncio,json,os,sys\n"
        "from pathlib import Path\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "app=FastMCP('RedJohn owned failure regression')\n"
        "events=Path(sys.argv[1])\n"
        "prior=json.loads(events.read_text()) if events.exists() else {'effects':0}\n"
        "prior['pid']=os.getpid();events.write_text(json.dumps(prior))\n"
        "@app.tool()\n"
        "async def commit_then_drop() -> str:\n"
        " row=json.loads(events.read_text());row['effects']+=1;events.write_text(json.dumps(row))\n"
        " os._exit(7)\n"
        "@app.tool()\n"
        "async def read_marker() -> str:\n"
        " return str(os.getpid())\n"
        "@app.tool()\n"
        "async def slow_effect() -> str:\n"
        " row=json.loads(events.read_text());row['started']=True\n"
        " events.write_text(json.dumps(row))\n"
        " await asyncio.sleep(30)\n"
        " row['effects']+=1;events.write_text(json.dumps(row));return 'done'\n"
        "app.run(transport='stdio')\n"
    )
    registry = McpRegistry()
    registry.register(
        McpConnectionRequest(
            config=McpConnectionConfig(
                name="owned",
                transport="stdio",
                command=sys.executable,
                args=[str(server), str(events)],
                session_timeout_seconds=5,
            )
        )
    )
    return registry, events


async def test_real_stdio_idle_session_keeps_memory_reservation_and_server_state(tmp_path):
    registry, events = real_registry(tmp_path)
    pool = governor(max_workers=1, max_contexts=1)
    owner = LegacyExecution(tmp_path / "agents.db", pool)
    registry.bind_governor(pool)
    try:
        first = await call_mcp.on_invoke_tool(
            context(registry, owner), json.dumps({"connection": "owned", "tool": "read_marker"})
        )
        pid = json.loads(events.read_text())["pid"]
        assert first["text"] == str(pid)
        assert pool.snapshot()["active"] == {"context": 1}
        assert pool.snapshot()["reserved_bytes"] == pool.envelope.worker_memory_budget
        with pytest.raises(ResourceAdmissionError):
            pool.acquire("context")
        owner.model_start("root")
        assert pool.snapshot()["active"] == {"context": 1, "worker": 1}
        owner.model_end("root")
        second = await call_mcp.on_invoke_tool(
            context(registry, owner), json.dumps({"connection": "owned", "tool": "read_marker"})
        )
        assert second["text"] == str(pid)
        assert json.loads(events.read_text())["pid"] == pid
    finally:
        await registry.close()
        assert pool.snapshot()["active"] == {}
        await owner.close()
        pool.close()


async def test_failed_cleanup_retains_reservation_until_successful_retry(tmp_path):
    pool = governor(max_workers=1)
    owner = LegacyExecution(tmp_path / "agents.db", pool)
    attempts = []

    async def cleanup():
        attempts.append(True)
        if len(attempts) == 1:
            raise RuntimeError("owned cleanup fault")

    with pytest.raises(RuntimeError, match="cleanup fault"):
        await owner.run("bounded-timeout", lambda: asyncio.sleep(10), timeout=0.01, cleanup=cleanup)
    assert pool.snapshot()["active"] == {"worker": 1}
    with pytest.raises(ResourceAdmissionError):
        pool.acquire("scanner")
    assert owner.db.execute("SELECT status,error_code FROM rj_legacy_execution").fetchone() == (
        "inconclusive",
        "legacy_cleanup_failed",
    )
    await owner.close()
    assert attempts == [True, True]
    assert pool.snapshot()["active"] == {}
    pool.close()


async def test_shell_spawn_before_handle_with_cleanup_failure_retains_reservation(tmp_path):
    pool = governor(max_workers=1)
    cleanup_attempts = []

    async def terminate():
        cleanup_attempts.append(True)
        if len(cleanup_attempts) == 1:
            raise RuntimeError("owned termination failure")

    async def interrupted_before_handle():
        raise asyncio.CancelledError

    owner = LegacyExecution(
        tmp_path / "agents.db",
        pool,
        sandbox_session=SimpleNamespace(pty_terminate_all=terminate),
    )
    with pytest.raises(RuntimeError, match="termination failure"):
        await owner.shell("exec_command", {}, interrupted_before_handle)
    assert pool.snapshot()["active"] == {"worker": 1}
    with pytest.raises(ResourceAdmissionError):
        pool.acquire("scanner")
    assert owner.db.execute("SELECT status,error_code FROM rj_legacy_execution").fetchone() == (
        "inconclusive",
        "sdk_process_cleanup_failed",
    )
    await owner.close()
    assert cleanup_attempts == [True, True]
    assert pool.snapshot()["active"] == {}
    pool.close()


async def test_shell_deadline_includes_the_initial_sdk_yield(tmp_path):
    pool = governor(max_workers=1)
    terminated = asyncio.Event()
    elapsed = []
    began = time.monotonic()

    async def terminate():
        elapsed.append(time.monotonic() - began)
        terminated.set()

    async def delayed_handle():
        # Initial SDK streaming time is part of the execution deadline, not an
        # extra interval before a second full timeout starts.
        await asyncio.sleep(0.2)
        return "Process running with session ID 7\nOutput:\n"

    owner = LegacyExecution(
        tmp_path / "agents.db",
        pool,
        shell_timeout_seconds=0.3,
        sandbox_session=SimpleNamespace(pty_terminate_all=terminate),
    )
    try:
        await owner.shell("exec_command", {}, delayed_handle)
        await asyncio.wait_for(terminated.wait(), 0.2)
        assert 0.25 <= elapsed[0] < 0.45
        assert pool.snapshot()["active"] == {}
        assert owner.db.execute("SELECT status,error_code FROM rj_legacy_execution").fetchone() == (
            "timed_out",
            "sdk_process_deadline_exceeded",
        )
    finally:
        await owner.close()
        pool.close()


async def wait_started(events):
    async with asyncio.timeout(10):
        while True:
            if events.exists():
                try:
                    row = json.loads(events.read_text())
                except json.JSONDecodeError:
                    row = {}
                if row.get("started"):
                    return row
            await asyncio.sleep(0.01)


async def test_real_stdio_unknown_mutation_is_never_replayed(tmp_path):
    registry, events = real_registry(tmp_path)
    owner = LegacyExecution(tmp_path / "agents.db", ResourceGovernor())
    registry.bind_governor(owner.governor)
    try:
        result = await asyncio.wait_for(
            call_mcp.on_invoke_tool(
                context(registry, owner),
                json.dumps({"connection": "owned", "tool": "commit_then_drop"}),
            ),
            15,
        )
        assert result["success"] is False
        assert result.get("code") == "mcp_unknown_execution_outcome", result
        assert json.loads(events.read_text())["effects"] == 1
        assert owner.governor.snapshot()["active"] == {}
        assert owner.db.execute(
            "SELECT status FROM rj_legacy_execution ORDER BY started_at"
        ).fetchall() == [("succeeded",), ("inconclusive",)]
    finally:
        await registry.close()
        await owner.close()
        owner.governor.close()


async def test_real_stdio_cancellation_terminates_worker_and_releases_lease(tmp_path):
    registry, events = real_registry(tmp_path)
    owner = LegacyExecution(tmp_path / "agents.db", ResourceGovernor())
    registry.bind_governor(owner.governor)
    task = asyncio.create_task(
        call_mcp.on_invoke_tool(
            context(registry, owner),
            json.dumps({"connection": "owned", "tool": "slow_effect"}),
        )
    )
    try:
        row = await wait_started(events)
        assert owner.governor.snapshot()["active"] == {"worker": 1, "context": 1}
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 15)
        assert json.loads(events.read_text())["effects"] == 0
        with pytest.raises(ProcessLookupError):
            os.kill(row["pid"], 0)
        assert owner.governor.snapshot()["active"] == {}
        assert owner.db.execute(
            "SELECT status FROM rj_legacy_execution ORDER BY started_at DESC LIMIT 1"
        ).fetchone() == ("cancelled",)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await registry.close()
        await owner.close()
        owner.governor.close()


async def test_real_sdk_pty_keeps_lease_until_polled_completion_and_closes(tmp_path):
    client = UnixLocalSandboxClient()
    session = await client.create(manifest=Manifest(root=str(tmp_path)))
    await session.start()
    pool = governor(max_workers=1)
    owner = LegacyExecution(tmp_path / "agents.db", pool, sandbox_session=session)
    try:
        tool = _wrap_exec_command(ExecCommandTool(session=session))
        result = await tool.on_invoke_tool(
            context(owner=owner),
            json.dumps(
                {
                    "cmd": "sleep 1.2",
                    "yield_time_ms": 0,
                    "login": False,
                }
            ),
        )
        assert "session ID" in result, result
        handle = int(re.search(r"session ID (\d+)", result).group(1))
        assert pool.snapshot()["active"] == {"worker": 1}
        with pytest.raises(ResourceAdmissionError):
            pool.acquire("scanner")
        await asyncio.sleep(1.3)
        poll = _wrap_write_stdin(WriteStdinTool(session=session))
        result = await poll.on_invoke_tool(
            context(owner=owner),
            json.dumps(
                {
                    "session_id": handle,
                    "chars": "",
                    "yield_time_ms": 10,
                }
            ),
        )
        assert "Process exited with code 0" in result
        assert pool.snapshot()["active"] == {}
        result = await tool.on_invoke_tool(
            context(owner=owner),
            json.dumps(
                {
                    "cmd": "sleep 30",
                    "yield_time_ms": 0,
                    "login": False,
                }
            ),
        )
        assert "Process running" in result
        await owner.close()
        assert pool.snapshot()["active"] == {}
        with sqlite3.connect(tmp_path / "agents.db") as db:
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM rj_legacy_execution WHERE status='running'"
                ).fetchone()[0]
                == 0
            )
    finally:
        await owner.close()
        await session.stop()
        await client.delete(session)
        pool.close()
