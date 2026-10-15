"""MCP Manager: real stdio MCP server (fixture), real initialize/list/call.

Mock-free: spawns fixtures/core_mcp_server.py (FastMCP, stdio transport)
as a subprocess and talks the MCP protocol to it.
"""

from __future__ import annotations

import asyncio
import sys

import pytest
from redjohn_core.errors import RJError
from redjohn_core.mcp_manager import MCPManager
from redjohn_core.models import MCPConnection, MCPTransport, ServiceState

from .conftest import MCP_SERVER, make_run_in


async def _connect(store) -> tuple[MCPManager, MCPConnection]:
    from redjohn_core.settings import Settings

    mgr = MCPManager(store, Settings())
    conn = MCPConnection(
        name="fixture",
        transport=MCPTransport.STDIO,
        command=[sys.executable, str(MCP_SERVER)],
    )
    async with store.write() as s:
        await store.insert_mcp(s, conn)
    conn = await mgr.connect(conn)
    return mgr, conn


async def test_stdio_connect_list_tools(store) -> None:
    mgr, conn = await _connect(store)
    assert conn.status == ServiceState.LIVE, conn.error
    assert conn.tools == ["mcp:fixture:ping"]
    # persisted status
    stored = await store.get_mcp(conn.mcp_id)
    assert stored.status == ServiceState.LIVE
    await mgr.disconnect(conn.mcp_id)


async def test_mcp_call_tool_roundtrip(store) -> None:
    from redjohn_core.settings import Settings

    settings = Settings()
    mgr = MCPManager(store, settings)
    conn = MCPConnection(
        name="fixture2",
        transport=MCPTransport.STDIO,
        command=[sys.executable, str(MCP_SERVER)],
    )
    async with store.write() as s:
        await store.insert_mcp(s, conn)
    conn = await mgr.connect(conn)
    assert conn.status == ServiceState.LIVE, conn.error
    assert conn.tools == ["mcp:fixture2:ping"]

    out = await mgr.call_tool("mcp:fixture2:ping", {"text": "hello"}, timeout_seconds=15.0)
    assert out == "pong:hello"

    await mgr.disconnect(conn.mcp_id)


async def test_mcp_slow_call_does_not_block_another_call_and_disconnect_cancels_it(store):
    mgr, conn = await _connect(store)
    slow = asyncio.create_task(mgr.call_tool(
        "mcp:fixture:ping", {"text": "slow", "delay_seconds": 10.0}, timeout_seconds=15.0,
    ))
    try:
        await asyncio.sleep(0.1)
        fast = await asyncio.wait_for(
            mgr.call_tool("mcp:fixture:ping", {"text": "fast"}, timeout_seconds=15.0), 2.0,
        )
        assert fast == "pong:fast"
        assert not slow.done()
    finally:
        await mgr.disconnect(conn.mcp_id)
    with pytest.raises(RJError, match="closed"):
        await slow


async def test_mcp_tool_via_runner_scope_enforced(engine) -> None:
    """An MCP tool call with a target outside agent scope never reaches the
    server; inside scope it executes for real."""
    from redjohn_core.models import Agent, AgentRole, AgentStatus, ToolInvocationStatus

    store = engine.store
    conn = MCPConnection(
        name="scoped", transport=MCPTransport.STDIO,
        command=[sys.executable, str(MCP_SERVER)],
    )
    async with store.write() as s:
        await store.insert_mcp(s, conn)
    conn = await engine.mcp_manager.connect(conn)
    assert conn.status == ServiceState.LIVE, conn.error

    run = await make_run_in(store, tools=["mcp:scoped:*"])
    agent = Agent(run_id=run.run_id, name="M", task="t", role=AgentRole.SPECIALIST,
                  status=AgentStatus.RUNNING,
                  allowed_targets=["app.acme.test"], allowed_tools=["mcp:scoped:*"])
    async with store.write() as s:
        await store.insert_agent(s, agent)

    ok = await engine.tool_runner.execute(
        run=run, agent=agent, tool="mcp:scoped:ping", args={"text": "scoped"}, step=0, call_index=0,
    )
    assert ok.status == ToolInvocationStatus.COMPLETED
    assert "pong:scoped" in ok.output_text

    bad = await engine.tool_runner.execute(
        run=run, agent=agent, tool="mcp:scoped:ping",
        args={"text": "x", "host": "evil.com"}, step=0, call_index=1,
    )
    assert bad.status == ToolInvocationStatus.FAILED
    assert "scope" in (bad.error or "")
