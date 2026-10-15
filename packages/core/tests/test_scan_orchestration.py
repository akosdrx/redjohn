"""Scan-profile inheritance, real local skill loading and session-scoped source/MCP tools."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from langchain_core.messages import HumanMessage, SystemMessage
from redjohn_core.agents import AgentRuntime, initial_input
from redjohn_core.errors import RJError
from redjohn_core.mcp_defaults import default_templates, run_connection
from redjohn_core.mcp_manager import MCPManager
from redjohn_core.model_gateway import ModelResponse, ToolSpec
from redjohn_core.models import Agent, AgentRole, MCPConnection, MCPTransport, ScanMode
from redjohn_core.prompts import agent_system_prompt
from redjohn_core.skill_registry import SCAN_PROFILE_SKILLS, SkillRegistry
from redjohn_core.source_inspection import github_repository, list_source_files, read_source_file

from .conftest import MCP_SERVER, make_run_in, make_settings, python_for_subprocess


@pytest.mark.parametrize("mode", list(ScanMode))
async def test_coordinator_and_children_inherit_profile(store, mode):
    run = (await make_run_in(store)).model_copy(update={"scan_mode": mode})
    root = Agent(
        run_id=run.run_id,
        name="Coordinator",
        task="",
        role=AgentRole.COORDINATOR,
        allowed_targets=run.scope.allowed_targets,
        allowed_tools=["builtin:*"],
    )
    child = root.model_copy(update={"parent_agent_id": root.agent_id, "role": AgentRole.SPECIALIST})
    for agent in (root, child):
        prompt = agent_system_prompt(agent, run)
        assert f"Inherited scan mode: {mode.value}" in prompt
        assert SCAN_PROFILE_SKILLS[mode.value] in prompt
        assert "[Master methodology]" in prompt
        assert run.run_id in prompt
        assert "never escalate" in prompt
        assert initial_input(agent, run)["messages"][1].content


async def test_catalog_registers_offline_and_reads_references(store):
    registry = SkillRegistry()
    await registry.register(store)
    assert len(registry.search(limit=50)) == 28
    master = registry.get("00-master-pentest-methodology")
    stored = await store.get_skill(master.skill_id)
    assert stored.source == "redjohn-local"
    assert stored.ov_uri is None
    assert "D1" in registry.read_file(master.name, "references/evidence-gates.md")
    assert registry.search("auth access")[0].name == "30-auth-access-control"
    assert registry.get("15-cms-ecommerce-rce").name == "15-cms-ecommerce-rce"
    assert registry.get("62-mcp-ai-surface-audit").name == "62-mcp-ai-surface-audit"
    assert registry.get("95-finding-verifier").name == "95-finding-verifier"
    with pytest.raises(RJError, match="outside"):
        registry.read_file(master.name, "../../README.md")


async def test_each_turn_reasserts_current_system_prompt(engine):
    run = await make_run_in(engine.store)
    agent = Agent(
        run_id=run.run_id,
        name="Assessment",
        task="Inspect",
        allowed_targets=run.scope.allowed_targets,
        allowed_tools=["builtin:echo"],
    )
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
    captured = {}

    async def complete(**values):
        captured.update(values)
        return ModelResponse(content="covered", done=True)

    async def count(*args):
        return 10

    engine.gateway = SimpleNamespace(complete=complete, input_tokens=count)
    await AgentRuntime(engine).node_turn(
        {
            "messages": [SystemMessage(content="stale instructions"), HumanMessage(content="inspect")],
            "steps": 0,
        },
        {"configurable": {"thread_id": agent.agent_id}},
    )
    assert captured["messages"][0]["role"] == "system"
    assert "Follow these instructions on every turn" in captured["messages"][0]["content"]
    assert "stale instructions" not in str(captured["messages"])


async def test_local_source_reads_preserve_directory_and_symlink_scope(store, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("auth = required\n")
    outside = tmp_path / "secret.txt"
    outside.write_text("outside")
    (root / "escape.txt").symlink_to(outside)
    run = (await make_run_in(store, targets=[str(root)])).model_copy(update={"authorized_target": str(root)})
    agent = Agent(run_id=run.run_id, name="Source", task="read", allowed_targets=[str(root)])
    assert "auth = required" in read_source_file(run, agent, "app.py", 1000)
    assert json.loads(list_source_files(run, agent))["files"] == ["app.py"]
    for path in ("../secret.txt", "escape.txt", str(outside)):
        with pytest.raises(RJError, match="outside"):
            read_source_file(run, agent, path, 1000)


async def test_github_repository_is_exactly_authorized(store):
    run = (await make_run_in(store, targets=["https://github.com/acme/product"])).model_copy(
        update={"authorized_target": "https://github.com/acme/product"}
    )
    agent = Agent(
        run_id=run.run_id, name="Repo", task="read", allowed_targets=["https://github.com/acme/product"]
    )
    assert github_repository(run, agent) == ("acme", "product")
    with pytest.raises(RJError):
        github_repository(
            run.model_copy(update={"authorized_target": "https://github.com/acme/other"}), agent
        )


async def test_managed_mcp_defaults_register_without_starting(engine):
    conns = await engine.store.list_mcps()
    assert {conn.name for conn in conns} == {conn.name for conn in default_templates(engine.settings)}
    assert engine.mcp_manager.live_connections() == []
    run = await make_run_in(engine.store)
    await engine.mcp_manager.ensure_run_connections(run)
    assert engine.mcp_manager.live_connections() == []  # fixture provider stays offline


async def test_managed_mcp_scopes_and_source_tools(store, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    run = (await make_run_in(store, targets=[str(root)])).model_copy(
        update={"authorized_target": str(root), "target_kind": "local_project"}
    )
    settings = make_settings(tmp_path)
    mgr = MCPManager(store, settings)
    agent = Agent(run_id=run.run_id, name="Read", task="read", allowed_targets=[str(root)])
    own = f"mcp:rj-{run.run_id}-filesystem:read_text_file"
    assert mgr.scope_violation(own, {"path": str(root / "app.py")}, run, agent) is None
    assert mgr.scope_violation(own, {"path": str(tmp_path / "secret")}, run, agent)
    assert mgr.scope_violation(own.replace("read_text_file", "write_file"), {}, run, agent)
    assert not mgr.tool_visible_to_run(own, "run_other")
    conn = run_connection(run, settings)
    assert conn and conn.command[-1] == str(root)
    assert conn.name.startswith(f"rj-{run.run_id}-")


async def test_mcp_discovered_schemas_are_preserved(store, tmp_path):
    mgr = MCPManager(store, make_settings(tmp_path))
    conn = MCPConnection(
        name="schema-fixture",
        transport=MCPTransport.STDIO,
        command=[python_for_subprocess(), str(MCP_SERVER)],
    )
    async with store.write() as session:
        await store.insert_mcp(session, conn)
    try:
        await mgr.connect(conn)
        definition = mgr.tool_definition("mcp:schema-fixture:ping")
        assert definition and "text" in definition["input_schema"]["properties"]
        original = ToolSpec("mcp:schema-fixture:ping", "placeholder", {"type": "object"})
        resolved = replace(
            original, description=definition["description"], input_schema=definition["input_schema"]
        )
        assert "text" in resolved.input_schema["properties"]
        assert "pong:schema" in (await mgr.call_tool(resolved.name, {"text": "schema"}, timeout_seconds=15))
    finally:
        await mgr.shutdown()


async def test_session_browser_blocks_redirects_and_arbitrary_node_code(store, tmp_path):
    run = (await make_run_in(store, targets=["https://app.acme.test"])).model_copy(
        update={"authorized_target": "https://app.acme.test", "target_kind": "web_application"}
    )
    conn = run_connection(run, make_settings(tmp_path))
    assert conn and "--isolated" in conn.command and "--block-service-workers" in conn.command
    guard = Path(conn.command[conn.command.index("--init-page") + 1]).read_text()
    assert "https://app.acme.test" in guard
    assert "maxRedirects: 0" in guard
    assert "allowed.has(new URL(destination).origin)" in guard
    assert "routeWebSocket" in guard
    mgr = MCPManager(store, make_settings(tmp_path))
    assert not mgr._managed_tool_allowed(conn.name, "browser_run_code")
    assert mgr._managed_tool_allowed(conn.name, "browser_navigate")


async def test_workspace_artifact_reader_is_session_scoped(engine, tmp_path):
    from redjohn_core.models import ToolInvocationStatus

    run = await make_run_in(engine.store)
    agent = Agent(run_id=run.run_id, name="Artifacts", task="read", allowed_tools=["builtin:*"])
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
    directory = engine.settings.work_root / run.run_id
    directory.mkdir()
    (directory / "snapshot.yml").write_text("heading: Scoped fixture")
    outside = tmp_path / "other-session.yml"
    outside.write_text("private")
    (directory / "escape.yml").symlink_to(outside)
    for index, (path, expected) in enumerate(
        [
            ("snapshot.yml", ToolInvocationStatus.COMPLETED),
            (str(outside), ToolInvocationStatus.FAILED),
            ("escape.yml", ToolInvocationStatus.FAILED),
        ]
    ):
        result = await engine.tool_runner.execute(
            run=run,
            agent=agent,
            tool="builtin:read_workspace_file",
            args={"path": path},
            step=0,
            call_index=index,
        )
        assert result.status == expected
        if expected == ToolInvocationStatus.COMPLETED:
            assert "Scoped fixture" in result.output_text
            assert result.evidence_refs


async def test_cancelling_mcp_startup_reaps_process(store, tmp_path):
    import asyncio
    import os

    from .conftest import wait_for

    pidfile = tmp_path / "mcp-startup.pid"
    script = "import os,time,sys; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(60)"
    mgr = MCPManager(store, make_settings(tmp_path))
    conn = MCPConnection(
        name="startup-cancel",
        transport=MCPTransport.STDIO,
        command=[python_for_subprocess(), "-c", script, str(pidfile)],
    )
    async with store.write() as session:
        await store.insert_mcp(session, conn)
    task = asyncio.create_task(mgr.connect(conn))
    await wait_for(pidfile.exists, timeout=5)
    pid = int(pidfile.read_text())
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await mgr.shutdown()
    assert not mgr._connecting
    assert not mgr.live_connections()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


async def test_natural_completion_closes_session_mcp_actor(engine):
    from redjohn_core.model_gateway import ToolCall
    from redjohn_core.models import AgentStatus, RunStatus

    from .conftest import wait_for

    run = await make_run_in(engine.store)
    agent = Agent(
        run_id=run.run_id,
        name="Completer",
        task="finish",
        role=AgentRole.COORDINATOR,
        status=AgentStatus.RUNNING,
        allowed_targets=run.scope.allowed_targets,
        allowed_tools=["builtin:complete_task"],
    )
    conn = MCPConnection(
        name=f"rj-{run.run_id}-filesystem",
        transport=MCPTransport.STDIO,
        command=[python_for_subprocess(), str(MCP_SERVER)],
    )
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
        await engine.store.insert_mcp(session, conn)
    (engine.settings.work_root / run.run_id).mkdir()
    await engine.mcp_manager.connect(conn)
    actor = engine.mcp_manager._live[conn.mcp_id].actor

    async def complete(**values):
        return ModelResponse(
            content="coverage complete",
            tool_calls=[
                ToolCall(id="finish", name="builtin:complete_task", args={"summary": "coverage complete"})
            ],
        )

    async def count(*args):
        return 10

    engine.gateway = SimpleNamespace(complete=complete, input_tokens=count)
    engine.spawn_agent(agent.agent_id)
    await wait_for(lambda: engine._runners[agent.agent_id].done(), timeout=10)
    assert (await engine.store.get_run(run.run_id)).status == RunStatus.COMPLETED
    assert actor.done()
    assert conn.mcp_id not in {item.mcp_id for item in await engine.store.list_mcps()}
    assert not engine.mcp_manager.live_connections()


async def test_stop_cancels_and_reaps_running_command(engine):
    import asyncio

    from redjohn_core.models import AgentStatus, ToolInvocationStatus

    from .conftest import wait_for

    run = await make_run_in(engine.store)
    agent = Agent(
        run_id=run.run_id,
        name="Command",
        task="fixture",
        status=AgentStatus.RUNNING,
        allowed_tools=["builtin:exec"],
    )
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
    task = asyncio.create_task(
        engine.tool_runner.execute(
            run=run,
            agent=agent,
            tool="builtin:exec",
            args={"argv": ["/bin/sleep", "20"]},
            step=0,
            call_index=0,
        )
    )
    await wait_for(lambda: bool(engine.tool_runner._procs.get(run.run_id)), timeout=5)
    process = next(iter(engine.tool_runner._procs[run.run_id]))
    await engine.tool_runner.kill_run(run.run_id)
    assert task.cancelled()
    assert process.returncode is not None
    invocations = await engine.store.list_invocations(run.run_id)
    assert invocations[0].status == ToolInvocationStatus.CANCELLED


def test_gui_path_resolves_homebrew_node_without_changing_process_environment(monkeypatch, tmp_path):
    import os

    from redjohn_core import mcp_defaults

    tools = tmp_path / "Homebrew" / "bin"
    tools.mkdir(parents=True)
    for name in ("npx", "node"):
        executable = tools / name
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
    restricted = str(tmp_path / "GUI-bin")
    monkeypatch.setenv("PATH", restricted)
    monkeypatch.setattr(mcp_defaults, "NODE_RUNTIME_DIRECTORIES", (tools,))
    command, env = mcp_defaults.resolve_node_runtime()
    assert command == str(tools / "npx")
    assert env["PATH"].split(os.pathsep)[0] == str(tools)
    assert os.environ["PATH"] == restricted


async def test_missing_managed_node_runtime_has_visible_prerequisite_error(store, monkeypatch, tmp_path):
    from redjohn_core import mcp_defaults
    from redjohn_core.models import ServiceState

    monkeypatch.setenv("PATH", str(tmp_path / "GUI-bin"))
    monkeypatch.setattr(mcp_defaults, "NODE_RUNTIME_DIRECTORIES", ())
    manager = MCPManager(store, make_settings(tmp_path))
    conn = MCPConnection(
        name="rj-run_missing-playwright",
        transport=MCPTransport.STDIO,
        command=["npx", "-y", "@playwright/mcp@0.0.83"],
    )
    async with store.write() as session:
        await store.insert_mcp(session, conn)
    conn = await manager.connect(conn)
    assert conn.status == ServiceState.DOWN
    assert "Node.js/npm is required" in conn.error
    assert not manager.live_connections()
    assert not manager._connecting
