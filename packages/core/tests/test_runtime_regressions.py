"""Regression coverage for the real Engine boundaries found in the audit."""
from __future__ import annotations

import asyncio
import re
import sys
from types import SimpleNamespace

import pytest
from redjohn_core.engine import Engine
from redjohn_core.errors import RJError
from redjohn_core.mailbox import post_message
from redjohn_core.model_gateway import AnthropicGateway, ModelResponse, ToolCall
from redjohn_core.models import Agent, AgentLimits, AgentStatus, RunStatus
from redjohn_core.runs import start_run

from .conftest import make_run_in, make_settings, wait_for


class CompletingGateway:
    name = "fixture"

    def __init__(self):
        self.calls = []

    async def complete(self, **kwargs):
        self.calls.append(kwargs)
        return ModelResponse(content="completed", tool_calls=(
            ToolCall(id="call-complete", name="builtin:complete_task", args={"summary": "done"}),
        ), usage={"input_tokens": 10, "output_tokens": 10})


async def test_anthropic_uses_provider_names_and_tool_result_blocks(engine):
    captured = {}

    async def create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(content=[], stop_reason="end_turn", usage=SimpleNamespace())

    gateway = AnthropicGateway(engine.settings)
    gateway._client = lambda: SimpleNamespace(messages=SimpleNamespace(create=create))
    run = await make_run_in(engine.store)
    agent = Agent(run_id=run.run_id, name="test", task="test", allowed_tools=["builtin:*"])
    messages = [
        {"role": "user", "content": "test"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call-1", "name": "builtin:echo", "args": {"text": "hi"}},
        ]},
        {"role": "tool", "content": "hi", "tool_call_id": "call-1"},
    ]
    await gateway.complete(agent=agent, run=run, step=0, messages=messages,
                           tools=engine.tool_specs_for(agent))
    assert all(re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", t["name"]) for t in captured["tools"])
    assert captured["messages"][1]["content"][0]["type"] == "tool_use"
    assert captured["messages"][2]["content"][0]["tool_use_id"] == "call-1"


async def test_run_token_budget_blocks_unfunded_model_call(engine):
    engine.gateway = CompletingGateway()
    run = await make_run_in(engine.store, status=RunStatus.CREATED,
                            limits=AgentLimits(token_budget=1))
    await start_run(engine, run.run_id)

    async def terminal():
        return (await engine.store.get_run(run.run_id)).status in (RunStatus.FAILED, RunStatus.COMPLETED)

    await wait_for(terminal)
    assert engine.gateway.calls == []
    assert (await engine.store.get_run(run.run_id)).status == RunStatus.FAILED


async def test_mailbox_survives_restart_during_model_call(tmp_path, monkeypatch):
    import redjohn_core.engine as engine_module

    settings = make_settings(tmp_path)
    eng = await Engine.create(settings)
    entered = asyncio.Event()

    class PausedGateway:
        name = "fixture"

        async def complete(self, **kwargs):
            entered.set()
            await asyncio.Event().wait()

    eng.gateway = PausedGateway()
    run = await make_run_in(eng.store)
    agent = Agent(run_id=run.run_id, name="test", task="test", status=AgentStatus.RUNNING,
                  allowed_tools=["builtin:*"])
    async with eng.store.write() as session:
        await eng.store.insert_agent(session, agent)
    await post_message(eng.store, run, from_agent_id="user", to_agent_id=agent.agent_id,
                       body="RESTART_SENTINEL")
    eng.spawn_agent(agent.agent_id)
    await asyncio.wait_for(entered.wait(), 5)
    await eng.shutdown()
    resumed = CompletingGateway()
    monkeypatch.setattr(engine_module, "gateway_from_settings", lambda _: resumed)
    eng = await Engine.create(settings)
    try:
        await wait_for(lambda: bool(resumed.calls))
        assert any("RESTART_SENTINEL" in str(m["content"]) for m in resumed.calls[0]["messages"])
    finally:
        await eng.shutdown()


async def test_exec_cannot_read_outside_workspace_or_connect(engine, tmp_path):
    secret = tmp_path / "outside-secret"
    secret.write_text("PRIVATE")
    run = await make_run_in(engine.store)
    agent = Agent(run_id=run.run_id, name="test", task="test", status=AgentStatus.RUNNING,
                  allowed_targets=["app.acme.test"], allowed_tools=["builtin:exec"])
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
    result = await engine.tool_runner.execute(
        run=run, agent=agent, tool="builtin:exec", step=0, call_index=0,
        args={"argv": [sys.executable, "-c", f"print(open({str(secret)!r}).read())"]},
    )
    assert "PRIVATE" not in result.output_text
    assert result.status.value == "failed"


async def test_runtime_records_openviking_messages(engine, monkeypatch):
    import redjohn_core.engine as engine_module

    recorded = []

    class Memory:
        async def create_session(self, **kwargs):
            return "viking://user/test/sessions/runtime"

        async def add_message(self, uri, role, content, **kwargs):
            recorded.append((role, content, kwargs))

        async def commit_session(self, *args, **kwargs):
            return "task-runtime"

    monkeypatch.setattr(engine_module, "safe_memory_store", lambda _: Memory())
    engine.settings.openviking_url = "http://fixture.invalid"
    engine.gateway = CompletingGateway()
    run = await make_run_in(engine.store, status=RunStatus.CREATED)
    await start_run(engine, run.run_id)

    async def completed():
        return (await engine.store.get_run(run.run_id)).status == RunStatus.COMPLETED

    await wait_for(completed)
    assert {r[0] for r in recorded} >= {"user", "assistant"}
    assert all(r[2].get("message_id") for r in recorded)


async def test_budget_reservation_is_shared_atomic_and_settles_once(engine):
    from redjohn_core.budgets import reserve_model, settle_model

    run = await make_run_in(engine.store, limits=AgentLimits(token_budget=500))
    agents = [Agent(run_id=run.run_id, name=f"agent-{i}", task="test") for i in range(2)]
    results = await asyncio.gather(*(reserve_model(engine.store, run, a, 0, 100, 300)
                                     for a in agents), return_exceptions=True)
    successes = [r for r in results if not isinstance(r, Exception)]
    assert len(successes) == 1
    assert sum(isinstance(r, RJError) and r.code == "budget_exhausted" for r in results) == 1
    winner = agents[next(i for i, r in enumerate(results) if not isinstance(r, Exception))]
    response = ModelResponse(content="cached", usage={"input_tokens": 100, "output_tokens": 20})
    await settle_model(engine.store, run, winner, successes[0], response)
    await settle_model(engine.store, run, winner, successes[0], response)
    replay = await reserve_model(engine.store, run, winner, 0, 100, 300)
    assert replay.response == response
    settlements = [e for e in await engine.store.list_events(run.run_id)
                   if e.data.get("kind") == "model.settled"]
    assert len(settlements) == 1


async def test_unsettled_budget_claim_survives_engine_restart(tmp_path):
    from redjohn_core.budgets import reserve_model

    settings = make_settings(tmp_path)
    engine = await Engine.create(settings)
    run = await make_run_in(engine.store, limits=AgentLimits(token_budget=500))
    agent = Agent(run_id=run.run_id, name="test", task="test")
    await reserve_model(engine.store, run, agent, 0, 100, 300)
    await engine.shutdown()
    engine = await Engine.create(settings)
    try:
        with pytest.raises(RJError, match="insufficient token budget"):
            await reserve_model(engine.store, run, agent, 0, 100, 300)
    finally:
        await engine.shutdown()


async def test_openviking_unknown_append_is_not_duplicated():
    import httpx
    from redjohn_core.ov.client import OpenVikingStore, OVTimeout

    class SDK:
        def __init__(self):
            self.messages = []

        async def get_session_context(self, session_id):
            return {"messages": self.messages}

        async def add_message(self, session_id, role, content):
            self.messages.append({"role": role, "content": content})
            raise httpx.ReadTimeout("response lost after server accepted message")

    memory = OpenVikingStore(SimpleNamespace(openviking_url="http://fixture.invalid",
                                             openviking_api_key="fixture-only"))
    memory._client = SDK()
    with pytest.raises(OVTimeout):
        await memory.add_message("viking://user/test/sessions/test", "user", "fixture",
                                  message_id="stable-message")
    await memory.add_message("viking://user/test/sessions/test", "user", "fixture",
                              message_id="stable-message")
    assert len(memory._client.messages) == 1


async def test_expired_time_budget_refuses_new_model_and_tool(engine):
    from datetime import timedelta

    from redjohn_core.budgets import reserve_model
    from redjohn_core.models import utcnow

    run = await make_run_in(engine.store, limits=AgentLimits(time_budget_seconds=1))
    run.started_at = utcnow() - timedelta(seconds=2)
    async with engine.store.write() as session:
        await engine.store.update_run_row(session, run)
    agent = Agent(run_id=run.run_id, name="test", task="test", allowed_tools=["builtin:*"])
    with pytest.raises(RJError, match="time budget"):
        await reserve_model(engine.store, run, agent, 0, 10, 10)
    with pytest.raises(RJError, match="time budget"):
        await engine.tool_runner.execute(run=run, agent=agent, tool="builtin:echo",
                                         args={"text": "no"}, step=0, call_index=0)


async def test_sandbox_blocks_real_loopback_connection(engine):
    seen = []

    async def handler(reader, writer):
        seen.append(await reader.read(1024))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    run = await make_run_in(engine.store)
    agent = Agent(run_id=run.run_id, name="test", task="test", status=AgentStatus.RUNNING,
                  allowed_targets=["app.acme.test"], allowed_tools=["builtin:exec"])
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
    async with server:
        result = await engine.tool_runner.execute(run=run, agent=agent, tool="builtin:exec",
            args={"target": "app.acme.test", "argv": [sys.executable, "-c",
                  f"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:{port}').read())"]},
            step=0, call_index=0)
    assert result.status.value == "failed"
    assert seen == []


async def test_scoped_http_allows_local_lab_but_rejects_redirect_escape():
    from redjohn_core.executor import scoped_http_get

    seen = []

    async def handler(reader, writer):
        request = await reader.read(4096)
        seen.append(request)
        if b"/redirect" in request:
            writer.write(b"HTTP/1.1 302 Found\r\nLocation: http://outside.invalid/\r\n"
                         b"Content-Length: 0\r\n\r\n")
        else:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        output = await scoped_http_get(f"http://127.0.0.1:{port}/", ["127.0.0.1"],
                                        output_cap=128, timeout=2)
        assert output == b"HTTP 200\nOK"
        with pytest.raises(RJError, match="outside scope"):
            await scoped_http_get(f"http://127.0.0.1:{port}/redirect", ["127.0.0.1"],
                                   output_cap=128, timeout=2)
    assert len(seen) == 2


async def test_scoped_http_rejects_private_dns_rebinding(monkeypatch):
    import redjohn_core.executor as executor

    async def rebound(host, port):
        return ["127.0.0.1"]

    monkeypatch.setattr(executor, "resolve_addresses", rebound)
    with pytest.raises(RJError, match="protected address"):
        await executor.scoped_http_get("https://app.acme.test/", ["app.acme.test"],
                                        output_cap=128, timeout=2)
    with pytest.raises(RJError, match="protected address"):
        await executor.scoped_http_get("http://127.0.0.1/", ["127.0.0.1"],
                                        output_cap=128, timeout=2, cloud=True)
