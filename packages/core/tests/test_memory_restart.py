"""Actual Engine/checkpoint restart; the external memory provider is a fixture."""
from __future__ import annotations

import asyncio

import pytest
from redjohn_core.engine import Engine
from redjohn_core.events import EventType
from redjohn_core.model_gateway import ModelResponse, ToolCall
from redjohn_core.models import Agent, AgentLimits, AgentRole, AgentStatus, RunStatus
from redjohn_core.runs import start_run

from .conftest import crash_engine, make_run_in, make_settings, wait_for
from .test_runtime_regressions import CompletingGateway


class MemoryProvider:
    """Provider-side state survives every client and Engine instance."""

    def __init__(self):
        self.messages = {}
        self.tasks = {}
        self.message_attempts = []
        self.accepted = asyncio.Event()
        self.finish = asyncio.Event()
        self.clients = 0

    def client(self):
        self.clients += 1
        provider = self

        class Client:
            async def create_session(self, *, session_id):
                return f"viking://user/test/sessions/{session_id}"

            async def add_message(self, uri, role, content, *, message_id):
                provider.message_attempts.append(message_id)
                provider.messages.setdefault(message_id, (uri, role, content))

            async def commit_session(self, uri, **kwargs):
                task = provider.tasks.setdefault(uri, f"extraction-{len(provider.tasks)}")
                provider.accepted.set()
                await provider.finish.wait()
                return task

            async def close(self):
                pass

        return Client()


@pytest.mark.parametrize("cut", ["accepted_extraction", "agent_complete_before_run_complete"])
async def test_engine_restart_finishes_memory_and_run_once(tmp_path, monkeypatch, cut):
    import redjohn_core.engine as module

    provider = MemoryProvider()
    calls = []

    class Gateway:
        name = "fixture"

        async def complete(self, **kwargs):
            calls.append(kwargs["step"])
            return ModelResponse(content="RESTART_MEMORY_SENTINEL", tool_calls=(
                ToolCall(id="finish", name="builtin:complete_task", args={"summary": "done"}),
            ), usage={"input_tokens": 10, "output_tokens": 10})

    monkeypatch.setattr(module, "gateway_from_settings", lambda _: Gateway())
    monkeypatch.setattr(module, "safe_memory_store", lambda _: provider.client())
    settings = make_settings(tmp_path)
    settings.openviking_url = "http://fixture.invalid"
    engine = await Engine.create(settings)
    interrupted = asyncio.Event()
    if cut == "agent_complete_before_run_complete":
        provider.finish.set()

        async def pause_after_status(run, agent):
            interrupted.set()
            await asyncio.Event().wait()

        engine._on_agent_terminal = pause_after_status
    run = await make_run_in(engine.store, status=RunStatus.CREATED,
                            # This tests crash recovery, not exhaustion. Allow
                            # the required system/master/scan instructions.
                            limits=AgentLimits(time_budget_seconds=60, token_budget=100000))
    await start_run(engine, run.run_id)
    await asyncio.wait_for(provider.accepted.wait(), 5)
    if cut == "agent_complete_before_run_complete":
        await asyncio.wait_for(interrupted.wait(), 5)
    before = await engine.store.list_agents(run.run_id)
    assert len(before) == 1
    agent_id = before[0].agent_id
    checkpoint = await engine._graph.aget_state({"configurable": {"thread_id": agent_id}})
    assert checkpoint.values["complete"] is True and not checkpoint.next
    assert (await engine.store.get_run(run.run_id)).status == RunStatus.RUNNING
    recorded = dict(provider.messages)
    usage = [e.model_dump() for e in await engine.store.list_events(run.run_id)
             if e.type == EventType.USAGE]
    await crash_engine(engine)

    # Fresh gateway, client, Store and graph; only provider and disk state remain.
    provider.finish.set()
    engine = await Engine.create(settings)
    try:
        async def completed():
            return (await engine.store.get_run(run.run_id)).status == RunStatus.COMPLETED

        await wait_for(completed, timeout=1)
        agent = await engine.store.get_agent(agent_id)
        assert agent.status == AgentStatus.COMPLETE
        assert agent.created_at == before[0].created_at
        assert agent.time_budget_seconds == before[0].time_budget_seconds == 60
        assert calls == [0]
        assert provider.messages == recorded
        assert len(provider.message_attempts) == len(recorded)
        assert len(provider.tasks) == 1
        events = await engine.store.list_events(run.run_id)
        assert [e.model_dump() for e in events if e.type == EventType.USAGE] == usage
        after = await engine._graph.aget_state({"configurable": {"thread_id": agent_id}})
        assert [(m.id, m.content) for m in after.values["messages"]] == [
            (m.id, m.content) for m in checkpoint.values["messages"]]
        assert sum(e.type == EventType.RUN_STATUS and e.data.get("status") == "completed"
                   for e in events) == 1
        assert sum(e.type == EventType.AGENT_STATUS and e.data.get("status") == "complete"
                   for e in events) == 1
    finally:
        await engine.shutdown()


async def test_child_result_survives_interruption_before_mail_insert(tmp_path, monkeypatch):
    import redjohn_core.engine as module

    gateway = CompletingGateway()
    monkeypatch.setattr(module, "gateway_from_settings", lambda _: gateway)
    settings = make_settings(tmp_path)
    engine = await Engine.create(settings)
    run = await make_run_in(engine.store)
    parent = Agent(run_id=run.run_id, name="parent", task="receive result", status=AgentStatus.PENDING)
    child = Agent(run_id=run.run_id, parent_agent_id=parent.agent_id, name="child", task="finish",
                  status=AgentStatus.RUNNING, allowed_tools=["builtin:*"])
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, parent)
        await engine.store.insert_agent(session, child)
    entered = asyncio.Event()
    original = module.mailbox.post_message

    async def block_result(*args, **kwargs):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(module.mailbox, "post_message", block_result)
    engine.spawn_agent(child.agent_id)
    await asyncio.wait_for(entered.wait(), 5)
    await crash_engine(engine)
    monkeypatch.setattr(module.mailbox, "post_message", original)
    engine = await Engine.create(settings)
    try:
        async def delivered():
            return await engine.store.list_messages(run.run_id)

        messages = await wait_for(delivered, timeout=1)
        assert len(messages) == 1 and messages[0].to_agent_id == parent.agent_id
        assert messages[0].idempotency_key == f"final-result:{child.agent_id}"
        state = await engine._graph.aget_state({"configurable": {"thread_id": child.agent_id}})
        await engine.finalize_agent(child.agent_id, state.values)
        assert len(await engine.store.list_messages(run.run_id)) == 1
        assert len(gateway.calls) == 1
    finally:
        await engine.shutdown()


async def test_finalization_does_not_overwrite_stop_during_memory_poll(engine):
    run = await make_run_in(engine.store)
    agent = Agent(run_id=run.run_id, name="coordinator", role=AgentRole.COORDINATOR,
                  task="finish", status=AgentStatus.RUNNING)
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
    ready, release = asyncio.Event(), asyncio.Event()

    async def delayed_commit(_agent):
        ready.set()
        await release.wait()

    engine._commit_memory_session = delayed_commit
    task = asyncio.create_task(engine.finalize_agent(agent.agent_id, {"complete": True}))
    await asyncio.wait_for(ready.wait(), 5)
    # External control plane stop, without relying on local task cancellation.
    async with engine.store.write() as session:
        run.status = RunStatus.STOPPED
        agent.status = AgentStatus.STOPPED
        await engine.store.update_run_row(session, run)
        await engine.store.update_agent_row(session, agent)
    release.set()
    await task
    assert (await engine.store.get_run(run.run_id)).status == RunStatus.STOPPED
    assert (await engine.store.get_agent(agent.agent_id)).status == AgentStatus.STOPPED


async def test_terminal_provider_failure_is_recorded_without_retry_loop(engine, monkeypatch):
    from redjohn_core.ov.client import OVTaskFailed

    run = await make_run_in(engine.store)
    agent = Agent(run_id=run.run_id, name="coordinator", role=AgentRole.COORDINATOR,
                  task="finish", status=AgentStatus.RUNNING,
                  ov_session_uri="viking://user/test/sessions/terminal-failure")
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
    attempts = []

    class FailedMemory:
        async def commit_session(self, *args, **kwargs):
            attempts.append(args)
            raise OVTaskFailed("original-task", "failed", "provider import deadlock")

    async def memory():
        return FailedMemory()

    monkeypatch.setattr(engine, "_memory", memory)
    await asyncio.wait_for(engine.finalize_agent(agent.agent_id, {"complete": True}), timeout=0.6)
    assert len(attempts) == 1
    current = await engine.store.get_agent(agent.agent_id)
    assert current.status == AgentStatus.FAILED
    assert "original-task" in current.current_activity
    assert (await engine.store.get_run(run.run_id)).status == RunStatus.FAILED


async def test_shutdown_waits_for_scheduler_transaction_cleanup(tmp_path, monkeypatch):
    from redjohn_core.db import engine_meta
    from sqlalchemy import insert, select

    engine = await Engine.create(make_settings(tmp_path))
    engine._sweep.cancel()
    try:
        await engine._sweep
    except asyncio.CancelledError:
        pass
    # Remove relay timing as an accidental barrier: the scheduler's own
    # transaction cleanup must be awaited even with no active subscribers.
    await engine.hub.stop()
    entered, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    store_closed = asyncio.Event()
    original_close = engine.store.close

    async def close_store():
        store_closed.set()
        await original_close()

    monkeypatch.setattr(engine.store, "close", close_store)

    async def sweep():
        async with engine.store.write() as session:
            await session.execute(insert(engine_meta).values(key="scheduler-cleanup", value={}))
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                await release.wait()

    engine._sweep = asyncio.create_task(sweep())
    await entered.wait()
    shutdown = asyncio.create_task(engine.shutdown())
    try:
        await asyncio.wait_for(cleaning.wait(), 1)
        await asyncio.sleep(0.05)
        assert not store_closed.is_set(), "storage was closed before scheduler rollback finished"
        assert not shutdown.done(), "engine released its profile while a scheduler write was still open"
        assert engine.settings.lock_path.exists()
    finally:
        release.set()
        await shutdown
        try:
            await engine._sweep
        except asyncio.CancelledError:
            pass
    restored = await Engine.create(make_settings(tmp_path))
    try:
        async with restored.store.read() as session:
            assert (await session.execute(select(engine_meta).where(
                engine_meta.c.key == "scheduler-cleanup"))).first() is None
    finally:
        await restored.shutdown()


async def test_cancelled_writer_finishes_sql_before_connection_teardown(store):
    import threading

    from sqlalchemy import event, text

    entered, release, finished, invalidated = (threading.Event() for _ in range(4))

    def pause():
        entered.set()
        release.wait(timeout=3)
        finished.set()
        return 1

    @event.listens_for(store.engine.sync_engine, "connect")
    def install_function(connection, _record):
        connection.create_function("redjohn_pause", 0, pause)

    @event.listens_for(store.engine.sync_engine, "invalidate")
    def on_invalidate(_connection, _record, _exception):
        if not finished.is_set():
            invalidated.set()

    async def writer():
        async with store.write() as session:
            await session.execute(text("INSERT INTO engine_meta (key, value) VALUES ('paused-write', '{}')"))
            await session.execute(text("SELECT redjohn_pause()"))

    task = asyncio.create_task(writer())
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        task.cancel()
        await asyncio.sleep(0.05)
        assert not invalidated.is_set(), "SQL was still running when cancellation invalidated its connection"
    finally:
        release.set()
        try:
            await task
        except asyncio.CancelledError:
            pass
    async with store.write() as session:
        assert (await session.execute(text(
            "SELECT value FROM engine_meta WHERE key='paused-write'"))).first() is None
        await session.execute(text("INSERT INTO engine_meta (key, value) VALUES ('next-write', '{}')"))


@pytest.mark.parametrize("outcome", ["success", "error"])
async def test_agent_deadline_during_memory_commit_is_terminal(engine, monkeypatch, outcome):
    from datetime import timedelta

    import redjohn_core.engine as module
    from redjohn_core.models import utcnow
    from redjohn_core.ov.protocol import MemoryUnavailable

    provider = MemoryProvider()
    client = provider.client()
    original = client.commit_session

    async def commit(*args, **kwargs):
        result = await original(*args, **kwargs)
        if outcome == "error":
            raise MemoryUnavailable("provider still processing")
        return result

    client.commit_session = commit
    monkeypatch.setattr(module, "safe_memory_store", lambda _: client)
    engine.settings.openviking_url = "http://fixture.invalid"
    engine.gateway = CompletingGateway()
    run = await make_run_in(engine.store, status=RunStatus.CREATED)
    await start_run(engine, run.run_id)
    await asyncio.wait_for(provider.accepted.wait(), 5)
    agent = (await engine.store.list_agents(run.run_id))[0]
    agent.time_budget_seconds = 1
    agent.created_at = utcnow() - timedelta(seconds=2)
    async with engine.store.write() as session:
        await engine.store.update_agent_row(session, agent)
    provider.finish.set()

    async def terminal():
        return (await engine.store.get_agent(agent.agent_id)).status in (
            AgentStatus.COMPLETE, AgentStatus.FAILED)

    await wait_for(terminal, timeout=1)
    assert (await engine.store.get_agent(agent.agent_id)).status == AgentStatus.FAILED
    assert (await engine.store.get_run(run.run_id)).status == RunStatus.FAILED


async def test_checkpoint_read_failure_never_starts_fresh_model_turn(engine, monkeypatch):
    gateway = CompletingGateway()
    engine.gateway = gateway
    original = engine.checkpointer.aget_tuple
    first = True

    async def transient_error(config):
        nonlocal first
        if first:
            first = False
            raise OSError("checkpoint storage temporarily unavailable")
        return await original(config)

    monkeypatch.setattr(engine.checkpointer, "aget_tuple", transient_error)
    run = await make_run_in(engine.store, status=RunStatus.CREATED)
    await start_run(engine, run.run_id)

    async def terminal():
        return (await engine.store.get_run(run.run_id)).status in (RunStatus.COMPLETED, RunStatus.FAILED)

    await wait_for(terminal)
    assert gateway.calls == []
    assert (await engine.store.get_run(run.run_id)).status == RunStatus.FAILED


async def test_hung_memory_commit_cannot_outlive_agent_deadline(engine, monkeypatch):
    import redjohn_core.engine as module

    provider = MemoryProvider()
    monkeypatch.setattr(module, "safe_memory_store", lambda _: provider.client())
    engine.settings.openviking_url = "http://fixture.invalid"
    engine.gateway = CompletingGateway()
    run = await make_run_in(engine.store)
    agent = Agent(run_id=run.run_id, name="coordinator", role=AgentRole.COORDINATOR,
                  task="finish", status=AgentStatus.RUNNING, allowed_tools=["builtin:*"],
                  time_budget_seconds=1)
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
    engine.spawn_agent(agent.agent_id)
    await asyncio.wait_for(provider.accepted.wait(), 1)

    async def failed():
        return (await engine.store.get_agent(agent.agent_id)).status == AgentStatus.FAILED

    await wait_for(failed, timeout=2)
    assert (await engine.store.get_run(run.run_id)).status == RunStatus.FAILED
    assert not provider.finish.is_set()


async def test_inbox_checkpoint_is_durable_before_ack_or_model(engine, monkeypatch):
    from redjohn_core.mailbox import post_message
    from redjohn_core.models import MessageStatus

    run = await make_run_in(engine.store)
    agent = Agent(run_id=run.run_id, name="receiver", task="read mail", status=AgentStatus.RUNNING,
                  allowed_tools=["builtin:*"])
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, agent)
    mail, _ = await post_message(engine.store, run, from_agent_id="user", to_agent_id=agent.agent_id,
                                 body="CHECKPOINT_BEFORE_ACK")
    gateway = CompletingGateway()
    engine.gateway = gateway
    ready, release = asyncio.Event(), asyncio.Event()
    original = engine.checkpointer.aput
    blocked = False

    async def delayed_put(config, checkpoint, metadata, versions):
        nonlocal blocked
        if not blocked and mail.message_id in checkpoint["channel_values"].get("pending_mail_ids", []):
            blocked = True
            ready.set()
            await release.wait()
        return await original(config, checkpoint, metadata, versions)

    monkeypatch.setattr(engine.checkpointer, "aput", delayed_put)
    engine.spawn_agent(agent.agent_id)
    await asyncio.wait_for(ready.wait(), 5)
    try:
        await asyncio.sleep(.05)
        assert (await engine.store.list_messages(run.run_id))[0].status == MessageStatus.QUEUED
        assert gateway.calls == []
    finally:
        release.set()
