"""Unit: supervisor delegation validation + capacity reservation atomics."""

from __future__ import annotations

import asyncio

import pytest
from redjohn_core import supervisor
from redjohn_core.errors import RJError
from redjohn_core.models import Agent, AgentLimits, AgentRole, AgentStatus, RunStatus
from redjohn_core.supervisor import DelegationRequest


def _req(parent_id: str, **over: object) -> DelegationRequest:
    base = {
        "parent_agent_id": parent_id,
        "name": "child",
        "task": "do something",
        "role": AgentRole.SPECIALIST,
        "allowed_targets": ("app.acme.test",),
        "allowed_tools": ("builtin:echo",),
    }
    base.update(over)
    return DelegationRequest(**base)  # type: ignore[arg-type]


async def _coordinator(store, run, *, tools=("builtin:*",)) -> Agent:
    coord = Agent(run_id=run.run_id, name="Coordinator", task=run.task,
                  role=AgentRole.COORDINATOR, status=AgentStatus.RUNNING, depth=0,
                  allowed_targets=list(run.scope.allowed_targets),
                  allowed_tools=list(tools))
    async with store.write() as s:
        await store.insert_agent(s, coord)
    return coord


async def test_scope_narrowing_rejected(store, run_factory) -> None:
    run = await run_factory(targets=["app.acme.test"])
    coord = await _coordinator(store, run)
    with pytest.raises(RJError) as exc:
        await supervisor.delegate(store, run, _req(
            coord.agent_id, allowed_targets=("evil.com",)))
    assert exc.value.code == "scope_violation"
    assert exc.value.status == 403


async def test_tool_narrowing_rejected(store, run_factory) -> None:
    run = await run_factory(tools=["builtin:echo"])
    coord = await _coordinator(store, run, tools=("builtin:echo",))
    with pytest.raises(RJError) as exc:
        await supervisor.delegate(store, run, _req(
            coord.agent_id, allowed_tools=("builtin:exec",)))
    assert exc.value.code == "scope_violation"


async def test_denied_tool_rejected(store, run_factory) -> None:
    run = await run_factory(tools=["builtin:*"], denied=["builtin:exec"])
    coord = await _coordinator(store, run)
    with pytest.raises(RJError) as exc:
        await supervisor.delegate(store, run, _req(
            coord.agent_id, allowed_tools=("builtin:exec",)))
    assert exc.value.code == "scope_violation"


async def test_depth_limit_enforced(store, run_factory) -> None:
    run = await run_factory(max_depth=1)
    coord = await _coordinator(store, run)
    child, _ = await supervisor.delegate(store, run, _req(coord.agent_id))
    assert child.depth == 1
    with pytest.raises(RJError) as exc:
        await supervisor.delegate(store, run, _req(child.agent_id, role=AgentRole.WORKER))
    assert exc.value.code == "scope_violation"  # depth clamp comes from scope.max_depth


async def test_workers_cannot_delegate(store, run_factory) -> None:
    run = await run_factory()
    coord = await _coordinator(store, run)
    worker, _ = await supervisor.delegate(store, run, _req(coord.agent_id, role=AgentRole.WORKER))
    with pytest.raises(RJError) as exc:
        await supervisor.delegate(store, run, _req(worker.agent_id))
    assert exc.value.code == "delegation_forbidden"


async def test_coordinator_role_rejected(store, run_factory) -> None:
    run = await run_factory()
    coord = await _coordinator(store, run)
    with pytest.raises(RJError) as exc:
        await supervisor.delegate(store, run, _req(coord.agent_id, role=AgentRole.COORDINATOR))
    assert exc.value.code == "unauthorized_agent_creation"


async def test_delegation_blocked_when_not_running(store, run_factory) -> None:
    run = await run_factory(status=RunStatus.STOPPING)
    coord = await _coordinator(store, run)
    with pytest.raises(RJError) as exc:
        await supervisor.delegate(store, run, _req(coord.agent_id))
    assert exc.value.code == "conflict"


@pytest.mark.parametrize("status", [RunStatus.STOPPING, RunStatus.STOPPED,
                                   RunStatus.COMPLETED, RunStatus.FAILED])
async def test_queued_delegation_rechecks_run_before_creating_child(store, run_factory, status):
    run = await run_factory()
    coord = await _coordinator(store, run)
    async with store.write() as session:
        pending = asyncio.create_task(supervisor.delegate(store, run, _req(coord.agent_id)))
        await asyncio.sleep(0)
        await store.update_run_row(session, run.model_copy(update={"status": status}))
    with pytest.raises(RJError) as exc:
        await asyncio.wait_for(pending, timeout=1)
    assert exc.value.code == "conflict"
    assert exc.value.details["run_status"] == status.value
    assert [agent.agent_id for agent in await store.list_agents(run.run_id)] == [coord.agent_id]


async def test_queued_promotion_rechecks_run_before_spawning(engine, monkeypatch):
    from .conftest import make_run_in

    run = await make_run_in(engine.store)
    coord = await _coordinator(engine.store, run)
    child = Agent(run_id=run.run_id, parent_agent_id=coord.agent_id, name="queued", task="test",
                  status=AgentStatus.QUEUED, depth=1)
    async with engine.store.write() as session:
        await engine.store.insert_agent(session, child)
    read = asyncio.Event()
    original_get_run = engine.store.get_run
    pending = None

    async def observing_get_run(run_id):
        saved = await original_get_run(run_id)
        if asyncio.current_task() is pending:
            read.set()
        return saved

    spawned = []
    monkeypatch.setattr(engine.store, "get_run", observing_get_run)
    monkeypatch.setattr(engine, "spawn_agent", lambda agent_id, **kwargs: spawned.append(agent_id))
    async with engine.store.write() as session:
        pending = asyncio.create_task(engine.promote(run.run_id))
        await asyncio.wait_for(read.wait(), timeout=1)
        await engine.store.update_run_row(session, run.model_copy(update={"status": RunStatus.STOPPING}))
    await asyncio.wait_for(pending, timeout=1)
    assert spawned == []
    assert (await engine.store.get_agent(child.agent_id)).status == AgentStatus.QUEUED


async def test_duplicate_delegation_returns_existing(store, run_factory) -> None:
    run = await run_factory()
    coord = await _coordinator(store, run)
    first, created1 = await supervisor.delegate(store, run, _req(coord.agent_id))
    second, created2 = await supervisor.delegate(store, run, _req(coord.agent_id))
    assert created1 and not created2
    assert first.agent_id == second.agent_id
    agents = await store.list_agents(run.run_id)
    assert len(agents) == 2  # coordinator + one child


async def test_total_capacity_cap(store, run_factory) -> None:
    run = await run_factory(max_agents=2, max_concurrent=10)
    coord = await _coordinator(store, run)
    await supervisor.delegate(store, run, _req(coord.agent_id, name="c1", task="t1"))
    with pytest.raises(RJError) as exc:
        await supervisor.delegate(store, run, _req(coord.agent_id, name="c2", task="t2"))
    assert exc.value.code == "conflict"


async def test_concurrency_slots_and_queueing(store, run_factory) -> None:
    run = await run_factory(limits=AgentLimits(max_concurrent_agents=2))
    coord = await _coordinator(store, run)  # occupies slot 1
    c1, _ = await supervisor.delegate(store, run, _req(coord.agent_id, name="c1", task="t1"))
    c2, _ = await supervisor.delegate(store, run, _req(coord.agent_id, name="c2", task="t2"))
    assert c1.status == AgentStatus.RUNNING   # took the last slot
    assert c2.status == AgentStatus.QUEUED    # capacity exhausted


async def test_waiting_parent_releases_last_slot(engine) -> None:
    """Last-slot rule: a WAITING parent must not consume the slot its child
    needs; the promotion scheduler hands the freed slot to the child."""
    from .conftest import make_run_in

    store = engine.store
    run = await make_run_in(store, limits=AgentLimits(max_concurrent_agents=2))
    coord = await _coordinator(store, run)
    parent, _ = await supervisor.delegate(store, run, _req(coord.agent_id, name="parent", task="pt"))
    assert parent.status == AgentStatus.RUNNING  # slots now 2/2

    # parent delegates -> child must queue (no free slot)
    child, _ = await supervisor.delegate(store, run, _req(parent.agent_id, name="child", task="ct",
                                                          role=AgentRole.WORKER))
    assert child.status == AgentStatus.QUEUED

    # parent waits -> releases its slot -> child promoted
    await supervisor.set_agent_status(store, run, parent, AgentStatus.WAITING,
                                      activity="waiting for child agents")
    await engine.promote(run.run_id)
    promoted = await store.get_agent(child.agent_id)
    assert promoted.status == AgentStatus.RUNNING

    # active count excludes WAITING agents
    async with store.read() as s:
        assert await store.count_active(s, run.run_id) == 2  # coordinator + child


async def test_cidr_and_wildcard_scope_matching() -> None:
    from redjohn_core.scope import target_covered

    assert target_covered("10.0.0.5", ["10.0.0.0/8"])
    assert not target_covered("192.168.1.5", ["10.0.0.0/8"])
    assert target_covered("api.app.acme.test", ["*.acme.test"])
    assert target_covered("acme.test", ["*.acme.test"])
    assert target_covered("https://app.acme.test/login", ["app.acme.test"])
    assert not target_covered("app.acme.test.evil.com", ["*.acme.test"])
    assert target_covered("anything", ["*"])
    assert not target_covered("x", [])
