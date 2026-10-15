"""Supervisor: server-side validated agent delegation + capacity accounting.

Every delegation — whether from the API or from an agent's ``builtin:delegate``
call — goes through :func:`delegate`, which enforces, atomically (inside one
``Store.write`` transaction):

* run is accepting delegations (RUNNING; stopping/stopped runs reject)
* parent belongs to the run and is not terminal; workers never delegate;
  coordinators are only spawned by the run manager at start
* depth: ``parent.depth + 1 <= min(limits.max_delegation_depth, scope.max_depth)``
* scope narrowing: child targets ⊆ parent targets; child tools ⊆ parent tools,
  minus scope ``denied_tools``
* totals: ``total_agents < min(limits.max_total_agents, scope.max_agents)``
* concurrency: child starts RUNNING when a slot is free, else QUEUED.
  Slots are consumed by RUNNING agents only — a WAITING parent releases its
  slot, so a waiting parent can never consume the last slot its child needs
  (the promotion scheduler in runs.py moves QUEUED -> RUNNING when slots free).
* duplicate delegation: identical (parent, task, targets, tools) returns the
  existing child instead of consuming capacity again.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from .db import Store
from .errors import conflict, forbidden, not_found, scope_violation
from .events import EventType
from .models import (
    Agent,
    AgentRole,
    AgentStatus,
    Run,
    RunStatus,
    ScopePolicy,
)

TERMINAL_AGENT_STATES = {AgentStatus.COMPLETE, AgentStatus.FAILED, AgentStatus.STOPPED}


@dataclass(frozen=True)
class DelegationRequest:
    parent_agent_id: str
    name: str
    task: str
    role: AgentRole = AgentRole.SPECIALIST
    allowed_targets: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()


def delegation_hash(parent_id: str, req: DelegationRequest) -> str:
    return hashlib.sha256(json.dumps(
        {
            "parent": parent_id,
            "name": req.name,
            "role": req.role.value,
            "task": req.task,
            "targets": sorted(req.allowed_targets),
            "tools": sorted(req.allowed_tools),
        },
        sort_keys=True,
    ).encode()).hexdigest()


def effective_limits(run: Run) -> tuple[int, int, int]:
    """(max_total, max_concurrent, max_depth): limits clamped by pinned scope."""
    scope: ScopePolicy = run.scope
    return (
        min(run.limits.max_total_agents, scope.max_agents),
        min(run.limits.max_concurrent_agents, scope.max_concurrent_agents),
        min(run.limits.max_delegation_depth, scope.max_depth),
    )


async def delegate(store: Store, run: Run, req: DelegationRequest) -> tuple[Agent, bool]:
    """Validate + create a child agent. Returns (agent, created_new)."""
    from .scope import targets_subset, tools_subset  # local: avoid import cycle

    async with store.write() as s:
        # The supplied snapshot may predate a stop/archive request. Validate
        # the authoritative status while holding the same transaction lock
        # used to insert the child, closing the STOPPING/delegation race.
        run = await store.get_run(run.run_id)
        if run.status != RunStatus.RUNNING:
            raise conflict(
                f"run {run.run_id} is {run.status.value}; delegation is only open while running",
                {"run_status": run.status.value},
            )
        parent_row = await _agent_in_session(store, s, req.parent_agent_id)
        if parent_row.run_id != run.run_id:
            raise not_found("agent", req.parent_agent_id)
        if parent_row.status in TERMINAL_AGENT_STATES:
            raise conflict(f"parent agent is {parent_row.status.value}; cannot delegate",
                           {"parent_status": parent_row.status.value})
        if parent_row.role == AgentRole.WORKER:
            raise forbidden("workers may not delegate", code="delegation_forbidden")
        if req.role == AgentRole.COORDINATOR:
            raise forbidden(
                "coordinator agents are created by the run manager only",
                code="unauthorized_agent_creation",
            )

        max_total, max_concurrent, max_depth = effective_limits(run)
        depth = parent_row.depth + 1
        if depth > max_depth:
            raise scope_violation(
                f"delegation depth {depth} exceeds limit {max_depth}",
                {"depth": depth, "max_depth": max_depth},
            )

        targets = list(req.allowed_targets) or list(parent_row.allowed_targets)
        tools = list(req.allowed_tools) or list(parent_row.allowed_tools)

        bad_targets = targets_subset(targets, parent_row.allowed_targets)
        if bad_targets:
            raise scope_violation(
                "child targets escape parent scope",
                {"rejected_targets": bad_targets, "parent_targets": parent_row.allowed_targets},
            )
        bad_tools = tools_subset(tools, parent_row.allowed_tools)
        if bad_tools:
            raise scope_violation(
                "child tools escape parent tool set",
                {"rejected_tools": bad_tools, "parent_tools": parent_row.allowed_tools},
            )
        denied = [t for t in tools if t in run.scope.denied_tools]
        if denied:
            raise scope_violation("child tools denied by scope policy", {"denied": denied})

        # duplicate / repeated delegation -> return the existing child
        dhash = delegation_hash(req.parent_agent_id, req)
        existing = await store.find_delegation(s, run.run_id, req.parent_agent_id, dhash)
        if existing is not None:
            return existing, False

        total = await store.count_agents(s, run.run_id)
        if total >= max_total:
            raise conflict(
                f"run agent budget exhausted ({total}/{max_total})",
                {"total_agents": total, "max_total_agents": max_total},
            )

        active = await store.count_active(s, run.run_id)
        status = AgentStatus.RUNNING if active < max_concurrent else AgentStatus.QUEUED

        child = Agent(
            run_id=run.run_id,
            parent_agent_id=req.parent_agent_id,
            role=req.role,
            name=req.name,
            task=req.task,
            status=status,
            depth=depth,
            allowed_targets=targets,
            allowed_tools=tools,
            time_budget_seconds=parent_row.time_budget_seconds,
            token_budget=parent_row.token_budget,
            current_activity="queued for capacity" if status == AgentStatus.QUEUED else "starting",
        )
        await store.insert_agent(s, child, dhash)
        await store.emit_simple(s, run, EventType.AGENT_STATUS, {
            "agent_id": child.agent_id,
            "parent_agent_id": child.parent_agent_id,
            "role": child.role.value,
            "name": child.name,
            "status": child.status.value,
            "depth": child.depth,
        }, agent_id=child.agent_id)
        return child, True


async def _agent_in_session(store: Store, session: AsyncSession, agent_id: str) -> Agent:
    return await store.get_agent_session(session, agent_id)


async def set_agent_status(
    store: Store,
    run: Run,
    agent: Agent,
    status: AgentStatus,
    *,
    activity: str | None = None,
    session: AsyncSession | None = None,
) -> Agent:
    """Status transition + agent.status event (caller owns the transaction
    when ``session`` is given)."""
    agent.status = status
    if activity is not None:
        agent.current_activity = activity
    if status in TERMINAL_AGENT_STATES and agent.finished_at is None:
        from .models import utcnow

        agent.finished_at = utcnow()

    data = {
        "agent_id": agent.agent_id,
        "parent_agent_id": agent.parent_agent_id,
        "role": agent.role.value,
        "name": agent.name,
        "status": agent.status.value,
        "depth": agent.depth,
        "activity": agent.current_activity,
    }

    if session is not None:
        await store.update_agent_row(session, agent)
        await store.emit_simple(session, run, EventType.AGENT_STATUS, data, agent_id=agent.agent_id)
    else:
        async with store.write() as s:
            await store.update_agent_row(s, agent)
            await store.emit_simple(s, run, EventType.AGENT_STATUS, data, agent_id=agent.agent_id)
    return agent
