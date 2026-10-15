"""Engine assembly: storage, hub, gateway, tools, MCP, scheduler, runners.

One Engine serves one data profile (enforced by the profile lock). Background
tasks: outbox relay (hub), capacity/waiter sweep. All concurrency is asyncio;
writes are serialized through ``Store.write``.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

import aiosqlite

from . import agents as agent_mod
from . import mailbox, supervisor
from .db import Store
from .errors import RJError
from .events import EventType
from .hub import Hub
from .locking import ProfileLock, acquire_profile_lock
from .logging import get_logger
from .mcp_manager import MCPManager
from .migrate import migrate
from .model_gateway import ModelGateway, ToolSpec, gateway_from_settings
from .models import (
    Agent,
    AgentRole,
    AgentStatus,
    Run,
    RunStatus,
    ServiceState,
    ServiceStatus,
    utcnow,
)
from .ov import MemoryUnavailable
from .ovsafe import safe_memory_store
from .settings import Settings
from .supervisor import TERMINAL_AGENT_STATES, DelegationRequest
from .tools import BUILTIN_TOOL_SPECS, ToolRunner


class _StopTurn(Exception):
    """Run/agent stopped while waiting for a dependency; end the graph turn."""


# Local-memory bootstrap retry budget. OpenViking is a local server with no
# model download, so a few short retries cover transient readiness; we never
# loop forever (that produced the perpetual "memory syncing" state).
MEMORY_BOOTSTRAP_ATTEMPTS = 6
MEMORY_BOOTSTRAP_RETRY_SECONDS = 5


class Engine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store: Store = None  # type: ignore[assignment]
        self.hub: Hub = None  # type: ignore[assignment]
        self.gateway: ModelGateway = None  # type: ignore[assignment]
        self.tool_runner: ToolRunner = None  # type: ignore[assignment]
        self.mcp_manager: MCPManager = None  # type: ignore[assignment]
        self.checkpointer: Any = None
        self._ckpt_conn: aiosqlite.Connection | None = None
        self._graph: Any = None
        self._runners: dict[str, asyncio.Task[None]] = {}
        self._sweep: asyncio.Task[None] | None = None
        self._lock: ProfileLock | None = None
        self._services: dict[str, ServiceStatus] = {}
        self._memory_client: Any = None
        self._memory_identity: tuple[Any, ...] | None = None
        self._memory_lock = asyncio.Lock()
        self.configuration_lock = asyncio.Lock()
        self._codex_auth: Any = None
        self._memory_bootstrap: asyncio.Task[None] | None = None
        self._managed_memory: Any = None
        self._memory_startup_status: ServiceStatus | None = None
        self._auto_memory_enabled = False
        self.token: str = ""
        self.started_at = utcnow()
        self._log = get_logger("engine")

    # -------------------------------------------------------------- lifecycle
    @classmethod
    async def create(
        cls, settings: Settings, *, with_lock: bool = True, auto_memory: bool = False
    ) -> Engine:
        from .logging import configure_logging

        configure_logging(settings.log_level)
        settings.ensure_dirs()
        engine = cls(settings)
        engine.token = settings.load_or_create_token()
        if with_lock:
            engine._lock = acquire_profile_lock(
                settings.lock_path, port=settings.port, token=engine.token
            )
        try:
            # Boot storage with retry on transient SQLite locks: a previous
            # engine process may still be draining its final transactions.
            for attempt in range(5):
                try:
                    await migrate(settings.db_path)
                    engine.store = Store.open(settings.db_url)
                    async with engine.store.write() as s:
                        await engine.store.ensure_default_workspace(s)
                    # durable checkpointer
                    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

                    engine._ckpt_conn = await aiosqlite.connect(str(settings.checkpoints_path))
                    engine.checkpointer = AsyncSqliteSaver(engine._ckpt_conn)
                    await engine.checkpointer.setup()
                    # restart maintenance: stale invocations -> unknown (never re-run)
                    stale = await engine.store.mark_started_invocations_unknown()
                    break
                except Exception as exc:
                    if "locked" not in str(exc) or attempt == 4:
                        raise
                    if engine.store is not None:
                        await engine.store.close()
                        engine.store = None  # type: ignore[assignment]
                    if engine._ckpt_conn is not None:
                        await engine._ckpt_conn.close()
                        engine._ckpt_conn = None
                    await asyncio.sleep(0.3)
            if stale:
                engine._log.warning("marked stale invocations unknown",
                                    extra={"count": len(stale)})

            engine.hub = Hub(
                engine.store,
                queue_size=settings.ws_queue_size,
                idle_sleep=settings.relay_idle_sleep,
            )
            engine.gateway = gateway_from_settings(settings)
            engine.mcp_manager = MCPManager(engine.store, settings)
            engine.tool_runner = ToolRunner(
                engine.store, settings,
                mcp_manager=engine.mcp_manager,
                delegate_hook=engine._delegate_hook,
                message_hook=engine._message_hook,
                memory_hook=engine.memory_store_or_wait,
            )
            engine._graph = agent_mod.build_agent_graph(engine)
            await engine.skill_registry.register(engine.store)
            await engine.mcp_manager.register_defaults()

            engine.set_service("api", ServiceState.LIVE, "engine up")
            engine.hub.start()
            engine._sweep = asyncio.create_task(engine._sweep_loop(), name="scheduler-sweep")
            if auto_memory:
                engine.start_memory_bootstrap()
            await engine._resume_after_restart()
        except Exception:
            if engine._lock:
                engine._lock.release()
            raise
        return engine

    async def shutdown(self) -> None:
        for task in list(self._runners.values()):
            task.cancel()
        await self.cancel_memory_bootstrap()
        if self._sweep:
            self._sweep.cancel()
            # Scheduler cancellation may still be rolling back a write. Finish
            # it before closing storage or allowing the next profile owner in.
            try:
                await self._sweep
            except asyncio.CancelledError:
                pass
        for task in list(self._runners.values()):
            task.cancel()
        for task in list(self._runners.values()):
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await self.mcp_manager.shutdown()
        if self._codex_auth is not None:
            await self._codex_auth.close()
        if self._memory_client is not None and hasattr(self._memory_client, "close"):
            await self._memory_client.close()
        if self._managed_memory is not None:
            await self._managed_memory.stop()
        await self.hub.stop()
        if self._ckpt_conn:
            await self._ckpt_conn.close()
        await self.store.close()
        if self._lock:
            self._lock.release()
            self._lock = None

    # ------------------------------------------------------------- services
    def set_service(
        self, name: str, state: ServiceState, detail: str = "", latency_ms: int | None = None
    ) -> None:
        self._services[name] = ServiceStatus(
            service=name, state=state, detail=detail, latency_ms=latency_ms,
        )

    async def set_activity(
        self,
        agent: Agent,
        run: Run,
        activity: str,
        *,
        message: str | None = None,
        kind: str | None = None,
        internal: bool = False,
    ) -> None:
        payload: dict[str, Any] = {"agent_id": agent.agent_id, "activity": activity}
        if message is not None:
            payload["message"] = message
        if kind is not None:
            payload["kind"] = kind
        if internal:
            payload["internal"] = True
        async with self.store.write() as s:
            if not internal:
                agent.current_activity = activity
                await self.store.update_agent_row(s, agent)
            await self.store.emit_simple(
                s, run, EventType.AGENT_ACTIVITY, payload, agent_id=agent.agent_id
            )

    def service_snapshot(self) -> list[ServiceStatus]:
        return list(self._services.values())

    async def openviking_status(self) -> ServiceStatus:
        if self._memory_startup_status is not None:
            return self._memory_startup_status
        if not self.settings.openviking_url:
            return ServiceStatus(service="openviking", state=ServiceState.NOT_CONFIGURED,
                                 detail="openviking_url not set")
        try:
            store = await self._memory()
            status = await asyncio.wait_for(store.status(), timeout=5.0)
            status.service = "openviking"
            return status
        except MemoryUnavailable as exc:
            return ServiceStatus(service="openviking", state=ServiceState.DOWN, detail=str(exc))
        except Exception as exc:
            return ServiceStatus(service="openviking", state=ServiceState.DOWN,
                                 detail=str(exc)[:300])

    def start_memory_bootstrap(self) -> None:
        self._auto_memory_enabled = True
        if self._memory_bootstrap is not None and not self._memory_bootstrap.done():
            return
        self._memory_startup_status = ServiceStatus(
            service="openviking", state=ServiceState.STARTING, detail="Preparing local memory"
        )
        self._memory_bootstrap = asyncio.create_task(
            self._bootstrap_memory(), name="local-memory-bootstrap"
        )

    async def cancel_memory_bootstrap(self) -> None:
        task = self._memory_bootstrap
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._memory_bootstrap = None
        self._memory_startup_status = None

    async def _bootstrap_memory(self) -> None:
        from .managed_memory import ManagedMemoryRuntime

        def progress(detail: str) -> None:
            self._memory_startup_status = ServiceStatus(
                service="openviking", state=ServiceState.STARTING, detail=detail
            )

        if self._managed_memory is None:
            self._managed_memory = ManagedMemoryRuntime(self.settings, progress)
        else:
            self._managed_memory.progress = progress
        # Bounded retry: OpenViking is a local server (no model download), so a
        # few short retries cover transient readiness. Looping forever would
        # pin the UI at a perpetual "syncing" spinner on a real failure, so we
        # stop and leave the last DOWN/not-live status for the user to see.
        for attempt in range(MEMORY_BOOTSTRAP_ATTEMPTS):
            try:
                self._managed_memory.settings = self.settings
                started = await self._managed_memory.start()
                if not started and not self.settings.openviking_url:
                    self._memory_startup_status = None
                    return
                # Configuration changed during initial provisioning. Replace
                # any cached adapter before the authenticated readiness check.
                async with self._memory_lock:
                    if self._memory_client is not None:
                        await self._memory_client.close()
                    self._memory_client = None
                    self._memory_identity = None
                self._memory_startup_status = None
                status = await self.openviking_status()
                if status.state == ServiceState.LIVE:
                    return
                self._memory_startup_status = status
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                detail = str(exc) if isinstance(exc, RJError) else (
                    f"Local memory initialization failed ({type(exc).__name__}); "
                    "check the local service logs and retry."
                )
                self._memory_startup_status = ServiceStatus(
                    service="openviking", state=ServiceState.DOWN, detail=detail
                )
            if attempt + 1 < MEMORY_BOOTSTRAP_ATTEMPTS:
                await asyncio.sleep(MEMORY_BOOTSTRAP_RETRY_SECONDS)

    # --------------------------------------------------------- agent running
    def spawn_agent(self, agent_id: str, input_: dict[str, Any] | str | None = "auto") -> None:
        if self.store.defer_after_commit(lambda: self.spawn_agent(agent_id, input_)):
            return
        existing = self._runners.get(agent_id)
        if existing and not existing.done():
            return
        self._runners[agent_id] = asyncio.create_task(
            self._run_agent(agent_id, input_), name=f"agent:{agent_id}"
        )

    async def _resolve_input(self, agent_id: str) -> dict[str, Any] | None:
        """"auto" spawn: resume from checkpoint when one exists, otherwise
        build the initial conversation input."""
        config = {"configurable": {"thread_id": agent_id},
                  "recursion_limit": self.settings.max_agent_steps * 4 + 16}
        # A failed read is not an absent checkpoint: starting fresh could repeat
        # model calls and replace a conversation whose durable state is unknown.
        tup = await self.checkpointer.aget_tuple(config)
        if tup is not None:
            return None
        agent = await self.store.get_agent(agent_id)
        run = await self.store.get_run(agent.run_id)
        return agent_mod.initial_input(agent, run)

    async def _run_agent(self, agent_id: str, input_: dict[str, Any] | str | None) -> None:
        config = {"configurable": {"thread_id": agent_id},
                  "recursion_limit": self.settings.max_agent_steps * 4 + 16}
        state: dict[str, Any] = {}
        try:
            if input_ == "auto":
                input_ = await self._resolve_input(agent_id)
            # Inbox ACKs and memory/model side effects in the next node depend
            # on the previous node's exact message IDs already being on disk.
            state = await self._graph.ainvoke(input_, config, durability="sync")
        except _StopTurn:
            state = {}
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._log.error("agent loop crashed", extra={"agent_id": agent_id, "error": str(exc)})
            state = {"failed": f"agent loop error: {exc}"}
        try:
            try:
                await self.finalize_agent(agent_id, state or {})
            except _StopTurn:
                return
            except Exception as exc:
                self._log.error("agent finalize failed", extra={"agent_id": agent_id, "error": str(exc)})
                # Do not strand a live agent with no runner after a finalization
                # error. Storage failures may still prevent recording the failure.
                await self.finalize_agent(agent_id, {"failed": f"agent finalize error: {exc}"})
        finally:
            try:
                agent_row = await self.store.get_agent(agent_id)
                run = await self.store.get_run(agent_row.run_id)
                if run.status in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.STOPPED):
                    # Finalization's transaction has committed before any external
                    # browser/repository process is torn down.
                    await self.mcp_manager.close_run(run.run_id)
            except Exception:
                pass

    async def finalize_agent(self, agent_id: str, state: dict[str, Any]) -> None:
        from .budgets import check_time

        agent = await self.store.get_agent(agent_id)
        run = await self.store.get_run(agent.run_id)
        if agent.status in TERMINAL_AGENT_STATES:
            return
        # Never hold the database write lock while the external extractor runs.
        if state.get("complete") and not state.get("failed") and run.status == RunStatus.RUNNING:
            try:
                await self.sync_memory_messages(agent, run, state.get("messages", []))
                await self._commit_memory_session(agent)
            except _StopTurn:
                pass  # Re-read the stopped state under the lock below.
            except Exception as exc:
                state = {"failed": f"memory finalization error: {exc}"}

        # Agent terminal state, parent result and coordinator run terminal state
        # are one commit. A crash at any await rolls all of them back, leaving
        # the completed graph checkpoint resumable on the next engine boot.
        async with self.store.write() as s:
            agent = await self.store.get_agent(agent_id)
            run = await self.store.get_run(agent.run_id)
            if agent.status in TERMINAL_AGENT_STATES:
                return
            if run.status != RunStatus.RUNNING:
                await supervisor.set_agent_status(self.store, run, agent, AgentStatus.STOPPED,
                                                  activity="run stopped", session=s)
                return
            if state.get("complete") and not state.get("failed"):
                try:
                    check_time(run, agent)
                except RJError as exc:
                    state = {"failed": str(exc)}
            if state.get("failed"):
                await supervisor.set_agent_status(self.store, run, agent, AgentStatus.FAILED,
                                                  activity=state["failed"], session=s)
                await self._on_agent_terminal(run, agent)
                return
            if state.get("complete"):
                summary = state.get("last_summary") or ""
                await supervisor.set_agent_status(self.store, run, agent, AgentStatus.COMPLETE,
                                                  activity=summary[:200], session=s)
                if agent.parent_agent_id:
                    await mailbox.post_message(
                        self.store, run, from_agent_id=agent.agent_id,
                        to_agent_id=agent.parent_agent_id, body=summary or "(no summary)",
                        kind="result", summary_ref=summary[:500] or None,
                        evidence_refs=list(state.get("evidence_refs", [])),
                        idempotency_key=f"final-result:{agent.agent_id}",
                    )
                    await self.wake_agent(agent.parent_agent_id, "child result delivered")
                await self._on_agent_terminal(run, agent)
                return
            if state.get("wait_children"):
                await supervisor.set_agent_status(self.store, run, agent, AgentStatus.WAITING,
                                                  activity="waiting for child agents", session=s)
                return
            # idle: graph ended without tool calls — stays RUNNING, wakes on mail
            agent.current_activity = "idle — awaiting mailbox"
            await self.store.update_agent_row(s, agent)

    async def _on_agent_terminal(self, run: Run, agent: Agent) -> None:
        if agent.role == AgentRole.COORDINATOR and run.status == RunStatus.RUNNING:
            final = RunStatus.COMPLETED if agent.status == AgentStatus.COMPLETE else RunStatus.FAILED
            async with self.store.write() as s:
                run.status = final
                run.finished_at = utcnow()
                await self.store.update_run_row(s, run)
                await self.store.emit_simple(s, run, EventType.RUN_STATUS, {
                    "run_id": run.run_id, "status": final.value,
                })
        await self.promote(run.run_id)

    # ------------------------------------------------------------- scheduler
    async def promote(self, run_id: str) -> None:
        """Move QUEUED agents to RUNNING while slots are free; reactivate
        WAITING parents whose children all reached a terminal state."""
        try:
            run = await self.store.get_run(run_id)
        except RJError:
            return
        if run.status != RunStatus.RUNNING:
            return
        async with self.store.read() as rs:
            snapshot_agents = await self._agents_in_session(rs, run_id)
        has_candidates = any(
            a.status == AgentStatus.QUEUED
            or (a.status == AgentStatus.WAITING and a.current_activity == "waiting for child agents")
            for a in snapshot_agents
        )
        if not has_candidates:
            return
        async with self.store.write() as s:
            # A stop may have committed while this sweep waited for SQLite.
            # Decisions about scheduling must use the state under the lock.
            run = await self.store.get_run(run_id)
            if run.status != RunStatus.RUNNING:
                return
            _, max_concurrent, _ = supervisor.effective_limits(run)
            promoted: list[Agent] = []
            active = await self.store.count_active(s, run_id)
            all_agents = await self._agents_in_session(s, run_id)
            queued = [a for a in all_agents if a.status == AgentStatus.QUEUED]
            for agent in queued:
                if active >= max_concurrent:
                    break
                agent.status = AgentStatus.RUNNING
                agent.current_activity = "starting"
                await self.store.update_agent_row(s, agent)
                await self.store.emit_simple(s, run, EventType.AGENT_STATUS, {
                    "agent_id": agent.agent_id, "parent_agent_id": agent.parent_agent_id,
                    "role": agent.role.value, "name": agent.name,
                    "status": agent.status.value, "depth": agent.depth,
                }, agent_id=agent.agent_id)
                active += 1
                promoted.append(agent)

            children_by_parent: dict[str, list[Agent]] = {}
            for a in all_agents:
                if a.parent_agent_id:
                    children_by_parent.setdefault(a.parent_agent_id, []).append(a)

            wake_parents: list[Agent] = []
            for agent in all_agents:
                if agent.status != AgentStatus.WAITING:
                    continue
                if agent.current_activity != "waiting for child agents":
                    continue
                children = children_by_parent.get(agent.agent_id, [])
                if children and all(c.status in TERMINAL_AGENT_STATES for c in children):
                    # A reactivated parent becomes a RUNNING slot consumer, so it
                    # must respect max_concurrent like QUEUED promotion does; the
                    # sweep loop retries once a slot frees.
                    if active >= max_concurrent:
                        break
                    agent.status = AgentStatus.RUNNING
                    agent.current_activity = "children finished"
                    await self.store.update_agent_row(s, agent)
                    await self.store.emit_simple(s, run, EventType.AGENT_STATUS, {
                        "agent_id": agent.agent_id, "parent_agent_id": agent.parent_agent_id,
                        "role": agent.role.value, "name": agent.name,
                        "status": agent.status.value, "depth": agent.depth,
                    }, agent_id=agent.agent_id)
                    active += 1
                    wake_parents.append(agent)

        for agent in promoted:
            self.spawn_agent(agent.agent_id)  # fresh start: checkpoint absent -> initial input?
        for parent in wake_parents:
            await self.wake_agent(parent.agent_id, "all child agents finished")

    async def _agents_in_session(self, s: Any, run_id: str) -> list[Agent]:
        from sqlalchemy import select

        from .db import _from
        from .db import agents as agents_table

        rows = (await s.execute(
            select(agents_table.c.data)
            .where(agents_table.c.run_id == run_id)
            .order_by(agents_table.c.created_at, agents_table.c.agent_id)
        )).all()
        return [_from(Agent, r.data) for r in rows]

    async def wake_agent(self, agent_id: str, reason: str) -> None:
        """Re-invoke an idle RUNNING agent's graph (new mailbox delivery etc.)."""
        try:
            agent = await self.store.get_agent(agent_id)
        except RJError:
            return
        if agent.status != AgentStatus.RUNNING:
            return
        task = self._runners.get(agent_id)
        if task and not task.done():
            return  # loop is live; it will read the inbox itself
        from langchain_core.messages import HumanMessage

        self.spawn_agent(agent_id, {
            "messages": [HumanMessage(content=f"[system] {reason}")],
            "done": False,
        })

    async def _sweep_loop(self) -> None:
        """Periodic safety net for capacity promotion and waiter reactivation."""
        while True:
            await asyncio.sleep(0.25)
            try:
                async with self.store.read() as s:
                    from sqlalchemy import select

                    from .db import runs as runs_table

                    rows = (await s.execute(
                        select(runs_table.c.run_id)
                        .where(runs_table.c.status == RunStatus.RUNNING.value)
                    )).all()
                for row in rows:
                    from .budgets import remaining_seconds

                    run = await self.store.get_run(row.run_id)
                    remaining = remaining_seconds(run)
                    if remaining is not None and remaining <= 0:
                        from .runs import stop_run

                        await stop_run(self, row.run_id)
                        continue
                    await self.promote(row.run_id)
                    await self._wake_pending_inbox(row.run_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._log.error("sweep error", extra={"error": str(exc)})

    async def _wake_pending_inbox(self, run_id: str) -> None:
        """Safety net for the final-turn delivery race: a message posted to an
        agent while it is finishing its last tool-less turn would otherwise sit
        QUEUED with no live runner to read it. Wake any RUNNING agent that has
        pending inbox messages and no live runner task (wake_agent no-ops when a
        runner is already live)."""
        from .mailbox import pending_inbox

        for agent in await self.store.list_agents(run_id):
            if agent.status != AgentStatus.RUNNING:
                continue
            task = self._runners.get(agent.agent_id)
            if task and not task.done():
                continue
            if await pending_inbox(self.store, agent.agent_id):
                await self.wake_agent(agent.agent_id, "inbox message pending")

    # ---------------------------------------------------------------- memory
    async def _memory(self) -> Any:
        identity = (self.settings.openviking_url, self.settings.openviking_api_key,
                    self.settings.openviking_account, self.settings.openviking_user,
                    self.settings.openviking_actor_peer, self.settings.openviking_processing_mode,
                    self.settings.openviking_timeout)
        async with self._memory_lock:
            if self._memory_client is None or identity != self._memory_identity:
                if self._memory_client is not None and hasattr(self._memory_client, "close"):
                    await self._memory_client.close()
                self._memory_client = safe_memory_store(self.settings)
                self._memory_identity = identity
            return self._memory_client

    async def ensure_memory_session(self, agent: Agent, run: Run) -> None:
        """Create an agent memory session, waiting visibly for provisioning."""
        # Fresh desktop profiles must not run without memory while their first
        # automatic configuration/download is still in progress. Run stop and
        # time budgets remain effective during this wait.
        while self._memory_bootstrap is not None and not self._memory_bootstrap.done():
            run, agent, _ = await self._memory_context(agent.agent_id)
            detail = (
                self._memory_startup_status.detail
                if self._memory_startup_status else "Preparing local memory"
            )
            await self.set_activity(agent, run, f"waiting for OpenViking memory ({detail})")
            await asyncio.sleep(self.settings.ov_retry_seconds)
        if not self.settings.openviking_url or agent.ov_session_uri:
            return
        while True:
            try:
                store = await self._memory()
                uri = await store.create_session(session_id=agent.agent_id)
            except Exception as exc:
                await supervisor.set_agent_status(
                    self.store, run, agent, AgentStatus.WAITING,
                    activity=f"waiting for OpenViking memory ({exc})",
                )
                await asyncio.sleep(self.settings.ov_retry_seconds)
                agent = await self.store.get_agent(agent.agent_id)
                run = await self.store.get_run(agent.run_id)
                if run.status in (RunStatus.STOPPING, RunStatus.STOPPED) or (
                    agent.status in TERMINAL_AGENT_STATES
                ):
                    raise _StopTurn from None
                continue
            async with self.store.write() as s:
                agent.ov_session_uri = uri
                if agent.status == AgentStatus.WAITING:
                    agent.status = AgentStatus.RUNNING
                await self.store.update_agent_row(s, agent)
                await self.store.emit_simple(s, run, EventType.AGENT_ACTIVITY, {
                    "agent_id": agent.agent_id, "activity": "memory session created",
                    "ov_session_uri": uri, "internal": True,
                }, agent_id=agent.agent_id)
            return

    async def memory_store_or_wait(self, agent: Agent, run: Run) -> Any:
        """Memory hook for memory-dependent tool steps: visible waiting state,
        never a fake success."""
        while True:
            try:
                return await self._memory()
            except MemoryUnavailable as exc:
                await supervisor.set_agent_status(
                    self.store, run, agent, AgentStatus.WAITING,
                    activity=f"waiting for OpenViking memory ({exc})",
                )
                await asyncio.sleep(self.settings.ov_retry_seconds)
                agent = await self.store.get_agent(agent.agent_id)
                run = await self.store.get_run(agent.run_id)
                if run.status in (RunStatus.STOPPING, RunStatus.STOPPED) or (
                    agent.status in TERMINAL_AGENT_STATES
                ):
                    raise _StopTurn from None

    async def sync_memory_messages(self, agent: Agent, run: Run, messages: list[Any]) -> None:
        """Publish checkpointed messages with stable IDs and durable acknowledgements."""
        if not self.settings.openviking_url:
            return
        await self.ensure_memory_session(agent, run)
        agent = await self.store.get_agent(agent.agent_id)
        async with self.store.read() as session:
            synced = await self.store.synced_memory_message_ids(session, run.run_id, agent.agent_id)
        for index, message in enumerate(messages):
            role = {"AIMessage": "assistant", "HumanMessage": "user", "ToolMessage": "user"}.get(
                type(message).__name__)
            if role is None:
                continue
            content = str(message.content)
            if getattr(message, "tool_calls", None):
                import json

                content += "\n[tool calls] " + json.dumps(message.tool_calls)
            if not content:
                continue
            key = str(message.id or hashlib.sha256(
                f"{agent.agent_id}:{index}:{content}".encode()).hexdigest())
            if key in synced:
                continue
            while True:
                try:
                    memory = await self._memory()
                    await memory.add_message(agent.ov_session_uri, role, content, message_id=key)
                    break
                except Exception as exc:
                    await self._wait_for_memory(agent, run, exc)
            async with self.store.write() as session:
                await self.store.emit_simple(session, run, EventType.AGENT_ACTIVITY, {
                    "activity": "memory message synchronized", "memory_message_id": key,
                    "internal": True,
                }, agent_id=agent.agent_id)
        current = await self.store.get_agent(agent.agent_id)
        if (current.status == AgentStatus.WAITING
                and current.current_activity.startswith("waiting for OpenViking")):
            await supervisor.set_agent_status(self.store, run, current, AgentStatus.RUNNING,
                                              activity="running")

    async def _wait_for_memory(self, agent: Agent, run: Run, exc: Exception) -> None:
        async with self.store.write() as session:
            current, agent, remaining = await self._memory_context(agent.agent_id)
            await supervisor.set_agent_status(self.store, current, agent, AgentStatus.WAITING,
                                              activity=f"waiting for OpenViking memory ({exc})",
                                              session=session)
        delay = self.settings.ov_retry_seconds
        await asyncio.sleep(min(delay, remaining) if remaining is not None else delay)

    async def _memory_context(self, agent_id: str) -> tuple[Run, Agent, float | None]:
        from .budgets import check_time

        agent = await self.store.get_agent(agent_id)
        run = await self.store.get_run(agent.run_id)
        if run.status != RunStatus.RUNNING or agent.status in TERMINAL_AGENT_STATES:
            raise _StopTurn
        return run, agent, check_time(run, agent)

    async def _commit_memory_session(self, agent: Agent) -> None:
        from .ov.client import OVTaskFailed

        if not agent.ov_session_uri:
            return
        while True:
            run, agent, remaining = await self._memory_context(agent.agent_id)
            try:
                store = await self._memory()
                # Provider polling may otherwise outlast the persisted agent or
                # run deadline. Cancellation does not cancel the remote task;
                # the adapter can discover that accepted task after a restart.
                async with asyncio.timeout(remaining):
                    await store.commit_session(agent.ov_session_uri, wait=True)
                await self._memory_context(agent.agent_id)
                return
            except _StopTurn:
                raise
            except OVTaskFailed:
                # A terminal provider task cannot recover through polling.
                # Keep its original identity and surface the failed outcome.
                raise
            except Exception as exc:
                await self._wait_for_memory(agent, run, exc)

    # ---------------------------------------------------------------- hooks
    async def _delegate_hook(self, parent: Agent, args: dict[str, Any]) -> Agent:
        run = await self.store.get_run(parent.run_id)
        role = AgentRole(str(args.get("role", "specialist")))
        req = DelegationRequest(
            parent_agent_id=parent.agent_id,
            name=str(args.get("name", "agent")),
            task=str(args.get("task", "")),
            role=role,
            allowed_targets=tuple(str(t) for t in args.get("allowed_targets", []) or []),
            allowed_tools=tuple(str(t) for t in args.get("allowed_tools", []) or []),
        )
        child, created = await supervisor.delegate(self.store, run, req)
        if created and child.status == AgentStatus.RUNNING:
            self.spawn_agent(child.agent_id)
        return child

    async def _message_hook(self, sender: Agent, args: dict[str, Any]) -> str:
        run = await self.store.get_run(sender.run_id)
        to = str(args.get("to", "parent"))
        if to == "parent":
            if not sender.parent_agent_id:
                raise RJError("validation_error", "agent has no parent", status=422)
            to = sender.parent_agent_id
        msg, _ = await mailbox.post_message(
            self.store, run, from_agent_id=sender.agent_id, to_agent_id=to,
            body=str(args.get("body", "")), kind=str(args.get("kind", "result")),
            summary_ref=args.get("summary_ref"),
            evidence_refs=[str(e) for e in args.get("evidence_refs", []) or []],
        )
        if to != "user":
            await self.wake_agent(to, "mailbox delivery")
        return f"sent {msg.message_id} to {to}"

    # ---------------------------------------------------------------- specs
    def tool_specs_for(self, agent: Agent) -> list[ToolSpec]:
        from .scope import tool_allowed

        specs: list[ToolSpec] = []
        for name, spec in BUILTIN_TOOL_SPECS.items():
            if tool_allowed(name, agent.allowed_tools):
                specs.append(ToolSpec(name=name, description=spec["description"],
                                      input_schema=spec["input_schema"]))
        for conn in self.mcp_manager.live_connections():
            for qualified in conn.tools:
                if tool_allowed(qualified, agent.allowed_tools):
                    specs.append(ToolSpec(name=qualified, description=f"MCP tool {qualified}",
                                          input_schema={"type": "object"}))
        return specs

    # -------------------------------------------------------------- restart
    async def _resume_after_restart(self) -> None:
        """Re-spawn loops for agents that were live when the engine stopped.
        LangGraph resumes from the durable checkpoint; in-flight tool
        invocations were already moved to 'unknown' (never re-executed)."""
        async with self.store.read() as s:
            from sqlalchemy import select

            from .db import _from
            from .db import agents as agents_table

            rows = (await s.execute(
                select(agents_table.c.data)
                .where(agents_table.c.status.in_([
                    AgentStatus.RUNNING.value, AgentStatus.WAITING.value,
                ]))
            )).all()
            live = [_from(Agent, r.data) for r in rows]
        for agent in live:
            self._log.info("resuming agent after restart", extra={"agent_id": agent.agent_id})
            self.spawn_agent(agent.agent_id)  # input None -> resume checkpoint
