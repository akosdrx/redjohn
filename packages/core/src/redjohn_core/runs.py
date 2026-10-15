"""Run Manager: create (pins scope snapshot), start (spawns coordinator),
stop (block delegation -> stop children -> kill tool processes).

Findings/evidence are plain rows and remain readable after a stop.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from . import supervisor
from .errors import RJError, conflict, validation
from .events import EventType
from .models import (
    Agent,
    AgentLimits,
    AgentRole,
    AgentStatus,
    PentestTargetKind,
    Project,
    Run,
    RunEnvironment,
    RunStatus,
    ScanMode,
    ScopePolicy,
    Target,
    TargetKind,
    utcnow,
)
from .supervisor import TERMINAL_AGENT_STATES

if TYPE_CHECKING:
    from .engine import Engine


def normalize_session_target(value: str, kind: PentestTargetKind) -> tuple[str, TargetKind]:
    """Validate operator input without fetching or executing the target."""
    value = value.strip()
    if not value:
        raise validation("An authorized target is required.")
    if kind == PentestTargetKind.LOCAL_PROJECT:
        path = Path(value).expanduser()
        if not path.is_absolute() or not path.is_dir():
            raise validation("Local project target must be an existing absolute directory.")
        return str(path.resolve()), TargetKind.LOCAL_PROJECT
    if kind == PentestTargetKind.GITHUB_REPOSITORY:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise validation("GitHub target has an invalid port.") from exc
        parts = parsed.path.strip("/").removesuffix(".git").split("/")
        if (parsed.scheme != "https" or parsed.hostname != "github.com"
                or parsed.username is not None or parsed.password is not None
                or port is not None or parsed.query or parsed.fragment
                or len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts)
                or any(p in (".", "..") for p in parts)):
            raise validation("GitHub target must be an HTTPS repository URL, such as https://github.com/owner/repo.")
        return f"https://github.com/{'/'.join(parts)}", TargetKind.GITHUB_REPOSITORY
    try:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        port = parsed.port
    except ValueError as exc:
        raise validation("Web target has an invalid port.") from exc
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or any(c.isspace() for c in value) or parsed.fragment):
        raise validation("Web target must be a domain or an HTTP(S) URL without credentials.")
    if "://" not in value:
        if parsed.path or parsed.query or port:
            raise validation("Use an HTTP(S) URL for a web target with a path or port.")
        return parsed.hostname, TargetKind.DOMAIN
    return value, TargetKind.URL


async def create_run(
    engine: Engine,
    *,
    project_id: str | None = None,
    name: str,
    task: str = "",
    scan_mode: ScanMode = ScanMode.STANDARD,
    authorized_target: str | None = None,
    target_kind: PentestTargetKind | None = None,
    environment: RunEnvironment | None = None,
    limits: AgentLimits | None = None,
    idempotency_key: str | None = None,
) -> Run:
    if environment == RunEnvironment.CLOUD_MANAGED:
        raise validation(
            "cloud_managed runs are not supported by the local engine profile",
            {"environment": environment.value},
        )
    store = engine.store
    if not name.strip():
        raise validation("Pentest name is required.")
    if project_id is not None and not project_id.strip():
        raise validation("Project ID must not be empty.")
    session_project = project_id is None
    if (authorized_target is None) != (target_kind is None):
        raise validation("Authorized target and target kind must be supplied together.")
    if session_project and (authorized_target is None or target_kind is None):
        raise validation("Authorized target and target kind are required for a pentest session.")
    normalized = None
    if authorized_target is not None and target_kind is not None:
        authorized_target, normalized = normalize_session_target(authorized_target, target_kind)
    project = await store.get_project(project_id) if project_id else None
    async with store.write() as s:
        ws = await store.ensure_default_workspace(s)
        if project is None:
            assert authorized_target is not None and normalized is not None
            project = Project(workspace_id=ws.workspace_id, name=name.strip())
            project_id = project.project_id
            await store.insert_project(s, project)
            session_scope = ScopePolicy(
                project_id=project_id, allowed_targets=[authorized_target],
                allowed_tools=["builtin:*", "mcp:*"],
            )
            await store.insert_scope(s, session_scope)
            target = Target(project_id=project_id, value=authorized_target, kind=normalized)
            await store.insert_target(s, target)
        assert project_id is not None
        scope = await store.latest_scope(s, project_id)
        if scope is None:
            # deny-all default scope v1; replace via PUT /projects/{id}/scope
            scope = ScopePolicy(project_id=project_id, version=1)
            await store.insert_scope(s, scope)
        if authorized_target is not None:
            from .scope import target_covered

            if not target_covered(authorized_target, scope.allowed_targets):
                raise validation("The authorized target must be covered by the project's pinned scope.")
        ws_id = project.workspace_id or ws.workspace_id
        ref_seq = await store.next_workspace_ref(s, ws_id)
        run = Run(
            workspace_id=ws_id,
            project_id=project_id,
            name=name.strip(),
            ref=f"RJ-{ref_seq:03d}",
            task=task,
            scan_mode=scan_mode,
            authorized_target=authorized_target,
            target_kind=target_kind,
            session_project=session_project,
            status=RunStatus.CREATED,
            scope=scope,  # pinned snapshot
            limits=limits or AgentLimits(),
            environment=environment or RunEnvironment.LOCAL,
            idempotency_key=idempotency_key,
        )
        await store.insert_run(s, run)
        await store.emit_simple(s, run, EventType.RUN_STATUS, {
            "run_id": run.run_id, "ref": run.ref, "status": run.status.value,
            "name": run.name, "scope_version": scope.version,
        })
        return run


async def start_run(
    engine: Engine, run_id: str, *,
    accepted_states: tuple[RunStatus, ...] = (RunStatus.CREATED,),
) -> Run:
    store = engine.store
    run = await store.get_run(run_id)
    if run.archived_at is not None:
        raise conflict("Restore an archived pentest before starting it.")
    if run.status == RunStatus.RUNNING:
        raise conflict("run is already running", {"run_status": run.status.value})
    if run.status not in accepted_states:
        raise conflict(
            f"cannot start a run in state {run.status.value}",
            {"run_status": run.status.value},
        )
    async with store.write() as s:
        run.status = RunStatus.STARTING
        await store.update_run_row(s, run)
        await store.emit_simple(s, run, EventType.RUN_STATUS, {
            "run_id": run.run_id, "status": run.status.value,
        })

        coordinator = Agent(
            run_id=run.run_id,
            parent_agent_id=None,
            role=AgentRole.COORDINATOR,
            name="Coordinator",
            task=run.task or run.name,
            status=AgentStatus.RUNNING,
            depth=0,
            allowed_targets=list(run.scope.allowed_targets),
            allowed_tools=list(run.scope.allowed_tools),
            time_budget_seconds=run.limits.time_budget_seconds,
            token_budget=run.limits.token_budget,
            current_activity="starting",
        )
        await store.insert_agent(s, coordinator, None)
        await store.emit_simple(s, run, EventType.AGENT_STATUS, {
            "agent_id": coordinator.agent_id, "parent_agent_id": None,
            "role": coordinator.role.value, "name": coordinator.name,
            "status": coordinator.status.value, "depth": 0,
        }, agent_id=coordinator.agent_id)

        run.status = RunStatus.RUNNING
        run.started_at = utcnow()
        await store.update_run_row(s, run)
        await store.emit_simple(s, run, EventType.RUN_STATUS, {
            "run_id": run.run_id, "status": run.status.value,
        })
    engine.spawn_agent(coordinator.agent_id)
    return run


async def stop_run(
    engine: Engine, run_id: str, *,
    accepted_states: tuple[RunStatus, ...] = (
        RunStatus.CREATED, RunStatus.RUNNING, RunStatus.STARTING, RunStatus.STOPPING, RunStatus.STOPPED,
    ),
) -> Run:
    """Stop: block new delegation -> stop children -> kill tool processes."""
    store = engine.store
    # 1. block new delegation (supervisor only accepts RUNNING)
    async with store.write() as s:
        # Coordinator completion may race the operator's click. Check the
        # current state under the same lock as the STOPPING mutation.
        run = await store.get_run(run_id)
        if run.status == RunStatus.STOPPED:
            return run
        if run.status not in accepted_states:
            raise conflict(
                f"cannot stop a run in state {run.status.value}",
                {"run_status": run.status.value},
            )
        run.status = RunStatus.STOPPING
        await store.update_run_row(s, run)
        await store.emit_simple(s, run, EventType.RUN_STATUS, {
            "run_id": run.run_id, "status": run.status.value,
        })

    # 2. stop children (deepest first), then 3. kill tool processes
    agents = await store.list_agents(run_id)
    pending: list[asyncio.Task[None]] = []
    for agent in sorted(agents, key=lambda a: a.depth, reverse=True):
        if agent.status in TERMINAL_AGENT_STATES:
            continue
        task = engine._runners.get(agent.agent_id)
        if task and not task.done():
            task.cancel()
            pending.append(task)
        await supervisor.set_agent_status(store, run, agent, AgentStatus.STOPPED,
                                          activity="run stopped")
    await engine.tool_runner.kill_run(run_id)
    # Runner cancellation may still commit an invocation or checkpoint. Finish
    # it before returning STOPPED or allowing deletion of session data.
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    for agent in agents:
        engine._runners.pop(agent.agent_id, None)
    await engine.mcp_manager.close_run(run_id)

    async with store.write() as s:
        run.status = RunStatus.STOPPED
        run.finished_at = utcnow()
        await store.update_run_row(s, run)
        await store.emit_simple(s, run, EventType.RUN_STATUS, {
            "run_id": run.run_id, "status": run.status.value,
        })
    return run


async def archive_run(engine: Engine, run_id: str, *, archived: bool = True) -> Run:
    run = await engine.store.get_run(run_id)
    if archived and run.status in (RunStatus.STARTING, RunStatus.RUNNING, RunStatus.STOPPING):
        try:
            run = await stop_run(engine, run_id)
        except RJError as exc:
            if exc.code != "conflict":
                raise
            run = await engine.store.get_run(run_id)
            if run.status not in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.STOPPED):
                raise
    if archived:
        # Terminal sessions can still have persisted managed connections
        # from a previous engine or an interrupted teardown. Release their
        # actors explicitly, including an idempotent archive retry.
        await engine.mcp_manager.close_run(run_id)
    if (run.archived_at is not None) == archived:
        return run
    async with engine.store.write() as s:
        run = await engine.store.get_run(run_id)
        run.archived_at = utcnow() if archived else None
        await engine.store.update_run_row(s, run)
        await engine.store.emit_simple(s, run, EventType.RUN_STATUS, {
            "run_id": run.run_id, "status": run.status.value,
            "archived_at": run.archived_at.isoformat() if run.archived_at else None,
        })
    return run


def _remove_owned_file(root: Path, storage_ref: str) -> None:
    """Only remove an artifact inside its managed root, never a target file."""
    path = root / storage_ref
    if not path.resolve().is_relative_to(root.resolve()) or path.resolve() == root.resolve():
        return
    if path.is_file() or path.is_symlink():
        path.unlink(missing_ok=True)


async def delete_run(engine: Engine, run_id: str) -> None:
    store = engine.store
    run = await store.get_run(run_id)
    if run.status in (RunStatus.STARTING, RunStatus.RUNNING, RunStatus.STOPPING):
        try:
            run = await stop_run(engine, run_id)
        except RJError as exc:
            if exc.code != "conflict":
                raise
            run = await store.get_run(run_id)
            if run.status not in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.STOPPED):
                raise
    agents = await store.list_agents(run_id)
    pending = [engine._runners[a.agent_id] for a in agents
               if a.agent_id in engine._runners and not engine._runners[a.agent_id].done()]
    for task in pending:
        task.cancel()
    await engine.tool_runner.kill_run(run_id)
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    # Read artifacts only after no cancelled runner can add a final record.
    artifacts = await store.list_evidence(run_id)
    report_items, _ = await store.list_reports_page(run_id=run_id, cursor=None, limit=100_000)
    await engine.mcp_manager.close_run(run_id)
    # Checkpoints are per agent, so deleting this session cannot affect a
    # concurrent pentest. Keep rows if checkpoint cleanup fails for retry.
    ov_viking_root = (engine.settings.profile_dir / "openviking" / "data" / "viking").resolve()
    for agent in agents:
        await engine.checkpointer.adelete_thread(agent.agent_id)
        engine._runners.pop(agent.agent_id, None)
        if ov_viking_root.is_dir():
            for session_dir in ov_viking_root.glob(f"*/user/*/sessions/{agent.agent_id}"):
                if session_dir.is_dir() and session_dir.resolve().is_relative_to(ov_viking_root):
                    shutil.rmtree(session_dir, ignore_errors=True)
    for artifact in artifacts:
        _remove_owned_file(engine.settings.evidence_dir, artifact.storage_ref)
    for report in report_items:
        _remove_owned_file(engine.settings.reports_dir, report.storage_ref)
    workdir = engine.settings.work_root / run_id
    if workdir.is_symlink():
        workdir.unlink()
    elif workdir.is_dir() and workdir.resolve().is_relative_to(engine.settings.work_root.resolve()):
        shutil.rmtree(workdir)
    async with store.write() as s:
        await store.delete_run_rows(s, run)
