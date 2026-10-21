"""Top-level RedJohn scan runner."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents import RunConfig
from agents.sandbox import SandboxRunConfig
from openai import RateLimitError

from redjohn.agents.factory import build_redjohn_agent, make_child_factory
from redjohn.agents.prompt import render_scope_prompt, render_system_prompt
from redjohn.assessment.host_resources import HostResourcePool, default_pool_path
from redjohn.assessment.os_memory import require_inline_memory_boundary
from redjohn.assessment.resources import ResourceGovernor
from redjohn.config import codex, grok, load_settings
from redjohn.config.models import (
    RedJohnProvider,
    configure_sdk_api_route,
    configure_sdk_model_defaults,
    model_supports_images,
    supports_strict_tool_schemas,
    uses_chat_completions_tool_schema,
)
from redjohn.config.settings import DEFAULT_MAX_TURNS
from redjohn.core.agents import AgentCoordinator, BudgetPolicy
from redjohn.core.execution import (
    respawn_subagents,
    run_agent_loop,
)
from redjohn.core.execution import (
    spawn_child_agent as start_child_agent,
)
from redjohn.core.hooks import BudgetExceededError, ReportUsageHooks, recomputed_budget_flags
from redjohn.core.inputs import (
    build_root_task,
    build_scan_targets,
    build_scope_context,
    make_model_settings,
)
from redjohn.core.paths import run_dir_for, runtime_state_dir
from redjohn.core.sessions import open_agent_session
from redjohn.report.state import get_global_report_state
from redjohn.runtime import session_manager
from redjohn.runtime.legacy_execution import LegacyExecution
from redjohn.telemetry import set_scan_phase
from redjohn.telemetry.logging import set_scan_id, setup_scan_logging
from redjohn.tools.finish.tool import finish_scan
from redjohn.tools.output_store import (
    WORKSPACE_SPILL_DIR,
    configure_spill_writer,
)


if TYPE_CHECKING:
    from agents.memory import SQLiteSession
    from agents.result import RunResultBase
    from agents.tool import Tool

    from redjohn.runtime.status import StatusSink
    from redjohn.tools.mcp import (
        McpConnectionRequest,
        McpRegistry,
    )


logger = logging.getLogger(__name__)


StreamEventSink = Callable[[str, Any], None]

# Receives the run's MCP connection roster as a list of non-secret status dicts
# ({"name", "provider", "tool_count", "dead", "state"}), once when the connections
# are registered and again on lifecycle transitions. An interface
# can persist it, render it, or forward it on as connection status. Kept as a
# snapshot of the whole roster (not a per-
# connection delta) so every call carries a consistent, current picture.
McpStatusSink = Callable[[list[dict[str, Any]]], None]


def _mcp_roster_payload(registry: McpRegistry) -> list[dict[str, Any]]:
    """The run's MCP roster as non-secret lifecycle status dicts."""
    return [
        {
            "name": status.name,
            "provider": status.provider,
            "tool_count": status.tool_count,
            "dead": status.dead,
            "state": status.state,
        }
        for status in registry.statuses()
    ]


def _mcp_prompt_roster(registry: McpRegistry) -> list[dict[str, Any]]:
    """The MCP roster rendered in agent prompts, with only verified counts."""
    return [
        {
            "name": summary.name,
            "purpose": summary.purpose,
            "tool_count": summary.tool_count if summary.state == "catalog_ready" else None,
            "state": summary.state,
        }
        for summary in registry.summaries()
    ]


def _record_mcp_connections(connection_names: list[str]) -> None:
    """Record which MCP servers this run configured, for the interfaces.

    A server's tools are offered to the model under a name built from the
    connection name and the tool's own name, which cannot be split back apart, so
    the TUI and the run viewer need the names to match a tool call against before
    they can show which server it went out to. Kept on the run record because the
    viewer reads a finished run from disk.
    """
    report_state = get_global_report_state()
    if report_state is None:
        return
    report_state.record_mcp_connections(connection_names)


def _note_exit_reason(reason: str) -> None:
    """Record why the scan stopped so the end-of-scan beacon reports it."""
    report_state = get_global_report_state()
    if report_state is not None and report_state.scan_ended_exit_reason is None:
        report_state.scan_ended_exit_reason = reason


def _persist_mcp_status(roster: list[dict[str, Any]]) -> None:
    """Write the run's non-secret MCP connection status roster to run.json.

    The viewer rebuilds its display by re-reading the run's files from disk, so
    it cannot see the in-memory ``mcp_status_sink`` the TUI consumes. Persisting
    the same non-secret roster (name / provider / tool_count / dead) gives the
    viewer a source it can poll. Runs regardless of whether an interface sink is
    attached, so the standalone / non-TUI CLI path records health too.
    """
    report_state = get_global_report_state()
    if report_state is None:
        return
    report_state.record_mcp_connection_status(roster)


def _merge_root_prompt_context(
    scope_context: dict[str, Any],
    extra_system_prompt_context: dict[str, Any] | None,
) -> dict[str, Any]:
    if not extra_system_prompt_context:
        return scope_context
    reserved_keys = scope_context.keys() & extra_system_prompt_context.keys()
    if reserved_keys:
        raise ValueError(
            "extra_system_prompt_context cannot override built-in scope keys: "
            f"{sorted(reserved_keys)}",
        )
    return {**scope_context, **extra_system_prompt_context}


def _compose_root_instructions_override(
    root_instructions_override: str | None,
    *,
    skills: list[str],
    scan_mode: str,
    is_whitebox: bool,
    is_diff_scoped: bool,
    interactive: bool,
    system_prompt_context: dict[str, Any],
    supports_images: bool,
) -> str | None:
    if root_instructions_override is None:
        return None

    base_instructions = render_system_prompt(
        skills=skills,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        is_root=True,
        is_diff_scoped=is_diff_scoped,
        interactive=interactive,
        system_prompt_context=system_prompt_context,
        include_scope=False,
        supports_images=supports_images,
    )
    return (
        f"{base_instructions}\n\n"
        "<root_scan_instructions_override>\n"
        "The following root scan instructions describe the task configuration.\n\n"
        f"{root_instructions_override}\n"
        "</root_scan_instructions_override>\n\n"
        f"{render_scope_prompt(system_prompt_context)}"
    )


def _validate_scan_options(model: str, budget_policy: BudgetPolicy) -> None:
    if not model:
        raise RuntimeError(
            "No LLM model configured. Set REDJOHN_LLM env or pass model= to run_redjohn_scan().",
        )
    if budget_policy not in ("stop", "pause"):
        raise ValueError(f"unknown budget_policy: {budget_policy!r}")


def _load_resume_snapshot(scan_id: str, agents_path: Path, agents_db: Path) -> dict[str, Any]:
    try:
        snapshot = json.loads(agents_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Cannot resume scan {scan_id}: agents.json is unreadable: {exc}",
        ) from exc
    if not agents_db.exists():
        raise RuntimeError(
            f"Cannot resume scan {scan_id}: missing SDK session database at {agents_db}",
        )
    if not isinstance(snapshot, dict):
        raise TypeError(f"Cannot resume scan {scan_id}: agents.json must contain an object")
    return snapshot


def _resume_root_id(scan_id: str, coordinator: AgentCoordinator) -> str:
    for agent_id, parent in coordinator.parent_of.items():
        if parent is None and agent_id in coordinator.statuses:
            return agent_id
    raise RuntimeError(
        f"Cannot resume scan {scan_id}: agents.json has no root agent (parent=None)",
    )


async def run_redjohn_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, Any]] | None = None,
    extra_files: list[dict[str, Any]] | Awaitable[list[dict[str, Any]] | None] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    budget_policy: BudgetPolicy = "stop",
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    root_instructions_override: str | None = None,
    extra_system_prompt_context: dict[str, Any] | None = None,
    status_sink: StatusSink | None = None,
    mcp_connection_requests: list[McpConnectionRequest] | None = None,
    mcp_status_sink: McpStatusSink | None = None,
    root_finish_tool: Tool = finish_scan,
    assessment_config_path: str | Path | None = None,
    assessment_caller: str | None = None,
) -> RunResultBase | None:
    """Run or resume one RedJohn scan against a sandbox.

    ``root_instructions_override`` adds root scan instructions to the rendered
    root prompt without replacing the system-verified scope block.
    ``extra_files`` entries (``{"workspace_path", "content"}``) are placed into
    the sandbox workspace at session bring-up; see
    :func:`redjohn.runtime.session_manager.create_or_reuse`.
    ``extra_system_prompt_context`` is merged into the root agent's scan
    context before prompt rendering. Child agents keep the standard scan prompt
    and context.
    ``budget_policy`` decides what happens when the LLM spend reaches
    ``max_budget_usd``: ``"stop"`` warns the agents as the limit approaches and
    ends the scan at it; ``"pause"`` tells the agents nothing and parks every
    agent before its next LLM call until the caller resumes the scan through
    ``coordinator.resume_budget()`` (optionally with a higher limit) or cancels
    it. ``coordinator.pause_budget()`` parks a running scan the same way.
    ``mcp_connection_requests`` supplies the run's inert MCP configurations from
    any source. When ``None`` (the command-line default), it reads
    ``~/.redjohn/mcp-servers.json`` itself. Connections are established only
    when selected through MCP tools; callers pass inert configs plus metadata
    and never live sessions.
    ``root_finish_tool`` is the tool the root agent ends the run with.
    """

    def report(phase: str) -> None:
        if status_sink is not None:
            status_sink(phase)

    if scan_id is None:
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    run_dir = run_dir_for(scan_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    from redjohn.assessment.host_binding import prepare_host_assessment

    prepared_assessment = prepare_host_assessment(
        scan_config,
        scan_id,
        run_dir,
        config_path=assessment_config_path,
        caller=assessment_caller,
    )
    if prepared_assessment is not None:
        prepared_assessment.check_workspace_authority(local_sources or [])
        configured = prepared_assessment.host.configured
        require_inline_memory_boundary(configured.config, configured.envelope.total_memory_budget)
    teardown_logging = setup_scan_logging(run_dir)
    root_id: str | None = None
    sessions_to_close: list[SQLiteSession] = []
    mcp_registry: McpRegistry | None = None
    legacy_execution: LegacyExecution | None = None
    owns_governor = prepared_assessment is None
    sandbox_ready = False
    topology_ready = False
    try:
        set_scan_id(scan_id)

        agents_path = state_dir / "agents.json"
        agents_db = state_dir / "agents.db"
        is_resume = agents_path.exists()

        logger.info(
            "%s RedJohn scan %s (image=%s, max_turns=%d, interactive=%s, run_dir=%s)",
            "Resuming" if is_resume else "Starting",
            scan_id,
            image,
            max_turns,
            interactive,
            run_dir,
        )

        settings = load_settings()
        configure_sdk_model_defaults(settings)
        resolved_model = (model or settings.llm.model or "").strip()
        _validate_scan_options(resolved_model, budget_policy)
        if resolved_model != (settings.llm.model or "").strip() and not (
            codex.subscription_model(resolved_model) or grok.subscription_model(resolved_model)
        ):
            configure_sdk_api_route(resolved_model, settings)
        logger.info("LLM model resolved: %s", resolved_model)
        chat_completions_tools = uses_chat_completions_tool_schema(resolved_model, settings)
        strict_tool_schemas = supports_strict_tool_schemas(resolved_model)
        if not strict_tool_schemas:
            logger.info("Sending non-strict tool schemas: %s caps strict tools", resolved_model)
        supports_images = model_supports_images(resolved_model)
        if not supports_images:
            logger.info("Leaving out image tools: %s does not accept images", resolved_model)

        if coordinator is None:
            coordinator = AgentCoordinator()
        coordinator.set_snapshot_path(agents_path)
        coordinator.set_budget_policy(budget_policy)
        coordinator.root_finish_tool = root_finish_tool.name

        from redjohn.tools.coverage.tools import hydrate_coverage_from_disk
        from redjohn.tools.notes.tools import hydrate_notes_from_disk
        from redjohn.tools.threat_model.tools import hydrate_threat_models_from_disk
        from redjohn.tools.todo.tools import hydrate_todos_from_disk

        hydrate_todos_from_disk(state_dir)
        hydrate_notes_from_disk(state_dir)
        hydrate_coverage_from_disk(state_dir)
        hydrate_threat_models_from_disk(state_dir)

        if is_resume:
            snap = _load_resume_snapshot(scan_id, agents_path, agents_db)
            await coordinator.restore(snap)
            root_id = _resume_root_id(scan_id, coordinator)
            topology_ready = True
            report_state = get_global_report_state()
            if report_state is not None:
                budget_stopped, reserve_stopped = recomputed_budget_flags(
                    report_state.get_total_llm_cost(),
                    max_budget_usd,
                    interactive=interactive,
                    budget_policy=budget_policy,
                )
                # Under the pause policy the hooks re-park at the first call if the
                # spend is still at the limit, so a restored pause flag would only
                # hold agents back after the limit was raised.
                await coordinator.reset_budget_stops(
                    budget_stopped=budget_stopped,
                    reserve_stopped=reserve_stopped,
                    budget_paused=(
                        interactive and budget_policy != "pause" and coordinator.budget_paused
                    ),
                )
            logger.info(
                "Resume: restored coordinator with %d agent(s); root=%s",
                len(coordinator.statuses),
                root_id,
            )
        else:
            root_id = uuid.uuid4().hex[:8]

        logger.info("Bringing up sandbox session for scan %s", scan_id)
        set_scan_phase("sandbox_init")
        bundle = await session_manager.create_or_reuse(
            scan_id,
            image=image,
            local_sources=local_sources or [],
            extra_files=extra_files,
            status_sink=status_sink,
            protected_host_paths=(
                prepared_assessment.protected_paths() if prepared_assessment is not None else ()
            ),
        )
        sandbox_ready = True
        report("Waiting for the first model response")
        logger.info("Sandbox ready for scan %s", scan_id)
        set_scan_phase("agent_setup")

        sandbox_session = bundle["session"]

        async def _spill_to_workspace(output_id: str, text: str) -> str | None:
            """Write an oversized tool result into the sandbox; return its path or None."""
            path = f"{WORKSPACE_SPILL_DIR}/{output_id}.txt"
            try:
                await sandbox_session.write(Path(path), io.BytesIO(text.encode("utf-8")))
            except Exception:
                logger.exception("failed to spill tool output to sandbox workspace")
                return None
            return path

        configure_spill_writer(_spill_to_workspace)

        targets = scan_config.get("targets") or []
        scan_mode = str(scan_config.get("scan_mode") or "deep")
        is_whitebox = any(t.get("type") == "local_code" for t in targets)
        diff_scope = scan_config.get("diff_scope")
        is_diff_scoped = bool(isinstance(diff_scope, dict) and diff_scope.get("active"))
        skills = list(scan_config.get("skills") or [])
        root_task = build_root_task(scan_config)
        model_settings = make_model_settings(
            settings.llm.reasoning_effort,
            model_name=resolved_model,
            force_required_tool_choice=settings.llm.force_required_tool_choice,
            request_timeout=settings.llm.timeout,
            prompt_cache=settings.llm.prompt_cache,
            extra_headers=settings.llm.extra_headers,
            max_output_tokens=settings.llm.max_output_tokens,
        )
        run_config = RunConfig(
            model=resolved_model,
            model_provider=RedJohnProvider(),
            model_settings=model_settings,
            sandbox=SandboxRunConfig(client=bundle["client"], session=bundle["session"]),
            trace_include_sensitive_data=False,
            # A hallucinated tool name is a recoverable model mistake, not a scan-ending
            # error: hand it back as a tool result so the agent can correct itself.
            tool_not_found_behavior="return_error_to_model",
        )
        hooks = ReportUsageHooks(
            model=resolved_model,
            max_budget_usd=max_budget_usd,
            max_turns=max_turns,
            interactive=interactive,
            budget_policy=budget_policy,
        )
        coordinator.set_budget_limit_setter(hooks.set_max_budget_usd)
        if interactive and budget_policy != "pause":
            coordinator.set_budget_extender(hooks.extend_budget)

        scope_context = build_scope_context(scan_config)
        if prepared_assessment is not None:
            scope_context["assessment"] = prepared_assessment.metadata()

        # Attach the run's MCP connections and hold their live sessions in a
        # per-run registry. The connections are source-agnostic: a caller
        # (the SaaS/pro product) can supply them as mcp_connection_requests, and
        # when it does not the command-line path reads them from
        # ~/.redjohn/mcp-servers.json here. Either way one shared engine routine
        # does the connecting and populating. Nothing is registered as an agent
        # tool: every agent reaches these connections on demand through the
        # list_mcps / describe_mcp / call_mcp tools, guided by brief static prompt
        # guidance when any connection exists. Fail-open: a missing config, or a
        # server that will not connect, must never break a run.
        from redjohn.tools.mcp import (
            McpConnectionRequest,
            McpRegistry,
            load_user_mcp_configs,
        )

        mcp_registry = McpRegistry()
        try:
            if mcp_connection_requests is None:
                # Command-line default: read the user's file and wrap each config
                # in a bare request (no provider or transform), so this path is
                # exactly the old behavior.
                mcp_requests = [
                    McpConnectionRequest(config=config) for config in load_user_mcp_configs()
                ]
            else:
                mcp_requests = mcp_connection_requests
            if mcp_requests:
                for request in mcp_requests:
                    mcp_registry.register(request)
                _record_mcp_connections(mcp_registry.names())
                report(f"MCP: configured {len(mcp_registry)} connection(s); available on demand")
                scope_context["mcp_available"] = True
                scope_context["mcp_connections"] = _mcp_prompt_roster(mcp_registry)

                def _emit_mcp_status() -> None:
                    scope_context["mcp_connections"] = _mcp_prompt_roster(mcp_registry)
                    roster = _mcp_roster_payload(mcp_registry)
                    _persist_mcp_status(roster)
                    if mcp_status_sink is not None:
                        try:
                            mcp_status_sink(roster)
                        except Exception:
                            logger.exception("MCP status sink failed")

                mcp_registry.set_status_sink(_emit_mcp_status)
                _emit_mcp_status()
                # Configurations remain inert until the agent selects a
                # connection through MCP discovery/dispatch. Registration
                # does not start every optional provider at scan boot.
        except Exception:
            logger.exception("Failed to configure user MCP servers; continuing without them")

        root_context = _merge_root_prompt_context(scope_context, extra_system_prompt_context)
        root_instructions = _compose_root_instructions_override(
            root_instructions_override,
            skills=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            system_prompt_context=root_context,
            supports_images=supports_images,
        )

        root_agent = build_redjohn_agent(
            name="Coordinator",
            skills=skills,
            is_root=True,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            strict_tool_schemas=strict_tool_schemas,
            system_prompt_context=root_context,
            instructions_override=root_instructions,
            supports_images=supports_images,
            finish_tool=root_finish_tool,
        )

        if not is_resume:
            await coordinator.register(
                root_id,
                "Root Agent",
                parent_id=None,
                task=root_task,
                skills=skills,
            )
            topology_ready = True

        child_agent_builder = make_child_factory(
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            strict_tool_schemas=strict_tool_schemas,
            system_prompt_context=scope_context,
            supports_images=supports_images,
        )

        async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
            return await start_child_agent(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
                **kwargs,
            )

        if prepared_assessment is not None:
            await prepared_assessment.start()

        shared_governor = (
            prepared_assessment.host.configured.runtime.governor
            if prepared_assessment is not None
            else ResourceGovernor(host_pool=HostResourcePool(default_pool_path()))
        )
        legacy_execution = LegacyExecution(
            agents_db,
            shared_governor,
            control=prepared_assessment.host.control if prepared_assessment else None,
            sandbox_session=bundle["session"],
            shell_transport=(
                prepared_assessment.host.configured.runtime.browser if prepared_assessment else None
            ),
        )
        mcp_registry.bind_governor(shared_governor)
        legacy_execution.bind_mcp_registry(mcp_registry)

        context: dict[str, Any] = {
            "coordinator": coordinator,
            "sandbox_session": bundle["session"],
            "caido_client": bundle["caido_client"],
            "mcp_registry": mcp_registry,
            "agent_id": root_id,
            "parent_id": None,
            "interactive": interactive,
            "spawn_child_agent": spawn_child_agent,
            "scan_targets": build_scan_targets(scan_config),
            "max_context_images": settings.runtime.max_context_images,
            "supports_images": supports_images,
            "legacy_execution": legacy_execution,
            "assessment_governor": shared_governor,
        }
        if prepared_assessment is not None:
            context["assessment_service"] = prepared_assessment.host.control
            context["assessment_governor"] = prepared_assessment.host.configured.runtime.governor

        root_session = open_agent_session(root_id, agents_db)
        sessions_to_close.append(root_session)
        await coordinator.attach_runtime(root_id, session=root_session)

        if is_resume:
            await respawn_subagents(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                parent_ctx=context,
                root_id=root_id,
                event_sink=event_sink,
                hooks=hooks,
            )

        initial_input: Any = [] if is_resume else root_task

        # Resume + new ``--instruction``: SDK replay drives root from
        # agents.db with ``initial_input=[]``, so a brand-new instruction
        # passed on the resume CLI would otherwise be silently ignored.
        # Inject it as a fresh user message in root's SDK session; the
        # next run cycle will replay it with the rest of the session.
        resume_instruction = str(scan_config.get("resume_instruction") or "").strip()
        if is_resume and resume_instruction:
            await coordinator.send(
                root_id,
                {
                    "from": "user",
                    "type": "instruction",
                    "priority": "high",
                    "content": resume_instruction,
                },
            )
            logger.info(
                "Resume: injected new instruction into root SDK session (len=%d)",
                len(resume_instruction),
            )

        async with coordinator._lock:
            root_status = coordinator.statuses.get(root_id)

        set_scan_phase("agent_loop")
        result = await run_agent_loop(
            agent=root_agent,
            initial_input=initial_input,
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            coordinator=coordinator,
            agent_id=root_id,
            interactive=interactive,
            session=root_session,
            start_parked=bool(interactive and is_resume and root_status != "running"),
            event_sink=event_sink,
            hooks=hooks,
        )
        if not interactive and result is not None:
            final = getattr(result, "final_output", None)
            # Lifecycle tools mark the root completed.
            async with coordinator._lock:
                root_completed = coordinator.statuses.get(root_id) == "completed"
            if not root_completed:
                logger.error(
                    "Scan %s ended without calling finish_scan. The agent "
                    "emitted a text-only turn instead of a lifecycle tool call, "
                    "so no executive report was written. Final output (first "
                    "300 chars): %r",
                    scan_id,
                    str(final)[:300],
                )
        return result  # noqa: TRY300
    except BudgetExceededError as exc:
        logger.info("Scan %s stopped: %s", scan_id, exc)
        _note_exit_reason("budget_exceeded")
        if topology_ready and root_id is not None and coordinator is not None:
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "stopped")
        return None
    except RateLimitError as exc:
        logger.warning(
            "Scan %s stopped: persistent rate limit from the LLM provider (%s). "
            "Resume with 'redjohn --resume %s' once the limit clears.",
            scan_id,
            exc,
            scan_id,
        )
        _note_exit_reason("rate_limited")
        if topology_ready and root_id is not None and coordinator is not None:
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "stopped")
        return None
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("Scan %s interrupted by the user", scan_id)
        if topology_ready and root_id is not None and coordinator is not None:
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "running")
        raise
    except BaseException:
        logger.exception("RedJohn scan %s failed", scan_id)
        if topology_ready and root_id is not None and coordinator is not None:
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "failed")
        raise
    finally:
        try:
            configure_spill_writer(None)
            # Settle descendants before closing sessions: on a clean finish a child
            # can still be mid-turn, and closing its session underneath it crashes it.
            if topology_ready and root_id is not None and coordinator is not None:
                with contextlib.suppress(Exception):
                    await coordinator.cancel_descendants(root_id)
            for s in sessions_to_close:
                with contextlib.suppress(Exception):
                    s.close()
            if mcp_registry is not None:
                with contextlib.suppress(Exception):
                    await mcp_registry.close()
            try:
                if legacy_execution is not None:
                    await legacy_execution.close()
                    if owns_governor:
                        legacy_execution.governor.close()
            finally:
                if topology_ready and coordinator is not None:
                    with contextlib.suppress(Exception):
                        await coordinator._maybe_snapshot()
                if cleanup_on_exit and sandbox_ready:
                    logger.info("Tearing down sandbox session for scan %s", scan_id)
                    await session_manager.cleanup(scan_id)
                logger.info("RedJohn scan %s done", scan_id)
        finally:
            try:
                if prepared_assessment is not None:
                    task = asyncio.current_task()
                    await prepared_assessment.host.close(
                        cancel_running=bool(task is not None and task.cancelling())
                    )
            finally:
                teardown_logging()
