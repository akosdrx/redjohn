"""UI-independent state and command controller for interactive RedJohn clients."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import time
import webbrowser
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.config import load_settings
from redjohn.config.model_catalog import resolve_model_effort_spec, short_model_label
from redjohn.config.settings import DEFAULT_MAX_TURNS
from redjohn.interface.tui.backend.live_view import TuiLiveView
from redjohn.interface.tui.backend.llm_picker import LlmPicker
from redjohn.interface.tui.backend.projection import (
    MAX_TERMINAL_EVENTS,
    MAX_TERMINAL_VULNERABILITIES,
    SCAN_MODES,
    SCOPE_MODES,
    bounded_state_projection,
    collection_item_projection,
    sanitize_terminal_text,
    terminal_projection,
)
from redjohn.interface.utils import is_subscription_run


logger = logging.getLogger(__name__)

_OV_PROBE_TTL_SECONDS = 30.0
_ov_probe_cache: dict[str, Any] = {}
_ov_probe_state: dict[str, float] = {"cached_at": 0.0}


def _cached_openviking_status() -> dict[str, Any]:
    """Advisory UI status: probe at most once per TTL instead of every snapshot.

    Snapshots are rebuilt on every broadcast flush, and each probe rewrites
    ``ov.conf`` and resolves model routing.
    """
    now = time.monotonic()
    if not _ov_probe_cache or now - _ov_probe_state["cached_at"] > _OV_PROBE_TTL_SECONDS:
        try:
            from redjohn.memory.openviking.config import probe_openviking_status

            _ov_probe_cache.clear()
            _ov_probe_cache.update(probe_openviking_status())
            _ov_probe_state["cached_at"] = now
        except Exception:
            logger.debug("OpenViking status probe failed", exc_info=True)
    return dict(_ov_probe_cache)


if TYPE_CHECKING:
    import argparse

    from redjohn.report.state import ReportState


_STOPPABLE_AGENT_STATUSES = frozenset({"running", "waiting", "budget_paused"})

ChangeCallback = Callable[[], None]
StartCallback = Callable[[], Awaitable[None]]
VerifyCallback = Callable[[], Awaitable[None]]
QuitCallback = Callable[[], Awaitable[None]]


class TuiController:
    """Own setup state and expose serializable scan state to any TUI."""

    def __init__(
        self,
        args: argparse.Namespace,
        *,
        live_view: TuiLiveView | None = None,
        coordinator: Any = None,
        report_state: ReportState | None = None,
        on_start: StartCallback | None = None,
        on_verify: VerifyCallback | None = None,
        on_quit: QuitCallback | None = None,
        on_change: ChangeCallback | None = None,
    ) -> None:
        self.args = args
        self.live_view = live_view or TuiLiveView()
        self.coordinator = coordinator
        self.report_state = report_state
        self.scan_loop: asyncio.AbstractEventLoop | None = None
        self.setup_mode = bool(args.needs_setup)
        self.scan_started = not self.setup_mode
        self._start_in_progress = False
        self.scan_state = "setup" if self.setup_mode else "running"
        self.targets = [
            str(target["original"])
            for target in args.targets_info
            if isinstance(target, dict) and target.get("original")
        ]
        instruction = args.instruction
        self.instruction = instruction.strip() if isinstance(instruction, str) else ""
        requested_scan_mode = str(args.scan_mode)
        self.scan_mode = requested_scan_mode if requested_scan_mode in SCAN_MODES else "deep"
        raw_budget = args.max_budget_usd
        self.max_budget_usd = (
            float(raw_budget)
            if isinstance(raw_budget, int | float)
            and not isinstance(raw_budget, bool)
            and math.isfinite(float(raw_budget))
            and raw_budget > 0
            else None
        )
        raw_turns = args.max_turns
        self.max_turns = (
            raw_turns
            if isinstance(raw_turns, int) and not isinstance(raw_turns, bool) and raw_turns > 0
            else DEFAULT_MAX_TURNS
        )
        requested_scope = str(args.scope_mode)
        self.scope_mode = requested_scope if requested_scope in SCOPE_MODES else "auto"
        raw_diff_base = args.diff_base
        self.diff_base = raw_diff_base.strip() if isinstance(raw_diff_base, str) else None
        # Host directory mounted for the agent to work in when the scan has no
        # target, set only once the user confirms it. It is a workspace, not a
        # target: it carries no scan scope, and the instruction is the only
        # source of truth for what to do.
        self.workspace_mount: str | None = None
        # A target-less launch enters the live view and asks there before
        # anything is prepared; this holds the directory awaiting that answer.
        self.pending_workspace_mount: str | None = None
        self.messages: list[dict[str, str]] = []
        self._next_message_id = 1
        self.error: str | None = None
        # The run's MCP connection roster (name / tool_count / dead), pushed by
        # the engine via the mcp_status_sink once the connections are established
        # and again each time one dies. Empty for a run with no MCP connections,
        # so the Go sidebar simply omits the panel. Non-secret by construction.
        self.mcp_connections: list[dict[str, Any]] = []
        self.viewer_status = "idle"
        self.viewer_url: str | None = None
        self._viewer_httpd: Any = None
        self._on_start = on_start
        self._on_verify = on_verify
        self._on_quit = on_quit
        self._on_change = on_change
        self._llm_picker = LlmPicker()
        self._mcp_names = _configured_mcp_names()
        self._skill_catalog = _skill_catalog()
        self._skill_names = [entry["name"] for entry in self._skill_catalog]
        self.selected_skills: list[str] = []

    def set_change_callback(self, callback: ChangeCallback) -> None:
        self._on_change = callback

    def notify_changed(self) -> None:
        if self._on_change is not None:
            self._on_change()

    def set_runtime(
        self,
        *,
        report_state: ReportState | None = None,
        scan_loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if report_state is not None:
            self.report_state = report_state
        if scan_loop is not None:
            self.scan_loop = scan_loop

    def set_mcp_connections(self, roster: list[dict[str, Any]]) -> None:
        """Store the run's MCP connection roster and repaint.

        ``roster`` is the engine's non-secret status snapshot: one entry per
        connection carrying ``name``, ``tool_count``, and ``dead``. Called once
        when the connections are established (all healthy) and again whenever a
        connection dies (the same whole-roster snapshot, with that one now dead)."""
        self.mcp_connections = [
            {
                "name": str(entry.get("name", "")),
                "tool_count": int(entry.get("tool_count", 0) or 0),
                "dead": bool(entry.get("dead", False)),
            }
            for entry in roster
            if isinstance(entry, dict) and entry.get("name")
        ]
        self.notify_changed()

    def fail_preparation(self, detail: str) -> None:
        self.scan_state = "failed"
        self.error = detail
        self.notify_changed()

    def add_message(self, text: str, level: str = "info") -> None:
        self._append_message(text, level)
        self.notify_changed()

    def _append_message(self, text: str, level: str) -> None:
        self.messages.append(
            {
                "id": f"message-{self._next_message_id}",
                "text": sanitize_terminal_text(text),
                "level": sanitize_terminal_text(level),
            }
        )
        self._next_message_id += 1
        self.messages = self.messages[-200:]

    def snapshot(self) -> dict[str, Any]:
        """Return small mutable state; histories are streamed as collections."""
        model = ""
        effort = ""
        supported_efforts: list[str] = []
        swarm_model = ""
        swarm_effort = ""
        swarm_profile = "full"
        swarm_role_models: dict[str, str] = {}
        ov_online = False
        ov_model = "auto"
        ov_embed_model = "local/bge-small"
        with contextlib.suppress(Exception):
            settings_obj = load_settings()
            llm = settings_obj.llm
            model = (llm.model or "").strip()
            swarm_model = (llm.swarm_model or "").strip()
            swarm_profile = llm.swarm_profile.strip() or "full"
            swarm_role_models = dict(llm.swarm_role_models or {})
            if model:
                spec = resolve_model_effort_spec(model)
                supported_efforts = list(spec.supported_efforts)
                effort = llm.reasoning_effort
                if supported_efforts and effort not in supported_efforts:
                    effort = spec.default_effort or supported_efforts[0]
            effective_swarm = swarm_model or model
            if effective_swarm:
                swarm_spec = resolve_model_effort_spec(effective_swarm)
                swarm_effort = llm.swarm_reasoning_effort or effort or swarm_spec.default_effort
            ov_status = _cached_openviking_status()
            ov_online = bool(ov_status.get("online", False))
            ov_model = str(ov_status.get("short_vlm_model") or "auto")
            ov_embed_model = str(ov_status.get("embedding_model") or "local/bge-small")
        usage: dict[str, Any] = {}
        if self.report_state is not None:
            usage = dict(self.report_state.get_total_llm_usage())
        subscription = False
        with contextlib.suppress(Exception):
            subscription = is_subscription_run(self.report_state)
        state = {
            "setup_mode": self.setup_mode,
            "scan_started": self.scan_started,
            "scan_state": self.scan_state,
            "targets": [
                terminal_projection(target, max_string=128) for target in self.targets[:16]
            ],
            "target_count": len(self.targets),
            "working_dir": str(Path.cwd()),
            "pending_mount": self.pending_workspace_mount or "",
            "instruction": terminal_projection(self.instruction, max_string=2 * 1024),
            "scan_mode": self.scan_mode,
            "max_budget_usd": self.max_budget_usd,
            "max_turns": self.max_turns,
            "scope_mode": self.scope_mode,
            "diff_base": terminal_projection(self.diff_base, max_string=256),
            "model": terminal_projection(model, max_string=256),
            "short_model": terminal_projection(
                short_model_label(model) if model else "", max_string=64
            ),
            "reasoning_effort": effort,
            "supported_efforts": supported_efforts,
            "swarm_model": terminal_projection(swarm_model, max_string=256),
            "short_swarm_model": terminal_projection(
                short_model_label(swarm_model or model) if (swarm_model or model) else "",
                max_string=64,
            ),
            "swarm_reasoning_effort": swarm_effort,
            "swarm_profile": swarm_profile,
            "swarm_role_models": terminal_projection(
                swarm_role_models, max_string=128, max_items=10
            ),
            "openviking_online": ov_online,
            "openviking_model": terminal_projection(ov_model, max_string=64),
            "openviking_embed_model": terminal_projection(ov_embed_model, max_string=64),
            "caido_url": terminal_projection(
                getattr(self.report_state, "caido_url", None), max_string=1024
            ),
            "messages": [
                {
                    "id": str(message.get("id", ""))[:64],
                    "text": terminal_projection(message.get("text", ""), max_string=256),
                    "level": str(message.get("level", "info"))[:32],
                }
                for message in self.messages[-10:]
            ],
            "usage": terminal_projection(usage, max_string=256, max_items=20),
            "subscription": subscription,
            "connections": self._connection_projection(),
            "skills": [terminal_projection(name, max_string=64) for name in self._skill_names],
            "selected_skills": [
                terminal_projection(name, max_string=64)
                for name in self._effective_selected_skills()
            ],
            "skill_count": len(self._skill_names),
            "viewer_status": self.viewer_status,
            "viewer_url": terminal_projection(self.viewer_url, max_string=1024),
            "error": terminal_projection(self.error, max_string=2 * 1024),
        }
        return bounded_state_projection(state)

    def _connection_projection(self) -> list[dict[str, Any]]:
        """Configured MCP servers, with live session health when a scan has it.

        A server that has not connected, or whose session died, is ``dead``.
        The TUI paints that red and a live session green.
        """
        live = {
            str(entry.get("name", "")): entry
            for entry in self.mcp_connections
            if isinstance(entry, dict) and entry.get("name")
        }
        ordered = list(self._mcp_names)
        for name in live:
            if name not in ordered:
                ordered.append(name)
        ov_status: dict[str, Any] = {}
        with contextlib.suppress(Exception):
            ov_status = _cached_openviking_status()
            if ov_status.get("enabled", True) and "openviking" not in ordered:
                ordered.insert(0, "openviking")
        rows: list[dict[str, Any]] = []
        for name in ordered[:32]:
            if name == "openviking" and ov_status:
                ov_online = bool(ov_status.get("online", False))
                ov_tools = int(ov_status.get("tool_count", 13)) if ov_online else 0
                entry = live.get(name)
                if entry is not None and entry.get("tool_count", 0) > 0:
                    ov_tools = int(entry["tool_count"])
                rows.append(
                    {
                        "name": "openviking",
                        "tool_count": ov_tools,
                        "dead": not ov_online,
                    }
                )
                continue
            entry = live.get(name)
            if entry is None:
                rows.append(
                    {
                        "name": terminal_projection(name, max_string=64),
                        "tool_count": 0,
                        "dead": True,
                    }
                )
                continue
            rows.append(
                {
                    "name": terminal_projection(entry["name"], max_string=64),
                    "tool_count": entry["tool_count"],
                    "dead": entry["dead"],
                }
            )
        return rows

    def collection(self, name: str) -> list[dict[str, Any]]:
        """Return one bounded terminal projection with stable item identities."""
        if name == "agents":
            return [
                {
                    key: terminal_projection(agent.get(key), max_string=256, max_items=5)
                    for key in (
                        "id",
                        "name",
                        "parent_id",
                        "status",
                        "error_message",
                        "created_at",
                        "updated_at",
                    )
                    if key in agent
                }
                for agent in self.live_view.agents.values()
            ]
        if name == "events":
            return [collection_item_projection(event) for event in self.live_view.events]
        if name == "vulnerabilities":
            reports = (
                self.report_state.vulnerability_reports if self.report_state is not None else []
            )[-MAX_TERMINAL_VULNERABILITIES:]
            result: list[dict[str, Any]] = []
            for index, report in enumerate(reports):
                projected = collection_item_projection(report)
                report_id = projected.get("id")
                if not isinstance(report_id, str) or not report_id:
                    projected["id"] = f"vulnerability-{index}"
                result.append(projected)
            return result
        raise ValueError(f"Unknown collection: {name}")

    def collection_snapshot(self, name: str) -> tuple[int | None, list[dict[str, Any]]]:
        """Return a collection cursor and complete bounded projection."""
        if name == "events":
            cursor, events = self.live_view.event_snapshot(limit=MAX_TERMINAL_EVENTS)
            return cursor, [collection_item_projection(event) for event in events]
        return None, self.collection(name)

    def collection_changes(
        self,
        name: str,
        cursor: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Return event upserts since a monotonic source cursor."""
        if name != "events":
            raise ValueError(f"Collection {name!r} does not expose incremental changes")
        next_cursor, events = self.live_view.event_changes_since(cursor)
        return next_cursor, [
            collection_item_projection(event) for event in events[-MAX_TERMINAL_EVENTS:]
        ]

    async def handle(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "setup.add_target": self._add_target,
            "setup.set_instruction": self._set_instruction,
            "setup.start": self._start,
            "setup.confirm_mount": self._confirm_mount,
            "agent.send_message": self._send_message,
            "agent.stop": self._stop_agent,
            "viewer.open": self._open_viewer,
            "app.quit": self._quit,
            "llm.catalog": self._llm_catalog,
            "llm.connect": self._llm_connect,
            "llm.auth_status": self._llm_auth_status,
            "llm.auth_cancel": self._llm_auth_cancel,
            "llm.select_model": self._llm_select_model,
            "llm.set_effort": self._llm_set_effort,
            "llm.set_swarm": self._llm_set_swarm,
            "skills.catalog": self._skills_catalog,
            "skills.toggle": self._skills_toggle,
            "pentest.run": self._pentest_run,
        }
        handler = handlers.get(command)
        if handler is None:
            raise ValueError(f"Unknown command: {command}")
        result = await handler(payload)
        self.notify_changed()
        return result

    async def _add_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        target = self._required_string(payload, "target")
        if target not in self.targets:
            self.targets.append(target)
        return {"target": target, "total": len(self.targets)}

    async def _set_instruction(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        instruction = payload.get("instruction", "")
        if not isinstance(instruction, str):
            raise TypeError("instruction must be a string")
        self.instruction = instruction.strip()
        return {"instruction": self.instruction}

    async def _start(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.scan_started or self._start_in_progress:
            raise RuntimeError("Scan is already starting or running")
        # Launching with no target mounts the working directory, so it requires
        # the user's explicit confirmation rather than happening silently.
        mount_working_dir = payload.get("mount_working_dir", False)
        if not isinstance(mount_working_dir, bool):
            raise TypeError("mount_working_dir must be a boolean")
        model = (load_settings().llm.model or "").strip()
        if not model:
            raise ValueError("No model configured. Run /models to choose one.")
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        if not self.targets and not mount_working_dir:
            raise ValueError("No target set. Add a target first.")
        # The model check runs while still on the start screen, for a bare
        # prompt as much as for a named target, so a failure lands in the setup
        # log where the user can fix it and retry rather than in a dead run.
        await self._verify_model()
        if not self.targets:
            # Mounting the working directory needs the user's confirmation, and
            # that is asked in the live view. Enter it now and prepare nothing
            # until the answer arrives, so declining leaves no run behind.
            self.pending_workspace_mount = str(Path.cwd())
            self.setup_mode = False
            self.scan_started = True
            self.scan_state = "preparing"
            return {"started": True}
        await self._begin_scan()
        return {"started": True}

    async def _verify_model(self) -> None:
        if self._on_verify is None:
            return
        self._start_in_progress = True
        try:
            await self._on_verify()
        finally:
            self._start_in_progress = False

    async def _begin_scan(self) -> None:
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        self._start_in_progress = True
        try:
            await self._on_start()
        except Exception as exc:
            if not self.setup_mode:
                # The live view is already up, so the failure has to show there.
                self.fail_preparation(str(exc))
            raise
        finally:
            self._start_in_progress = False
        self.setup_mode = False
        self.scan_started = True
        self.scan_state = "running"

    async def _confirm_mount(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Answer the pending working-directory mount asked for in the live view."""
        mount = self.pending_workspace_mount
        if mount is None:
            raise RuntimeError("No mount confirmation is pending")
        approved = payload.get("approved")
        if not isinstance(approved, bool):
            raise TypeError("approved must be a boolean")
        self.pending_workspace_mount = None
        # Declining skips the mount, it does not abandon the scan. The prompt is
        # the whole of the input either way; the working directory is only an
        # extra the agent may look at, so the run goes ahead without one.
        self.workspace_mount = mount if approved else None
        await self._begin_scan()
        return {"approved": approved}

    async def _send_message(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = self._required_string(payload, "agent_id")
        message = self._required_string(payload, "message")
        if self.coordinator is None:
            raise RuntimeError("Agent coordinator is unavailable")
        if self.scan_loop is None or self.scan_loop.is_closed():
            raise RuntimeError("Scan loop is not ready")
        self.live_view.record_user_message(agent_id, message)
        if self.scan_loop is asyncio.get_running_loop():
            delivered = await self.coordinator.send(
                agent_id,
                {"from": "user", "content": message, "type": "instruction"},
            )
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.coordinator.send(
                    agent_id,
                    {"from": "user", "content": message, "type": "instruction"},
                ),
                self.scan_loop,
            )
            delivered = await asyncio.wrap_future(future)
        if not delivered:
            raise RuntimeError("Message could not be delivered")
        self.live_view.upsert_agent(agent_id, status="waiting", error_message=None)
        return {"sent": True}

    async def _stop_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = self._required_string(payload, "agent_id")
        agent = self.live_view.agents.get(agent_id)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_id}")
        status = str(agent.get("status", ""))
        if status not in _STOPPABLE_AGENT_STATUSES:
            raise RuntimeError(f"Agent '{agent_id}' cannot be stopped while {status or 'unknown'}")
        if self.coordinator is None or self.scan_loop is None or self.scan_loop.is_closed():
            raise RuntimeError("Scan loop is not ready")
        if self.scan_loop is asyncio.get_running_loop():
            accepted = await self.coordinator.cancel_descendants_graceful(agent_id)
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.coordinator.cancel_descendants_graceful(agent_id), self.scan_loop
            )
            accepted = await asyncio.wrap_future(future)
        if not accepted:
            raise RuntimeError(f"Agent '{agent_id}' is no longer active")
        return {"stopped": True}

    async def _open_viewer(self, _payload: dict[str, Any]) -> dict[str, Any]:
        if self.viewer_url:
            with contextlib.suppress(Exception):
                webbrowser.open(self.viewer_url)
            return {"status": "running", "url": self.viewer_url}
        if self.report_state is None:
            self.viewer_status = "failed"
            return {"status": self.viewer_status, "error": "Scan output is not ready"}
        try:
            from redjohn.interface.tui.backend.messages import (
                send_user_message_to_agent,
            )
            from redjohn.interface.viewer.server import (
                authorized_url,
                bundle_is_built,
                serve,
            )

            if not bundle_is_built():
                self.viewer_status = "unavailable"
                return {"status": self.viewer_status, "error": "Viewer UI not built"}

            def steer(agent_id: str, message: str) -> bool:
                return send_user_message_to_agent(
                    coordinator=self.coordinator,
                    loop=self.scan_loop,
                    live_view=self.live_view,
                    target_agent_id=agent_id,
                    message=message,
                    notify_changed=self.notify_changed,
                    wait_for_delivery=True,
                )

            httpd, url, token = serve(
                self.report_state.get_run_dir(),
                open_browser=True,
                steer_handler=steer,
            )
            self._viewer_httpd = httpd
            self.viewer_url = authorized_url(url, token)
            self.viewer_status = "running"
            with contextlib.suppress(Exception):
                from redjohn.telemetry import posthog

                live = self.report_state.run_record.get("status") not in {
                    "completed",
                    "stopped",
                    "failed",
                    "interrupted",
                }
                await asyncio.to_thread(posthog.viewer_opened, source="tui", live=live)
        except Exception:  # noqa: BLE001 - viewer startup failures must not crash the TUI
            self.viewer_status = "failed"
            return {"status": self.viewer_status, "error": "Viewer failed to start"}
        else:
            return {"status": self.viewer_status, "url": self.viewer_url}

    def close_viewer(self) -> None:
        httpd = self._viewer_httpd
        if httpd is None:
            return
        self._viewer_httpd = None
        with contextlib.suppress(Exception):
            httpd.shutdown()
            httpd.server_close()

    async def _quit(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self.close_viewer()
        if self._on_quit is not None:
            await self._on_quit()
        self.scan_state = "stopped"
        return {"quitting": True}

    async def _llm_catalog(self, _payload: dict[str, Any]) -> dict[str, Any]:
        return self._llm_picker.catalog()

    async def _llm_connect(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._llm_picker.connect(payload)

    async def _llm_auth_status(self, _payload: dict[str, Any]) -> dict[str, Any]:
        return self._llm_picker.auth_status()

    async def _llm_auth_cancel(self, _payload: dict[str, Any]) -> dict[str, Any]:
        return self._llm_picker.cancel()

    async def _llm_select_model(self, payload: dict[str, Any]) -> dict[str, Any]:
        model_id = payload.get("model")
        if not isinstance(model_id, str):
            raise TypeError("model must be a string")
        target = str(payload.get("target") or payload.get("scope") or "both")
        role = payload.get("role")
        return self._llm_picker.select_model(
            model_id,
            scan_started=self.scan_started,
            target=target,
            role=role if isinstance(role, str) else None,
        )

    async def _llm_set_effort(self, payload: dict[str, Any]) -> dict[str, Any]:
        effort = payload.get("effort")
        if not isinstance(effort, str):
            raise TypeError("effort must be a string")
        target = str(payload.get("target") or "orchestrator")
        return self._llm_picker.set_effort(
            effort,
            scan_started=self.scan_started,
            target=target,
        )

    async def _llm_set_swarm(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._llm_picker.set_swarm(payload, scan_started=self.scan_started)

    def _effective_selected_skills(self) -> list[str]:
        merged = list(self.selected_skills)
        if not self.scan_started:
            return merged
        selectable_names = {
            entry["name"]: entry["id"]
            for entry in self._skill_catalog
            if entry.get("selectable", True)
        }
        with contextlib.suppress(Exception):
            from redjohn.skills import get_loaded_skill_names

            for loaded_name in get_loaded_skill_names():
                canonical = selectable_names.get(loaded_name)
                if canonical and canonical not in merged and loaded_name not in merged:
                    merged.append(canonical)
        return merged

    async def _skills_catalog(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self._skill_catalog = _skill_catalog()
        self._skill_names = [entry["name"] for entry in self._skill_catalog]
        effective = self._effective_selected_skills()
        selected_set = set(effective)
        entries = [
            {
                **entry,
                "selected": entry["id"] in selected_set or entry["name"] in selected_set,
            }
            for entry in self._skill_catalog
        ]
        return {
            "skills": entries,
            "selected": effective,
            "selected_skills": effective,
            "total": len(entries),
        }

    async def _skills_toggle(self, payload: dict[str, Any]) -> dict[str, Any]:
        skill_id = str(
            payload.get("skill") or payload.get("id") or payload.get("name") or ""
        ).strip()
        if not skill_id:
            self.selected_skills.clear()
            return {"selected": [], "cleared": True}
        self._skill_catalog = _skill_catalog()
        match = next(
            (
                entry
                for entry in self._skill_catalog
                if entry["id"] == skill_id or entry["name"] == skill_id
            ),
            None,
        )
        if match is None:
            raise ValueError(f"Unknown skill: {skill_id}")
        if not match.get("selectable", True):
            raise ValueError(
                f"Skill '{match['name']}' is a core system contract and is always active"
            )
        canonical = str(match["id"])
        if canonical in self.selected_skills:
            self.selected_skills.remove(canonical)
            active = False
        elif match["name"] in self.selected_skills:
            self.selected_skills.remove(match["name"])
            active = False
        else:
            if len(self.selected_skills) >= 8:
                raise ValueError("Maximum 8 specialist skills can be pinned at once")
            self.selected_skills.append(canonical)
            active = True
        selected_set = set(self.selected_skills)
        entries = [
            {
                **entry,
                "selected": entry["id"] in selected_set or entry["name"] in selected_set,
            }
            for entry in self._skill_catalog
        ]
        return {
            "id": canonical,
            "name": match["name"],
            "active": active,
            "selected": list(self.selected_skills),
            "selected_skills": list(self.selected_skills),
            "skills": entries,
        }

    async def _pentest_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Launch or extend a Swarm pentest directly from ``/rj <target> [instructions]``."""
        raw = str(payload.get("raw") or "").strip()
        explicit_target = str(payload.get("target") or "").strip()
        explicit_instruction = str(payload.get("instruction") or "").strip()
        if raw and not explicit_target:
            parts = raw.split(maxsplit=1)
            explicit_target = parts[0].strip()
            if len(parts) > 1 and not explicit_instruction:
                explicit_instruction = parts[1].strip()
        if not explicit_target:
            raise ValueError("Usage: /rj <target> [instructions]")

        if explicit_target not in self.targets:
            self.targets.append(explicit_target)
        if explicit_instruction:
            self.instruction = explicit_instruction

        if not self.scan_started:
            await self._start({"mount_working_dir": False})
            return {
                "started": True,
                "target": explicit_target,
                "instruction": self.instruction,
            }

        root_id = self._root_agent_id()
        if not root_id:
            raise RuntimeError("No active Coordinator agent found for this session")
        swarm_directive = (
            f"[OPERATOR /rj PENTEST COMMAND]\n"
            f"Target added to scope: {explicit_target}\n"
            + (f"Operator instructions: {explicit_instruction}\n" if explicit_instruction else "")
            + "Immediately decompose this target and spawn specialist Swarm agents "
            "to execute the assessment."
        )
        await self._send_message({"agent_id": root_id, "message": swarm_directive})
        return {
            "started": True,
            "dispatched_to": root_id,
            "target": explicit_target,
            "instruction": explicit_instruction,
        }

    def _root_agent_id(self) -> str | None:
        for agent_id, agent in self.live_view.agents.items():
            if not agent.get("parent_id"):
                return str(agent_id)
        if self.live_view.agents:
            return str(next(iter(self.live_view.agents)))
        return None

    @staticmethod
    def _required_string(payload: dict[str, Any], name: str) -> str:
        value = payload.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    def _require_setup_mutable(self) -> None:
        if not self.setup_mode or self.scan_started or self._start_in_progress:
            raise RuntimeError("Setup can no longer be changed after the scan starts")


def _configured_mcp_names() -> list[str]:
    try:
        from redjohn.tools.mcp.loader import load_user_mcp_configs

        return [config.name for config in load_user_mcp_configs()]
    except (ImportError, OSError, ValueError, RuntimeError):
        return []


def _skill_catalog() -> list[dict[str, Any]]:
    try:
        from redjohn.skills import discover_skill_catalog

        return [entry.to_dict() for entry in discover_skill_catalog(include_internal=True)]
    except (ImportError, OSError, ValueError, RuntimeError):
        return []


def _skill_names() -> list[str]:
    return [entry["name"] for entry in _skill_catalog()]
