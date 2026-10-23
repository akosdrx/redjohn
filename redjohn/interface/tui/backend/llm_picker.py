"""Model and effort selection for the Go TUI.

OAuth polling runs on a background task so the IPC read loop stays free. The
device code and API key never go back to the terminal; the TUI only sees the
user code, the verification URL, and the model ids.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from redjohn.config import codex, grok, load_settings
from redjohn.config.loader import (
    save_llm_selection,
    save_openviking_selection,
    save_swarm_llm_selection,
)
from redjohn.config.model_catalog import (
    EFFORTS,
    CatalogEntry,
    catalog_payload,
    connection_clears_base,
    find_entry,
    format_model_setting,
    list_models,
    resolve_model_effort_spec,
    short_model_label,
)
from redjohn.interface.auth_cli import (
    _CallbackServer,
    begin_chatgpt_browser_login,
    finish_chatgpt_browser_login,
)


logger = logging.getLogger(__name__)

_BROWSER_TIMEOUT_S = 300.0
DevicePoll = Callable[[], dict[str, Any] | str | None]


@dataclass
class PendingLink:
    entry: CatalogEntry
    api_key: str | None


class LlmPicker:
    """One in-flight sign-in plus the connection waiting for a model choice."""

    def __init__(self) -> None:
        self._generation = 0
        self._task: asyncio.Task[None] | None = None
        self._status: dict[str, Any] = {"phase": "idle"}
        self._pending: PendingLink | None = None
        self._browser: _CallbackServer | None = None

    def catalog(self) -> dict[str, Any]:
        return catalog_payload()

    async def connect(self, payload: dict[str, Any]) -> dict[str, Any]:
        entry_id = payload.get("id")
        if not isinstance(entry_id, str) or not entry_id.strip():
            raise ValueError("id is required")
        entry = find_entry(entry_id.strip())
        if entry is None or entry.auth is None:
            raise ValueError(f"Unknown provider: {entry_id}")
        self.cancel()
        try:
            if entry.auth == "api_key":
                return await self._connect_api_key(entry, payload.get("api_key"))
            if entry.auth == "oauth_browser":
                return self._connect_browser(entry)
            return self._connect_device(entry)
        except (codex.CodexAuthError, grok.GrokAuthError) as exc:
            raise RuntimeError(str(exc)) from exc

    def auth_status(self) -> dict[str, Any]:
        return dict(self._status)

    def cancel(self) -> dict[str, Any]:
        self._generation += 1
        task = self._task
        self._task = None
        if task is not None and not task.done():
            task.cancel()
        browser = self._browser
        self._browser = None
        if browser is not None:
            browser.cancel()
        self._pending = None
        self._status = {"phase": "idle"}
        return {"cancelled": True}

    def select_model(
        self,
        model_id: str,
        *,
        scan_started: bool,
        target: str = "both",
        role: str | None = None,
    ) -> dict[str, Any]:
        pending = self._pending
        if pending is None:
            raise RuntimeError("Connect a provider before choosing a model.")
        if not isinstance(model_id, str) or not model_id.strip():
            raise ValueError("model is required")
        setting = format_model_setting(pending.entry.route, model_id)
        clear_base = connection_clears_base(pending.entry)
        subscription = pending.entry.route in {"chatgpt", "grok"}
        spec = resolve_model_effort_spec(setting)
        default_effort = spec.default_effort or "high"
        normalized_target = (target or "both").strip().lower()
        clean_role = role.strip().lower() if isinstance(role, str) and role.strip() else None

        if clean_role:
            save_swarm_llm_selection(
                role=clean_role,
                role_model=setting,
                swarm_api_key=None if subscription else pending.api_key,
                swarm_api_base=None if clear_base else pending.entry.api_base,
                clear_swarm_api_key=subscription,
                clear_swarm_api_base=clear_base,
            )
        elif normalized_target == "openviking":
            save_openviking_selection(
                enabled=True,
                vlm_model=setting,
                vlm_api_key=None if subscription else pending.api_key,
                vlm_api_base=None if clear_base else pending.entry.api_base,
                clear_vlm_api_key=subscription,
                clear_vlm_api_base=clear_base,
            )
            with contextlib.suppress(Exception):
                from redjohn.memory.openviking.config import ensure_openviking_configured

                ensure_openviking_configured()
        elif normalized_target == "swarm":
            save_swarm_llm_selection(
                swarm_model=setting,
                swarm_api_key=None if subscription else pending.api_key,
                swarm_api_base=None if clear_base else pending.entry.api_base,
                swarm_reasoning_effort=default_effort,
                clear_swarm_api_key=subscription,
                clear_swarm_api_base=clear_base,
            )
        else:
            save_llm_selection(
                model=setting,
                model_label=short_model_label(setting),
                supported_efforts=spec.supported_efforts,
                api_key=None if subscription else pending.api_key,
                api_base=None if clear_base else pending.entry.api_base,
                reasoning_effort=default_effort,
                clear_api_key=subscription,
                clear_api_base=clear_base,
                propagate_to_swarm=(normalized_target == "both"),
            )
        self._pending = None
        self._status = {"phase": "idle"}
        return {
            "model": setting,
            "short_model": short_model_label(setting),
            "effort": default_effort,
            "supported_efforts": list(spec.supported_efforts),
            "target": normalized_target,
            "role": clean_role or "",
            "applied": "live" if scan_started else "saved",
        }

    def set_effort(
        self,
        effort: str,
        *,
        scan_started: bool,
        target: str = "orchestrator",
    ) -> dict[str, Any]:
        if not isinstance(effort, str):
            raise TypeError("effort must be a string")
        normalized = effort.strip().lower()
        if normalized not in EFFORTS:
            choices = ", ".join(EFFORTS)
            raise ValueError(f"effort must be one of: {choices}")
        llm = load_settings().llm
        normalized_target = (target or "orchestrator").strip().lower()
        active_model = (
            (llm.swarm_model or llm.model or "").strip()
            if normalized_target == "swarm"
            else (llm.model or "").strip()
        )
        if not active_model:
            raise ValueError("Select a model with /models before setting reasoning effort.")
        spec = resolve_model_effort_spec(active_model)
        if spec.supported_efforts and normalized not in spec.supported_efforts:
            supported = ", ".join(spec.supported_efforts)
            raise ValueError(
                f"{short_model_label(active_model)} supports effort levels: {supported}"
            )
        if normalized_target == "swarm":
            save_swarm_llm_selection(swarm_reasoning_effort=normalized)
        else:
            save_llm_selection(reasoning_effort=normalized)
            if not (llm.swarm_model or "").strip():
                save_swarm_llm_selection(swarm_reasoning_effort=normalized)
        return {
            "effort": normalized,
            "target": normalized_target,
            "applied": "live" if scan_started else "saved",
        }

    def set_swarm(self, payload: dict[str, Any], *, scan_started: bool) -> dict[str, Any]:
        action = str(payload.get("action") or "").strip().lower()
        if action == "inherit":
            save_swarm_llm_selection(clear_swarm_model=True, clear_role_models=True)
            return {"status": "inherit", "applied": "live" if scan_started else "saved"}
        if action == "clear_roles":
            save_swarm_llm_selection(clear_role_models=True)
            return {"status": "roles_cleared", "applied": "live" if scan_started else "saved"}
        if action == "profile" or ("profile" in payload and not action):
            profile = str(payload.get("profile") or "full").strip().lower()
            valid_profiles = {
                "full",
                "balanced",
                "fast",
                "deep",
                "recon",
                "exploit",
                "whitebox",
                "single",
            }
            if profile not in valid_profiles:
                raise ValueError("Invalid swarm profile")
            save_swarm_llm_selection(swarm_profile=profile)
            return {
                "status": "profile_updated",
                "swarm_profile": profile,
                "applied": "live" if scan_started else "saved",
            }
        if action == "set_model":
            model = str(payload.get("model") or "").strip()
            if not model:
                raise ValueError("model is required")
            role = str(payload.get("role") or "").strip().lower() or None
            spec = resolve_model_effort_spec(model)
            if role:
                save_swarm_llm_selection(role=role, role_model=model)
            else:
                save_swarm_llm_selection(
                    swarm_model=model,
                    swarm_reasoning_effort=spec.default_effort or "high",
                )
            return {
                "status": "model_updated",
                "model": model,
                "role": role or "",
                "applied": "live" if scan_started else "saved",
            }
        if action == "openviking_inherit":
            save_openviking_selection(
                enabled=True,
                clear_vlm_model=True,
                clear_vlm_api_key=True,
                clear_vlm_api_base=True,
            )
            with contextlib.suppress(Exception):
                from redjohn.memory.openviking.config import ensure_openviking_configured

                ensure_openviking_configured()
            return {"status": "openviking_inherit", "applied": "live" if scan_started else "saved"}
        if action == "openviking_embed":
            embed_provider = str(payload.get("provider") or "local").strip().lower()
            if embed_provider == "openai":
                save_openviking_selection(
                    enabled=True,
                    embedding_provider="openai",
                    embedding_model="text-embedding-3-small",
                    embedding_dimension=1536,
                )
            else:
                save_openviking_selection(
                    enabled=True,
                    embedding_provider="local",
                    embedding_model="bge-small-zh-v1.5-f16",
                    embedding_dimension=512,
                )
            with contextlib.suppress(Exception):
                from redjohn.memory.openviking.config import ensure_openviking_configured

                ensure_openviking_configured()
            return {
                "status": "openviking_embed_updated",
                "embedding_provider": embed_provider,
                "applied": "live" if scan_started else "saved",
            }
        if action == "openviking_toggle":
            new_enabled = not bool(load_settings().openviking.enabled)
            save_openviking_selection(enabled=new_enabled)
            with contextlib.suppress(Exception):
                from redjohn.memory.openviking.config import ensure_openviking_configured

                ensure_openviking_configured()
            return {
                "status": "openviking_toggled",
                "enabled": new_enabled,
                "applied": "live" if scan_started else "saved",
            }
        if action == "openviking_set_model":
            model = str(payload.get("model") or "").strip()
            if not model:
                raise ValueError("model is required")
            save_openviking_selection(enabled=True, vlm_model=model)
            with contextlib.suppress(Exception):
                from redjohn.memory.openviking.config import ensure_openviking_configured

                ensure_openviking_configured()
            return {
                "status": "openviking_model_updated",
                "model": model,
                "applied": "live" if scan_started else "saved",
            }
        raise ValueError(f"Unknown swarm action: {action}")

    async def _connect_api_key(self, entry: CatalogEntry, api_key: object) -> dict[str, Any]:
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("API key is required")
        key = api_key.strip()
        models, source = await asyncio.to_thread(list_models, entry, key)
        self._pending = PendingLink(entry=entry, api_key=key)
        status = _models_status(entry, models, source)
        self._status = status
        return status

    def _connect_browser(self, entry: CatalogEntry) -> dict[str, Any]:
        url, verifier, state, server = begin_chatgpt_browser_login()
        self._browser = server
        generation = self._generation
        self._status = {
            "phase": "browser",
            "url": url,
            "message": "Finish signing in in the browser.",
        }
        self._task = asyncio.create_task(
            self._finish_browser(entry, generation, server, verifier, state)
        )
        return dict(self._status)

    def _connect_device(self, entry: CatalogEntry) -> dict[str, Any]:
        if entry.route == "grok":
            started = grok.start_device_code()
            poll = _grok_poll(str(started["device_code"]))
        else:
            started = codex.start_device_code()
            poll = _codex_poll(str(started["device_auth_id"]), str(started["user_code"]))
        _open_browser(str(started["verification_url"]))
        generation = self._generation
        self._status = {
            "phase": "device",
            "url": started["verification_url"],
            "user_code": started["user_code"],
            "message": "Enter the code in the browser, then wait here.",
        }
        self._task = asyncio.create_task(
            self._poll_device(
                entry,
                generation,
                interval=float(started["interval"]),
                deadline=time.time() + float(started["expires_in"]),
                poll=poll,
            )
        )
        return dict(self._status)

    async def _finish_browser(
        self,
        entry: CatalogEntry,
        generation: int,
        server: _CallbackServer,
        verifier: str,
        state: str,
    ) -> None:
        try:
            record = await asyncio.to_thread(
                finish_chatgpt_browser_login,
                server,
                verifier,
                state,
                _BROWSER_TIMEOUT_S,
            )
        except asyncio.CancelledError:
            raise
        except (codex.CodexAuthError, OSError, ValueError, RuntimeError) as exc:
            logger.debug("ChatGPT browser sign-in failed", exc_info=True)
            self._fail(generation, str(exc))
            return
        finally:
            if self._browser is server:
                self._browser = None
        if generation != self._generation:
            return
        codex.save_record(record)
        self._ready(entry, generation, api_key=None)

    async def _poll_device(
        self,
        entry: CatalogEntry,
        generation: int,
        *,
        interval: float,
        deadline: float,
        poll: DevicePoll,
    ) -> None:
        wait = max(interval, 1.0)
        try:
            while time.time() < deadline:
                await asyncio.sleep(wait)
                if generation != self._generation:
                    return
                result = await asyncio.to_thread(poll)
                if generation != self._generation:
                    return
                if result is None or result == "pending":
                    continue
                if result == "slow_down":
                    wait = min(wait + 5.0, 30.0)
                    continue
                if not isinstance(result, dict):
                    self._fail(generation, "Sign-in returned an unexpected response.")
                    return
                self._store_device_record(entry, result)
                token = None if entry.route == "chatgpt" else _access_token(result)
                self._ready(entry, generation, api_key=token)
                return
        except asyncio.CancelledError:
            raise
        except (
            codex.CodexAuthError,
            grok.GrokAuthError,
            OSError,
            ValueError,
            RuntimeError,
        ) as exc:
            logger.debug("Device sign-in failed", exc_info=True)
            self._fail(generation, str(exc))
            return
        self._fail(generation, "Sign-in timed out.")

    def _store_device_record(self, entry: CatalogEntry, result: dict[str, Any]) -> None:
        if entry.route == "grok":
            grok.save_record(result)
            return
        codex.save_record(result)

    def _ready(self, entry: CatalogEntry, generation: int, *, api_key: str | None) -> None:
        if generation != self._generation:
            return
        try:
            models, source = list_models(entry, api_key)
        except (OSError, ValueError, RuntimeError) as exc:
            logger.debug("Model list failed after sign-in", exc_info=True)
            self._fail(generation, str(exc))
            return
        stored_key = None if entry.route in {"chatgpt", "grok"} else api_key
        self._pending = PendingLink(entry=entry, api_key=stored_key)
        self._status = _models_status(entry, models, source)

    def _fail(self, generation: int, message: str) -> None:
        if generation != self._generation:
            return
        self._pending = None
        self._status = {"phase": "error", "message": message}


def _models_status(
    entry: CatalogEntry,
    models: list[dict[str, str]],
    source: str,
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "phase": "models",
        "provider": entry.label,
        "models": models,
        "source": source,
    }
    if source == "fallback":
        status["note"] = "Showing the built-in model list."
    return status


def _access_token(result: dict[str, Any]) -> str | None:
    access = result.get("access")
    return access if isinstance(access, str) and access else None


def _grok_poll(device_code: str) -> DevicePoll:
    def poll() -> dict[str, Any] | str | None:
        return grok.poll_device_code(device_code)

    return poll


def _codex_poll(device_auth_id: str, user_code: str) -> DevicePoll:
    def poll() -> dict[str, Any] | str | None:
        return codex.poll_device_code(device_auth_id, user_code)

    return poll


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        logger.debug("could not open browser", exc_info=True)
