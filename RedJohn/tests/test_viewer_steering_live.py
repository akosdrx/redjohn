"""Actual Chromium -> authenticated Viewer -> coordinator -> SQLite session.

All transport and UI code is real. The owned agent has no LLM runner, therefore
delivery/retry evidence is not a live model response or full provider E2E.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import httpx
import pytest
from playwright.async_api import async_playwright, expect

from redjohn.config import loader
from redjohn.core.agents import AgentCoordinator
from redjohn.core.sessions import open_agent_session
from redjohn.interface.tui.backend.live_view import TuiLiveView
from redjohn.interface.tui.backend.messages import send_user_message_to_agent
from redjohn.interface.viewer import auth, server


if TYPE_CHECKING:
    from pathlib import Path


async def test_actual_viewer_steering_delivery_denial_and_retry(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not server.bundle_is_built():
        pytest.skip("blocked_missing_dependency: build actual Viewer assets first")
    # Only paths and telemetry configuration are isolated; no handlers,
    # responses, browser transports or delivery functions are replaced.
    monkeypatch.setattr(auth, "AUTH_PATH", tmp_path / "viewer-auth.json")
    monkeypatch.setattr(loader, "_override", tmp_path / "isolated-config.json")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setenv("REDJOHN_TELEMETRY", "0")
    output = tmp_path / "owned-run"
    output.mkdir()
    (output / "run.json").write_text(
        json.dumps(
            {
                "run_id": "owned-viewer-run",
                "run_name": "Owned Viewer delivery fixture",
                "status": "running",
                "start_time": "2026-01-01T00:00:00Z",
                "targets_info": [{"original": "http://127.0.0.1"}],
                "user_instruction": "Owned delivery fixture; no model execution",
            }
        )
    )
    coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(output / ".state" / "agents.json")
    await coordinator.register("owned-worker", "Owned Viewer worker", None)
    session = open_agent_session("owned-worker", output / ".state" / "agents.db")
    await session.add_items([{"role": "user", "content": "Internal owned fixture task"}])
    await coordinator.attach_runtime("owned-worker", session=session, resumable=True)
    live_view = TuiLiveView()
    loop = asyncio.get_running_loop()

    def steer(agent_id: str, message: str) -> bool:
        return send_user_message_to_agent(
            coordinator=coordinator,
            loop=loop,
            live_view=live_view,
            target_agent_id=agent_id,
            message=message,
            wait_for_delivery=True,
        )

    httpd, base, token = server.serve(output, open_browser=False, steer_handler=steer)
    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            denied = await client.post(
                base + "/api/agents/steer",
                json={"agent_id": "owned-worker", "message": "unauthenticated"},
            )
            assert denied.status_code == 403
            assert coordinator.pending_counts["owned-worker"] == 0
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                context = await browser.new_context(
                    viewport={"width": 1440, "height": 1100}, reduced_motion="reduce"
                )
                page = await context.new_page()
                failures: list[str] = []
                page.on("pageerror", lambda error: failures.append(str(error)))
                await page.goto(server.authorized_url(base, token), wait_until="domcontentloaded")
                await page.get_by_role("button", name="Expand live prompt composer").click()
                composer = page.get_by_placeholder("Send a live prompt to the running pentest…")
                await composer.fill("Retest the owned fixed fixture")
                await page.get_by_role("button", name="Send prompt", exact=True).click()
                await expect(page.get_by_text("Sent to Root agent", exact=True)).to_be_visible()
                assert coordinator.pending_counts["owned-worker"] == 1
                count, _items = await coordinator.consume_pending(
                    "owned-worker", include_items=True
                )
                assert count == 1
                assert "Retest the owned fixed fixture" in str(await session.get_items())

                # A terminal agent without a resume loop is not reachable.
                await coordinator.request_stop("owned-worker")
                await coordinator.attach_runtime("owned-worker", resumable=False)
                await composer.fill("Do not lose this retry instruction")
                await composer.press("Enter")
                await expect(
                    page.get_by_text(
                        "Could not reach that agent (it may have finished).", exact=True
                    )
                ).to_be_visible()
                await expect(composer).to_have_value("Do not lose this retry instruction")
                await expect(
                    page.get_by_role("button", name="Send prompt", exact=True)
                ).to_be_enabled()
                assert coordinator.pending_counts["owned-worker"] == 0

                await coordinator.attach_runtime("owned-worker", resumable=True)
                await page.get_by_role("button", name="Send prompt", exact=True).click()
                await expect(page.get_by_text("Sent to Root agent", exact=True)).to_be_visible()
                await expect(composer).to_have_value("")
                assert coordinator.statuses["owned-worker"] == "waiting"
                await coordinator.consume_pending("owned-worker", include_items=True)
                assert "Do not lose this retry instruction" in str(await session.get_items())
                assert len(live_view.events) == 2
                assert not failures
                await context.close()
            finally:
                await browser.close()
    finally:
        await asyncio.to_thread(httpd.shutdown)
        httpd.server_close()
        session.close()
