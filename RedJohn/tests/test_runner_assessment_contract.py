"""Root wiring/fault contracts with model and sandbox startup doubles.

The runner, coordinator, SDK session, approval files and assessment service are
real. These tests do not claim live model, sandbox or UI interaction coverage.
"""

import asyncio
import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from redjohn.config.settings import LlmSettings, Settings
from redjohn.core import execution, runner
from redjohn.tools.mcp import McpConnectionConfig, McpConnectionRequest
from tests.test_host_assessment_live import invoke
from tests.test_host_binding_contract import scan_for


@pytest.fixture
def root_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("REDJOHN_ASSESSMENT_APPROVAL_KEY", str(tmp_path / "keys/host.key"))
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "pool.sqlite3"))
    settings = Settings(llm=LlmSettings(model="contract-model", api_key="synthetic-test-key"))
    monkeypatch.setattr(runner, "load_settings", lambda: settings)
    monkeypatch.setattr("redjohn.agents.factory.load_settings", lambda: settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda *_: None)
    monkeypatch.setattr(runner, "configure_sdk_api_route", lambda *_: None)
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan: tmp_path / "run")
    logging_closed = []
    monkeypatch.setattr(
        runner, "setup_scan_logging", lambda _path: lambda: logging_closed.append(True)
    )
    create = AsyncMock(
        return_value={
            "client": SimpleNamespace(),
            "session": SimpleNamespace(),
            "caido_client": SimpleNamespace(),
        }
    )
    cleanup = AsyncMock()
    monkeypatch.setattr(runner.session_manager, "create_or_reuse", create)
    monkeypatch.setattr(runner.session_manager, "cleanup", cleanup)
    return SimpleNamespace(
        settings=settings,
        logging_closed=logging_closed,
        create=create,
        cleanup=cleanup,
        output=tmp_path / "run",
    )


async def test_root_binds_actual_service_and_keeps_configured_mcps_inert(
    root_environment, monkeypatch
):
    seen = []

    async def model_loop(**kwargs):
        context = kwargs["context"]
        service = context["assessment_service"]
        seen.append(service)
        assert context["assessment_governor"] is service.governor
        assert context["mcp_registry"].statuses()[0].state == "configured"
        health = await invoke(service, "system_health")
        assert health["ok"] is True
        assert health["result"]["controller"]["mode"] == "host_bound_persistent_scheduler"
        assert "HOST-BOUND ASSESSMENT" in kwargs["agent"].instructions
        assert "caller-spoof" not in kwargs["agent"].instructions
        await kwargs["coordinator"].set_status(kwargs["agent_id"], "completed")

    monkeypatch.setattr(runner, "run_agent_loop", model_loop)
    request = McpConnectionRequest(
        config=McpConnectionConfig(
            name="inert-contract", transport="stdio", command="must-not-run-redjohn-contract"
        )
    )
    await runner.run_redjohn_scan(
        scan_config=scan_for("https://example.invalid"),
        image="startup-double",
        scan_id="root-bound",
        mcp_connection_requests=[request],
    )
    assert len(seen) == 1
    assert (await invoke(seen[0], "system_health"))["error"]["code"] == "engagement_runtime_closed"
    report = json.loads((root_environment.output / "assessment-report.json").read_text())
    assert report["metrics"]["resources"]["active"] == {}
    assert root_environment.logging_closed == [True]
    root_environment.cleanup.assert_awaited_once_with("root-bound")


async def test_prompt_context_cannot_replace_host_approval(root_environment, monkeypatch):
    model_loop = AsyncMock()
    monkeypatch.setattr(runner, "run_agent_loop", model_loop)
    with pytest.raises(ValueError, match="cannot override built-in scope keys"):
        await runner.run_redjohn_scan(
            scan_config=scan_for("https://example.invalid"),
            image="startup-double",
            scan_id="context-injection",
            mcp_connection_requests=[],
            extra_system_prompt_context={"assessment": {"caller": "caller-spoof"}},
        )
    model_loop.assert_not_awaited()
    assert root_environment.logging_closed == [True]
    assert not (root_environment.output / ".state/assessment-host.json").exists()
    assert not (root_environment.output / ".state/agents.json").exists()


@pytest.mark.parametrize("failure", ["model_configuration", "sandbox_start"])
async def test_early_root_failures_always_close_logging(root_environment, failure):
    if failure == "model_configuration":
        root_environment.settings.llm.model = None
    else:
        root_environment.create.side_effect = RuntimeError("sandbox-start-contract-failure")
    with pytest.raises(RuntimeError):
        await runner.run_redjohn_scan(
            scan_config=scan_for("https://example.invalid"),
            image="startup-double",
            scan_id="early-failure",
            mcp_connection_requests=[],
        )
    assert root_environment.logging_closed == [True]
    assert not (root_environment.output / ".state/assessment-host.json").exists()
    assert not (root_environment.output / ".state/agents.json").exists()


async def test_sandbox_cleanup_failure_still_closes_host_service(root_environment, monkeypatch):
    seen = []

    async def model_loop(**kwargs):
        seen.append(kwargs["context"]["assessment_service"])

    monkeypatch.setattr(runner, "run_agent_loop", model_loop)
    root_environment.cleanup.side_effect = RuntimeError("sandbox-cleanup-contract-failure")
    with pytest.raises(RuntimeError, match="sandbox-cleanup-contract-failure"):
        await runner.run_redjohn_scan(
            scan_config=scan_for("https://example.invalid"),
            image="startup-double",
            scan_id="cleanup-failure",
            mcp_connection_requests=[],
        )
    assert (await invoke(seen[0], "system_health"))["error"]["code"] == "engagement_runtime_closed"
    assert root_environment.logging_closed == [True]


async def test_root_cancellation_closes_the_bound_service(root_environment, monkeypatch):
    ready = asyncio.Event()
    seen = []

    async def model_loop(**kwargs):
        seen.append(kwargs["context"]["assessment_service"])
        ready.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(runner, "run_agent_loop", model_loop)
    task = asyncio.create_task(
        runner.run_redjohn_scan(
            scan_config=scan_for("https://example.invalid"),
            image="startup-double",
            scan_id="cancelled-root",
            mcp_connection_requests=[],
        )
    )
    await asyncio.wait_for(ready.wait(), timeout=5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)
    assert (await invoke(seen[0], "system_health"))["error"]["code"] == "engagement_runtime_closed"
    assert root_environment.logging_closed == [True]


async def test_child_receives_the_same_host_service_and_governor(root_environment, monkeypatch):
    child_ready = asyncio.Event()
    parent_contexts, child_contexts = [], []

    async def child_loop(**kwargs):
        context = kwargs["context"]
        child_contexts.append(context)
        assert (await invoke(context["assessment_service"], "system_health"))["ok"] is True
        await kwargs["coordinator"].set_status(kwargs["agent_id"], "completed")
        child_ready.set()

    async def root_loop(**kwargs):
        context = kwargs["context"]
        parent_contexts.append(context)
        child = await context["spawn_child_agent"](
            parent_ctx=context,
            name="Contract Child",
            task="Read host health only",
            skills=[],
            parent_history=[],
        )
        assert child["success"] is True
        await asyncio.wait_for(child_ready.wait(), timeout=5)
        await kwargs["coordinator"].set_status(kwargs["agent_id"], "completed")

    monkeypatch.setattr(runner, "run_agent_loop", root_loop)
    monkeypatch.setattr(execution, "run_agent_loop", child_loop)
    await runner.run_redjohn_scan(
        scan_config=scan_for("https://example.invalid"),
        image="startup-double",
        scan_id="shared-child",
        mcp_connection_requests=[],
    )
    assert len(parent_contexts) == len(child_contexts) == 1
    parent, child = parent_contexts[0], child_contexts[0]
    assert parent["assessment_service"] is child["assessment_service"]
    assert parent["assessment_governor"] is child["assessment_governor"]
    assert parent["agent_id"] == child["parent_id"]
    assert parent["agent_id"] != child["agent_id"]
    assert root_environment.logging_closed == [True]
    assert (await invoke(child["assessment_service"], "system_health"))["error"][
        "code"
    ] == "engagement_runtime_closed"


@pytest.mark.parametrize(
    "saved",
    [
        '{"unfinished":',
        json.dumps({"statuses": {}, "parent_of": {}, "custom_user_data": "KEEP"}),
        json.dumps({"statuses": {}, "parent_of": {"root": None}, "custom_user_data": "KEEP"}),
    ],
)
async def test_rejected_resume_preserves_saved_bytes(root_environment, monkeypatch, saved):
    state = root_environment.output / ".state"
    state.mkdir(parents=True)
    snapshot = state / "agents.json"
    snapshot.write_text(saved)
    sqlite3.connect(state / "agents.db").close()
    model_loop = AsyncMock()
    monkeypatch.setattr(runner, "run_agent_loop", model_loop)
    with pytest.raises(RuntimeError):
        await runner.run_redjohn_scan(
            scan_config=scan_for("https://example.invalid"),
            image="startup-double",
            scan_id="invalid-resume",
            mcp_connection_requests=[],
        )
    assert snapshot.read_text() == saved
    model_loop.assert_not_awaited()
    assert root_environment.logging_closed == [True]


async def test_valid_root_resume_preserves_sdk_history_and_the_same_queue(
    root_environment, monkeypatch
):
    sessions, services = [], []

    async def model_loop(**kwargs):
        session = kwargs["session"]
        service = kwargs["context"]["assessment_service"]
        assert service.store.path == session.db_path
        if not sessions:
            await session.add_items([{"role": "user", "content": "owned-session-sentinel"}])
        else:
            assert kwargs["initial_input"] == []
        assert (await session.get_items())[0]["content"] == "owned-session-sentinel"
        assert len(service.store.surfaces(service.policy.engagement_id)) == 1
        sessions.append(kwargs["agent_id"])
        services.append(service)
        await kwargs["coordinator"].set_status(kwargs["agent_id"], "completed")

    monkeypatch.setattr(runner, "run_agent_loop", model_loop)
    for _ in range(2):
        await runner.run_redjohn_scan(
            scan_config=scan_for("https://example.invalid"),
            image="startup-double",
            scan_id="valid-resume",
            mcp_connection_requests=[],
        )
    assert len(sessions) == 2 and sessions[0] == sessions[1]
    assert services[0] is not services[1]
    for service in services:
        assert (await invoke(service, "system_health"))["error"][
            "code"
        ] == "engagement_runtime_closed"
    assert root_environment.logging_closed == [True, True]
