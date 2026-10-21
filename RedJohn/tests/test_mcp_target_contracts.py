"""Policy/scheduler fault contracts, kept separate from real target worker E2E."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from agents.tool_context import ToolContext

from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from redjohn.runtime.legacy_execution import LegacyExecution
from redjohn.tools.mcp import McpConnectionConfig, McpConnectionRequest, McpRegistry
from redjohn.tools.mcp.agent_tools import call_mcp


@asynccontextmanager
async def bound(tmp_path):
    store = AssessmentStore(tmp_path / "agents.db")
    runtime = AssessmentRuntime(
        store,
        EngagementPolicy(
            "mcp-contract",
            "operator",
            ("https://127.0.0.1:443",),
            profile="isolated-lab",
            egress_mode="local-fixture",
        ),
        caller="operator",
        envelope=ResourceEnvelope(max_workers=1),
        host_pool_path=tmp_path / "host-pool.db",
    )
    runtime.scheduler.lease_seconds = 0.06
    registry = McpRegistry()
    source = tmp_path / "controller-approved-worker.py"
    source.write_text("# synthetic contract fixture: never executed\n")
    entry = registry.register(
        McpConnectionRequest(
            config=McpConnectionConfig(
                name="owned",
                transport="stdio",
                command=sys.executable,
                args=[str(source)],
                tool_authorizations=[
                    {
                        "tool": "read",
                        "effect": "target-read",
                        "schema_sha256": "a" * 64,
                        "server_name": "synthetic-unit-descriptor",
                        "server_version": "not-live",
                        "allowed_arguments": ["url"],
                        "url_arguments": ["url"],
                    }
                ],
            )
        )
    )
    registry.bind_governor(runtime.governor)
    owner = LegacyExecution(
        store.path,
        runtime.governor,
        control=runtime.control,
        sandbox_session=SimpleNamespace(),
        shell_transport=runtime.browser,
    )
    owner.bind_mcp_registry(registry)
    ctx = ToolContext(
        context={"legacy_execution": owner, "mcp_registry": registry},
        tool_name="call_mcp",
        tool_call_id="contract",
        tool_arguments="{}",
    )
    try:
        yield runtime, owner, entry, ctx
    finally:
        await registry.close()
        await owner.close()
        await runtime.close()
        store.close()


@pytest.mark.parametrize(
    "linux", [False, True], ids=["missing-pid-boundary", "missing-sdk-attachment"]
)
async def test_missing_target_backend_stays_blocked_before_any_worker_start(
    tmp_path, monkeypatch, linux
):
    monkeypatch.setattr("redjohn.runtime.mcp_target._linux_pid_boundary", lambda: linux)
    async with bound(tmp_path) as (runtime, _owner, entry, ctx):
        surface = Surface("https://127.0.0.1:443/observed")
        surface_id = runtime.store.upsert_surface(runtime.policy.engagement_id, surface)
        response = await call_mcp.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "connection": "owned",
                    "tool": "read",
                    "arguments": {"url": surface.url},
                    "surface_id": surface_id,
                }
            ),
        )
        assert response["ok"], response
        assert entry.session is None
        await runtime.scheduler.run_batch(max_jobs=1)
        row = runtime.store.jobs(runtime.policy.engagement_id)[0]
        assert row["execution_status"] == "failed" and row["coverage_status"] == "blocked"
        expected = (
            "mcp_target_local_backend_attachment_unavailable"
            if linux
            else "mcp_target_process_tree_boundary_unavailable"
        )
        assert row["result"]["error"]["code"] == expected
        assert entry.session is None and entry._resource_lease is None
        assert runtime.governor.snapshot()["active"] == {}


@pytest.mark.parametrize(
    "surface",
    [
        Surface("https://127.0.0.1:443/post", method="POST"),
        Surface("https://127.0.0.1:443/auth", actor_id="alice"),
        Surface("https://127.0.0.1:443/inferred", source="inferred"),
    ],
)
async def test_unsupported_replay_shape_is_explicit_and_not_a_negative_observation(
    tmp_path, surface
):
    async with bound(tmp_path) as (runtime, _owner, entry, ctx):
        surface_id = runtime.store.upsert_surface(runtime.policy.engagement_id, surface)
        response = await call_mcp.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "connection": "owned",
                    "tool": "read",
                    "arguments": {"url": surface.url},
                    "surface_id": surface_id,
                }
            ),
        )
        assert response["success"] is False
        assert response["code"] == "mcp_target_observed_anonymous_get_required"
        assert not runtime.store.jobs(runtime.policy.engagement_id)
        assert entry.session is None and not runtime.governor.snapshot()["active"]


def _capture_dispatch_timeout(monkeypatch, adapter_type, times):
    original = asyncio.wait_for

    async def observe(awaitable, timeout):
        if (
            isinstance(awaitable, asyncio.Task)
            and awaitable.get_coro().__qualname__ == adapter_type.run.__qualname__
        ):
            times["dispatch_timeout"] = timeout
        # Observe the real scheduler timer argument without altering its clock,
        # task, timeout, cancellation or returned result.
        return await original(awaitable, timeout)

    monkeypatch.setattr(asyncio, "wait_for", observe)


def _assert_shared_dispatch_budget(times, budget):
    # Timer delivery can be delayed by a busy event loop. The actual remaining
    # budget passed to wait_for must still deduct the completed preparation.
    assert 0 < times["dispatch_timeout"] < 0.7
    assert times["dispatch_timeout"] <= budget - times["prepare"]


async def _shared_deadline_probe(tmp_path, monkeypatch, *, callback_delay=0):
    async with bound(tmp_path) as (runtime, _owner, _entry, _ctx):
        surface_id = runtime.store.upsert_surface(
            runtime.policy.engagement_id, Surface("https://127.0.0.1:443/observed")
        )
        phases = []
        times = {}

        class Prepared:
            owner_process_only = True
            dispatch_memory_bytes = 4 * 1024**2

            async def prepare(self, _job, _surface, _spec):
                started = time.monotonic()
                lease = runtime.governor.acquire("context", estimated_bytes=1024)
                initial = runtime.store.jobs(runtime.policy.engagement_id)[0]["lease_until"]
                try:
                    phases.append("prepare")
                    assert runtime.governor.snapshot()["active"] == {"context": 1}
                    await asyncio.sleep(0.2)
                    later = runtime.store.jobs(runtime.policy.engagement_id)[0]["lease_until"]
                    assert later > initial
                finally:
                    times["prepare"] = time.monotonic() - started
                    lease.release()

            async def run(self, *_args):
                phases.append("dispatch")
                assert runtime.governor.snapshot()["active"] == {"worker": 1}
                assert runtime.governor.snapshot()["reserved_bytes"] == 4 * 1024**2
                started = time.monotonic()
                if callback_delay:
                    # A deliberately delayed timeout callback reproduces the
                    # old wall-clock oracle's failure deterministically.
                    asyncio.get_running_loop().call_soon(time.sleep, callback_delay)
                try:
                    await asyncio.sleep(2)
                finally:
                    times["dispatch"] = time.monotonic() - started

            async def cancel(self):
                phases.append("cancel")

            async def cleanup(self):
                phases.append("cleanup")

        _capture_dispatch_timeout(monkeypatch, Prepared, times)
        runtime.scheduler.adapters["mcp_target_read"] = Prepared()
        spec = JobSpec(
            surface_id,
            "mcp_readonly_observation",
            "mcp_target_read",
            policy_revision=runtime.policy.revision,
            timeout_seconds=0.8,
            idempotent=False,
        )
        runtime.store.submit(runtime.policy, [spec])
        started = time.monotonic()
        await runtime.scheduler.run_batch(max_jobs=1)
        elapsed = time.monotonic() - started
        times["elapsed"] = elapsed
        row = runtime.store.jobs(runtime.policy.engagement_id)[0]
        assert row["execution_status"] == "timed_out"
        assert row["coverage_status"] == "inconclusive"
        assert phases == ["prepare", "dispatch", "cancel", "cleanup"]
        assert elapsed < 1.5
        _assert_shared_dispatch_budget(times, spec.timeout_seconds)
        assert runtime.governor.snapshot()["active"] == {}
        return times


async def test_prepare_heartbeat_shared_deadline_and_cleanup_with_one_worker(
    tmp_path, monkeypatch, record_property
):
    times = await _shared_deadline_probe(tmp_path, monkeypatch)
    for name, measured in times.items():
        record_property("deadline_probe_" + name, measured)


async def test_delayed_timeout_callback_keeps_the_original_shared_dispatch_budget(
    tmp_path, monkeypatch, record_property
):
    times = await _shared_deadline_probe(tmp_path, monkeypatch, callback_delay=0.71)
    assert times["dispatch"] >= 0.7  # The former oracle fails despite the correct timer budget.
    for name, measured in times.items():
        record_property("deadline_probe_" + name, measured)


async def test_dispatch_timeout_probe_rejects_reset_budget_mutation(monkeypatch, record_property):
    class Prepared:
        async def run(self):
            await asyncio.sleep(0)

    times = {"prepare": 0.2}
    _capture_dispatch_timeout(monkeypatch, Prepared, times)
    # Model a reset-at-dispatch regression at the timer seam only. Production
    # scheduler code stays unchanged and the probe delegates to real wait_for.
    await asyncio.wait_for(asyncio.create_task(Prepared().run()), timeout=0.8)
    assert times["dispatch_timeout"] == 0.8
    with pytest.raises(AssertionError):
        _assert_shared_dispatch_budget(times, 0.8)
    record_property("reset_timeout_mutation_rejected", "true")


async def test_failed_prepare_cleans_partial_context_and_never_dispatches(tmp_path):
    async with bound(tmp_path) as (runtime, _owner, _entry, _ctx):
        surface_id = runtime.store.upsert_surface(
            runtime.policy.engagement_id, Surface("https://127.0.0.1:443/observed")
        )
        dispatched = []

        class Failed:
            async def prepare(self, *_args):
                lease = runtime.governor.acquire("context", estimated_bytes=1024)
                try:
                    raise PolicyDenied("owned_prepare_rejection")
                finally:
                    lease.release()

            async def run(self, *_args):
                dispatched.append(True)

        runtime.scheduler.adapters["mcp_target_read"] = Failed()
        runtime.store.submit(
            runtime.policy,
            [
                JobSpec(
                    surface_id,
                    "mcp_readonly_observation",
                    "mcp_target_read",
                    policy_revision=runtime.policy.revision,
                    idempotent=False,
                )
            ],
        )
        await runtime.scheduler.run_batch(max_jobs=1)
        row = runtime.store.jobs(runtime.policy.engagement_id)[0]
        assert row["execution_status"] == "failed" and row["coverage_status"] == "blocked"
        assert row["result"]["error"]["code"] == "owned_prepare_rejection"
        assert not dispatched and runtime.governor.snapshot()["active"] == {}


async def test_changed_explicit_runtime_bytes_block_a_queued_job(tmp_path):
    async with bound(tmp_path) as (runtime, _owner, entry, ctx):
        surface = Surface("https://127.0.0.1:443/observed")
        surface_id = runtime.store.upsert_surface(runtime.policy.engagement_id, surface)
        submitted = await call_mcp.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "connection": "owned",
                    "tool": "read",
                    "surface_id": surface_id,
                    "arguments": {"url": surface.url},
                }
            ),
        )
        assert submitted["ok"], submitted
        (tmp_path / "controller-approved-worker.py").write_text("# changed after host approval\n")
        await runtime.scheduler.run_batch(max_jobs=1)
        row = runtime.store.jobs(runtime.policy.engagement_id)[0]
        assert row["execution_status"] == "failed" and row["coverage_status"] == "blocked"
        assert row["result"]["error"]["code"] == "mcp_target_host_configuration_changed"
        assert entry.session is None and not runtime.governor.snapshot()["active"]
