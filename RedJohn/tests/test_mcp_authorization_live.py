"""Real owned stateful MCP provider calls with host-approved semantic contracts.

The provider is a local stdio service, independent of the assessment web target.
No public repository/cloud API or credential is used. Target-effect transport
limitations are asserted as blockers, not reported as negative security scans.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import sys

import pytest
from agents.tool_context import ToolContext

from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.models import stable_key
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.store import AssessmentStore
from redjohn.runtime.legacy_execution import LegacyExecution
from redjohn.tools.mcp import McpConnectionConfig, McpConnectionRequest, McpRegistry
from redjohn.tools.mcp.agent_tools import call_mcp, get_mcp_tool_schema
from redjohn.tools.mcp.authorization import server_identity
from redjohn.tools.mcp.config import McpToolAuthorization
from redjohn.tools.mcp.loader import load_user_mcp_configs


@pytest.fixture
async def owned_provider(tmp_path, request):
    server = tmp_path / "provider.py"
    events = tmp_path / "events.json"
    server.write_text(
        "import json,os,sys\n"
        "from pathlib import Path\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "app=FastMCP('RedJohn owned provider policy')\n"
        "events=Path(sys.argv[1])\n"
        "row=json.loads(events.read_text()) if events.exists() else {'calls':0,'mutations':0}\n"
        "row['pid']=os.getpid();events.write_text(json.dumps(row))\n"
        "@app.tool()\n"
        "def read_repository(repository: str) -> str:\n"
        " row=json.loads(events.read_text());row['calls']+=1;events.write_text(json.dumps(row))\n"
        " return repository\n"
        "@app.tool()\n"
        "def mutate_object(repository: str, object_id: str, drop: bool=False) -> str:\n"
        " row=json.loads(events.read_text());row['calls']+=1;row['mutations']+=1\n"
        " events.write_text(json.dumps(row))\n"
        " if drop: os._exit(7)\n"
        " return object_id\n"
        "@app.tool()\n"
        "def target_metadata(url: str) -> str:\n"
        " raise AssertionError('unattested target execution must never start')\n"
        "app.run(transport='stdio')\n"
    )
    config = McpConnectionConfig(
        name="owned", transport="stdio", command=sys.executable, args=[str(server), str(events)]
    )
    # Operator metadata review is host work. It does not execute a target tool.
    review = McpRegistry()
    entry = review.register(McpConnectionRequest(config=config))
    descriptors = await entry.ensure_catalog()
    identity = server_identity(entry)
    await review.close()
    hashes = {tool.name: stable_key(tool.inputSchema) for tool in descriptors}
    rules = [
        McpToolAuthorization(
            tool="read_repository",
            effect="provider-read",
            schema_sha256=hashes["read_repository"],
            server_name=identity["name"],
            server_version=identity["version"],
            allowed_arguments=["repository"],
            fixed_arguments={"repository": "owned/repository"},
        ),
        McpToolAuthorization(
            tool="mutate_object",
            effect="provider-mutate",
            schema_sha256=hashes["mutate_object"],
            server_name=identity["name"],
            server_version=identity["version"],
            allowed_arguments=["repository", "object_id", "drop"],
            fixed_arguments={"repository": "owned/repository", "object_id": "fixture-1"},
            workflow_ref="owned-disposable-object",
            profiles=["active-staging", "isolated-lab"],
        ),
        McpToolAuthorization(
            tool="target_metadata",
            effect="target-read",
            schema_sha256=hashes["target_metadata"],
            server_name=identity["name"],
            server_version=identity["version"],
            allowed_arguments=["url"],
            url_arguments=["url"],
        ),
    ]
    config.tool_authorizations = rules
    operator_file = tmp_path / "operator-mcp.json"
    operator_file.write_text(json.dumps([config.model_dump(mode="json")]))
    original = operator_file.read_bytes()
    config = load_user_mcp_configs(operator_file)[0]
    store = AssessmentStore(tmp_path / "state/agents.db")
    policy = store.register(
        EngagementPolicy(
            "assessment",
            "operator",
            ("https://different-web-target.invalid",),
            egress_mode="unavailable",
            profile=getattr(request, "param", "isolated-lab"),
        )
    )
    pool = ResourceGovernor()
    control = AssessmentControl(store, policy, caller="operator", governor=pool)
    owner = LegacyExecution(store.path, pool, control=control)
    registry = McpRegistry()
    registry.bind_governor(pool)
    entry = registry.register(McpConnectionRequest(config=config))
    ctx = ToolContext(
        context={"legacy_execution": owner, "mcp_registry": registry},
        tool_name="call_mcp",
        tool_call_id="authorized-provider",
        tool_arguments="{}",
    )
    try:
        yield ctx, entry, events, control
    finally:
        await registry.close()
        assert pool.snapshot()["active"] == {}
        await owner.close()
        control.close()
        pool.close()
        store.close()
        assert operator_file.read_bytes() == original


async def invoke(ctx, tool, arguments):
    return await asyncio.wait_for(
        call_mcp.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "connection": "owned",
                    "tool": tool,
                    "arguments": arguments,
                }
            ),
        ),
        15,
    )


async def test_provider_context_is_separate_from_assessment_target_and_keeps_session(
    owned_provider,
):
    ctx, _entry, events, _control = owned_provider
    first = await invoke(ctx, "read_repository", {"repository": "owned/repository"})
    assert first["text"] == "owned/repository"
    first_pid = json.loads(events.read_text())["pid"]
    second = await invoke(ctx, "read_repository", {"repository": "owned/repository"})
    assert second["text"] == "owned/repository"
    assert json.loads(events.read_text()) == {"pid": first_pid, "calls": 2, "mutations": 0}
    denied = await invoke(ctx, "read_repository", {"repository": "other/repository"})
    assert denied["success"] is False
    assert denied["code"] == "mcp_fixed_provider_context_denied"
    unknown = await invoke(
        ctx,
        "read_repository",
        {
            "repository": "owned/repository",
            "command": "must-not-run",
        },
    )
    assert unknown["code"] == "mcp_argument_contract_denied"
    assert json.loads(events.read_text()) == {"pid": first_pid, "calls": 2, "mutations": 0}


async def test_approved_mutation_is_not_replayed_after_unknown_outcome(owned_provider):
    ctx, _entry, events, _control = owned_provider
    result = await invoke(
        ctx,
        "mutate_object",
        {
            "repository": "owned/repository",
            "object_id": "fixture-1",
            "drop": True,
        },
    )
    assert result["success"] is False
    assert result["code"] == "mcp_unknown_execution_outcome"
    assert json.loads(events.read_text())["mutations"] == 1
    assert json.loads(events.read_text())["calls"] == 1


async def test_approved_mutation_has_positive_result_and_fixed_workflow(owned_provider):
    ctx, _entry, events, _control = owned_provider
    result = await invoke(
        ctx,
        "mutate_object",
        {
            "repository": "owned/repository",
            "object_id": "fixture-1",
        },
    )
    assert result["text"] == "fixture-1"
    assert json.loads(events.read_text())["mutations"] == 1
    denied = await invoke(
        ctx,
        "mutate_object",
        {
            "repository": "owned/repository",
            "object_id": "unapproved-object",
        },
    )
    assert denied["code"] == "mcp_fixed_provider_context_denied"
    assert json.loads(events.read_text())["mutations"] == 1


@pytest.mark.parametrize("owned_provider", ["safe-production"], indirect=True)
async def test_mutation_contract_does_not_grant_safe_production_effects(owned_provider):
    ctx, entry, events, _control = owned_provider
    result = await invoke(
        ctx,
        "mutate_object",
        {
            "repository": "owned/repository",
            "object_id": "fixture-1",
        },
    )
    assert result["code"] == "mcp_effect_profile_denied"
    assert entry.session is None
    assert json.loads(events.read_text())["mutations"] == 0


async def test_unattested_target_tool_is_blocked_before_connecting(owned_provider):
    ctx, entry, events, _control = owned_provider
    before = json.loads(events.read_text())
    result = await invoke(ctx, "target_metadata", {"url": "https://different-web-target.invalid"})
    assert result["success"] is False
    assert result["code"] == "mcp_target_worker_boundary_not_attested"
    assert entry.session is None
    assert json.loads(events.read_text()) == before


@pytest.mark.parametrize("field", ["schema_sha256", "server_version"])
async def test_changed_schema_or_version_blocks_execution(owned_provider, field):
    ctx, entry, events, _control = owned_provider
    rule = entry.config.tool_authorizations[0]
    setattr(rule, field, "0" * 64 if field == "schema_sha256" else "unreviewed-version")
    result = await invoke(ctx, "read_repository", {"repository": "owned/repository"})
    assert result["success"] is False
    expected = (
        "mcp_tool_schema_changed" if field == "schema_sha256" else "mcp_server_identity_changed"
    )
    assert result["code"] == expected
    assert json.loads(events.read_text())["calls"] == 0


async def test_schema_metadata_exposes_version_and_hash_for_host_review(owned_provider):
    ctx, entry, _events, _control = owned_provider
    result = await get_mcp_tool_schema.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "connection": "owned",
                "tool": "read_repository",
            }
        ),
    )
    assert result["schema_sha256"] == entry.config.tool_authorizations[0].schema_sha256
    assert result["server_identity"] == server_identity(entry)


async def test_real_http_provider_endpoint_fault_and_recovery_keep_target_scope_separate(tmp_path):  # noqa: PLR0915
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    state = tmp_path / "http-state.json"
    state.write_text(json.dumps({"calls": 0, "fault": False}))
    server = tmp_path / "http-provider.py"
    server.write_text(
        "import json,sys\n"
        "from pathlib import Path\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "state=Path(sys.argv[1])\n"
        "app=FastMCP('RedJohn owned HTTP provider',host='127.0.0.1',port=int(sys.argv[2]))\n"
        "@app.tool()\n"
        "def read_repository(repository: str) -> str:\n"
        " row=json.loads(state.read_text())\n"
        " if row['fault']: raise ValueError('owned provider unavailable')\n"
        " row['calls']+=1;state.write_text(json.dumps(row));return repository\n"
        "app.run(transport='streamable-http')\n"
    )
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(server),
        str(state),
        str(port),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )
    registry = McpRegistry()
    store = AssessmentStore(tmp_path / "state/agents.db")
    pool = ResourceGovernor()
    policy = store.register(
        EngagementPolicy(
            "web-assessment",
            "operator",
            ("https://unrelated-target.invalid",),
            egress_mode="unavailable",
            profile="isolated-lab",
        )
    )
    control = AssessmentControl(store, policy, caller="operator", governor=pool)
    owner = LegacyExecution(store.path, pool, control=control)
    try:
        async with asyncio.timeout(10):
            while True:
                if process.returncode is not None:
                    raise AssertionError("owned HTTP provider failed to start")
                try:
                    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
                except OSError:
                    await asyncio.sleep(0.02)
                else:
                    writer.close()
                    await writer.wait_closed()
                    break
        config = McpConnectionConfig(name="owned", url=f"http://127.0.0.1:{port}/mcp")
        entry = registry.register(McpConnectionRequest(config=config))
        catalog = await entry.ensure_catalog()
        descriptor = next(tool for tool in catalog if tool.name == "read_repository")
        identity = server_identity(entry)
        config.tool_authorizations = [
            McpToolAuthorization(
                tool="read_repository",
                effect="provider-read",
                schema_sha256=stable_key(descriptor.inputSchema),
                server_name=identity["name"],
                server_version=identity["version"],
                allowed_arguments=["repository"],
                fixed_arguments={"repository": "owned/repository"},
            )
        ]
        ctx = ToolContext(
            context={"legacy_execution": owner, "mcp_registry": registry},
            tool_name="call_mcp",
            tool_call_id="http-provider",
            tool_arguments="{}",
        )
        result = await invoke(ctx, "read_repository", {"repository": "owned/repository"})
        assert result["text"] == "owned/repository"
        state.write_text(json.dumps({"calls": 1, "fault": True}))
        failed = await invoke(ctx, "read_repository", {"repository": "owned/repository"})
        assert failed["success"] is False
        assert process.returncode is None
        assert owner.governor.snapshot()["active"] == {}
        state.write_text(json.dumps({"calls": 1, "fault": False}))
        recovered = await invoke(ctx, "read_repository", {"repository": "owned/repository"})
        assert recovered["text"] == "owned/repository"
        assert json.loads(state.read_text())["calls"] == 2
        denied = await invoke(ctx, "read_repository", {"repository": "outside/repository"})
        assert denied["code"] == "mcp_fixed_provider_context_denied"
        assert json.loads(state.read_text())["calls"] == 2
        assert (
            owner.db.execute(
                "SELECT COUNT(*) FROM rj_legacy_execution WHERE status='inconclusive'"
            ).fetchone()[0]
            == 1
        )
    finally:
        await registry.close()
        await owner.close()
        control.close()
        pool.close()
        store.close()
        if process.returncode is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
