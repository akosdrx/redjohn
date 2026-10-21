"""Real Linux SDK/namespace/MCP/scheduler target reads against owned HTTPS fixtures."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.unix_local import UnixLocalSandboxClient
from agents.tool_context import ToolContext

from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.fixture import FixtureServer
from redjohn.assessment.models import Surface, stable_key
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.runtime.legacy_execution import LegacyExecution
from redjohn.runtime.local_backend import RedJohnLocalSandboxSession
from redjohn.tools.mcp import McpConnectionConfig, McpConnectionRequest, McpRegistry
from redjohn.tools.mcp.agent_tools import call_mcp
from redjohn.tools.mcp.authorization import identity_for
from redjohn.tools.mcp.session import SupervisedMcpSession


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="requires_real_linux_mcp_namespace")


def _server_source(workspace):
    source = workspace / "owned_target_mcp.py"
    events = workspace / "worker-events.json"
    source.write_text(
        "import asyncio,json,os,pathlib,socket,subprocess,sys,urllib.request,urllib.parse\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "app=FastMCP('RedJohn owned confined target fixture')\n"
        f"events=pathlib.Path({str(events)!r})\n"
        "calls=0\n"
        "@app.tool()\n"
        "async def inspect_url(url: str,outside_url: str) -> dict:\n"
        " global calls\n"
        " calls+=1\n"
        " prior=json.loads(events.read_text()) if events.exists() else {'calls':0}\n"
        " prior['calls']+=1;prior['url']=url;events.write_text(json.dumps(prior))\n"
        " if url.endswith('/slow'):\n"
        "  subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
        "start_new_session=True)\n"
        "  await asyncio.sleep(30)\n"
        " if url.endswith('/oversized'):\n"
        "  sys.stdout.write('x'*(1024*1024+1));sys.stdout.flush();await asyncio.sleep(30)\n"
        " body=json.load(urllib.request.urlopen(url,timeout=3))\n"
        " direct=socket.socket();direct.settimeout(.3)\n"
        " parsed=urllib.parse.urlsplit(url)\n"
        " blocked=direct.connect_ex(('127.0.0.1',parsed.port))!=0;direct.close()\n"
        " try:urllib.request.urlopen(outside_url,timeout=3);offscope=0\n"
        " except urllib.error.HTTPError as exc:offscope=exc.code\n"
        " try:urllib.request.urlopen(urllib.request.Request(url,headers={"
        "'Cookie':'fixture_actor=alice'}),timeout=3);auth_header=0\n"
        " except urllib.error.HTTPError as exc:auth_header=exc.code\n"
        " if url.endswith('/idle'):\n"
        "  async def later():\n"
        "   await asyncio.sleep(.15)\n"
        "   try:urllib.request.urlopen(url,timeout=2)\n"
        "   except Exception:pass\n"
        "  asyncio.create_task(later())\n"
        " return {'body':body,'calls':calls,'pid':os.getpid(),'blocked':blocked,"
        "'offscope':offscope,'auth_header':auth_header,"
        "'secret':os.environ.get('REDJOHN_TEST_PROVIDER_SECRET'),"
        "'netns':os.readlink('/proc/self/ns/net'),'cap':[s for s in "
        "pathlib.Path('/proc/self/status').read_text().splitlines() "
        "if s.startswith('CapEff:')][0]}\n"
        "app.run()\n"
    )
    return source, events


async def _reviewed_config(source, outside, timeout=10):
    config = McpConnectionConfig(
        name="owned",
        transport="stdio",
        command=sys.executable,
        args=[str(source)],
        session_timeout_seconds=timeout,
        idempotent_tools=["inspect_url"],
    )
    review = SupervisedMcpSession(config)
    try:
        assert await review.start()
        descriptor = (await review.list_tools())[0]
        identity = identity_for(review.server)
    finally:
        await review.aclose()
    return McpConnectionConfig.model_validate(
        {
            **config.model_dump(),
            "tool_authorizations": [
                {
                    "tool": "inspect_url",
                    "effect": "target-read",
                    "server_name": identity["name"],
                    "server_version": identity["version"],
                    "schema_sha256": stable_key(descriptor.inputSchema),
                    "allowed_arguments": ["url", "outside_url"],
                    "url_arguments": ["url"],
                    "fixed_arguments": {"outside_url": outside.origin + "/blocked"},
                }
            ],
        }
    )


@asynccontextmanager
async def _owned(tmp_path, fixture, config, workspace):
    store = AssessmentStore(tmp_path / "state/agents.db")
    policy = EngagementPolicy(
        "owned-mcp-target",
        "operator",
        (fixture.origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
        request_budget=32,
    )
    runtime = AssessmentRuntime(
        store,
        policy,
        caller="operator",
        envelope=ResourceEnvelope(max_workers=1),
        host_pool_path=tmp_path / "host-pool.db",
        browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
    )
    runtime.scheduler.lease_seconds = 0.3
    client = UnixLocalSandboxClient()
    session = await client.create(manifest=Manifest(root=str(workspace)))
    await session.start()
    session._inner.__class__ = RedJohnLocalSandboxSession
    registry = McpRegistry()
    registry.register(McpConnectionRequest(config=config))
    registry.bind_governor(runtime.governor)
    owner = LegacyExecution(
        store.path,
        runtime.governor,
        control=runtime.control,
        sandbox_session=session,
        shell_transport=runtime.browser,
    )
    owner.bind_mcp_registry(registry)
    ctx = ToolContext(
        context={"legacy_execution": owner, "mcp_registry": registry},
        tool_name="call_mcp",
        tool_call_id="owned-target",
        tool_arguments="{}",
    )

    async def submit(path):
        surface = Surface(fixture.origin + path)
        surface_id = store.upsert_surface(runtime.policy.engagement_id, surface)
        response = await call_mcp.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "connection": "owned",
                    "tool": "inspect_url",
                    "surface_id": surface_id,
                    "arguments": {
                        "url": surface.url,
                        **config.tool_authorizations[0].fixed_arguments,
                    },
                }
            ),
        )
        assert response["ok"], response
        return response["result"]["job_ids"][0]

    try:
        yield SimpleNamespace(
            runtime=runtime,
            store=store,
            registry=registry,
            owner=owner,
            submit=submit,
            policy=runtime.policy,
        )
    finally:
        await registry.close()
        await owner.close()
        await session.stop()
        await client.delete(session)
        await runtime.close()
        store.close()


def _result(run, job_id):
    row = next(row for row in run.store.jobs(run.policy.engagement_id) if row["id"] == job_id)
    assert row["execution_status"] == "succeeded", row
    ref = row["result"]["summary"]["evidence_refs"][0]
    evidence = json.loads(run.store.evidence_get(run.policy.engagement_id, ref)["excerpt"])
    return json.loads(evidence["text"]), row


def _process_tree(root):
    rows = subprocess.check_output(["/bin/ps", "-axo", "pid=,ppid="], text=True, timeout=3)
    children = {}
    for row in rows.splitlines():
        child, parent = map(int, row.split())
        children.setdefault(parent, []).append(child)
    pending, found = [root], set()
    while pending:
        pid = pending.pop()
        if pid not in found:
            found.add(pid)
            pending.extend(children.get(pid, []))
    return found


async def test_real_target_queue_restart_https_namespace_state_and_idle_egress(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("REDJOHN_TEST_PROVIDER_SECRET", "controller-only")
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    source, _events = _server_source(workspace)
    with TLSFixtureServer() as fixture, FixtureServer() as outside:
        config = await _reviewed_config(source, outside)
        async with _owned(tmp_path, fixture, config, workspace) as run:
            first = await run.submit("/api/me")
            assert run.registry.get("owned").session is None
            assert not fixture.counts
        async with _owned(tmp_path, fixture, config, workspace) as run:
            assert await run.runtime.scheduler.run_batch(max_jobs=1) == [first]
            initial, first_row = _result(run, first)
            assert initial["blocked"] and initial["offscope"] == 403
            assert initial["auth_header"] == 403
            assert initial["secret"] is None
            assert initial["netns"] != str(Path("/proc/self/ns/net").readlink())
            assert int(initial["cap"].split()[1], 16) == 0
            assert initial["body"] == {"actor": "anonymous", "path": "/api/me"}
            assert set(first_row["spec"]["options"]) == {"connection", "tool", "contract_sha256"}
            assert first_row["spec"]["idempotent"] is False
            second = await run.submit("/api/idle")
            await run.runtime.scheduler.run_batch(max_jobs=1)
            later, _row = _result(run, second)
            assert later["calls"] == 2 and later["pid"] == initial["pid"]
            await asyncio.sleep(0.3)
            assert fixture.counts == {"/api/me": 1, "/api/idle": 1}
            assert not outside.counts
            adapter = run.owner._mcp_target
            assert adapter._boundaries["owned"].proxy.admission_denials >= 1
            assert run.runtime.governor.snapshot()["active"] == {"context": 1}
            assert run.registry.get("owned")._resource_lease.estimated_bytes == 256 * 1024**2
            assert await run.runtime.scheduler.run_batch(max_jobs=1) == []
            assert run.store.request_usage(run.policy) == 2


@pytest.mark.parametrize("mode", ["cancel", "timeout"])
async def test_real_target_cancel_deadline_and_detached_descendant_cleanup(tmp_path, mode):
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    source, events = _server_source(workspace)
    with TLSFixtureServer() as fixture, FixtureServer() as outside:
        config = await _reviewed_config(source, outside, timeout=3)
        async with _owned(tmp_path, fixture, config, workspace) as run:
            job_id = await run.submit("/slow")
            task = asyncio.create_task(run.runtime.scheduler.run_batch(max_jobs=1))
            deadline = time.monotonic() + 8
            while not events.exists() and not task.done() and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            assert events.exists(), run.store.jobs(run.policy.engagement_id)
            transport = run.registry.get("owned").session._bound_transports[0]
            pid = transport._process.pid
            pids = _process_tree(pid)
            assert len(pids) >= 3
            if mode == "cancel":
                response = await run.runtime.control.call(
                    "jobs_cancel",
                    {
                        "policy_revision": run.policy.revision,
                        "job_id": job_id,
                    },
                )
                assert response["ok"], response
            await asyncio.wait_for(task, timeout=8)
            row = run.store.jobs(run.policy.engagement_id)[0]
            assert row["execution_status"] == {"cancel": "cancelled", "timeout": "timed_out"}[mode]
            assert row["coverage_status"] in {"partial", "inconclusive"}
            deadline = time.monotonic() + 2
            while (
                any(Path(f"/proc/{pid}").exists() for pid in pids) and time.monotonic() < deadline
            ):
                await asyncio.sleep(0.02)
            assert all(not Path(f"/proc/{pid}").exists() for pid in pids)
            assert run.runtime.governor.snapshot()["active"] == {}
            assert not fixture.counts and not outside.counts
            assert not run.owner._mcp_target._boundaries


async def test_real_target_oversized_stdio_is_inconclusive_without_replay(tmp_path):
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    source, events = _server_source(workspace)
    with TLSFixtureServer() as fixture, FixtureServer() as outside:
        config = await _reviewed_config(source, outside)
        async with _owned(tmp_path, fixture, config, workspace) as run:
            job_id = await run.submit("/oversized")
            await run.runtime.scheduler.run_batch(max_jobs=1)
            row = next(
                row for row in run.store.jobs(run.policy.engagement_id) if row["id"] == job_id
            )
            assert row["execution_status"] == "failed"
            assert row["coverage_status"] == "inconclusive"
            assert row["attempt"] == 1
            assert json.loads(events.read_text())["calls"] == 1
            assert not fixture.counts and not outside.counts
            response = await run.runtime.control.call(
                "jobs_get_status",
                {
                    "policy_revision": run.policy.revision,
                },
            )
            assert response["ok"], response
