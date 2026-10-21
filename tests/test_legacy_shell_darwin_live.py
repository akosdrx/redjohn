"""Real macOS Seatbelt/SDK commands against owned HTTP and HTTPS fixtures."""

from __future__ import annotations

import json
import os
import shlex
import socket
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from agents.sandbox.capabilities.tools.shell_tool import ExecCommandTool
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.unix_local import UnixLocalSandboxClient
from agents.tool_context import ToolContext

from redjohn.agents.factory import _wrap_exec_command
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.fixture import FixtureServer
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.runtime.legacy_execution import LegacyExecution
from redjohn.runtime.local_backend import RedJohnLocalSandboxSession


pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="requires_real_macos_seatbelt")


@asynccontextmanager
async def _owned_shell(tmp_path, origin, tls=None):
    store = AssessmentStore(tmp_path / "state/agents.db")
    policy = store.register(
        EngagementPolicy(
            "owned-macos-shell",
            "operator",
            (origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
        )
    )
    pool = ResourceGovernor()
    control = AssessmentControl(store, policy, caller="operator", governor=pool)
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    client = UnixLocalSandboxClient()
    session = await client.create(manifest=Manifest(root=str(workspace)))
    await session.start()
    session._inner.__class__ = RedJohnLocalSandboxSession
    transport = SimpleNamespace(
        request_admission=lambda _url: store.consume_requests(policy),
        tls_config=tls,
        on_response=None,
    )
    owner = LegacyExecution(
        store.path, pool, control=control, sandbox_session=session, shell_transport=transport
    )
    tool = _wrap_exec_command(ExecCommandTool(session=session))
    ctx = ToolContext(
        context={"legacy_execution": owner},
        tool_name="exec_command",
        tool_call_id="owned-shell",
        tool_arguments="{}",
    )

    async def execute(source, yield_time_ms=10000):
        return await tool.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "cmd": shlex.join([sys.executable, "-c", source]),
                    "login": False,
                    "yield_time_ms": yield_time_ms,
                }
            ),
        )

    try:
        yield SimpleNamespace(
            owner=owner,
            pool=pool,
            control=control,
            store=store,
            workspace=workspace,
            session=session,
            execute=execute,
        )
    finally:
        await owner.close()
        await session.stop()
        await client.delete(session)
        control.close()
        pool.close()
        store.close()


@pytest.mark.parametrize("https", [False, True], ids=["http", "https"])
async def test_real_macos_bound_shell_proxy_filesystem_and_descendants(
    tmp_path, monkeypatch, https
):
    monkeypatch.setenv("REDJOHN_TEST_PROVIDER_SECRET", "controller-only")
    factory = TLSFixtureServer if https else FixtureServer
    with factory() as fixture, FixtureServer() as outside:
        tls = BrowserTLSConfig(upstream_ca_file=fixture.ca_file) if https else None
        async with _owned_shell(tmp_path, fixture.origin, tls) as run:
            private = tmp_path / "private-controller-file"
            private.write_text("not-in-workspace")
            source = f"""
import errno,json,os,pathlib,py_compile,socket,subprocess,sys,urllib.request
pathlib.Path('owned.py').write_text('value=42')
py_compile.compile('owned.py',doraise=True)
result={{'response':json.load(urllib.request.urlopen({fixture.origin + "/api/me"!r},timeout=5)),
 'home':os.environ['HOME'],'secret':os.environ.get('REDJOHN_TEST_PROVIDER_SECRET')}}
sock=socket.socket();sock.settimeout(1)
result['direct']=sock.connect_ex(('127.0.0.1',{fixture.server.server_port}));sock.close()
try:pathlib.Path({str(private)!r}).read_text();result['private_file']=0
except OSError as exc:result['private_file']=exc.errno
child=subprocess.run([sys.executable,'-c',
 "import socket;print(socket.socket().connect_ex(('127.0.0.1',{fixture.server.server_port})))"],
 capture_output=True,text=True,timeout=3)
result['child_direct']=int(child.stdout.strip())
try:urllib.request.urlopen({outside.origin + "/outside"!r},timeout=3);result['offscope']=0
except urllib.error.HTTPError as exc:result['offscope']=exc.code
try:
 urllib.request.build_opener(urllib.request.ProxyHandler({{}})).open(
  {fixture.origin + "/direct"!r},timeout=3)
 result['proxy_bypass']=0
except urllib.error.URLError as exc:result['proxy_bypass']=exc.reason.errno
print(json.dumps(result))
"""
            result = await run.execute(source)
            assert "Process exited with code 0" in result, json.dumps(result)
            row = json.loads(result.partition("Output:\n")[2].strip())
            assert row == {
                "response": {"actor": "anonymous", "path": "/api/me"},
                "home": str(run.workspace),
                "secret": None,
                "direct": 1,
                "private_file": 1,
                "child_direct": 1,
                "offscope": 403,
                "proxy_bypass": 1,
            }
            boundary = run.owner._shell_boundary
            assert (
                boundary.boundary.attestations[0]["method"] == "darwin_seatbelt_negative_controls"
            )
            assert boundary.proxy.forwarded_requests == 1
            assert boundary.proxy.denied_requests >= 1
            assert fixture.counts == {"/api/me": 1}
            assert not outside.counts
            assert list((run.workspace / "__pycache__").glob("owned.*.pyc"))
            assert run.pool.snapshot()["active"] == {}
            used = run.store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0]
            assert used == 1


async def test_real_macos_bound_shell_close_kills_worker_and_removes_proxy(tmp_path):
    with FixtureServer() as fixture:
        async with _owned_shell(tmp_path, fixture.origin) as run:
            source = "import os,time;print(os.getpid(),flush=True);time.sleep(30)"
            result = await run.execute(source, 0)
            assert "Process running with session ID" in result, json.dumps(result)
            assert run.pool.snapshot()["active"] == {"worker": 1}
            handle = next(iter(run.owner._shell))
            pid = run.session._inner._pty_processes[handle].process.pid
            os.kill(pid, 0)
            boundary = run.owner._shell_boundary
            port = boundary.boundary.proxy_port
            assets = Path(boundary._assets.name)
            await run.owner.close()
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)
            with socket.socket() as sock:
                assert sock.connect_ex(("127.0.0.1", port)) != 0
            assert not boundary.proxy._tasks and not boundary.proxy._writers
            assert not assets.exists()
            assert run.pool.snapshot()["active"] == {}
