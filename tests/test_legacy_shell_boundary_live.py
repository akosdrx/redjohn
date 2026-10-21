"""Real local SDK commands inside the attested Linux namespace and policy proxy."""

from __future__ import annotations

import functools
import http.server
import json
import shlex
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from agents.sandbox.capabilities.tools.shell_tool import ExecCommandTool
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.unix_local import UnixLocalSandboxClient
from agents.tool_context import ToolContext

from redjohn.agents.factory import _wrap_exec_command
from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.store import AssessmentStore
from redjohn.runtime.legacy_execution import LegacyExecution
from redjohn.runtime.local_backend import RedJohnLocalSandboxSession


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="requires_real_linux_namespaces")


async def test_real_sdk_shell_egress_workspace_policy_and_child_namespace(tmp_path):  # noqa: PLR0915
    root = tmp_path / "web"
    root.mkdir()
    (root / "marker").write_text("redjohn-owned-shell-fixture")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    policy = EngagementPolicy(
        "owned-shell", "operator", (origin,), profile="isolated-lab", egress_mode="local-fixture"
    )
    store = AssessmentStore(tmp_path / "state/agents.db")
    policy = store.register(policy)
    pool = ResourceGovernor()
    control = AssessmentControl(store, policy, caller="operator", governor=pool)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    client = UnixLocalSandboxClient()
    session = await client.create(manifest=Manifest(root=str(workspace)))
    await session.start()
    # The real RedJohn local backend uses this same SDK subclass during create.
    session._inner.__class__ = RedJohnLocalSandboxSession
    transport = SimpleNamespace(
        request_admission=lambda _url: store.consume_requests(policy),
        tls_config=None,
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
    source = (
        "import json,os,socket,urllib.request,pathlib; "
        "p=pathlib.Path('owned-build.py');p.write_text('value=42'); "
        "import py_compile;py_compile.compile(str(p),doraise=True); "
        f"response=urllib.request.urlopen({origin + '/marker'!r},timeout=5).read().decode(); "
        "s=socket.socket();s.settimeout(.5); "
        f"blocked=s.connect_ex(('127.0.0.1',{server.server_port}))!=0; "
        "print(json.dumps({'response':response,'direct_blocked':blocked,"
        "'net':os.readlink('/proc/self/ns/net'),'cap':"
        "[x for x in pathlib.Path('/proc/self/status').read_text().splitlines() "
        "if x.startswith('CapEff:')][0]}))"
    )
    try:
        result = await tool.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "cmd": shlex.join([sys.executable, "-c", source]),
                    "login": False,
                    "yield_time_ms": 10000,
                }
            ),
        )
        assert "Process exited with code 0" in result, json.dumps(result)
        row = json.loads(result.partition("Output:\n")[2].strip())
        assert row["response"] == "redjohn-owned-shell-fixture"
        assert row["direct_blocked"] is True
        assert row["net"] != str(Path("/proc/self/ns/net").readlink())
        assert int(row["cap"].split()[1], 16) == 0
        assert (workspace / "__pycache__").is_dir()
        assert owner._shell_boundary.proxy.forwarded_requests == 1
        assert pool.snapshot()["active"] == {}
        denied = "import urllib.request;urllib.request.urlopen('http://outside.invalid/',timeout=3)"
        result = await tool.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "cmd": shlex.join([sys.executable, "-c", denied]),
                    "login": False,
                }
            ),
        )
        assert "Process exited with code 1" in result, result
        assert owner._shell_boundary.proxy.denied_requests >= 1
        assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 1
    finally:
        await owner.close()
        await session.stop()
        await client.delete(session)
        control.close()
        pool.close()
        store.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
