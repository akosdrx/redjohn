from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from redjohn_core.codex_gateway import CodexAppServer, CodexGateway
from redjohn_core.errors import RJError
from redjohn_core.model_gateway import ToolSpec
from redjohn_core.settings import Settings


def fake_cli(tmp_path: Path, *, planner=False, unexpected=False, delay=False) -> Settings:
    binary = tmp_path / "fake-codex"
    binary.write_text(
        f"#!{sys.executable}\n"
        + f"planner={planner!r}\nunexpected={unexpected!r}\ndelay={delay!r}\n"
        + """
import json,os,sys
from pathlib import Path
home=Path(os.environ['CODEX_HOME'])
def send(value):
    print(json.dumps(value), flush=True)
for line in sys.stdin:
    request=json.loads(line)
    with (home/'requests.jsonl').open('a') as f: f.write(line)
    method=request.get('method')
    identifier=request.get('id')
    if identifier is None: continue
    result={}
    if method=='account/read':
        account={'type':'chatgpt','planType':'plus','tokens':'never-return-this'}
        result={'account':account if planner or (home/'signed-in').exists() else None}
    if method=='model/list':
        result={'data':[{'model':'account-model','id':'m','displayName':'Account model'}]}
    if method=='account/login/start': result={'type':'chatgptDeviceCode','loginId':'login-1','verificationUrl':'https://auth.openai.com/codex/device','userCode':'ABCD-1234'}
    if method=='thread/start': result={'thread':{'id':'thread-1'}}
    if method=='turn/start': result={'turn':{'id':'turn-1'}}
    send({'id':identifier,'result':result})
    if method=='account/login/start':
        (home/'signed-in').write_text('fixture-only')
        send({'method':'account/login/completed','params':{'loginId':'login-1','success':True}})
    if method=='account/logout':
        (home/'signed-in').unlink(missing_ok=True)
    if method=='turn/start' and not delay:
        if unexpected:
            send({'method':'item/started','params':{'threadId':'thread-1','item':{'type':'commandExecution'}}})
        else:
            payload={'content':'Checking scope','tool_calls':[
                {'name':'scoped/tool','arguments':'{"target":"authorized.example"}'}]}
            send({'method':'item/completed','params':{'threadId':'thread-1','item':{'type':'agentMessage','text':json.dumps(payload)}}})
            send({'method':'thread/tokenUsage/updated','params':{'threadId':'thread-1','tokenUsage':{'total':{'inputTokens':19,'outputTokens':7}}}})
            send({'method':'turn/completed','params':{'threadId':'thread-1','turn':{'status':'completed'}}})
"""
    )
    binary.chmod(0o700)
    return Settings(
        redjohn_home=tmp_path, codex_binary=str(binary), model_provider="codex", model_name="account-model"
    )


@pytest.mark.asyncio
async def test_official_device_flow_state_and_tokens_stay_private(tmp_path):
    server = CodexAppServer(fake_cli(tmp_path))
    try:
        assert (await server.status())["authenticated"] is False
        result = await server.login_start()
        assert result["userCode"] == "ABCD-1234"
        status = await server.status()
        assert status["authenticated"] is True
        assert status["login"]["state"] == "completed"
        assert status["models"][0]["id"] == "account-model"
        assert "never-return-this" not in json.dumps(status)
        await server.logout()
        assert (await server.status())["authenticated"] is False
    finally:
        await server.close()
    assert server.process is None


@pytest.mark.asyncio
async def test_codex_structured_plan_keeps_tools_in_redjohn_and_records_usage(tmp_path):
    settings = fake_cli(tmp_path, planner=True)
    gateway = CodexGateway(settings)
    result = await gateway.complete(
        agent=None,
        run=None,
        step=0,
        messages=[{"role": "user", "content": "check"}],
        tools=[
            ToolSpec(
                "scoped/tool",
                "scoped probe",
                {"type": "object", "required": ["target"], "properties": {"target": {"type": "string"}}},
            )
        ],
    )
    assert result.tool_calls[0].name == "scoped/tool"
    assert result.tool_calls[0].args["target"] == "authorized.example"
    assert result.usage == {"input_tokens": 19, "output_tokens": 7}
    requests = [
        json.loads(line)
        for line in (settings.profile_dir / "codex" / "requests.jsonl").read_text().splitlines()
    ]
    start = next(r for r in requests if r.get("method") == "thread/start")
    assert start["params"]["environments"] == []
    assert start["params"]["sandbox"] == "read-only"
    assert start["params"]["ephemeral"] is True


@pytest.mark.asyncio
async def test_codex_internal_tool_interrupts_and_does_not_appear_as_redjohn_evidence(tmp_path):
    settings = fake_cli(tmp_path, planner=True, unexpected=True)
    with pytest.raises(RJError, match="internal tool"):
        await CodexGateway(settings).complete(agent=None, run=None, step=0, messages=[], tools=[])
    methods = [
        json.loads(line).get("method")
        for line in (settings.profile_dir / "codex" / "requests.jsonl").read_text().splitlines()
    ]
    assert "turn/interrupt" in methods


@pytest.mark.asyncio
async def test_cancelled_codex_model_call_closes_its_process(tmp_path):
    import asyncio

    settings = fake_cli(tmp_path, planner=True, delay=True)
    task = asyncio.create_task(
        CodexGateway(settings).complete(agent=None, run=None, step=0, messages=[], tools=[])
    )
    capture = settings.profile_dir / "codex" / "requests.jsonl"
    async with asyncio.timeout(5):
        while not capture.exists() or '"turn/start"' not in capture.read_text():  # noqa: ASYNC110 - observe a child-process file
            await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    assert '"turn/interrupt"' in capture.read_text()
