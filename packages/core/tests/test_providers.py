from __future__ import annotations

import json
import stat

import httpx
import pytest
from redjohn_core.model_gateway import ToolSpec, gateway_from_settings
from redjohn_core.settings import Settings


@pytest.mark.asyncio
async def test_zai_gateway_maps_tool_history_and_usage():
    from redjohn_core.compat_gateway import OpenAICompatibleGateway

    settings = Settings(
        model_provider="zai-coding-plan", model_name="glm-4.7", model_api_key="test-private-key"
    )
    seen = []

    def reply(request):
        seen.append((request, json.loads(request.content)))
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "content": "checking",
                            "tool_calls": [
                                {
                                    "id": "c2",
                                    "type": "function",
                                    "function": {
                                        "name": OpenAICompatibleGateway.wire_name("mcp:probe/a"),
                                        "arguments": '{"value":"ok"}',
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 18, "completion_tokens": 7},
            },
        )

    gateway = OpenAICompatibleGateway(settings, transport=httpx.MockTransport(reply))
    tool = ToolSpec("mcp:probe/a", "probe", {"type": "object"})
    response = await gateway.complete(
        agent=None,
        run=None,
        step=1,
        tools=[tool],
        max_output_tokens=123,
        messages=[
            {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "name": tool.name, "args": {}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "ok"},
        ],
    )
    request, body = seen[0]
    assert str(request.url) == "https://api.z.ai/api/coding/paas/v4/chat/completions"
    assert request.headers["authorization"] == "Bearer test-private-key"
    assert body["max_tokens"] == 123
    assert body["thinking"] == {"type": "disabled"}
    assert body["messages"][0]["tool_calls"][0]["function"]["name"] == body["tools"][0]["function"]["name"]
    assert body["messages"][1]["tool_call_id"] == "c1"
    assert response.tool_calls[0].name == tool.name
    assert response.usage == {"input_tokens": 18, "output_tokens": 7}


async def test_background_model_timeout_reaches_the_http_transport():
    from redjohn_core.compat_gateway import OpenAICompatibleGateway

    seen = []
    def reply(request):
        assert "authorization" not in request.headers
        seen.append(request.extensions["timeout"]["read"])
        message = {"message": {"content": "OK"}, "finish_reason": "stop"}
        return httpx.Response(200, json={"choices": [message]})

    gateway = OpenAICompatibleGateway(
        Settings(model_provider="custom", model_base_url="http://127.0.0.1:1234/v1"),
        transport=httpx.MockTransport(reply), request_timeout_seconds=600,
    )
    await gateway.complete(agent=None, run=None, step=0, messages=[], tools=[])
    assert seen == [600]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        {"content": "", "tool_calls": [{"id": "c", "function": {"name": "unknown", "arguments": "{}"}}]},
        {"content": "", "tool_calls": [{"id": "c", "function": {"name": "known", "arguments": "not-json"}}]},
    ],
)
async def test_gateway_rejects_invalid_or_unadvertised_tool_calls(message):
    from redjohn_core.compat_gateway import OpenAICompatibleGateway
    from redjohn_core.errors import RJError

    def reply(request):
        return httpx.Response(200, json={"choices": [{"message": message, "finish_reason": "tool_calls"}]})

    gateway = OpenAICompatibleGateway(
        Settings(model_provider="deepseek", model_api_key="test"), transport=httpx.MockTransport(reply)
    )
    with pytest.raises(RJError):
        await gateway.complete(agent=None, run=None, step=0, messages=[], tools=[])


@pytest.mark.asyncio
async def test_provider_error_does_not_expose_key_or_body(caplog):
    from redjohn_core.compat_gateway import OpenAICompatibleGateway
    from redjohn_core.errors import RJError

    key = "private-do-not-return"
    caplog.set_level("DEBUG")
    transport = httpx.MockTransport(lambda r: httpx.Response(401, text=key))
    gateway = OpenAICompatibleGateway(Settings(model_provider="zai", model_api_key=key), transport=transport)
    with pytest.raises(RJError) as caught:
        await gateway.complete(agent=None, run=None, step=0, messages=[], tools=[])
    assert key not in str(caught.value)
    assert all(key not in record.getMessage() for record in caplog.records)


def test_provider_credentials_survive_reload_without_plaintext_or_api_disclosure(tmp_path):
    from redjohn_core.integrations import IntegrationStore

    settings = Settings(redjohn_home=tmp_path)
    config = IntegrationStore(settings)
    item = config.save_provider(
        {"label": "My z.ai", "provider": "zai", "model": "glm-4.7", "api_key": "private-test-token"}
    )
    config.activate(item["id"])
    reloaded = Settings.load({"REDJOHN_HOME": str(tmp_path)})
    assert reloaded.model_provider == "zai"
    assert bool(reloaded.model_api_key == "private-test-token")
    assert "private-test-token" not in json.dumps(config.public())
    assert "private-test-token" not in config.path.read_text()
    assert stat.S_IMODE(config.path.stat().st_mode) == 0o600
    assert "private-test-token" not in repr(reloaded)
    assert gateway_from_settings(reloaded).name == "zai"


def test_endpoint_change_requires_new_key_and_loopback_http_only(tmp_path):
    from redjohn_core.errors import RJError
    from redjohn_core.integrations import IntegrationStore

    config = IntegrationStore(Settings(redjohn_home=tmp_path))
    item = config.save_provider(
        {
            "provider": "custom",
            "label": "private",
            "model": "my-model",
            "base_url": "https://first.example/v1",
            "api_key": "test",
        }
    )
    with pytest.raises(RJError):
        config.save_provider(
            {
                "id": item["id"],
                "provider": "custom",
                "label": "private",
                "model": "my-model",
                "base_url": "https://second.example/v1",
            }
        )
    with pytest.raises(RJError):
        config.save_provider(
            {"provider": "custom", "label": "unsafe", "model": "m", "base_url": "http://remote.example/v1"}
        )


@pytest.mark.asyncio
async def test_activation_changes_live_gateway_and_is_not_fake_saved(api, engine):
    client = api
    r = await client.post(
        "/api/v1/integrations/providers",
        json={"label": "Z.ai", "provider": "zai", "model": "glm-4.7", "api_key": "test"},
    )
    assert r.status_code == 201
    assert "api_key" not in r.json()
    selected = await client.post(f"/api/v1/integrations/providers/{r.json()['id']}/activate")
    assert selected.status_code == 200
    assert engine.gateway.name == "zai"
