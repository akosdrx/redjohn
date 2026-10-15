"""Consent, saved-provider reuse and a narrowly authorized memory model bridge."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest
from redjohn_core import managed_memory, memory_model_proxy
from redjohn_core.integrations import IntegrationStore, atomic_private_json
from redjohn_core.model_gateway import ModelResponse

from .test_managed_memory_bootstrap import fixture_boundaries


@pytest.mark.parametrize("content", [
    '"""A normal memory summary"""',
    '"""{"profile":"a fact"}"""',
    '"""sdk.set_profile(content=invalid syntax!)"""',
    '"""import os\nos.system("command")"""',
])
def test_non_operations_and_invalid_quoted_output_are_preserved(content):
    assert memory_model_proxy.normalize_memory_output(content) == content


async def test_unconfigured_launch_does_not_start_services_or_download(engine, api, monkeypatch):
    calls, requests = fixture_boundaries(monkeypatch)
    engine.start_memory_bootstrap()
    await engine._memory_bootstrap
    config = (await api.get("/api/v1/integrations/memory")).json()
    assert not config["configured"]
    assert not calls and not requests
    assert not (engine.settings.profile_dir / "openviking" / "ov.conf").exists()
    response = await api.post("/api/v1/integrations/memory/auto-start")
    assert response.status_code == 202
    await engine._memory_bootstrap
    assert not calls and not requests


async def test_setup_requires_saved_provider_and_user_selects_model(api, engine, monkeypatch):
    start = AsyncMock(return_value=True)
    monkeypatch.setattr(managed_memory.ManagedMemoryRuntime, "start", start)
    # Missing provider_connection_id + embedding fields → request validation rejects it.
    invalid = await api.post(
        "/api/v1/integrations/memory/setup", json={"model": "some-model"}
    )
    assert invalid.status_code == 422
    store = IntegrationStore(engine.settings)
    provider = store.save_provider(
        {
            "provider": "custom",
            "base_url": "https://provider.example/v1",
            "model": "agent-model",
            "api_key": "upstream-private",
        }
    )
    result = await api.post(
        "/api/v1/integrations/memory/setup",
        json={
            "provider_connection_id": provider["id"],
            "model": "memory-model",
            "embedding_base_url": "https://embeddings.example/v1",
            "embedding_model": "embed-model",
            "embedding_api_key": "embed-private",
            "embedding_dimension": 1536,
        },
    )
    assert result.status_code == 202
    await asyncio.sleep(0.01)
    start.assert_awaited()
    assert store.read()["memory"]["selected_model"] == "memory-model"
    assert "upstream-private" not in result.text
    assert "embed-private" not in result.text
    await engine.cancel_memory_bootstrap()


async def test_bridge_uses_saved_credentials_but_key_cannot_administer_engine(api, engine, monkeypatch):
    store = IntegrationStore(engine.settings)
    provider = store.save_provider(
        {
            "provider": "custom",
            "base_url": "https://provider.example/v1",
            "model": "agent-model",
            "api_key": "upstream-private",
        }
    )
    data = store.read()
    data["memory"] = {
        "provider_connection_id": provider["id"],
        "selected_model": "memory-model",
        "model_proxy_secret": store.encrypt("bridge-private"),
    }
    atomic_private_json(store.path, data)
    captured = []
    complete = AsyncMock(return_value=ModelResponse(content='{"profile":"sample"}'))

    def gateway(settings, *, request_timeout_seconds=120):
        assert request_timeout_seconds == 600
        captured.append(settings)
        return type("Gateway", (), {"complete": complete})()

    monkeypatch.setattr(memory_model_proxy, "gateway_from_settings", gateway)
    body = {
        "model": "memory-model",
        "temperature": 0.0,
        "messages": [{"role": "user", "content": "Summarize this text."}],
    }
    denied = await api.post("/memory-model/v1/chat/completions", json=body)
    assert denied.status_code == 401
    headers = {"Authorization": "Bearer bridge-private"}
    assert (await api.get("/api/v1/settings", headers=headers)).status_code == 401
    allowed = await api.post("/memory-model/v1/chat/completions", json=body, headers=headers)
    assert allowed.status_code == 200
    assert captured[0].model_api_key == "upstream-private"
    assert captured[0].model_name == "memory-model"
    assert "upstream-private" not in allowed.text
    assert complete.call_args.kwargs["tools"] == []
    assert complete.call_args.kwargs["temperature"] == 0.0
    operation = 'sdk.set_profile(content="""# Mira\nBudapest""")'
    complete.return_value = ModelResponse(content='"""' + operation + '"""')
    normalized = await api.post("/memory-model/v1/chat/completions", json=body, headers=headers)
    assert normalized.json()["choices"][0]["message"]["content"] == operation
    complete.return_value = ModelResponse(content='"""python\n' + operation + '\n"""')
    labeled = await api.post("/memory-model/v1/chat/completions", json=body, headers=headers)
    assert labeled.json()["choices"][0]["message"]["content"] == operation
    assert (
        await api.post(
            "/memory-model/v1/chat/completions", json={**body, "model": "unselected"}, headers=headers
        )
    ).status_code == 422


async def test_changing_managed_memory_model_keeps_the_tenant_key(api, engine, monkeypatch):
    monkeypatch.setattr(managed_memory.ManagedMemoryRuntime, "start", AsyncMock(return_value=True))
    store = IntegrationStore(engine.settings)
    provider = store.save_provider(
        {
            "provider": "custom",
            "base_url": "https://provider.example/v1",
            "model": "agent-model",
            "api_key": "upstream-private",
        }
    )
    data = store.read()
    url = "http://127.0.0.1:60091"
    data["memory"] = {"managed_port": 60091, "openviking_url": url,
                      "service_secret": store.encrypt("existing-tenant-key")}
    atomic_private_json(store.path, data)
    engine.settings.openviking_url = url
    engine.settings.openviking_api_key = "existing-tenant-key"
    result = await api.post("/api/v1/integrations/memory/setup", json={
        "provider_connection_id": provider["id"],
        "model": "memory-model",
        "embedding_base_url": "https://embeddings.example/v1",
        "embedding_model": "embed-model",
        "embedding_api_key": "embed-private",
        "embedding_dimension": 1536,
    })
    assert result.status_code == 202
    assert engine.settings.openviking_url == url
    assert engine.settings.openviking_api_key == "existing-tenant-key"
    assert store.decrypt(store.read()["memory"]["service_secret"]) == "existing-tenant-key"
    await engine.cancel_memory_bootstrap()
