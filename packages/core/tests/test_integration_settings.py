from __future__ import annotations

import json

import httpx
import pytest
from redjohn_core.integrations import IntegrationStore
from redjohn_core.memory_config import generate_server_config, memory_public
from redjohn_core.settings import Settings


@pytest.mark.asyncio
async def test_settings_validation_does_not_echo_credentials(api):
    r = await api.post(
        "/api/v1/integrations/providers",
        json={"provider": "zai", "model": "glm-4.7", "api_key": {"secret": "must-not-echo"}},
    )
    assert r.status_code == 422
    assert "must-not-echo" not in r.text


@pytest.mark.asyncio
async def test_memory_service_key_is_not_a_language_model_key(api, engine):
    r = await api.put(
        "/api/v1/integrations/memory",
        json={
            "openviking_url": "http://127.0.0.1:1942",
            "openviking_account": "redjohn",
            "openviking_user": "local-user",
            "openviking_processing_mode": "",
            "service_api_key": "service-private-test",
        },
    )
    assert r.status_code == 200
    assert r.json()["service_key_configured"] is True
    assert "service-private-test" not in r.text
    assert engine.settings.model_api_key is None
    loaded = Settings.load(
        {"REDJOHN_HOME": str(engine.settings.redjohn_home), "REDJOHN_PROFILE": engine.settings.data_profile}
    )
    assert bool(loaded.openviking_api_key == "service-private-test")
    assert loaded.openviking_processing_mode == ""


def server_values(**extra):
    return {
        "language_base_url": "https://api.deepseek.com",
        "language_model": "deepseek-chat",
        "language_api_key": "language-private-test",
        "embedding_base_url": "https://api.openai.com/v1",
        "embedding_model": "text-embedding-3-small",
        "embedding_api_key": "embedding-private-test",
        "embedding_dimension": 1536,
        **extra,
    }


def test_memory_wizard_generates_real_config_without_clobbering_or_claiming_readiness(tmp_path):
    settings = Settings(redjohn_home=tmp_path)
    result = generate_server_config(settings, server_values())
    path = settings.profile_dir / "openviking" / "ov.conf"
    server = json.loads(path.read_text())
    assert bool(server["vlm"]["api_key"] == "language-private-test")
    assert bool(server["embedding"]["dense"]["api_key"] == "embedding-private-test")
    assert server["memory"]["extraction_enabled"] is True
    assert result["model_config_applied"] is False
    assert "language-private-test" not in json.dumps(result)
    assert "embedding-private-test" not in json.dumps(result)
    assert "private-test" not in IntegrationStore(settings).path.read_text()
    generate_server_config(
        settings,
        server_values(language_model="different-model", language_api_key=None, embedding_api_key=None),
    )
    assert json.loads(path.with_suffix(".conf.backup").read_text())["vlm"]["model"] == "deepseek-chat"


def test_memory_wizard_prevents_embedding_dimension_mismatch(tmp_path):
    from redjohn_core.errors import RJError

    settings = Settings(redjohn_home=tmp_path)
    generate_server_config(settings, server_values())
    with pytest.raises(RJError):
        generate_server_config(settings, server_values(embedding_dimension=768))


@pytest.mark.asyncio
async def test_provider_switch_is_blocked_during_active_run(api, engine):
    from .conftest import make_run_in

    await make_run_in(engine.store)
    r = await api.post(
        "/api/v1/integrations/providers",
        json={"provider": "zai", "model": "glm-4.7", "api_key": "private-test"},
    )
    assert r.status_code == 201
    selected = await api.post(f"/api/v1/integrations/providers/{r.json()['id']}/activate")
    assert selected.status_code == 409
    assert engine.gateway.name == "fixture"


@pytest.mark.asyncio
async def test_failed_catalog_refresh_keeps_offline_catalog(tmp_path):
    from redjohn_core.errors import RJError
    from redjohn_core.provider_catalog import read_catalog, refresh_catalog

    settings = Settings(redjohn_home=tmp_path)
    before = read_catalog(settings)
    with pytest.raises(RJError):
        await refresh_catalog(settings, transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    assert read_catalog(settings) == before
    assert any(p["id"] == "zai-coding-plan" for p in before["providers"])


@pytest.mark.asyncio
async def test_report_download_is_authenticated_and_returns_the_persisted_artifact(api, engine):
    from .conftest import make_run_in

    run = await make_run_in(engine.store)
    created = await api.post(f"/api/v1/pentests/{run.run_id}/reports", json={"format": "json"})
    assert created.status_code == 201
    report = created.json()
    listing = await api.get("/api/v1/reports", params={"run_id": run.run_id})
    assert listing.json()["items"][0]["report_id"] == report["report_id"]
    response = await api.get(f"/api/v1/reports/{report['report_id']}/download")
    assert response.status_code == 200
    assert response.json()["run"]["run_id"] == run.run_id
    assert "attachment" in response.headers["content-disposition"]


@pytest.mark.asyncio
async def test_mcp_api_does_not_return_private_environment(api, engine):
    from redjohn_core.models import MCPConnection, MCPTransport

    connection = MCPConnection(
        name="private", transport=MCPTransport.STDIO, command=["unused"], env={"API_KEY": "mcp-private-test"}
    )
    async with engine.store.write() as session:
        await engine.store.insert_mcp(session, connection)
    response = await api.get("/api/v1/mcps")
    assert response.status_code == 200
    assert "mcp-private-test" not in response.text


@pytest.mark.asyncio
async def test_native_memory_cannot_start_without_engine_owned_supervision(tmp_path):
    from redjohn_core import managed_memory as module
    from redjohn_core.errors import RJError

    settings = Settings(redjohn_home=tmp_path)
    generate_server_config(settings, server_values())
    with pytest.raises(RJError, match="child processes are supervised"):
        await module.start_memory(settings)
    assert memory_public(settings)["model_config_applied"] is False


@pytest.mark.asyncio
async def test_owned_memory_restart_remains_available_while_a_run_waits_for_processing(
    api, engine, monkeypatch
):
    import hashlib
    from unittest.mock import AsyncMock

    from redjohn_core import managed_memory
    from redjohn_core.integrations import atomic_private_json

    from .conftest import make_run_in

    settings = engine.settings
    generate_server_config(settings, server_values())
    settings.openviking_url = "http://127.0.0.1:1942"
    config = IntegrationStore(settings)
    data = config.read()
    data["memory"].update(
        {
            "managed_process": 12345,
            "managed_port": 1942,
            "applied_config_sha256": hashlib.sha256(
                (settings.profile_dir / "openviking" / "ov.conf").read_bytes()
            ).hexdigest(),
        }
    )
    atomic_private_json(config.path, data)
    await make_run_in(engine.store)
    restarted = AsyncMock(return_value=memory_public(settings))
    monkeypatch.setattr(managed_memory, "start_memory", restarted)
    response = await api.post("/api/v1/integrations/memory/start")
    assert response.status_code == 200
    restarted.assert_awaited_once()
    assert restarted.await_args.kwargs["runtime"] is engine._managed_memory


@pytest.mark.asyncio
async def test_starting_a_different_memory_connection_is_blocked_during_a_run(api, engine):
    from .conftest import make_run_in

    await make_run_in(engine.store)
    response = await api.post("/api/v1/integrations/memory/start")
    assert response.status_code == 409
