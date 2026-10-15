from __future__ import annotations

import pytest
from redjohn_core import serve
from redjohn_core.integrations import IntegrationStore
from redjohn_core.settings import Settings


def test_explicit_core_profile_loads_its_own_credentials_before_engine_creation(tmp_path, monkeypatch):
    for name, provider in (("default", "zai"), ("alternate", "deepseek")):
        config = IntegrationStore(Settings(redjohn_home=tmp_path, data_profile=name))
        item = config.save_provider(
            {"provider": provider, "model": "test-model", "api_key": name + "-private-test"}
        )
        config.activate(item["id"])
    monkeypatch.setenv("REDJOHN_HOME", str(tmp_path))
    monkeypatch.setenv("REDJOHN_PROFILE", "default")
    monkeypatch.setenv("RJ_MEMORY_AUTO_START", "1")
    for name in ("RJ_MODEL_PROVIDER", "RJ_MODEL_NAME", "RJ_MODEL_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    captured = []

    async def create(settings, *, auto_memory=False):
        assert auto_memory is True
        captured.append(settings)
        raise RuntimeError("captured-settings")

    monkeypatch.setattr(serve.Engine, "create", create)
    with pytest.raises(RuntimeError, match="captured-settings"):
        serve.main(["--profile", "alternate"])
    assert captured[0].data_profile == "alternate"
    assert captured[0].model_provider == "deepseek"
    assert bool(captured[0].model_api_key == "alternate-private-test")
