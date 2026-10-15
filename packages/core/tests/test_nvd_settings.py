from redjohn_core.integrations import IntegrationStore


async def test_nvd_key_is_optional_encrypted_and_write_only(api, engine):
    public = (await api.get("/api/v1/integrations/nvd")).json()
    assert public == {"key_configured": False, "requests_per_30_seconds": 5}
    invalid = await api.put("/api/v1/integrations/nvd", json={"api_key": "key\nheader"})
    assert invalid.status_code == 422
    result = await api.put("/api/v1/integrations/nvd", json={"api_key": "nvd-private-test-key"})
    assert result.status_code == 200
    assert result.json() == {"key_configured": True, "requests_per_30_seconds": 50}
    assert "nvd-private-test-key" not in result.text
    store = IntegrationStore(engine.settings)
    assert "nvd-private-test-key" not in store.path.read_text()
    assert store.decrypt(store.read()["nvd"]["secret"]) == "nvd-private-test-key"
    assert "nvd-private-test-key" not in (await api.get("/api/v1/integrations/nvd")).text
    removed = await api.delete("/api/v1/integrations/nvd")
    assert removed.json() == {"key_configured": False, "requests_per_30_seconds": 5}
