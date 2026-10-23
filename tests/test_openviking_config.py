"""Unit coverage for OpenViking config gating and secret hygiene."""

from __future__ import annotations

import json
import stat
from types import SimpleNamespace

from redjohn.memory.openviking import config as ov


def test_external_url_requires_opt_in_and_https(monkeypatch) -> None:
    monkeypatch.delenv("REDJOHN_OPENVIKING_ALLOW_REMOTE", raising=False)
    assert ov._external_url_allowed("https://mem.example.com") is False

    monkeypatch.setenv("REDJOHN_OPENVIKING_ALLOW_REMOTE", "1")
    assert ov._external_url_allowed("https://mem.example.com") is True
    assert ov._external_url_allowed("http://mem.example.com") is False
    assert ov._external_url_allowed("file:///etc/passwd") is False
    assert ov._external_url_allowed("https://") is False


def _fake_settings(tmp_path) -> SimpleNamespace:
    return SimpleNamespace(
        openviking=SimpleNamespace(
            workspace=str(tmp_path / "ws"),
            vlm_model="",
            vlm_provider="",
            vlm_api_key="",
            vlm_api_base="",
            embedding_provider="",
            embedding_model="",
            embedding_api_key="",
            embedding_api_base="",
            embedding_dimension=None,
            url="",
        ),
        llm=SimpleNamespace(model="", api_key="", api_base=""),
    )


def test_ov_conf_is_private_with_no_cors_and_root_key(monkeypatch, tmp_path) -> None:
    ov_dir = tmp_path / "ov"
    monkeypatch.setattr(ov, "DEFAULT_OV_DIR", ov_dir)
    monkeypatch.setattr(ov, "DEFAULT_OV_CONF", ov_dir / "ov.conf")
    monkeypatch.setattr(ov, "load_settings", lambda: _fake_settings(tmp_path))

    conf_path = ov.ensure_openviking_configured()

    assert conf_path == ov_dir / "ov.conf"
    assert stat.S_IMODE(conf_path.stat().st_mode) == 0o600
    payload = json.loads(conf_path.read_text(encoding="utf-8"))
    assert payload["server"]["cors_origins"] == []
    assert isinstance(payload["server"]["root_api_key"], str)
    assert payload["server"]["root_api_key"]

    key_path = ov_dir / "ov.root_key"
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert key_path.read_text(encoding="utf-8").strip() == payload["server"]["root_api_key"]

    workspace = tmp_path / "ws"
    assert stat.S_IMODE(workspace.stat().st_mode) == 0o700

    # The stable key is reused, not regenerated, on the next write.
    first_key = payload["server"]["root_api_key"]
    ov.ensure_openviking_configured()
    assert (
        json.loads(conf_path.read_text(encoding="utf-8"))["server"]["root_api_key"]
        == first_key
    )


def test_dimension_change_backs_up_index_instead_of_deleting(monkeypatch, tmp_path) -> None:
    ov_dir = tmp_path / "ov"
    monkeypatch.setattr(ov, "DEFAULT_OV_DIR", ov_dir)
    monkeypatch.setattr(ov, "DEFAULT_OV_CONF", ov_dir / "ov.conf")
    monkeypatch.setattr(ov, "load_settings", lambda: _fake_settings(tmp_path))

    workspace = tmp_path / "ws"
    collection = workspace / "vectordb" / "context"
    collection.mkdir(parents=True)
    (collection / "collection_meta.json").write_text('{"Dimension": 512}', encoding="utf-8")
    (collection / "index.bin").write_bytes(b"payload")

    settings = _fake_settings(tmp_path)
    settings.openviking.embedding_provider = "openai"
    settings.openviking.embedding_model = "text-embedding-3-small"
    settings.openviking.embedding_dimension = 1536
    # Any truthy key keeps the OpenAI route; the value is synthetic, not a secret.
    settings.openviking.embedding_api_key = f"test-embedding-route-{tmp_path.name}"
    monkeypatch.setattr(ov, "load_settings", lambda: settings)

    ov.ensure_openviking_configured()

    backup = workspace / "vectordb" / "context.bak-512"
    assert backup.is_dir()
    assert (backup / "index.bin").read_bytes() == b"payload"
    assert not collection.exists()
