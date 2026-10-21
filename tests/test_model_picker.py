"""Model picker catalog, credential persistence, and the interactive startup gate."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import pytest

from redjohn.config import loader
from redjohn.config.codex import interpret_device_poll, interpret_device_start
from redjohn.config.grok import interpret_device_poll as interpret_grok_poll
from redjohn.config.grok import interpret_device_start as interpret_grok_start
from redjohn.config.model_catalog import (
    catalog_payload,
    find_entry,
    format_model_setting,
    models_from_payload,
)
from redjohn.interface.environment import validate_environment


if TYPE_CHECKING:
    from pathlib import Path


def _labels(section: str) -> list[str]:
    payload = catalog_payload()
    for item in payload["sections"]:
        if item["title"] == section:
            return [entry["label"] for entry in item["entries"]]
    raise AssertionError(section)


def _child_labels(parent_id: str) -> list[str]:
    entry = find_entry(parent_id)
    assert entry is not None
    return [child.label for child in entry.children]


def test_catalog_sections_match_the_picker() -> None:
    assert _labels("Recommended") == [
        "abliteration.ai",
        "z.ai",
        "z.ai coding plan",
        "Venice AI",
    ]
    assert _labels("Other models") == [
        "OpenAI",
        "Anthropic",
        "Kimi for Coding (kimi.ai)",
        "Kimi for Coding (kimi.com)",
        "Xiaomi",
        "xAI",
    ]
    assert _child_labels("openai") == [
        "Sign in with ChatGPT",
        "Codex Browser (Legacy)",
        "Codex Device Code (Legacy)",
        "API Key",
    ]
    assert _child_labels("xiaomi") == [
        "API",
        "Token Plan (China)",
        "Token Plan (Europe)",
        "Token Plan (Singapore)",
    ]
    assert _child_labels("xai") == ["SuperGrok Subscription", "API Key"]
    xiaomi = find_entry("xiaomi")
    assert xiaomi is not None
    assert [child.api_base for child in xiaomi.children] == [
        "https://api.xiaomimimo.com/v1",
        "https://token-plan-cn.xiaomimimo.com/v1",
        "https://token-plan-ams.xiaomimimo.com/v1",
        "https://token-plan-sgp.xiaomimimo.com/v1",
    ]


def test_format_model_setting_routes() -> None:
    assert format_model_setting("openai", "glm-5") == "openai/glm-5"
    assert format_model_setting("anthropic", "claude-opus-4-7") == "anthropic/claude-opus-4-7"
    assert format_model_setting("xai", "grok-4") == "xai/grok-4"
    assert format_model_setting("chatgpt", "gpt-5.4") == "chatgpt/gpt-5.4"
    assert format_model_setting("grok", "grok-4") == "grok/grok-4"


def test_models_from_payload_skips_non_chat() -> None:
    models = models_from_payload(
        {
            "data": [
                {"id": "glm-5", "display_name": "GLM 5"},
                {"id": "text-embedding-3-large"},
                {"id": "whisper-1"},
                "mimo-v2.6-flash",
            ]
        }
    )
    assert [item["id"] for item in models] == ["glm-5", "mimo-v2.6-flash"]
    assert models[0]["label"] == "GLM 5"


def test_codex_device_payloads() -> None:
    started = interpret_device_start(
        {"device_auth_id": "dev", "user_code": "ABCD-EFGH", "interval": "5"}
    )
    assert started is not None
    assert started["user_code"] == "ABCD-EFGH"
    assert started["verification_url"].endswith("/codex/device")
    assert interpret_device_poll(403, {}) is None
    assert interpret_device_poll(
        200, {"authorization_code": "code", "code_verifier": "verifier"}
    ) == {"code": "code", "verifier": "verifier"}


def test_grok_device_payloads() -> None:
    started = interpret_grok_start(
        {
            "device_code": "secret",
            "user_code": "XYZ",
            "verification_uri_complete": "https://auth.x.ai/device?user_code=XYZ",
            "interval": 5,
            "expires_in": 600,
        }
    )
    assert started is not None
    assert started["verification_url"].startswith("https://auth.x.ai/device")
    assert interpret_grok_poll(400, {"error": "authorization_pending"}) == "pending"
    assert interpret_grok_poll(400, {"error": "slow_down"}) == "slow_down"
    record = interpret_grok_poll(
        200,
        {"access_token": "access", "refresh_token": "refresh", "expires_in": 3600},
    )
    assert isinstance(record, dict)
    assert record["access_token"] == "access"


def test_interactive_start_does_not_require_a_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("REDJOHN_LLM", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    previous_override = loader._override
    try:
        loader.apply_config_override(tmp_path / "empty.json")
        validate_environment(require_model=False)
        with pytest.raises(SystemExit):
            validate_environment(require_model=True)
    finally:
        loader._override = previous_override
        loader.invalidate_settings_cache()


def test_save_llm_selection_writes_the_connection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "cli-config.json"
    monkeypatch.delenv("REDJOHN_LLM", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("REDJOHN_REASONING_EFFORT", raising=False)
    previous_override = loader._override
    try:
        loader.apply_config_override(config)
        loader.save_llm_selection(
            model="openai/glm-5",
            api_key="test-key",
            api_base="https://api.z.ai/api/paas/v4",
            reasoning_effort="medium",
        )
        saved = json.loads(config.read_text(encoding="utf-8"))
        assert saved["env"]["REDJOHN_LLM"] == "openai/glm-5"
        assert saved["env"]["LLM_API_KEY"] == "test-key"
        assert saved["env"]["LLM_API_BASE"] == "https://api.z.ai/api/paas/v4"
        assert saved["env"]["REDJOHN_REASONING_EFFORT"] == "medium"
        settings = loader.load_settings()
        assert settings.llm.model == "openai/glm-5"
        assert settings.llm.reasoning_effort == "medium"

        loader.save_llm_selection(
            model="chatgpt/gpt-5.4",
            clear_api_key=True,
            clear_api_base=True,
        )
        saved = json.loads(config.read_text(encoding="utf-8"))
        assert saved["env"]["REDJOHN_LLM"] == "chatgpt/gpt-5.4"
        assert "LLM_API_KEY" not in saved["env"]
        assert "LLM_API_BASE" not in saved["env"]
        assert saved["env"]["REDJOHN_REASONING_EFFORT"] == "medium"
    finally:
        loader._override = previous_override
        loader.invalidate_settings_cache()
        for name in (
            "REDJOHN_LLM",
            "LLM_API_KEY",
            "LLM_API_BASE",
            "OPENAI_BASE_URL",
            "REDJOHN_REASONING_EFFORT",
        ):
            os.environ.pop(name, None)
