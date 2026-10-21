"""Synthetic settings/schema contracts; no provider or model is contacted."""

import pytest
from pydantic import ValidationError

from redjohn.config.settings import LlmSettings
from redjohn.core.inputs import make_model_settings


def test_default_model_output_cap_remains_unset(monkeypatch):
    monkeypatch.delenv("LLM_MAX_OUTPUT_TOKENS", raising=False)
    assert LlmSettings().max_output_tokens is None
    assert make_model_settings(None, model_name="contract-model").max_tokens is None


def test_configured_output_cap_reaches_actual_sdk_settings(monkeypatch):
    monkeypatch.setenv("LLM_MAX_OUTPUT_TOKENS", "2048")
    settings = LlmSettings()
    assert settings.max_output_tokens == 2048
    actual = make_model_settings(
        None, model_name="contract-model", max_output_tokens=settings.max_output_tokens
    )
    assert actual.max_tokens == 2048


@pytest.mark.parametrize("value", ["0", "-1", "65537", "not-a-number"])
def test_invalid_provider_output_budget_is_rejected(monkeypatch, value):
    monkeypatch.setenv("LLM_MAX_OUTPUT_TOKENS", value)
    with pytest.raises(ValidationError):
        LlmSettings()
