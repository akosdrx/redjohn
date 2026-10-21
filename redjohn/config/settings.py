"""RedJohn application settings — pydantic-settings powered."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"]
SwarmProfile = Literal[
    "full",
    "balanced",
    "fast",
    "deep",
    "recon",
    "exploit",
    "whitebox",
    "single",
]
ApiType = Literal["responses", "chat_completions"]

DEFAULT_MAX_TURNS = 500


def _lowercase(value: object) -> object:
    """Enum-like env values are matched case-insensitively (``None`` is ``none``)."""
    if isinstance(value, str):
        stripped = value.strip().lower()
        return stripped if stripped else None
    return value


_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class LlmSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="REDJOHN_LLM")
    api_type: ApiType | None = Field(
        default=None,
        validation_alias=AliasChoices("REDJOHN_API_TYPE", "REDJOHN_FORCE_API"),
        description="Force 'responses' or 'chat_completions' API path",
    )
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY"),
        repr=False,
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    extra_headers: dict[str, str] | None = Field(
        default=None,
        alias="LLM_EXTRA_HEADERS",
        repr=False,
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="REDJOHN_REASONING_EFFORT")
    model_label: str | None = Field(default=None, alias="REDJOHN_LLM_LABEL")
    supported_efforts: list[str] | None = Field(
        default=None,
        alias="REDJOHN_LLM_SUPPORTED_EFFORTS",
    )
    swarm_model: str | None = Field(default=None, alias="REDJOHN_SWARM_LLM")
    swarm_reasoning_effort: ReasoningEffort | None = Field(
        default=None,
        alias="REDJOHN_SWARM_REASONING_EFFORT",
    )
    swarm_api_key: str | None = Field(
        default=None,
        alias="SWARM_LLM_API_KEY",
        repr=False,
    )
    swarm_api_base: str | None = Field(
        default=None,
        alias="SWARM_LLM_API_BASE",
    )
    swarm_profile: SwarmProfile = Field(
        default="full",
        alias="REDJOHN_SWARM_PROFILE",
    )
    swarm_role_models: dict[str, str] | None = Field(
        default=None,
        alias="REDJOHN_SWARM_ROLE_MODELS",
    )
    force_required_tool_choice: bool = Field(
        default=False,
        alias="REDJOHN_FORCE_REQUIRED_TOOL_CHOICE",
    )
    prompt_cache: bool = Field(
        default=True,
        alias="REDJOHN_PROMPT_CACHE",
    )
    # Providers cache prompts in fixed-size token blocks, so a fully cached prompt
    # can read back up to a block short. 128 covers the largest common size
    # (OpenAI; DeepSeek and GLM use 64, vLLM defaults to 16).
    cache_block_tokens: int = Field(default=128, ge=1, alias="REDJOHN_CACHE_BLOCK_TOKENS")
    openrouter_sticky_sessions: bool = Field(
        default=False,
        alias="REDJOHN_OPENROUTER_STICKY_SESSIONS",
    )
    disable_streaming: bool = Field(
        default=False,
        alias="LLM_DISABLE_STREAMING",
    )
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")
    preflight_timeout: int = Field(default=30, ge=1, alias="LLM_PREFLIGHT_TIMEOUT")
    stream_idle_timeout: int = Field(default=300, ge=0, alias="LLM_STREAM_IDLE_TIMEOUT")
    stream_first_event_timeout: int = Field(
        default=120, ge=0, alias="LLM_STREAM_FIRST_EVENT_TIMEOUT"
    )
    stream_total_timeout: int = Field(default=600, ge=0, alias="LLM_STREAM_TOTAL_TIMEOUT")
    max_tool_calls_per_turn: int = Field(
        default=32,
        ge=0,
        alias="LLM_MAX_TOOL_CALLS_PER_TURN",
    )
    max_output_tokens: int | None = Field(
        default=None,
        ge=1,
        le=65536,
        alias="LLM_MAX_OUTPUT_TOKENS",
        description="Optional provider-enforced output token cap for every agent model call",
    )

    @field_validator(
        "api_type",
        "swarm_reasoning_effort",
        mode="before",
    )
    @classmethod
    def _normalize_case(cls, value: object) -> object:
        return _lowercase(value)

    @field_validator("reasoning_effort", mode="before")
    @classmethod
    def _normalize_reasoning_effort(cls, value: object) -> object:
        normalized = _lowercase(value)
        return "high" if normalized is None else normalized

    @field_validator("swarm_profile", mode="before")
    @classmethod
    def _normalize_swarm_profile(cls, value: object) -> object:
        normalized = _lowercase(value)
        return "full" if normalized is None else normalized

    @field_validator("supported_efforts", mode="before")
    @classmethod
    def _parse_supported_efforts(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            if stripped.startswith("["):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, list):
                        return [str(item).strip().lower() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [part.strip().lower() for part in stripped.split(",") if part.strip()]
        return value

    @field_validator("swarm_role_models", mode="before")
    @classmethod
    def _parse_role_models(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items() if v}
            return None
        return value


class DedupeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="REDJOHN_DEDUPE_MODEL")
    reasoning_effort: ReasoningEffort | None = Field(
        default=None,
        alias="REDJOHN_DEDUPE_REASONING_EFFORT",
    )
    api_key: str | None = Field(default=None, alias="DEDUPE_LLM_API_KEY", repr=False)
    api_base: str | None = Field(default=None, alias="DEDUPE_LLM_API_BASE")
    extra_headers: dict[str, str] | None = Field(
        default=None,
        alias="DEDUPE_LLM_EXTRA_HEADERS",
        repr=False,
    )

    @field_validator("reasoning_effort", mode="before")
    @classmethod
    def _normalize_case(cls, value: object) -> object:
        return _lowercase(value)


class ContextSettings(BaseSettings):
    """Context-window management: per-tool-output caps and history compaction."""

    model_config = _BASE_CONFIG

    auto_compact: bool = Field(default=True, alias="REDJOHN_CONTEXT_AUTO_COMPACT")
    compact_buffer_tokens: int = Field(default=20_000, gt=0, alias="REDJOHN_CONTEXT_BUFFER_TOKENS")
    keep_tokens: int = Field(default=8_000, gt=0, alias="REDJOHN_CONTEXT_KEEP_TOKENS")
    fallback_context_tokens: int = Field(
        default=200_000, gt=0, alias="REDJOHN_CONTEXT_FALLBACK_TOKENS"
    )
    summary_max_tokens: int = Field(default=4_096, gt=0, alias="REDJOHN_CONTEXT_SUMMARY_TOKENS")
    tool_output_max_tokens: int = Field(default=8_000, gt=0, alias="REDJOHN_TOOL_OUTPUT_MAX_TOKENS")
    tool_output_max_lines: int = Field(default=2_000, gt=0, alias="REDJOHN_TOOL_OUTPUT_MAX_LINES")
    # Floor above the truncation-notice size so a preview always fits.
    tool_output_max_bytes: int = Field(
        default=50 * 1024, ge=1024, alias="REDJOHN_TOOL_OUTPUT_MAX_BYTES"
    )


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/redjohn-ai/redjohn-sandbox:1.3.0",
        alias="REDJOHN_IMAGE",
    )
    backend: str = Field(default="local", alias="REDJOHN_RUNTIME_BACKEND")
    # Max screenshot/image tool outputs kept live per agent context (0 = none).
    max_context_images: int = Field(default=3, ge=0, alias="REDJOHN_MAX_CONTEXT_IMAGES")


class TelemetrySettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(default=False, alias="REDJOHN_TELEMETRY")


WebSearchProvider = Literal["auto", "perplexity", "exa", "duckduckgo", "browser"]
ExaSearchType = Literal["auto", "fast", "instant", "deep-lite", "deep", "deep-reasoning"]


class IntegrationSettings(BaseSettings):
    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(
        default=None,
        alias="PERPLEXITY_API_KEY",
        repr=False,
    )
    exa_api_key: str | None = Field(
        default=None,
        alias="EXA_API_KEY",
        repr=False,
    )
    web_search_provider: WebSearchProvider = Field(
        default="auto",
        alias="REDJOHN_WEB_SEARCH_PROVIDER",
    )
    exa_search_type: ExaSearchType = Field(
        default="auto",
        alias="REDJOHN_EXA_SEARCH_TYPE",
    )
    exa_num_results: int = Field(
        default=5,
        ge=1,
        le=100,
        alias="REDJOHN_EXA_NUM_RESULTS",
    )
    postman_api_key: str | None = Field(
        default=None,
        alias="POSTMAN_API_KEY",
        repr=False,
    )


class ViewerSettings(BaseSettings):
    model_config = _BASE_CONFIG

    # Base URL of the RedJohn relay the local viewer proxies to for email
    # verification and encrypted report delivery. The browser never talks to
    # the relay directly; the local server is the only caller.
    app_url: str = Field(default="https://app.redjohn.ai", alias="REDJOHN_APP_URL")


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    dedupe: DedupeSettings = Field(default_factory=DedupeSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    context: ContextSettings = Field(default_factory=ContextSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    viewer: ViewerSettings = Field(default_factory=ViewerSettings)
