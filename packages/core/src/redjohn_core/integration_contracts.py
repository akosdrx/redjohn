"""Public local integration DTOs. Credentials occur only in write-only inputs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ProviderConnectionDTO(BaseModel):
    id: str
    label: str
    provider: str
    model: str
    base_url: str
    credential_configured: bool
    auth_method: Literal["api_key", "oauth"]


class ProviderListDTO(BaseModel):
    items: list[ProviderConnectionDTO]
    active_provider: str | None
    runtime_provider: str | None = None
    runtime_model: str | None = None


class CatalogModelDTO(BaseModel):
    id: str
    name: str
    context: int | None = None
    output: int | None = None
    reasoning: bool = False
    tool_call: bool = True


class CatalogProviderDTO(BaseModel):
    id: str
    name: str
    base_url: str
    default_model: str
    auth_method: Literal["api_key", "oauth"]
    models: list[CatalogModelDTO]


class ProviderCatalogDTO(BaseModel):
    providers: list[CatalogProviderDTO]
    updated_at: str | None = None
    source: str
    cached: bool


class CodexLoginDTO(BaseModel):
    loginId: str
    verificationUrl: str
    userCode: str
    state: Literal["pending", "completed", "failed"]


class CodexModelDTO(BaseModel):
    id: str
    name: str


class CodexStatusDTO(BaseModel):
    available: bool
    authenticated: bool
    plan: str | None = None
    models: list[CodexModelDTO]
    login: CodexLoginDTO | None = None


class MemoryConfigDTO(BaseModel):
    configured: bool = False
    mode: Literal["provider", "local"] = "provider"
    provider_connection_id: str | None = None
    language_model: str = ""
    local_models_installed: bool = False
    openviking_url: str
    openviking_account: str
    openviking_user: str
    openviking_processing_mode: str
    service_key_configured: bool
    generated_config: str | None
    server_models: dict[str, Any]
    model_config_applied: bool
    managed_process: int | None = None


class NvdConfigDTO(BaseModel):
    key_configured: bool
    requests_per_30_seconds: int


class NativeToolDTO(BaseModel):
    id: str
    name: str
    source_url: str
    available: bool
    origin: Literal["system", "bundled"] | None
    version: str | None
    # True for the lightweight single-binary scanners RedJohn can fetch on
    # demand on this platform; false for heavy tools that must be installed.
    downloadable: bool = False


class NativeToolsDTO(BaseModel):
    items: list[NativeToolDTO]
    platform: str


class ProviderCheckDTO(BaseModel):
    state: Literal["live"]
    detail: str
    usage: dict[str, int] = Field(default_factory=dict)
