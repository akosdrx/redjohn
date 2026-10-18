"""The connection-config contract for the MCP client.

Describes one MCP server the client can connect to: its transport, endpoint or
launch command, optional auth, and an optional tool allowlist. Field names are
stable; callers build against them.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


DEFAULT_MAX_CONCURRENT_CALLS = 4
McpProfile = Literal["safe-production", "active-staging", "isolated-lab"]


def _default_profiles() -> list[McpProfile]:
    return ["safe-production", "active-staging", "isolated-lab"]


class BearerAuth(BaseModel):
    """Header-token auth, sent as ``Authorization: Bearer <token>``."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["bearer"] = "bearer"
    token: str = Field(min_length=1, repr=False)


McpAuth = Annotated[BearerAuth, Field(discriminator="kind")]


class McpToolAuthorization(BaseModel):
    """Operator-reviewed effect contract; endpoint configuration is not target authority."""

    model_config = ConfigDict(extra="forbid")
    tool: str = Field(min_length=1, max_length=128)
    effect: Literal["provider-read", "provider-mutate", "target-read", "target-mutate"]
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    server_name: str = Field(min_length=1, max_length=256)
    server_version: str = Field(min_length=1, max_length=128)
    allowed_arguments: list[str] = Field(default_factory=list, max_length=64)
    fixed_arguments: dict[str, Any] = Field(default_factory=dict, repr=False)
    context_free: bool = False
    """Explicit approval for public metadata tools without account/project context."""
    url_arguments: list[str] = Field(default_factory=list, max_length=16)
    actor_id: str = Field(default="anonymous", min_length=1, max_length=128)
    workflow_ref: str = Field(default="", max_length=128)
    profiles: list[McpProfile] = Field(
        default_factory=_default_profiles,
        min_length=1,
        max_length=3,
    )

    @model_validator(mode="after")
    def _check_argument_contract(self) -> McpToolAuthorization:
        if (
            len(set(self.allowed_arguments)) != len(self.allowed_arguments)
            or any(not name or len(name) > 128 for name in self.allowed_arguments)
            or set(self.fixed_arguments) - set(self.allowed_arguments)
            or set(self.url_arguments) - set(self.allowed_arguments)
            or len(json.dumps(self.fixed_arguments, allow_nan=False).encode()) > 8192
        ):
            raise ValueError("invalid_mcp_argument_contract")
        if self.effect.startswith("target-") and not self.url_arguments:
            raise ValueError("mcp_target_contract_requires_url_arguments")
        if self.effect.startswith("provider-") and self.url_arguments:
            raise ValueError("mcp_provider_contract_is_not_assessment_target_scope")
        if (
            self.effect == "provider-read"
            and self.allowed_arguments
            and not self.fixed_arguments
            and not self.context_free
        ):
            raise ValueError("mcp_provider_contract_requires_fixed_context_or_metadata_approval")
        if self.effect == "provider-mutate" and (not self.fixed_arguments or not self.workflow_ref):
            raise ValueError("mcp_provider_mutation_requires_fixed_context_and_workflow")
        return self


class McpConnectionConfig(BaseModel):
    """One MCP server the client can connect to.

    Two transports are supported: streamable ``http`` (a remote endpoint) and
    ``stdio`` (a local server launched as a subprocess).
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    """Namespaced tool prefix, unique per run (e.g. ``github``)."""

    transport: Literal["http", "stdio"] = "http"
    """``http`` for a streamable HTTP endpoint, ``stdio`` for a local subprocess."""

    url: str | None = Field(default=None, min_length=1)
    """The MCP server endpoint. Required for ``http``."""

    auth: McpAuth | None = None
    """Bearer token for the server. Optional; a local stdio server usually
    needs none."""

    command: str | None = Field(default=None, min_length=1)
    """The executable to launch for ``stdio``. Required for ``stdio``."""

    args: list[str] = Field(default_factory=list)
    """Arguments passed to ``command`` (stdio only)."""

    env: dict[str, str] = Field(default_factory=dict)
    """Extra environment variables for the stdio subprocess."""

    allowed_tools: list[str] | None = None
    """Tool allowlist, applied after the server lists its tools. ``None`` (the
    default) exposes every tool the server lists; a list restricts to it."""

    active_tools: list[str] = Field(default_factory=list)
    """Small scan-relevant subset ranked ahead of the broader allowed catalog."""

    idempotent_tools: list[str] = Field(default_factory=list)
    """Operator-reviewed calls safe to retry after an unknown transport outcome.

    MCP tool annotations are untrusted metadata and never grant this permission.
    The default makes a failed call inconclusive without repeating its effects.
    """

    tool_authorizations: list[McpToolAuthorization] = Field(default_factory=list, max_length=64)
    """Private host-owned contracts required for calls in a bound assessment.

    Generic unbound MCP usage remains compatible. Catalog discovery is allowed
    so the operator can inspect a schema/version before approving a contract.
    """

    queue_max_items: int = Field(default=32, ge=1, le=128)
    """Bound pending requests instead of retaining an unbounded task backlog."""

    notes: str | None = None
    """Free-text notes for the agent describing what this connection is and how
    to use it. When set, the note becomes the connection's purpose line in the
    MCP inventory every agent renders in its prompt, so it describes the
    connection once rather than being repeated onto each of its tools."""

    http_timeout_seconds: float = Field(default=30.0, gt=0)
    """HTTP request timeout; the SDK's 5-second default is below tool p95s."""

    sse_read_timeout_seconds: float = Field(default=300.0, gt=0)
    """Stream read timeout; the SDK's 5-second default is below tool p95s."""

    session_timeout_seconds: float = Field(default=60.0, gt=0)
    """MCP operation timeout for SQL queries and cloud describe fan-outs."""

    max_concurrent_calls: int = Field(default=DEFAULT_MAX_CONCURRENT_CALLS, ge=1)
    """Maximum concurrent calls for this connection name across sessions."""

    @model_validator(mode="after")
    def _check_transport_fields(self) -> McpConnectionConfig:
        if self.transport == "http" and not self.url:
            raise ValueError("an http MCP connection requires 'url'")
        if self.transport == "stdio" and not self.command:
            raise ValueError("a stdio MCP connection requires 'command'")
        if len({rule.tool for rule in self.tool_authorizations}) != len(self.tool_authorizations):
            raise ValueError("duplicate_mcp_tool_authorization")
        if any(
            rule.effect.endswith("-mutate") and rule.tool in self.idempotent_tools
            for rule in self.tool_authorizations
        ):
            raise ValueError("mcp_mutating_tool_must_not_auto_replay")
        return self
