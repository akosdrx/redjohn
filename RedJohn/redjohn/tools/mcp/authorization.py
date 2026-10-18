"""Host-approved MCP effect contracts, separate from service transport authority.

No network is performed here and no tool annotation grants permission. Remote
providers remain trusted implementations of the operator-reviewed contract;
checking a schema/version does not attest a remote server's actual behavior.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from redjohn.assessment.models import stable_key
from redjohn.assessment.policy import PolicyDenied


if TYPE_CHECKING:
    from mcp.types import Tool as MCPTool

    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.tools.mcp.config import McpToolAuthorization
    from redjohn.tools.mcp.registry import McpConnectionEntry


class McpAuthorizationError(PolicyDenied):
    """A concrete missing/rejected operator contract, not a negative scan."""


def contract_for(entry: McpConnectionEntry, tool: str) -> McpToolAuthorization:
    config = entry.config
    rule = (
        next((rule for rule in config.tool_authorizations if rule.tool == tool), None)
        if config
        else None
    )
    if rule is None:
        raise McpAuthorizationError("mcp_tool_authorization_missing")
    if rule.effect.startswith("target-"):
        if config is not None and config.transport == "http":
            raise McpAuthorizationError("mcp_remote_target_boundary_unavailable")
        # A URL argument check is not redirect/DNS/socket enforcement. Only a
        # host-owned, actually attested worker launch can satisfy this boundary;
        # no boolean or annotation supplied by the remote tool grants it.
        raise McpAuthorizationError("mcp_target_worker_boundary_not_attested")
    return rule


def server_identity(entry: McpConnectionEntry) -> dict[str, str]:
    return identity_for(entry.server)


def identity_for(server: object) -> dict[str, str]:
    initialized = getattr(server, "server_initialize_result", None)
    info = getattr(initialized, "serverInfo", None)
    return {
        "name": str(getattr(info, "name", "")),
        "version": str(getattr(info, "version", "")),
    }


def authorize_arguments(
    rule: McpToolAuthorization, arguments: dict[str, Any], policy: EngagementPolicy
) -> None:
    if policy.profile not in rule.profiles:
        raise McpAuthorizationError("mcp_effect_profile_denied")
    try:
        encoded = json.dumps(arguments, allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError):
        raise McpAuthorizationError("mcp_invalid_argument_document") from None
    if len(encoded) > 65536 or set(arguments) - set(rule.allowed_arguments):
        raise McpAuthorizationError("mcp_argument_contract_denied")
    if any(
        key not in arguments or stable_key(arguments[key]) != stable_key(value)
        for key, value in rule.fixed_arguments.items()
    ):
        raise McpAuthorizationError("mcp_fixed_provider_context_denied")
    if rule.effect == "target-mutate":
        # A remote generic tool cannot inherit workflow/body authorization or
        # cancellation from an endpoint string. Use a reviewed scheduled adapter.
        raise McpAuthorizationError("mcp_target_mutation_requires_scheduled_adapter")
    if rule.effect == "provider-mutate" and policy.profile not in {
        "active-staging",
        "isolated-lab",
    }:
        raise McpAuthorizationError("mcp_provider_mutation_profile_denied")
    if rule.effect == "target-read":
        policy.check_capability(domains=("web",), profiles=tuple(rule.profiles))
        policy.check_actor(rule.actor_id)
        for name in rule.url_arguments:
            value = arguments.get(name)
            urls = value if isinstance(value, list) else [value]
            if not urls or len(urls) > 16:
                raise McpAuthorizationError("mcp_target_url_argument_required")
            for url in urls:
                if not isinstance(url, str):
                    raise McpAuthorizationError("mcp_target_url_argument_required")
                policy.check_readonly_request(url, "GET")


def authorize_descriptor(
    entry: McpConnectionEntry,
    rule: McpToolAuthorization,
    descriptor: MCPTool,
    *,
    server: object = None,
) -> None:
    identity = identity_for(server) if server is not None else server_identity(entry)
    if identity != {"name": rule.server_name, "version": rule.server_version}:
        raise McpAuthorizationError("mcp_server_identity_changed")
    if stable_key(descriptor.inputSchema or {"type": "object"}) != rule.schema_sha256:
        raise McpAuthorizationError("mcp_tool_schema_changed")
