"""The generic MCP discovery and dispatch tools every agent carries.

Under the generic-dispatch model an agent does not get one tool per MCP tool.
It gets four primary tools and discovers connections on demand:

- ``list_mcps()`` returns the connections available this run — each connection's
  id, name, description, and tool count, with no tool schemas — so the model can
  discover what it can reach without any inventory in the system prompt.
- ``search_mcp_tools(connection, query)`` returns a small ranked candidate set.
- ``get_mcp_tool_schema(connection, tool)`` returns one exact input schema.
- ``call_mcp(connection, tool, arguments)`` dispatches one call to a
  connection's tool and returns its result.

``describe_mcp`` remains as a compatibility path for older prompts, but current
agents use targeted search and one-schema lookup instead of receiving a whole
provider catalog in one model turn.

All four read the per-run :class:`~redjohn.tools.mcp.registry.McpRegistry` from the
run context under :data:`~redjohn.tools.mcp.registry.MCP_REGISTRY_CONTEXT_KEY`. They
are ordinary ``FunctionTool`` objects placed in the agent factory's base tool set,
so the factory's output-bounding and disk-spill wrapping apply to their results
automatically.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from redjohn.assessment.models import error_record, stable_key
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.resources import ResourceAdmissionError
from redjohn.runtime.legacy_execution import legacy_from_context
from redjohn.tools.mcp.authorization import (
    authorize_arguments,
    authorize_descriptor,
    contract_for,
    server_identity,
)
from redjohn.tools.mcp.client import _errored_tool_output
from redjohn.tools.mcp.naming import namespaced_tool_name
from redjohn.tools.mcp.registry import MCP_REGISTRY_CONTEXT_KEY, McpRegistry
from redjohn.tools.mcp.session import McpConnectionUnavailableError


if TYPE_CHECKING:
    from agents.mcp import MCPServer
    from mcp.types import Tool as MCPTool

    from redjohn.tools.mcp.registry import McpConnectionEntry


def _registry_from_ctx(ctx: RunContextWrapper) -> McpRegistry | None:
    context = ctx.context if isinstance(ctx.context, dict) else {}
    registry = context.get(MCP_REGISTRY_CONTEXT_KEY)
    return registry if isinstance(registry, McpRegistry) else None


_NO_CONNECTIONS = "No MCP connections are configured for this run."
_MCP_DISCOVERY_WAIT_SECONDS = 30.0


async def _catalog_for(ctx: RunContextWrapper, entry: McpConnectionEntry) -> list[Any]:
    context = ctx.context if isinstance(ctx.context, dict) else {}
    owner = legacy_from_context(context)
    if owner is not None and entry.name != "openviking":
        return await owner.run(
            f"mcp-catalog:{entry.name}",
            entry.ensure_catalog,
            timeout=_MCP_DISCOVERY_WAIT_SECONDS,
            cleanup=entry.close,
        )
    try:
        async with asyncio.timeout(_MCP_DISCOVERY_WAIT_SECONDS):
            return await entry.ensure_catalog()
    except (TimeoutError, asyncio.CancelledError):
        await entry.close()
        raise


def _unknown_connection(connection: str, registry: McpRegistry) -> str:
    available = ", ".join(registry.names()) or "(none)"
    return f"Unknown MCP connection {connection!r}. Available connections: {available}."


def _scheduled_targets(registry: McpRegistry, name: str) -> list[str]:
    entry = registry.get(name)
    if entry is None or entry.config is None or entry._target_adapter is None:
        return []
    return [rule.tool for rule in entry.config.tool_authorizations if rule.effect == "target-read"]


def _format_tool(tool: MCPTool) -> str:
    schema = json.dumps(tool.inputSchema or {"type": "object"}, indent=2, ensure_ascii=False)
    description = (tool.description or "").strip() or "(no description)"
    return f"- {tool.name}: {description}\n  input schema:\n{schema}"


@function_tool(timeout=60)
async def list_mcps(ctx: RunContextWrapper) -> dict[str, Any]:
    """List configured MCP connections without starting optional providers.

    Read-only. Returns one entry per connection with its ``id`` (the exact name
    you pass to the other MCP tools), ``name``, ``description``, and
    ``tool_count`` (null while the catalog is unknown). Connections remain inert
    until a selected search/schema/call needs that provider. The response does
    not include tool schemas. Call
    ``search_mcp_tools`` next. Then call ``get_mcp_tool_schema`` for one selected
    tool before you call ``call_mcp``. Returns an empty ``connections`` list when
    the run has no MCP connections.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return {"connections": []}
    dead_by_name = {status.name: status.dead for status in registry.statuses()}
    return {
        "connections": [
            {
                "id": summary.name,
                "name": summary.name,
                "description": summary.purpose,
                "tool_count": summary.tool_count if summary.state == "catalog_ready" else None,
                "dead": dead_by_name.get(summary.name, False),
                "state": summary.state,
                "scheduled_target_tools": _scheduled_targets(registry, summary.name),
            }
            for summary in registry.summaries()
        ]
    }


@function_tool(timeout=60)
async def describe_mcp(ctx: RunContextWrapper, connection: str) -> str:
    """Return one connection's full tool catalog as a compatibility fallback.

    Read-only. This result can be large because it includes every tool schema.
    First use ``search_mcp_tools`` and ``get_mcp_tool_schema``. Use this fallback
    only when targeted search cannot identify an expected tool. Nothing is read
    from the connected account.

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    try:
        tools = await _catalog_for(ctx, entry)
    except (McpConnectionUnavailableError, ResourceAdmissionError, TimeoutError) as exc:
        return str(exc)
    if not tools:
        return f"MCP connection {connection!r} offers no tools."
    header = f"MCP connection {connection!r} offers {len(tools)} tool(s):"
    body = "\n".join(_format_tool(tool) for tool in tools)
    return f"{header}\n{body}"


def _search_score(tool: MCPTool, query_terms: list[str], active: bool) -> tuple[int, str]:
    name = tool.name.lower()
    description = (tool.description or "").lower()
    if not query_terms:
        return (100 if active else 0, name)
    score = 100 if active else 0
    matched_terms = 0
    for term in query_terms:
        if name == term:
            score += 60
            matched_terms += 1
        elif name.startswith(term):
            score += 35
            matched_terms += 1
        elif term in name:
            score += 25
            matched_terms += 1
        elif term in description:
            score += 10
            matched_terms += 1
    if matched_terms == 0:
        return (-1, name)
    return (score + (matched_terms * 5), name)


@function_tool(timeout=60)
async def search_mcp_tools(
    ctx: RunContextWrapper,
    connection: str,
    query: str,
    limit: int = 8,
) -> dict[str, Any] | str:
    """Search one connection's tools without returning their full schemas.

    The first search lazily connects the provider and caches its catalog. Results
    contain only names, short descriptions, and whether each tool is in the
    scan's active set. Call ``get_mcp_tool_schema`` for the selected tool.

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
        query: Capability words such as ``page content`` or ``workspace identity``.
        limit: Maximum candidates to return, from 1 through 20.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    try:
        tools = await _catalog_for(ctx, entry)
    except (McpConnectionUnavailableError, ResourceAdmissionError, TimeoutError) as exc:
        return str(exc)
    terms = [term for term in query.lower().split() if term]
    bounded_limit = min(max(limit, 1), 20)
    ranked = [
        (score, tool)
        for tool in tools
        if (score := _search_score(tool, terms, tool.name in entry.active_tools))[0] >= 0
    ]
    if not ranked:
        ranked = [
            ((100, tool.name.lower()), tool) for tool in tools if tool.name in entry.active_tools
        ]
    ranked.sort(key=lambda item: (-item[0][0], item[0][1]))
    return {
        "connection": connection,
        "query": query,
        "matches": [
            {
                "name": tool.name,
                "description": (tool.description or "").strip() or None,
                "active": tool.name in entry.active_tools,
            }
            for _, tool in ranked[:bounded_limit]
        ],
    }


@function_tool(timeout=60)
async def get_mcp_tool_schema(
    ctx: RunContextWrapper,
    connection: str,
    tool: str,
) -> dict[str, Any] | str:
    """Return one MCP tool's exact input schema.

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
        tool: One exact tool name returned by ``search_mcp_tools``.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    try:
        tools = await _catalog_for(ctx, entry)
    except (McpConnectionUnavailableError, ResourceAdmissionError, TimeoutError) as exc:
        return str(exc)
    match = next((candidate for candidate in tools if candidate.name == tool), None)
    if match is None:
        return (
            f"Unknown tool {tool!r} on MCP connection {connection!r}. "
            "Call search_mcp_tools to find an available tool."
        )
    return {
        "connection": connection,
        "name": match.name,
        "description": (match.description or "").strip() or None,
        "input_schema": match.inputSchema or {"type": "object"},
        "schema_sha256": stable_key(match.inputSchema or {"type": "object"}),
        "server_identity": server_identity(entry),
    }


@function_tool(timeout=120, strict_mode=False)
async def call_mcp(  # noqa: PLR0912, PLR0915 - explicit validation and lifecycle boundaries
    ctx: RunContextWrapper,
    connection: str,
    tool: str,
    arguments: Any = None,
    surface_id: str | None = None,
) -> Any:
    """Call one tool on one MCP connection and return its result.

    Use the connection id from ``list_mcps``. Use the tool name from
    ``search_mcp_tools``. Pass an object that matches the schema from
    ``get_mcp_tool_schema``. Omit the arguments for a tool that takes no
    arguments.

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
        tool: The tool name exactly as reported by ``search_mcp_tools``.
        arguments: The tool's arguments as a JSON object of names to values (for
            example ``{"path": "app.py"}``), or omitted/empty for a tool that
            takes none. Pass an object, not a stringified object. Match the shape
            that ``get_mcp_tool_schema`` returned.
        surface_id: Existing observed surface reference for a host-bound target
            read. Such calls enqueue a durable job and return its ID. They never
            dispatch directly; retrieve completion/evidence with assessment tools.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    invalid_arguments = (
        f"Invalid arguments for {connection!r}.{tool}: expected a JSON object of "
        "argument names to values, or none. Call get_mcp_tool_schema for the schema."
    )
    if isinstance(arguments, str):
        # The ``arguments`` parameter is schema-less (an open object is not
        # expressible as a strict tool schema), so some models serialize it as a
        # JSON string instead of a bare object. Accept a string that decodes to an
        # object so a correct call is not rejected over its encoding.
        if len(arguments.encode()) > 65536:
            return invalid_arguments
        stripped = arguments.strip()
        try:
            arguments = json.loads(stripped) if stripped else {}
        except json.JSONDecodeError:
            return invalid_arguments
    if arguments is not None and not isinstance(arguments, dict):
        return invalid_arguments
    try:
        if len(json.dumps(arguments or {}, allow_nan=False).encode()) > 65536:
            return invalid_arguments
    except (TypeError, ValueError, RecursionError):
        return invalid_arguments
    context = ctx.context if isinstance(ctx.context, dict) else {}
    owner = legacy_from_context(context)
    rule = None
    if surface_id is not None and (owner is None or owner.control is None):
        return _errored_tool_output(
            error_record(
                "mcp_target_bound_assessment_required", category="policy", coverage_effect="blocked"
            )
        )
    if owner is not None and owner.control is not None and connection != "openviking":
        try:
            owner.check_policy()
            rule = contract_for(entry, tool)
            authorize_arguments(rule, arguments or {}, owner.control.policy)
            if rule.effect.startswith("target-"):
                assert entry._target_adapter is not None
                return await entry._target_adapter.submit(entry, tool, arguments or {}, surface_id)
            if surface_id is not None:
                raise PolicyDenied("mcp_surface_reference_requires_target_contract")  # noqa: TRY301
        except (PolicyDenied, ResourceAdmissionError) as exc:
            return _errored_tool_output(
                error_record(
                    str(exc),
                    category="policy",
                    coverage_effect="blocked",
                )
            )
    try:
        available = await _catalog_for(ctx, entry)
    except (McpConnectionUnavailableError, ResourceAdmissionError, TimeoutError) as exc:
        return _errored_tool_output(str(exc))
    valid_names = {mcp_tool.name for mcp_tool in available}
    if tool not in valid_names:
        return (
            f"Unknown tool {tool!r} on MCP connection {connection!r}. "
            "Call search_mcp_tools, then get_mcp_tool_schema."
        )

    async def authorize_live_server(server: MCPServer) -> None:
        if rule is None or owner is None or owner.control is None:
            return
        owner.check_policy()
        authorize_arguments(rule, arguments or {}, owner.control.policy)
        # The session may reconnect between discovery and execution. Validate
        # the actual replacement server on its owning task immediately before
        # sending a call, not merely the stale registry/catalog snapshot.
        descriptors = await server.list_tools()
        descriptor = next((item for item in descriptors if item.name == tool), None)
        if descriptor is None:
            raise PolicyDenied("mcp_authorized_tool_unavailable")
        authorize_descriptor(entry, rule, descriptor, server=server)

    async def dispatch() -> Any:
        session = await entry.ensure_connected()
        return await session.dispatch(
            tool,
            arguments or {},
            label=namespaced_tool_name(connection, tool),
            result_transform=entry.result_transform,
            supports_images=context.get("supports_images", True),
            before_call=authorize_live_server if rule is not None else None,
        )

    timeout = min(110, entry.config.session_timeout_seconds if entry.config else 60)
    try:
        if owner is not None and connection != "openviking":
            return await owner.run(
                f"mcp-call:{connection}:{tool}",
                dispatch,
                timeout=timeout,
                cleanup=entry.close,
                estimated_bytes=0 if entry._resource_lease is not None else 1024 * 1024,
            )
        async with asyncio.timeout(timeout):
            return await dispatch()
    except ResourceAdmissionError:
        return _errored_tool_output(
            error_record(
                "mcp_resource_admission_denied", category="resource", coverage_effect="blocked"
            )
        )
    except TimeoutError:
        await entry.close()
        return _errored_tool_output(
            error_record(
                "mcp_operation_timeout",
                coverage_effect="inconclusive",
                recovery_action="reconcile_before_replay",
            )
        )
    except asyncio.CancelledError:
        await entry.close()
        raise
