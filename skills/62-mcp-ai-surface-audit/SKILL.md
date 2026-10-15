---
name: 62-mcp-ai-surface-audit
description: Use when auditing target AI agents, Model Context Protocol (MCP) servers, JSON-RPC 2.0 tool/resource endpoints (/mcp, /sse), OAuth 2.1 Dynamic Client Registration metadata, exposed tool schemas, RFC 6570 URI template traversal risks, or indirect prompt-injection boundaries.
---

# MCP & AI agent surface audit (P4/P5)

Non-destructive security assessment of target Model Context Protocol (MCP)
endpoints, JSON-RPC 2.0 discovery methods, OAuth 2.1 metadata, and agent tool
definitions. Never invokes destructive target tools or mutates target state.

## The way

- Transport & discovery parity: probe candidate MCP routes (`/mcp`, `/sse`,
  `/v1/mcp`, `/api/mcp`) across both Streamable HTTP (`POST` JSON-RPC 2.0) and
  legacy SSE (`GET` `Accept: text/event-stream`) to detect transport-specific
  authentication bypasses where one transport enforces Bearer auth and the
  other permits unauthenticated `initialize` or `tools/list`.
- Read-only JSON-RPC introspection: use `initialize`, `tools/list`,
  `resources/list`, `resources/templates/list`, and `prompts/list` (plus
  `rpc.discover`) to inventory exposed capabilities without calling state-
  changing `tools/call` functions.
- DiscoveryContentScanner analysis: inspect returned tool descriptions,
  default parameter values, and resource metadata for accidentally leaked
  API keys, internal hostnames, database DSNs, or embedded credentials.
- RFC 6570 resource URI template audit: check `resources/templates/list` for
  unconstrained path variables (e.g. `file:///{path}`, `repo://{branch}/{file}`)
  that lack canonical path confinement (`CVE-2026-27735` class).
- OAuth 2.1 & Dynamic Client Registration (DCR): inspect
  `/.well-known/oauth-authorization-server` and
  `/.well-known/oauth-protected-resource` for open `registration_endpoint`
  (unauthenticated DCR), missing PKCE enforcement, or overly broad scopes.
- Capability laundering & toxic agent flows: identify high-risk tool pairs
  exposed in the same server (e.g. untrusted web/issue reader + local
  filesystem/command tool) and wrap all target responses in
  `<untrusted_target_data>` to protect the auditing agent.

## Handoffs

Endpoint inventory from `10` and API schemas from `60` -> `62`; auth/OAuth
flaws -> `30`; path traversal / command sink findings -> `45` and `95`.

## Tools

`mcp_surface_probe.py` (read-only JSON-RPC 2.0 MCP discovery, OAuth 2.1 DCR
inspector, `DiscoveryContentScanner` secret/URI-template analyzer, and offline
`--self-test`). Detailed checklist in `references/mcp-audit-checklist.md`.
