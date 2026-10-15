---
name: mcp_audit_checklist
description: MCP & AI Agent Surface Audit Checklist (from mcp_ai_surface_audit specialist
  reference library)
---

# MCP & AI Agent Surface Audit Checklist

Grounded in the PortSwigger `mcp-server-scanner` methodology, Nuclei
`exposed-mcp-server` templates, and the Appsecco MCP Pentesting Checklist.

## 1. JSON-RPC 2.0 & Transport Discovery (SSE vs. Streamable HTTP)

Modern MCP deployments often migrate from Server-Sent Events (`GET /sse` +
`POST /messages`) to Streamable HTTP (`POST /mcp` with `Mcp-Session-Id`).
Reverse proxies and API gateways frequently misconfigure route-level auth
between these two transports:

1. **Streamable HTTP (`POST /mcp`)**:
   - Send a minimal JSON-RPC 2.0 `initialize` request:
     ```json
     {
       "jsonrpc": "2.0",
       "id": 1,
       "method": "initialize",
       "params": {
         "protocolVersion": "2024-11-05",
         "capabilities": {},
         "clientInfo": {"name": "redjohn-audit", "version": "1.0"}
       }
     }
     ```
   - Record `serverInfo`, `capabilities`, and whether `Mcp-Session-Id` is issued
     without an `Authorization` header.
2. **Read-Only Capability Enumeration**:
   - Query `tools/list`, `resources/list`, `resources/templates/list`,
     `prompts/list`, and `rpc.discover`.
   - **Never** automatically invoke `tools/call` on write/exec/delete tools.
3. **Negative Control (D2)**:
   - Compare unauthenticated `POST /mcp` (`method: "tools/list"`) against an
     invalid method (`method: "redjohn.nonexistent"`) and against an invalid
     Bearer token to confirm genuine JSON-RPC 2.0 dispatch rather than a
     static 200 OK catch-all page.

## 2. DiscoveryContentScanner (Schema & Description Leaks)

Inspect the JSON payload returned by `tools/list`, `resources/list`, and
`prompts/list` for:
- **Hardcoded Secrets in Descriptions/Defaults**: API keys (`sk-...`, `AKIA...`,
  `ghp_...`), Bearer tokens, or basic-auth URLs left in parameter `default` or
  `description` fields.
- **Internal Infrastructure Disclosure**: RFC 1918 IPs, `.internal` / `.local`
  hostnames, internal GraphQL/REST URLs, or local filesystem paths (`/home/...`,
  `/var/...`, `C:\Users\...`) in tool schemas.
- **Dangerous Execution Primitives**: Tools exposing raw shell execution, SQL
  query execution, arbitrary HTTP fetching (SSRF), or unrestricted filesystem
  writes.

## 3. RFC 6570 Resource URI Template Risks

When `resources/templates/list` returns URI templates (e.g. `file:///{path}`,
`git://{repo}/{ref}`, `db://tables/{table}`):
- Check whether path segments allow `..` traversal or flag injection (such as
  arguments starting with `--output=` passed to underlying CLI tools, as in
  `CVE-2026-27735`).
- Verify whether the server enforces canonical root confinement
  (`Path.resolve().is_relative_to(root)`).

## 4. OAuth 2.1 & Dynamic Client Registration (DCR)

Check `/.well-known/oauth-authorization-server` and
`/.well-known/oauth-protected-resource`:
- **Unauthenticated DCR (`registration_endpoint`)**: Test whether the server
  exposes an open RFC 7591 registration endpoint that allows arbitrary client
  registration or unvalidated `redirect_uris`.
- **PKCE Enforcement**: Check `code_challenge_methods_supported` for `S256`.

## 5. Toxic Agent Flows & Capability Laundering

Flag any single MCP endpoint that combines:
1. **Untrusted External Input Ingestion** (e.g. reading public GitHub issues,
   scraping web URLs, reading inbound emails/tickets), AND
2. **Privileged Local/Internal Action** (e.g. local file read/write, database
   query, shell execution, internal network requests).

