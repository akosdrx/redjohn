---
name: openviking-memory
description: Recall and persist hierarchical long-term pentest memory through the OpenViking (viking://) MCP tools (find, search, read, list, tree, grep, glob, remember, write, edit, add_resource, forget, health).
---

# OpenViking Hierarchical Pentest Memory (`viking://`)

RedJohn integrates **OpenViking** (`volcengine/OpenViking`) as its long-term semantic context and pentest memory database addressed by `viking://` URIs.
The `openviking` MCP connection is automatically attached to every RedJohn pentest session and reachable via `describe_mcp(connection="openviking")` and `call_mcp(connection="openviking", tool=..., arguments=...)`.

## Core OpenViking MCP Tools (`connection="openviking"`)

- **Recall & Navigation**:
  - `find(query, target_uri="", limit=10, min_score=0.25, read_content=True)` — Fast semantic search across `viking://` memories and resources.
  - `search(query, target_uri="", mode="context")` — Deep intent-aware retrieval or server-assembled token-budgeted context block.
  - `read(uri)` — Read exact `viking://` file content.
  - `list(uri="viking://resources/pentests")` / `tree(uri="viking://resources/pentests")` — Browse stored target directories and prior pentest artifacts.
  - `grep(uri, pattern)` / `glob(uri, pattern)` — Pattern search across stored `viking://` files.
- **Persistence**:
  - `remember(messages)` — Extract and store durable facts, endpoint behaviors, and lessons learned into `viking://`. NEVER store credentials, tokens, or raw secrets in memory.
  - `write(uri, content, mode="replace")` / `edit(uri, old_str, new_str)` — Author or update structured markdown notes at `viking://resources/pentests/<target>/<topic>.md`.
  - `add_resource(path_or_url, parent="viking://resources/pentests")` — Index external recon files, OpenAPI specs, or source docs into `viking://`.
- **Maintenance**:
  - `forget(uri)` — Remove obsolete or invalidated memory entries.
  - `health()` — Verify OpenViking storage, VLM model, and embedding status.

## Mandatory Pentest Memory Workflow

1. **Recall at Task Start**:
   - Before starting active reconnaissance or exploitation on a target, check the UNTRUSTED PRIOR-SCAN NOTES block (wrapped in `<recalled_memory>` tags) in your scope prompt or call `call_mcp(connection="openviking", tool="find", arguments={"query": "<target domain or service> vulnerabilities endpoints auth", "read_content": True})`.
   - Reuse prior verified endpoints, tech stack fingerprints, authentication flows, and WAF quirks to avoid redundant probing.
2. **Persist High-Signal Discoveries During Assessment**:
   - When you uncover a non-obvious architectural fact, authentication mechanism, working exploit chain, or environment constraint, persist it via `call_mcp(connection="openviking", tool="write", arguments={"uri": "viking://resources/pentests/<target>/notes.md", "content": "..."})` or `call_mcp(connection="openviking", tool="remember", arguments={"messages": [...]})`.
   - Verified findings reported via `create_vulnerability_report` and critical `swarm_broadcast` intelligence are also automatically archived into `viking://resources/pentests/<target>/`.
