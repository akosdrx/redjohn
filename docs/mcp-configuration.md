# Operator-managed MCP connections

RedJohn has no built-in MCP server defaults. CLI startup, TUI setup and the Kali
installer do not create or modify `~/.redjohn/mcp-servers.json`. A missing file
means no MCP connections. Invalid JSON or invalid entries are logged and skipped;
the original file is left intact.

Create a JSON list yourself when a custom server is required. Set
`REDJOHN_MCP_CONFIG` to use a different file. For example, an existing local
server can be selected without a package download:

```json
[
  {
    "name": "my-local-server",
    "transport": "stdio",
    "command": "/absolute/path/to/python",
    "args": ["/absolute/path/to/reviewed_server.py"],
    "allowed_tools": ["read_inventory"]
  }
]
```

The existing HTTP transport, explicit environment settings, tool allowlists,
per-run `--mcp-server` / `--mcp-exclude` selection and connection supervision
remain supported. The generic agent runner warms up the connections the operator
selected. Custom MCP subprocesses use their own supervision; the assessment
scheduler's namespace, network and resource guarantees do not automatically
apply to arbitrary MCP servers.

The native `lookup_cve` tool still queries NVD, OSV, CISA KEV and FIRST EPSS.
The native `hunt` tool and the persistent browser/inventory/Nuclei assessment
workflow do not require CVE or OSINT MCP servers. The removed OSINT server's
additional external providers are not claimed as implemented native adapters.

Older installations may already contain automatically generated `cve-mcp` and
`osint-mcp` entries. Remove those entries explicitly from that installation's
configuration if they are no longer wanted. RedJohn never rewrites existing
operator configuration, even when a connection uses a former default name.
There is no automatic migration or replacement list.
