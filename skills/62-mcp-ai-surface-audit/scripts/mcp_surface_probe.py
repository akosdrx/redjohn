#!/usr/bin/env python3
"""Non-destructive MCP & AI Agent Surface Auditor (62-mcp-ai-surface-audit).

Performs read-only JSON-RPC 2.0 introspection (initialize, tools/list,
resources/list, resources/templates/list, prompts/list), OAuth 2.1 metadata
inspection, DiscoveryContentScanner secret/path leak checks, RFC 6570 URI
template traversal auditing, and Toxic Agent Flow (Capability Laundering)
detection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

SECRET_PATTERNS = (
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("api_token", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b")),
    ("bearer_secret", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{16,}\b")),
    ("dsn_credentials", re.compile(r"\b(?:postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@")),
)

INTERNAL_HOST_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|[a-z0-9-]+\.(?:internal|local|corp|lan))\b",
    re.IGNORECASE,
)

UNTRUSTED_INGEST_KEYWORDS = ("issue", "ticket", "web", "fetch", "url", "scrape", "email", "comment", "search")
PRIVILEGED_SINK_KEYWORDS = (
    "exec",
    "shell",
    "command",
    "bash",
    "write_file",
    "read_file",
    "filesystem",
    "sql",
    "query",
    "git_diff",
    "delete",
)

RISKY_URI_TEMPLATE_RE = re.compile(r"(?:file:///|git://|ssh://|://\{[^}]+\}|\{[a-zA-Z0-9_]*path[a-zA-Z0-9_]*\})", re.IGNORECASE)


def compute_tool_hash(tool: dict[str, Any]) -> str:
    payload = {
        "name": str(tool.get("name", "")),
        "description": str(tool.get("description", "")),
        "inputSchema": tool.get("inputSchema") or tool.get("input_schema") or {},
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def analyze_mcp_discovery_payload(
    *,
    tools: list[dict[str, Any]] | None = None,
    resources: list[dict[str, Any]] | None = None,
    resource_templates: list[dict[str, Any]] | None = None,
    prompts: list[dict[str, Any]] | None = None,
    oauth_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run DiscoveryContentScanner, RFC 6570 URI audit, OAuth DCR audit, and Toxic Flow analysis."""
    tools = tools or []
    resources = resources or []
    resource_templates = resource_templates or []
    prompts = prompts or []
    oauth_metadata = oauth_metadata or {}

    findings: list[dict[str, Any]] = []
    tool_hashes: dict[str, str] = {}
    ingest_tools: list[str] = []
    sink_tools: list[str] = []

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name", "unknown"))
        desc = str(tool.get("description", ""))
        schema_str = json.dumps(tool.get("inputSchema") or tool.get("input_schema") or {})
        combined = f"{name}\n{desc}\n{schema_str}"
        tool_hashes[name] = compute_tool_hash(tool)

        lowered = f"{name} {desc}".casefold()
        if any(k in lowered for k in UNTRUSTED_INGEST_KEYWORDS):
            ingest_tools.append(name)
        if any(k in lowered for k in PRIVILEGED_SINK_KEYWORDS):
            sink_tools.append(name)

        for label, pattern in SECRET_PATTERNS:
            if pattern.search(combined):
                findings.append(
                    {
                        "category": "discovery_secret_leak",
                        "severity": "high",
                        "subject": f"tool:{name}",
                        "detail": f"Tool metadata exposes {label} pattern in description or default schema.",
                    }
                )
        if INTERNAL_HOST_RE.search(combined):
            findings.append(
                {
                    "category": "discovery_internal_host_disclosure",
                    "severity": "low",
                    "subject": f"tool:{name}",
                    "detail": "Tool metadata discloses private RFC1918 IP or internal hostname.",
                }
            )

    for tmpl in resource_templates:
        if not isinstance(tmpl, dict):
            continue
        uri_tmpl = str(tmpl.get("uriTemplate") or tmpl.get("uri_template") or "")
        tname = str(tmpl.get("name") or uri_tmpl)
        if RISKY_URI_TEMPLATE_RE.search(uri_tmpl):
            findings.append(
                {
                    "category": "rfc6570_uri_template_traversal_surface",
                    "severity": "medium",
                    "subject": f"resource_template:{tname}",
                    "detail": (
                        f"URI template {uri_tmpl!r} accepts path/scheme expansion; verify canonical "
                        "Path.resolve().is_relative_to() confinement and CLI flag sanitization."
                    ),
                }
            )

    if ingest_tools and sink_tools:
        findings.append(
            {
                "category": "toxic_agent_flow_capability_laundering",
                "severity": "high",
                "subject": "mcp_server_toolset",
                "detail": (
                    f"Server combines untrusted ingestion tools ({', '.join(ingest_tools[:5])}) "
                    f"with privileged execution/filesystem sinks ({', '.join(sink_tools[:5])}), "
                    "enabling indirect prompt-injection capability laundering."
                ),
            }
        )

    if oauth_metadata:
        reg_ep = oauth_metadata.get("registration_endpoint")
        pkce_methods = oauth_metadata.get("code_challenge_methods_supported") or []
        if reg_ep:
            findings.append(
                {
                    "category": "oauth_dynamic_client_registration_exposed",
                    "severity": "medium",
                    "subject": str(reg_ep),
                    "detail": "OAuth 2.1 Dynamic Client Registration (DCR) endpoint is advertised; verify auth/redirect_uri restrictions.",
                }
            )
        if "S256" not in pkce_methods:
            findings.append(
                {
                    "category": "oauth_pkce_s256_missing",
                    "severity": "medium",
                    "subject": "oauth_metadata",
                    "detail": "OAuth authorization server metadata does not advertise S256 PKCE support.",
                }
            )

    return {
        "tool_count": len(tools),
        "resource_count": len(resources),
        "resource_template_count": len(resource_templates),
        "prompt_count": len(prompts),
        "tool_hashes": tool_hashes,
        "untrusted_ingest_tools": ingest_tools,
        "privileged_sink_tools": sink_tools,
        "findings": findings,
    }


def _jsonrpc_post(url: str, method: str, params: dict[str, Any] | None = None, timeout: float = 6.0) -> dict[str, Any]:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "RedJohn-MCP-Surface-Audit/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(131072).decode("utf-8", errors="replace")
            return {"status": resp.status, "json": json.loads(raw)}
    except Exception as exc:
        return {"status": 0, "error": str(exc)[:200]}


def probe_live_target(base_url: str, timeout: float = 6.0) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Provide a valid http:// or https:// target URL")

    root = f"{parsed.scheme}://{parsed.netloc}"
    mcp_url = base_url if parsed.path and parsed.path != "/" else f"{root}/mcp"

    init_res = _jsonrpc_post(
        mcp_url,
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "redjohn-audit", "version": "1.0"},
        },
        timeout=timeout,
    )
    neg_res = _jsonrpc_post(mcp_url, "redjohn.nonexistent.method", {}, timeout=timeout)
    tools_res = _jsonrpc_post(mcp_url, "tools/list", {}, timeout=timeout)
    templates_res = _jsonrpc_post(mcp_url, "resources/templates/list", {}, timeout=timeout)

    tools = ((tools_res.get("json") or {}).get("result") or {}).get("tools") or []
    templates = ((templates_res.get("json") or {}).get("result") or {}).get("resourceTemplates") or []

    analysis = analyze_mcp_discovery_payload(
        tools=tools if isinstance(tools, list) else [],
        resource_templates=templates if isinstance(templates, list) else [],
    )
    return {
        "target": mcp_url,
        "initialize_status": init_res.get("status"),
        "negative_control_error_present": "error" in (neg_res.get("json") or {}),
        "analysis": analysis,
    }


def run_selftest() -> int:
    sample_tools = [
        {
            "name": "fetch_github_issue",
            "description": "Fetch public GitHub issue text using default token ghp_1234567890abcdefghijklmnopqrstuv",
            "inputSchema": {"type": "object", "properties": {"issue_url": {"type": "string"}}},
        },
        {
            "name": "exec_local_git_diff",
            "description": "Execute git diff on internal host 10.24.0.15",
            "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}},
        },
    ]
    sample_templates = [
        {"name": "local_file", "uriTemplate": "file:///{path}"},
    ]
    sample_oauth = {
        "issuer": "https://auth.example.test",
        "registration_endpoint": "https://auth.example.test/register",
        "code_challenge_methods_supported": ["plain"],
    }
    report = analyze_mcp_discovery_payload(
        tools=sample_tools,
        resource_templates=sample_templates,
        oauth_metadata=sample_oauth,
    )
    categories = {f["category"] for f in report["findings"]}
    assert "discovery_secret_leak" in categories, "Expected secret leak detection"
    assert "discovery_internal_host_disclosure" in categories, "Expected internal host detection"
    assert "rfc6570_uri_template_traversal_surface" in categories, "Expected RFC6570 template check"
    assert "toxic_agent_flow_capability_laundering" in categories, "Expected Toxic Agent Flow detection"
    assert "oauth_dynamic_client_registration_exposed" in categories, "Expected OAuth DCR detection"
    assert "oauth_pkce_s256_missing" in categories, "Expected PKCE S256 check"
    assert len(report["tool_hashes"]) == 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="Authorized target URL or MCP endpoint")
    parser.add_argument("--self-test", action="store_true", help="Run offline self-test suite")
    args = parser.parse_args()
    if args.self_test:
        return run_selftest()
    if not args.url:
        parser.error("Provide --url or --self-test")
    print(json.dumps(probe_live_target(args.url), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
