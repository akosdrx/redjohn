"""Read the open-source user's MCP servers from ``~/.strix/mcp-servers.json``.

An open-source user lists the MCP servers they want the agent to reach in a
small JSON file. Strix reads it at the start of a run and connects to each
server, holding the live sessions in the run's registry for the agent to reach
on demand. The file is optional; without it the run simply gets no MCP
connections.

Parsing is fail-open. A single malformed entry is logged and skipped rather than
raising, so one bad row never blocks the servers that are valid, and a missing
or unreadable file yields an empty list.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from strix.tools.mcp.config import McpConnectionConfig


logger = logging.getLogger(__name__)


_DEFAULT_PATH: Path = Path.home() / ".strix" / "mcp-servers.json"
_PATH_ENV_VAR = "STRIX_MCP_CONFIG"
# Per-run selection, set by the --mcp-server / --mcp-exclude CLI flags. Each is a
# comma-separated list of connection names.
_ONLY_ENV_VAR = "STRIX_MCP_ONLY"
_EXCLUDE_ENV_VAR = "STRIX_MCP_EXCLUDE"


def default_redjohn_mcp_entries(python_executable: str | None = None) -> list[dict[str, Any]]:
    """Return the built-in RedJohn MCP server definitions for Kali Linux."""
    py = python_executable or sys.executable or "python3"
    return [
        {
            "name": "redjohn_scanners",
            "transport": "stdio",
            "command": py,
            "args": ["-m", "redjohn_core.native_tool_mcp"],
            "notes": (
                "RedJohn native Kali Linux security scanners & SAST "
                "(nuclei_scan, nuclei_search_templates, httpx_probe, http_fingerprint_probe, "
                "ffuf_scan, katana_crawl, arjun_scan, dalfox_scan, sqlmap_scan, subfinder_search, "
                "wayback_urls, gau_urls, zap_scan, metasploit_search, metasploit_info, "
                "metasploit_assess, nmap_scan, wpscan_scan, gobuster_scan, nikto_scan, "
                "ast_sink_search, tool_inventory, scan_status, stop_scan)."
            ),
        },
        {
            "name": "redjohn_vuln_intel",
            "transport": "stdio",
            "command": py,
            "args": ["-m", "redjohn_core.vuln_intel_mcp"],
            "notes": (
                "RedJohn vulnerability intelligence & CVE/OSV/EPSS/KEV/Shodan InternetDB correlation "
                "(vuln_query_package, vuln_query_batch, vuln_query_cve, "
                "vuln_enrich_priority, vuln_internetdb_host, nuclei_search_templates)."
            ),
        },
    ]


def ensure_default_mcp_servers_file(
    path: Path | None = None,
    *,
    python_executable: str | None = None,
) -> Path:
    """Ensure ``~/.strix/mcp-servers.json`` exists and contains the built-in RedJohn MCP servers.

    Preserves any user-defined MCP servers already in the file while adding or
    refreshing the Python interpreter path for ``redjohn_scanners`` and
    ``redjohn_vuln_intel`` if missing or pointing to a dead virtualenv.
    """
    target = _resolve_path(path)
    defaults = default_redjohn_mcp_entries(python_executable)
    default_by_name = {entry["name"]: entry for entry in defaults}

    existing_list: list[Any] = []
    if target.exists():
        try:
            loaded = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                existing_list = loaded
        except (OSError, json.JSONDecodeError):
            logger.warning("Could not parse existing %s; rebuilding with defaults", target)

    updated = False
    seen_names: set[str] = set()
    merged: list[Any] = []
    for item in existing_list:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            name = item["name"]
            seen_names.add(name)
            if name in default_by_name:
                cmd = item.get("command")
                if not isinstance(cmd, str) or not Path(cmd).exists():
                    item = {**item, "command": default_by_name[name]["command"]}
                    updated = True
                if item.get("notes") != default_by_name[name]["notes"]:
                    item = {**item, "notes": default_by_name[name]["notes"]}
                    updated = True
        merged.append(item)

    for entry in defaults:
        if entry["name"] not in seen_names:
            merged.append(entry)
            updated = True

    if not target.exists() or updated:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
        except OSError:
            logger.debug("Could not write default MCP config to %s", target, exc_info=True)
    return target


def _resolve_path(path: Path | None) -> Path:
    if path is not None:
        return path
    override = os.environ.get(_PATH_ENV_VAR)
    if override:
        return Path(override)
    return _DEFAULT_PATH


def _dedupe_by_name(configs: list[McpConnectionConfig]) -> list[McpConnectionConfig]:
    """Keep the first connection of each name, dropping later duplicates.

    A connection's name is its key in the run's registry, so two connections
    sharing a name would collide and the second would overwrite the first. Drop
    the duplicate here, with a warning, instead.
    """
    seen: set[str] = set()
    unique: list[McpConnectionConfig] = []
    for config in configs:
        if config.name in seen:
            logger.warning(
                "Ignoring MCP server %r: another connection already uses that name "
                "(names must be unique because they namespace the server's tools).",
                config.name,
            )
            continue
        seen.add(config.name)
        unique.append(config)
    return unique


def _parse_names(env_var: str) -> set[str]:
    return {name.strip() for name in os.environ.get(env_var, "").split(",") if name.strip()}


def _apply_run_selection(configs: list[McpConnectionConfig]) -> list[McpConnectionConfig]:
    """Restrict this run's connections to an optional include/exclude selection.

    ``STRIX_MCP_ONLY`` (if set) keeps only the named connections; then
    ``STRIX_MCP_EXCLUDE`` drops any named connection. With neither set, every
    connection is kept.
    """
    only = _parse_names(_ONLY_ENV_VAR)
    exclude = _parse_names(_EXCLUDE_ENV_VAR)
    if not only and not exclude:
        return configs

    available = {config.name for config in configs}
    for name in sorted((only | exclude) - available):
        logger.warning(
            "MCP connection selection named %r, which is not configured; ignoring it", name
        )

    selected: list[McpConnectionConfig] = []
    for config in configs:
        if only and config.name not in only:
            continue
        if config.name in exclude:
            continue
        selected.append(config)
    return selected


def load_user_mcp_configs(path: Path | None = None) -> list[McpConnectionConfig]:
    """Load MCP connection configs from the user's JSON file.

    The path is ``path`` if given, else ``$STRIX_MCP_CONFIG``, else
    ``~/.strix/mcp-servers.json``. The file is a JSON list of server entries.
    A missing file returns ``[]``; an unreadable or non-list file is logged and
    returns ``[]``; individual entries that fail validation are logged and
    skipped. Connections sharing a name are de-duplicated (first wins), and an
    optional per-run include/exclude selection is applied last.
    """
    source = _resolve_path(path)
    if not source.exists():
        return []

    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.exception("Could not read MCP config at %s; ignoring it", source)
        return []

    if not isinstance(raw, list):
        logger.warning("MCP config at %s is not a JSON list; ignoring it", source)
        return []

    entries = cast("list[object]", raw)
    configs: list[McpConnectionConfig] = []
    for index, entry in enumerate(entries):
        try:
            configs.append(McpConnectionConfig.model_validate(entry))
        except ValidationError as exc:
            logger.warning("Skipping invalid MCP server entry #%d in %s: %s", index, source, exc)

    return _apply_run_selection(_dedupe_by_name(configs))
