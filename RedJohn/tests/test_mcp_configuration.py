"""Read-only MCP configuration, startup contracts and a real local stdio round trip.

Startup tests replace scan/model execution. The stdio test launches an actual
MCP server process; it uses no model, package installer or external network.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from importlib import import_module
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from agents.tool_context import ToolContext

from redjohn.tools.mcp import (
    MCP_REGISTRY_CONTEXT_KEY,
    McpConnectionRequest,
    McpRegistry,
    call_mcp,
    load_user_mcp_configs,
    loader,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for key in ("REDJOHN_MCP_CONFIG", "REDJOHN_MCP_ONLY", "REDJOHN_MCP_EXCLUDE"):
        monkeypatch.delenv(key, raising=False)
    config = tmp_path / ".redjohn" / "mcp-servers.json"
    monkeypatch.setattr(loader, "_DEFAULT_PATH", config)
    return config


def _write_config(path: Path, entries: list[dict]) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(entries, indent=3) + "\n").encode()
    path.write_bytes(payload)
    return payload


@pytest.mark.asyncio
async def test_missing_config_does_not_create_directories_or_connections(
    isolated_config: Path,
) -> None:
    registry = McpRegistry()
    try:
        assert load_user_mcp_configs() == []
        await asyncio.wait_for(registry.start_warmup(), timeout=2)
        assert registry.names() == []
        assert load_user_mcp_configs() == []
        assert not isolated_config.parent.exists()
    finally:
        await registry.close()


@pytest.mark.parametrize("payload", [b"{unfinished", b"{}", b"null", b"[null, 12]"])
def test_invalid_config_is_not_replaced(isolated_config: Path, payload: bytes) -> None:
    isolated_config.parent.mkdir()
    isolated_config.write_bytes(payload)
    before = isolated_config.stat().st_mtime_ns
    assert load_user_mcp_configs() == []
    assert isolated_config.read_bytes() == payload
    assert isolated_config.stat().st_mtime_ns == before


@pytest.mark.parametrize("name", ["cve-mcp", "osint-mcp", "my-provider"])
def test_explicit_operator_entries_are_preserved(isolated_config: Path, name: str) -> None:
    payload = _write_config(
        isolated_config,
        [{"name": name, "url": "https://mcp.example.invalid/rpc", "notes": "operator-owned"}],
    )
    config = load_user_mcp_configs()
    assert len(config) == 1
    assert config[0].name == name
    assert config[0].notes == "operator-owned"
    assert isolated_config.read_bytes() == payload


def test_custom_path_and_duplicate_validation_preserve_the_file(
    tmp_path: Path, isolated_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    override = tmp_path / "private" / "custom.json"
    payload = _write_config(
        override,
        [
            {"name": "mine", "url": "https://mcp.example.invalid/first"},
            {"name": "mine", "url": "https://mcp.example.invalid/duplicate"},
            {"name": "invalid", "transport": "stdio"},
        ],
    )
    monkeypatch.setenv("REDJOHN_MCP_CONFIG", str(override))
    configs = load_user_mcp_configs()
    assert [(entry.name, entry.url) for entry in configs] == [
        ("mine", "https://mcp.example.invalid/first")
    ]
    assert override.read_bytes() == payload
    assert not isolated_config.exists()
    assert load_user_mcp_configs(tmp_path / "explicitly-missing.json") == []


@pytest.mark.parametrize(
    ("only", "exclude", "names"),
    [("", "", ["alpha", "beta"]), ("beta", "", ["beta"]), ("alpha,beta", "beta", ["alpha"])],
)
def test_run_selection_remains_read_only(
    isolated_config: Path,
    monkeypatch: pytest.MonkeyPatch,
    only: str,
    exclude: str,
    names: list[str],
) -> None:
    payload = _write_config(
        isolated_config,
        [{"name": name, "url": "https://mcp.example.invalid"} for name in ("alpha", "beta")],
    )
    monkeypatch.setenv("REDJOHN_MCP_ONLY", only)
    monkeypatch.setenv("REDJOHN_MCP_EXCLUDE", exclude)
    assert [entry.name for entry in load_user_mcp_configs()] == names
    assert isolated_config.read_bytes() == payload


@pytest.mark.parametrize("configured", [False, True])
def test_tui_setup_reads_only_operator_connections(isolated_config: Path, configured: bool) -> None:
    from redjohn.interface.tui.runtime import GoTuiRuntime  # noqa: PLC0415

    payload = (
        _write_config(isolated_config, [{"name": "mine", "url": "https://mcp.example.invalid"}])
        if configured
        else None
    )
    args = SimpleNamespace(
        needs_setup=True,
        targets_info=[],
        instruction="",
        scan_mode="deep",
        max_budget_usd=None,
        max_turns=8,
        scope_mode="auto",
        diff_base=None,
    )
    runtime = GoTuiRuntime(args)
    assert [row["name"] for row in runtime.controller.mcp_connections] == (
        ["mine"] if configured else []
    )
    if payload is not None:
        assert isolated_config.read_bytes() == payload
    else:
        assert not isolated_config.parent.exists()


def test_cli_scan_boot_does_not_create_mcp_config(
    isolated_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from redjohn.interface import cli  # noqa: PLC0415
    from redjohn.report import state  # noqa: PLC0415

    main = import_module("redjohn.interface.main")
    args = SimpleNamespace(non_interactive=True, resume_picker=False, run_name=None)
    monkeypatch.setattr(sys, "argv", ["redjohn", "-n"])
    monkeypatch.setattr(main, "parse_arguments", lambda: args)
    monkeypatch.setattr(
        main, "load_settings", lambda: SimpleNamespace(runtime=SimpleNamespace(backend="local"))
    )
    for name in (
        "setup_console_logging",
        "start_import_warmup",
        "wait_for_import_warmup",
        "start_background_check",
        "_fall_back_to_headless",
        "_bootstrap_scan",
        "validate_environment",
        "notify_update",
    ):
        monkeypatch.setattr(main, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(state, "get_global_report_state", lambda: None)
    ran = []

    async def run_scan(_args: object) -> None:
        ran.append(True)

    monkeypatch.setattr(cli, "run_cli", run_scan)
    main.main()
    assert ran == [True]
    assert not isolated_config.parent.exists()


@pytest.mark.asyncio
async def test_operator_stdio_server_round_trip_and_shutdown(
    isolated_config: Path, tmp_path: Path
) -> None:
    server = tmp_path / "operator_server.py"
    lifecycle = tmp_path / "lifecycle.json"
    server.write_text(
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "app = FastMCP('RedJohn local MCP regression')\n"
        "events = Path(sys.argv[1])\n"
        "events.write_text(json.dumps({'pid': os.getpid(), 'calls': []}))\n"
        "@app.tool()\n"
        "def read_marker(value: str) -> str:\n"
        "    row = json.loads(events.read_text())\n"
        "    row['calls'].append('read_marker')\n"
        "    events.write_text(json.dumps(row))\n"
        "    return value\n"
        "@app.tool()\n"
        "def hidden_tool() -> str:\n"
        "    raise AssertionError('tool outside allowlist was executed')\n"
        "app.run(transport='stdio')\n"
    )
    payload = _write_config(
        isolated_config,
        [
            {
                "name": "operator-local",
                "transport": "stdio",
                "command": sys.executable,
                "args": [str(server), str(lifecycle)],
                "allowed_tools": ["read_marker"],
            }
        ],
    )
    registry = McpRegistry()
    entry = registry.register(McpConnectionRequest(config=load_user_mcp_configs()[0]))
    try:
        await asyncio.wait_for(registry.start_warmup(), timeout=15)
        assert entry.state == "catalog_ready"
        assert [tool.name for tool in await entry.ensure_catalog()] == ["read_marker"]
        context = ToolContext(
            context={MCP_REGISTRY_CONTEXT_KEY: registry},
            tool_name="call_mcp",
            tool_call_id="redjohn-regression",
            tool_arguments="{}",
        )
        output = await call_mcp.on_invoke_tool(
            context,
            json.dumps(
                {
                    "connection": "operator-local",
                    "tool": "read_marker",
                    "arguments": {"value": "redjohn-native-mcp-ok"},
                }
            ),
        )
        assert output["text"] == "redjohn-native-mcp-ok"
        rejected = await call_mcp.on_invoke_tool(
            context, json.dumps({"connection": "operator-local", "tool": "hidden_tool"})
        )
        assert "Unknown tool" in rejected
        row = json.loads(lifecycle.read_text())
        assert row["pid"] != os.getpid()
        assert row["calls"] == ["read_marker"]
        assert isolated_config.read_bytes() == payload
    finally:
        await registry.close()
    with pytest.raises(ProcessLookupError):
        os.kill(row["pid"], 0)


def test_native_tools_and_report_outputs_remain_available(tmp_path: Path) -> None:
    from redjohn.agents.factory import _BASE_TOOLS  # noqa: PLC0415
    from redjohn.report.sarif import write_sarif  # noqa: PLC0415
    from redjohn.report.writer import write_vulnerabilities  # noqa: PLC0415

    assert {"lookup_cve", "hunt"} <= {tool.name for tool in _BASE_TOOLS}
    report = {
        "id": "redjohn-preservation",
        "title": "Harmless report regression",
        "severity": "info",
        "description": "Local serialization check, no vulnerability claim.",
        "timestamp": "2026-10-17T00:00:00Z",
    }
    assert write_vulnerabilities(tmp_path, [report], set()) == 1
    assert json.loads((tmp_path / "vulnerabilities.json").read_text()) == [report]
    assert (tmp_path / "vulnerabilities" / "redjohn-preservation.md").is_file()
    document = json.loads(write_sarif(tmp_path, [report]).read_text())
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["tool"]["driver"]["name"] == "RedJohn"
    assert len(document["runs"][0]["results"]) == 1
