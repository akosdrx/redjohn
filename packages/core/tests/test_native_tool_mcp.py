"""Scope, cancellation and live MCP behavior of native assessment jobs."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from redjohn_core.native_tool_mcp import SessionTools, ToolError, url_in_scope
from redjohn_core.tool_catalog import tool_command


def test_web_scope_separates_ports_protocols_and_paths():
    scope = ["http://127.0.0.1:8080/app"]
    assert url_in_scope("http://127.0.0.1:8080/app/login?q=1", scope)
    assert not url_in_scope("http://127.0.0.1:8081/app", scope)
    assert not url_in_scope("https://127.0.0.1:8080/app", scope)
    assert not url_in_scope("http://127.0.0.1:8080/app/%2e%2e/private", scope)
    assert not url_in_scope("http://user:password@127.0.0.1:8080/app", scope)
    assert url_in_scope("https://example.test:443/", ["https://example.test"])


def test_linux_reuses_system_but_skips_python_httpx(tmp_path, monkeypatch):
    from redjohn_core import tool_catalog

    system = tmp_path / "httpx"
    system.write_text("#!/usr/bin/python3\nfrom httpx import main\n")
    system.chmod(0o755)
    root = tmp_path / "tools"
    root.mkdir()
    bundled = root / "httpx"
    bundled.write_text("#!/bin/sh\nexit 0\n")
    bundled.chmod(0o755)
    (root / "tool-index.json").write_text(json.dumps({"tools": {"httpx": {"command": ["{root}/httpx"]}}}))
    monkeypatch.setenv("RJ_TOOLS_DIR", str(root))
    monkeypatch.setattr(tool_catalog.sys, "platform", "linux")
    monkeypatch.setattr(tool_catalog.shutil, "which", lambda *args, **kwargs: str(system))
    assert tool_command("httpx") == ([str(bundled)], "bundled")
    system.write_text("native ProjectDiscovery executable fixture")
    assert tool_command("httpx") == ([str(system)], "system")


async def test_stop_job_terminates_owned_descendants(tmp_path, monkeypatch):
    import redjohn_core.native_tool_mcp as native

    monkeypatch.setattr(native, "tool_command", lambda _: ([sys.executable], "bundled"))
    runtime = SessionTools(tmp_path, ["http://fixture.test"])
    code = (
        "import subprocess,sys,time,pathlib; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "pathlib.Path('child.pid').write_text(str(p.pid)); time.sleep(60)"
    )
    result = runtime.launch("fixture", "http://fixture.test", ["-c", code], 90)
    job = runtime.jobs[result["job_id"]]
    for _ in range(100):
        if (job["directory"] / "child.pid").exists():
            break
        await asyncio.sleep(0.02)
    child = int((job["directory"] / "child.pid").read_text())
    await runtime.shutdown()
    assert job["state"] == "stopped"
    assert job["process"].returncode is not None
    for _ in range(100):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        if sys.platform == "linux" and Path(f"/proc/{child}/stat").read_text().split()[2] == "Z":
            break  # terminated; the guest init process still owns the reap
        await asyncio.sleep(0.02)
    else:
        pytest.fail("Native job left a running descendant")


async def test_cancel_during_spawn_recovers_and_stops_handle(tmp_path, monkeypatch):
    runtime = SessionTools(tmp_path, ["http://fixture.test"])
    started = asyncio.Event()
    finished = asyncio.Event()
    child = object()
    stopped = []

    async def spawn(*args, **kwargs):
        started.set()
        await finished.wait()
        return child

    async def stop(process):
        stopped.append(process)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(runtime, "terminate", stop)
    task = asyncio.create_task(runtime.spawn(["fixture"]))
    await started.wait()
    task.cancel()
    finished.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stopped == [child]


async def test_native_mcp_handshake_and_scope_rejection(tmp_path):
    source = Path(__file__).resolve().parents[1] / "src"
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "redjohn_core.native_tool_mcp",
            "--workspace",
            str(tmp_path),
            "--targets",
            '["http://127.0.0.1:8123"]',
        ],
        env={"PYTHONPATH": str(source)},
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
        await client.initialize()
        names = {tool.name for tool in (await client.list_tools()).tools}
        expected = {"httpx_probe", "http_fingerprint_probe", "zap_scan", "metasploit_assess", "stop_scan"}
        assert expected <= names
        result = await client.call_tool("httpx_probe", {"url": "http://127.0.0.1:8124"})
        assert result.is_error
        assert "authorized" in result.content[0].text
        fp_err = await client.call_tool("http_fingerprint_probe", {"url": "http://127.0.0.1:8124"})
        assert fp_err.is_error
        assert "authorized" in fp_err.content[0].text
        assert not list(tmp_path.glob("tools/*"))


async def test_vuln_intel_mcp_handshake_and_opsec_guards(tmp_path):
    source = Path(__file__).resolve().parents[1] / "src"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "redjohn_core.vuln_intel_mcp", "--templates-root", str(tmp_path)],
        env={
            "PYTHONPATH": str(source),
            "REDJOHN_VULN_CACHE_DB": str(tmp_path / "cache.db"),
        },
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
        await client.initialize()
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert {
            "vuln_query_package",
            "vuln_query_batch",
            "vuln_query_cve",
            "vuln_enrich_priority",
            "vuln_internetdb_host",
            "nuclei_search_templates",
        } <= names
        priv_ip = await client.call_tool("vuln_internetdb_host", {"host_or_ip": "10.0.0.42"})
        assert not priv_ip.is_error
        assert "skipped_non_global_ip" in priv_ip.content[0].text
        internal_host = await client.call_tool(
            "vuln_internetdb_host", {"host_or_ip": "db.internal", "resolve_dns": True}
        )
        assert not internal_host.is_error
        assert "skipped_internal_hostname" in internal_host.content[0].text


def test_jobs_are_not_visible_to_another_pentest(tmp_path):
    first = SessionTools(tmp_path / "first", ["http://first.test"])
    second = SessionTools(tmp_path / "second", ["http://second.test"])
    job = first.new_job("httpx", "http://first.test")
    with pytest.raises(ToolError, match="Unknown job"):
        second.status(job["job_id"])
