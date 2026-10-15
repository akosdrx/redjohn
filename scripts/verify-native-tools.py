"""Exercise native tools and MCPs on a loopback fixture, without desktop screenshots."""
from __future__ import annotations

import argparse
import asyncio
import html
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "packages/core/src"))
from redjohn_core.tool_catalog import TOOLS, public_tools, tool_command
from redjohn_core.tool_checks import check_native_tool
from redjohn_core.mcp_defaults import write_browser_guard


class Fixture(BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self):
        type(self).requests += 1
        query = parse_qs(urlsplit(self.path).query)
        text = html.escape(query.get("q", [""])[0])
        body = f'<html><title>RedJohn tool fixture</title><a href="/health">health</a><p>{text}</p></html>'
        if "debug" in query:
            body += "debug parameter enabled"
        content = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *args):
        pass


async def invoke(client, name, arguments):
    result = await client.call_tool(name, arguments)
    assert not result.is_error, f"{name}: {[getattr(block, 'text', '') for block in result.content]}"
    text = "\n".join(getattr(block, "text", "") for block in result.content)
    try:
        return json.loads(text)
    except ValueError:
        return {"text": text}


async def verify(args, output, url, directory):
    inventory = public_tools(None)
    assert all(item["available"] for item in inventory["items"]), inventory
    for item in TOOLS:
        if item.id == "nist-nvd":
            continue
        start = time.monotonic()
        result = await asyncio.to_thread(check_native_tool, item.id)
        output["runtime_checks"][item.id] = {**result, "seconds": round(time.monotonic() - start, 3)}
        print("runtime verified", item.id, flush=True)

    command = [str(args.engine), "--tool-mcp"] if args.engine else [sys.executable, "-m", "redjohn_core.native_tool_mcp"]
    environment = {"RJ_TOOLS_DIR": str(args.tools), "PYTHONPATH": str(BASE / "packages/core/src")}
    params = StdioServerParameters(command=command[0], args=[*command[1:], "--workspace", str(directory), "--targets", json.dumps([url])], env=environment)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
        await client.initialize()
        output["native_mcp_tools"] = sorted(tool.name for tool in (await client.list_tools()).tools)
        cases = [
            ("httpx_probe", {"url": url, "timeout_seconds": 45}),
            ("ffuf_scan", {"url": url + "/FUZZ", "words": ["health", "admin"], "timeout_seconds": 45}),
            ("katana_crawl", {"url": url, "depth": 1, "timeout_seconds": 45}),
            ("nuclei_scan", {"url": url, "template": "http/misconfiguration/http-missing-security-headers.yaml", "timeout_seconds": 90}),
            ("arjun_scan", {"url": url, "parameters": ["debug", "safe"], "timeout_seconds": 90}),
            ("dalfox_scan", {"url": url + "/?q=fixture", "payload_limit": 1, "discover_parameters": False, "timeout_seconds": 90}),
            ("sqlmap_scan", {"url": url + "/?id=1", "timeout_seconds": 90}),
            ("zap_scan", {"url": url, "timeout_seconds": 90}),
            ("metasploit_info", {"module": "auxiliary/scanner/http/http_version", "timeout_seconds": 90}),
            ("metasploit_assess", {"url": url, "module": "auxiliary/scanner/http/http_version", "action": "scan", "timeout_seconds": 90}),
        ]
        for name, arguments in cases:
            start = time.monotonic()
            initial = await invoke(client, name, arguments)
            for _ in range(24):
                result = await invoke(client, "scan_status", {"job_id": initial["job_id"], "wait_seconds": 5})
                if result["state"] != "running":
                    break
            assert result["state"] == "completed", (name, result)
            assert result["exit_code"] == 0, (name, result)
            assert result["artifacts"], name
            output["fixture_executions"][name] = {"state": result["state"], "exit_code": result["exit_code"], "seconds": round(time.monotonic() - start, 3), "artifacts": result["artifacts"]}
            print("fixture execution verified", name, flush=True)
        outside = await client.call_tool("httpx_probe", {"url": "http://127.0.0.1:9"})
        assert outside.is_error
        output["scope_rejection"] = True

    browser = tool_command("playwright")[0]
    guard = write_browser_guard(directory, [url])
    browser_args = [*browser[1:], "--headless", "--isolated", "--block-service-workers", "--no-webmcp", "--allowed-origins", url, "--init-page", str(guard)]
    async with stdio_client(StdioServerParameters(command=browser[0], args=browser_args)) as (read, write), ClientSession(read, write) as client:
        await client.initialize()
        await invoke(client, "browser_navigate", {"url": url})
        snapshot = await invoke(client, "browser_snapshot", {})
        assert "RedJohn tool fixture" in json.dumps(snapshot)
        output["playwright_browser"] = "bundled Chromium navigation and snapshot succeeded"
        print("Playwright browser verified", flush=True)

    nvd = tool_command("nist-nvd")[0]
    async with stdio_client(StdioServerParameters(command=nvd[0], args=nvd[1:], env={"NVD_API_KEY": ""})) as (read, write), ClientSession(read, write) as client:
        await client.initialize()
        output["nvd_mcp_tools"] = sorted(tool.name for tool in (await client.list_tools()).tools)
        if args.live_nvd:
            result = await invoke(client, "get_cve", {"cveId": "CVE-2014-0160"})
            assert "CVE-2014-0160" in json.dumps(result)
            output["nvd_public_lookup"] = "CVE-2014-0160 returned without a key"
        print("NVD MCP verified", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools", type=Path, default=BASE / "resources/tools")
    parser.add_argument("--engine", type=Path)
    parser.add_argument("--live-nvd", action="store_true")
    parser.add_argument("--output", type=Path, default=BASE / "docs/evidence/native-tools.json")
    args = parser.parse_args()
    args.tools = args.tools.resolve()
    os.environ["RJ_TOOLS_DIR"] = str(args.tools)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    output = {"platform": sys.platform, "runtime_checks": {}, "fixture_executions": {}}
    try:
        with tempfile.TemporaryDirectory(prefix="redjohn-tools-verify-") as temporary:
            asyncio.run(verify(args, output, f"http://127.0.0.1:{server.server_port}", Path(temporary)))
    finally:
        server.shutdown()
    output["fixture_requests"] = Fixture.requests
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print("Native tools verified:", args.output, flush=True)


if __name__ == "__main__":
    main()
