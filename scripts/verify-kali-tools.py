"""Verify Kali system-tool reuse with a read-only mounted native RedJohn app.

Run inside the disposable Linux verification VM, after preparing a signed Kali
root filesystem at /var/lib/redjohn-kali-verify and its redjohnverify user.
All assessment requests use the driver's loopback fixture.
"""
from __future__ import annotations

import asyncio
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from importlib.util import module_from_spec, spec_from_file_location

spec = spec_from_file_location("native_verification", Path(__file__).with_name("verify-native-tools.py"))
fixture = module_from_spec(spec)
spec.loader.exec_module(fixture)


async def verify(url: str) -> dict:
    root = "/var/lib/redjohn-kali-verify"
    command = ["chroot", "--userspec=1000:1000", root, "/usr/bin/env",
               "HOME=/home/redjohnverify", "PATH=/usr/bin:/bin",
               "RJ_TOOLS_DIR=/opt/RedJohn/resources/tools",
               "/opt/RedJohn/resources/engine/redjohn-engine", "--tool-mcp",
               "--workspace", "/home/redjohnverify/native-acceptance", "--targets", json.dumps([url])]
    evidence = {"distribution": "Kali GNU/Linux Rolling 2026.3", "arch": "arm64",
                "environment": "signed Kali root filesystem; native Linux execution on the Ubuntu VM kernel",
                "checks": {}}
    async with stdio_client(StdioServerParameters(command="sudo", args=command)) as (read, write), ClientSession(read, write) as client:
        await client.initialize()
        inventory = await fixture.invoke(client, "tool_inventory", {})
        for item in inventory["items"]:
            if item["id"] in {"httpx", "ffuf", "arjun", "sqlmap"}:
                assert item["origin"] == "system", item
        assert all(item["available"] for item in inventory["items"]), inventory
        evidence["inventory"] = inventory
        cases = [
            ("httpx_probe", {"url": url, "timeout_seconds": 45}),
            ("ffuf_scan", {"url": url + "/FUZZ", "words": ["health", "admin"], "timeout_seconds": 45}),
            ("arjun_scan", {"url": url, "parameters": ["debug", "safe"], "timeout_seconds": 90}),
            ("sqlmap_scan", {"url": url + "/?id=1", "timeout_seconds": 90}),
            ("nuclei_scan", {"url": url, "template": "http/misconfiguration/http-missing-security-headers.yaml", "timeout_seconds": 90}),
        ]
        for name, args in cases:
            job = await fixture.invoke(client, name, args)
            for _ in range(24):
                result = await fixture.invoke(client, "scan_status", {"job_id": job["job_id"], "wait_seconds": 5})
                if result["state"] != "running":
                    break
            assert result["state"] == "completed" and result["exit_code"] == 0, (name, result)
            evidence["checks"][name] = {"state": result["state"], "artifacts": result["artifacts"]}
            print("Kali verified", name, flush=True)
    evidence["passed"] = True
    return evidence


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 0), fixture.Fixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        evidence = asyncio.run(verify(f"http://127.0.0.1:{server.server_port}"))
        destination = Path(__file__).resolve().parents[1] / "docs/evidence/kali-native-tools.json"
        destination.write_text(json.dumps(evidence, indent=2) + "\n")
        print("Kali evidence:", destination)
    finally:
        server.shutdown()
