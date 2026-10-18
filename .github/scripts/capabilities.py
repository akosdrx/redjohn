#!/usr/bin/env python3
"""Probe real runner boundaries; never disable host security controls."""

import asyncio
import json
import os
import platform
import tempfile
from pathlib import Path

from redjohn.assessment.egress import LinuxEgressBoundary
from redjohn.assessment.os_memory import LinuxMemoryBoundary
from redjohn.assessment.resources import MIB


async def probe():
    result = {"available": False, "blockers": [], "uid": os.getuid(),
              "machine": platform.machine(), "kernel": platform.release(),
              "namespace_available": False, "browser_available": False, "cgroup_available": False}
    for name in ("apparmor_restrict_unprivileged_userns", "unprivileged_userns_clone"):
        path = Path("/proc/sys/kernel") / name
        result[name] = path.read_text().strip() if path.exists() else "absent"
    if platform.system() != "Linux" or os.getuid() == 0:
        result["blockers"].append("unprivileged_linux_runner_required")
    with tempfile.TemporaryDirectory(prefix="redjohn-ci-capability-") as directory:
        server = await asyncio.start_server(lambda _reader, writer: writer.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        boundary = LinuxEgressBoundary(f"http://127.0.0.1:{port}", Path(directory))
        try:
            await boundary.start()
            await boundary.attest()
            result["network_namespace_attestations"] = list(boundary.attestations)
            result["namespace_available"] = True
        except Exception as exc:
            result["blockers"].append("kernel_egress:" + type(exc).__name__ + ":" + str(exc))
        finally:
            await boundary.close()
            server.close()
            await server.wait_closed()
    try:
        with LinuxMemoryBoundary({"delegated_root": os.environ["REDJOHN_TEST_CGROUP_ROOT"]}, 64 * MIB) as memory:
            result["cgroup"] = memory.snapshot()
            assert result["cgroup"]["memory_max_bytes"] == 64 * MIB
            assert result["cgroup"]["swap_max_bytes"] == 0
            result["cgroup_available"] = True
    except Exception as exc:
        result["blockers"].append("cgroup:" + type(exc).__name__ + ":" + str(exc))
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, chromium_sandbox=True, timeout=15000)
            try:
                page = await browser.new_page()
                await page.goto("about:blank", timeout=5000)
                result["chromium_version"] = browser.version
                result["browser_available"] = True
            finally:
                await browser.close()
    except Exception as exc:
        # Preserve the capability outcome without reflecting raw launch argv.
        result["blockers"].append("sandboxed_chromium:" + type(exc).__name__)
    result["available"] = not result["blockers"]
    Path("artifacts").mkdir(exist_ok=True)
    Path("artifacts/capabilities.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if result["available"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(probe()))
