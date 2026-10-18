#!/usr/bin/env python3
"""Probe real runner boundaries; never disable host security controls."""

import asyncio
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from redjohn.assessment.egress import LinuxEgressBoundary
from redjohn.assessment.os_memory import LinuxMemoryBoundary
from redjohn.assessment.resources import MIB


async def probe():
    result = {"available": False, "blockers": [], "uid": os.getuid(),
              "machine": platform.machine(), "kernel": platform.release(),
              "namespace_available": False, "browser_available": False, "cgroup_available": False}
    for name in ("apparmor_restrict_unprivileged_userns", "apparmor_restrict_unprivileged_unconfined", "unprivileged_userns_clone"):
        path = Path("/proc/sys/kernel") / name
        result[name] = path.read_text().strip() if path.exists() else "absent"
    if platform.system() != "Linux" or os.getuid() == 0:
        result["blockers"].append("unprivileged_linux_runner_required")
    try:
        profile = Path("/proc/self/attr/current").read_text().strip()
        result["apparmor_profile"] = profile
        assert profile == os.environ["REDJOHN_CI_APPARMOR_PROFILE"] + " (enforce)"
        status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        result["host_capabilities"] = {key: status[key].strip() for key in ("CapEff", "CapPrm", "CapAmb")}
        assert all(int(value, 16) == 0 for value in result["host_capabilities"].values())
        assert result["apparmor_restrict_unprivileged_userns"] == "1"
        assert result["apparmor_restrict_unprivileged_unconfined"] == "1"
        escaped = subprocess.run(["aa-exec", "-p", "unconfined", "--", "/usr/bin/true"], capture_output=True, timeout=10)
        result["profile_escape_denied"] = escaped.returncode != 0
        assert result["profile_escape_denied"]
        raw = subprocess.run(["unshare", "-Urn", sys.executable, "-I", "-S", "-c", (
            "import socket\ntry: socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)\n"
            "except PermissionError: print('raw_socket_denied')\nelse: raise SystemExit(2)"
        )], text=True, capture_output=True, timeout=10)
        result["nested_raw_socket_denied"] = raw.returncode == 0 and raw.stdout.strip() == "raw_socket_denied"
        assert result["nested_raw_socket_denied"]
    except Exception as exc:
        result["blockers"].append("scoped_apparmor:" + type(exc).__name__)
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
            browser = await playwright.chromium.launch(headless=True, chromium_sandbox=True,
                executable_path=playwright.chromium.executable_path, timeout=15000)
            try:
                page = await browser.new_page()
                await page.goto("chrome://sandbox", timeout=5000)
                sandbox = await page.locator("body").inner_text()
                result["chromium_sandbox_status"] = sandbox
                for check in ("PID namespaces\tYes", "Network namespaces\tYes", "Seccomp-BPF sandbox\tYes"):
                    assert check in sandbox
                cdp = await browser.new_browser_cdp_session()
                argv = (await cdp.send("Browser.getBrowserCommandLine"))["arguments"]
                result["unsafe_chromium_flags_absent"] = not any(flag in argv for flag in (
                    "--no-sandbox", "--disable-namespace-sandbox", "--disable-seccomp-filter-sandbox"))
                assert result["unsafe_chromium_flags_absent"]
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
