"""Kernel isolation tests; platform skips are capability gaps, never passes."""

from __future__ import annotations

import asyncio
import json
import platform
import shutil
import socket
import sys
from pathlib import Path

import pytest

from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary


async def test_egress_remote_workers_fail_closed_without_linux(tmp_path, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    boundary = LinuxEgressBoundary("http://127.0.0.1:18080", tmp_path / "worker")
    with pytest.raises(EgressUnavailable, match="linux_network_namespace_required"):
        await boundary.start()
    assert not boundary.active
    with pytest.raises(EgressUnavailable, match="not_attested"):
        boundary.wrap_argv([sys.executable, "-V"])
    await boundary.close()


async def test_egress_requires_specific_trusted_proxy_and_limits(tmp_path):
    for value in (
        "http://example.com:8080",
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://u:p@127.0.0.1:8080",
        "http://127.0.0.1:8080/path",
        "https://127.0.0.1:8080",
    ):
        with pytest.raises(ValueError, match="controller_loopback_proxy"):
            LinuxEgressBoundary(value, tmp_path)
    with pytest.raises(ValueError, match="invalid_egress_limits"):
        LinuxEgressBoundary("http://127.0.0.1:8080", tmp_path, max_connections=0)


async def test_egress_missing_bubblewrap_is_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    boundary = LinuxEgressBoundary("http://127.0.0.1:18080", tmp_path)
    with pytest.raises(EgressUnavailable, match="bubblewrap_missing"):
        await boundary.start()
    assert not boundary.active


@pytest.mark.skipif(platform.system() != "Linux", reason="actual Linux kernel namespaces required")
async def test_linux_boundary_close_terminates_only_its_active_worker(tmp_path):
    boundary = LinuxEgressBoundary("http://127.0.0.1:18080", tmp_path / "worker")
    await boundary.start()
    await boundary.attest()
    process = await asyncio.create_subprocess_exec(
        *boundary.wrap_argv([sys.executable, "-I", "-S", "-c", "import time; time.sleep(120)"]),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        async with asyncio.timeout(5):
            while len(boundary.attestations) < 2:
                await asyncio.sleep(0.02)
        await boundary.close()
        await asyncio.wait_for(process.wait(), 5)
        assert process.returncode != 0
        assert not boundary.active
    finally:
        await boundary.close()
        if process.returncode is None:
            process.kill()
            await process.wait()


@pytest.mark.skipif(platform.system() != "Linux", reason="actual Linux kernel namespaces required")
async def test_linux_cancel_preserves_other_worker_and_runs_finally_cleanup(tmp_path):
    boundary = LinuxEgressBoundary("http://127.0.0.1:18080", tmp_path / "worker")
    await boundary.start()
    await boundary.attest()
    processes = []
    try:
        for name in ("first", "second"):
            ready_file = str(boundary.workspace / (name + ".ready"))
            clean_file = str(boundary.workspace / (name + ".clean"))
            payload = (
                "import pathlib,signal,sys,time;"
                f"clean=pathlib.Path({clean_file!r});"
                "signal.signal(signal.SIGTERM,lambda *_:(clean.write_text('clean'),sys.exit(0)));"
                f"pathlib.Path({ready_file!r}).write_text('ready');"
                "time.sleep(120)"
            )
            processes.append(
                await asyncio.create_subprocess_exec(
                    *boundary.wrap_argv([sys.executable, "-I", "-S", "-c", payload]),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )
        async with asyncio.timeout(5):
            while not all(
                (boundary.workspace / (name + ".ready")).exists() for name in ("first", "second")
            ):
                await asyncio.sleep(0.02)
        await boundary.terminate_workers(processes[0].pid)
        await asyncio.wait_for(processes[0].wait(), 5)
        assert (boundary.workspace / "first.clean").read_text() == "clean"
        assert processes[1].returncode is None
        assert not (boundary.workspace / "second.clean").exists()
        assert boundary.active
    finally:
        await boundary.close()
        for process in processes:
            if process.returncode is None:
                await asyncio.wait_for(process.wait(), 5)
    assert (boundary.workspace / "second.clean").read_text() == "clean"


@pytest.mark.skipif(platform.system() != "Linux", reason="actual Linux kernel namespaces required")
async def test_linux_namespace_allows_only_attested_proxy_and_blocks_bypasses(tmp_path):  # noqa: PLR0915
    proxy_requests = []
    target_requests = []

    async def proxy_handler(reader, writer):
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            proxy_requests.append(request.decode())
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n"
                b"proxy-gateway-ok"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def target_handler(reader, writer):
        target_requests.append(await reader.read(32))
        writer.close()

    proxy = await asyncio.start_server(proxy_handler, "127.0.0.1", 0)
    target = await asyncio.start_server(target_handler, "127.0.0.1", 0)
    host_only_path = tmp_path / "host-only.sock"
    host_only_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    host_only_socket.bind(str(host_only_path))
    host_only_socket.listen(1)
    proxy_port = proxy.sockets[0].getsockname()[1]
    target_port = target.sockets[0].getsockname()[1]
    boundary = LinuxEgressBoundary(f"http://127.0.0.1:{proxy_port}", tmp_path / "worker")
    try:
        await boundary.start()
        attestation = await boundary.attest()
        assert attestation["interfaces"] == ("lo",)
        assert attestation["effective_capabilities"] == "0"
        assert attestation["no_new_privileges"]
        assert boundary.active
        # A host process cannot claim it is an isolated forwarding helper.
        _reader, unauthorized = await asyncio.open_unix_connection(boundary._socket_path)
        unauthorized.write(b"S")
        await unauthorized.drain()
        assert await _reader.read() == b""
        unauthorized.close()
        await unauthorized.wait_closed()
        payload = (
            r"""
import http.client, json, os, socket
result = {}
connection = http.client.HTTPConnection("127.0.0.1", PROXY_PORT, timeout=5)
connection.request("GET", "https://approved.example/observed")
response = connection.getresponse()
result["proxied"] = response.read().decode()
connection.close()
for name, family, address in (
    ("direct_ipv4", socket.AF_INET, ("127.0.0.1", TARGET_PORT)),
    ("direct_ipv6", socket.AF_INET6, ("::1", TARGET_PORT)),
):
    client = socket.socket(family, socket.SOCK_STREAM)
    client.settimeout(1)
    try:
        client.connect(address)
        result[name] = "BYPASS"
    except OSError:
        result[name] = "blocked"
    finally:
        client.close()
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    client.sendto(b"blocked DNS probe", ("198.18.0.1", 53))
    result["udp_dns"] = "BYPASS"
except OSError:
    result["udp_dns"] = "blocked"
finally:
    client.close()
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    client.close()
    result["raw_socket"] = "BYPASS"
except OSError:
    result["raw_socket"] = "blocked"
result["host_run_hidden"] = not os.path.exists("/run/docker.sock")
result["host_socket_hidden"] = not os.path.exists(HOST_SOCKET)
print(json.dumps(result))
""".replace("PROXY_PORT", str(proxy_port))
            .replace("TARGET_PORT", str(target_port))
            .replace("HOST_SOCKET", repr(str(host_only_path)))
        )
        process = await asyncio.create_subprocess_exec(
            *boundary.wrap_argv([sys.executable, "-I", "-S", "-c", payload]),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
        assert process.returncode == 0, stderr.decode()
        result = json.loads(stdout)
        assert result == {
            "proxied": "proxy-gateway-ok",
            "direct_ipv4": "blocked",
            "direct_ipv6": "blocked",
            "udp_dns": "blocked",
            "raw_socket": "blocked",
            "host_run_hidden": True,
            "host_socket_hidden": True,
        }
        assert len(proxy_requests) == 1
        assert not target_requests
        assert boundary.relay_connections == 1
        assert boundary.rejected_connections >= 1
        assert len(boundary.attestations) == 2
        assert (
            boundary.attestations[0]["namespaces"]["net"]
            != boundary.attestations[1]["namespaces"]["net"]
        )
    finally:
        assets = boundary._assets.name if boundary._assets is not None else None
        await boundary.close()
        assert not boundary.active
        if assets:
            assert not Path(assets).exists()
        proxy.close()
        target.close()
        await proxy.wait_closed()
        await target.wait_closed()
        host_only_socket.close()
