"""Actual local subprocess/framing/cleanup checks; no mocked MCP server transport."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from redjohn.tools.mcp.stdio_boundary import BoundedMcpStdio, McpStdioLaunch


def launch(tmp_path, source, *, maximum=4096):
    return BoundedMcpStdio(
        McpStdioLaunch(
            (sys.executable, "-I", "-c", source),
            {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
            str(tmp_path),
            max_message_bytes=maximum,
        )
    )


async def test_real_bounded_stdio_valid_frame_and_graceful_shutdown(tmp_path):
    message = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    source = f"import sys;print({json.dumps(message)!r},flush=True);sys.stdin.read()"
    transport = launch(tmp_path, source)
    with Path(os.devnull).open("w") as errlog:
        async with transport.streams(errlog) as (receive, _send):
            row = await receive.receive()
            assert row.message.model_dump(exclude_none=True) == message
            pid = transport._process.pid
            os.kill(pid, 0)
    transport.assert_stopped()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


async def test_real_bounded_stdio_oversized_unterminated_frame_kills_owned_child(tmp_path):
    source = "import sys,time;sys.stdout.write('x'*8192);sys.stdout.flush();time.sleep(30)"
    transport = launch(tmp_path, source)
    with Path(os.devnull).open("w") as errlog, pytest.raises(BaseExceptionGroup) as caught:
        async with transport.streams(errlog) as (receive, _send):
            pid = transport._process.pid
            await receive.receive()
    assert "mcp_stdio_message_limit_exceeded" in repr(caught.value)
    transport.assert_stopped()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


async def test_real_bounded_stdio_cancel_waiting_frame_kills_owned_child(tmp_path):
    transport = launch(tmp_path, "import time;time.sleep(30)")
    ready = asyncio.Event()
    pids = []

    async def run():
        with Path(os.devnull).open("w") as errlog:
            async with transport.streams(errlog) as (receive, _send):
                pids.append(transport._process.pid)
                ready.set()
                await receive.receive()

    task = asyncio.create_task(run())
    await ready.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    transport.assert_stopped()
    with pytest.raises(ProcessLookupError):
        os.kill(pids[0], 0)


async def test_real_bounded_stdio_missing_executable_has_no_live_cleanup_owner(tmp_path):
    transport = BoundedMcpStdio(
        McpStdioLaunch((str(tmp_path / "missing-owned-executable"),), {}, str(tmp_path))
    )
    with Path(os.devnull).open("w") as errlog, pytest.raises(FileNotFoundError):
        async with transport.streams(errlog):
            pytest.fail("missing executable cannot yield a live transport")
    transport.assert_stopped()
