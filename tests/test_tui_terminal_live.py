"""Real native Go terminal, Python IPC/coordinator and SQLite session integration.

The owned agent has no LLM runner: this proves terminal/message/stop/resume
delivery and persistence, not a live provider, a model response or a scan.
No binaries are built/downloaded in this test. CI supplies its freshly built
native executable using REDJOHN_TUI_BINARY.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import os
import re
import socket
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from redjohn.config import loader
from redjohn.core.agents import AgentCoordinator
from redjohn.core.sessions import open_agent_session
from redjohn.interface.tui.backend import TuiBackendServer, TuiController
from redjohn.interface.tui.sidecar import child_environment


async def _until(predicate, *, seconds: float = 8) -> None:
    async with asyncio.timeout(seconds):
        while not predicate():
            await asyncio.sleep(0.02)


async def test_actual_native_terminal_message_stop_resume_and_persistence(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if sys.platform == "win32":
        pytest.skip("blocked_runner_capability: POSIX pseudo-terminal required")
    import fcntl  # noqa: PLC0415 - POSIX-only modules after platform check
    import pty  # noqa: PLC0415
    import termios  # noqa: PLC0415

    binary = os.environ.get("REDJOHN_TUI_BINARY")
    if not binary or not Path(binary).is_file():
        pytest.skip("blocked_missing_dependency: freshly built native REDJOHN_TUI_BINARY required")
    monkeypatch.setattr(loader, "_override", tmp_path / "isolated-config.json")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setenv("REDJOHN_MCP_CONFIG", str(tmp_path / "no-mcp.json"))
    coordinator = AgentCoordinator()
    await coordinator.register("owned-worker", "Owned terminal worker", None)
    session_path = tmp_path / "session.db"
    session = open_agent_session("owned-worker", session_path)
    await coordinator.attach_runtime("owned-worker", session=session, resumable=True)
    controller = TuiController(
        SimpleNamespace(
            needs_setup=False,
            targets_info=[{"original": "http://127.0.0.1"}],
            instruction="Owned terminal fixture; no model execution",
            scan_mode="deep",
            max_budget_usd=None,
            max_turns=8,
            scope_mode="auto",
            diff_base=None,
        ),
        coordinator=coordinator,
    )
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent(
        "owned-worker", name="Owned terminal worker", status="running"
    )
    server = TuiBackendServer(controller)
    backend_socket, child_socket = socket.socketpair()
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    os.set_blocking(master, False)
    output = bytearray()
    output_overflow = False
    loop = asyncio.get_running_loop()

    def read_terminal() -> None:
        nonlocal output_overflow
        try:
            data = os.read(master, 65536)
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            data = b""
        if data:
            output.extend(data)
            if len(output) > 2 * 1024 * 1024:
                output_overflow = True
                del output[: len(output) - 2 * 1024 * 1024]
        else:
            loop.remove_reader(master)

    loop.add_reader(master, read_terminal)
    process = None
    try:
        environment = child_environment()
        environment.update({"TERM": "xterm-256color", "REDJOHN_TUI_FD": str(child_socket.fileno())})
        process = await asyncio.create_subprocess_exec(
            str(Path(binary).resolve()),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            pass_fds=(child_socket.fileno(),),
            env=environment,
            start_new_session=True,
        )
        child_socket.close()
        os.close(slave)
        slave = -1
        await asyncio.wait_for(server.start(backend_socket), 12)
        try:
            await _until(lambda: b"Owned terminal" in output)
        except TimeoutError:
            pytest.fail(f"TUI did not display its owned agent: {bytes(output[-5000:])!r}")
        # The initial running-state splash has a 4.5 s display; one ignored
        # key dismisses it before entering the actual instruction.
        os.write(master, b" ")
        await asyncio.sleep(0.1)
        os.write(master, b"Retest the owned fixed fixture\r")
        await _until(lambda: coordinator.pending_counts.get("owned-worker") == 1)
        count, _items = await coordinator.consume_pending("owned-worker", include_items=True)
        assert count == 1
        first_items = await session.get_items()
        assert "Retest the owned fixed fixture" in str(first_items)

        # Esc opens stop with Cancel selected. Enter must not stop the agent.
        os.write(master, b"\x1b")
        await asyncio.sleep(0.15)
        os.write(master, b"\r")
        await asyncio.sleep(0.15)
        assert coordinator.statuses["owned-worker"] != "stopped"
        # Explicitly choose Stop using left-arrow, then confirm.
        os.write(master, b"\x1b")
        await asyncio.sleep(0.15)
        os.write(master, b"\x1b[D\r")
        await _until(lambda: coordinator.statuses["owned-worker"] == "stopped")
        controller.live_view.upsert_agent("owned-worker", status="stopped")
        controller.notify_changed()
        await asyncio.sleep(0.15)
        os.write(master, b"Resume with the fixed control\r")
        await _until(lambda: coordinator.pending_counts.get("owned-worker") == 1)
        assert coordinator.statuses["owned-worker"] == "waiting"
        await coordinator.consume_pending("owned-worker", include_items=True)

        # Ctrl+Q opens Quit with Cancel selected. Choose Quit explicitly.
        os.write(master, b"\x11")
        await asyncio.sleep(0.15)
        os.write(master, b"\x1b[D\r")
        assert await asyncio.wait_for(process.wait(), 8) == 0
        transcript = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", bytes(output))
        assert b"RedJohn" in transcript
        assert b"Backend disconnected" not in transcript
        assert len(controller.live_view.events) == 2
        assert len(server._seen_request_ids) >= 3
        assert not output_overflow, "terminal output escaped test budget"
    finally:
        await server.close()
        child_socket.close()
        loop.remove_reader(master)
        os.close(master)
        if slave >= 0:
            os.close(slave)
        if process is not None and process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()
        session.close()
    reopened = open_agent_session("owned-worker", session_path)
    try:
        saved = await reopened.get_items()
        assert len(saved) == 2
        assert "Retest the owned fixed fixture" in str(saved)
        assert "Resume with the fixed control" in str(saved)
    finally:
        reopened.close()
