"""Host-owned stdio launch and bounded MCP framing for confined target workers.

The generic provider transport remains unchanged. This transport requires a
controller-built argv and environment; no shell interprets protocol input.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import anyio
from mcp import types
from mcp.shared.message import SessionMessage


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from anyio.abc import Process


@dataclass(frozen=True)
class McpStdioLaunch:
    argv: tuple[str, ...]
    environment: dict[str, str] = field(repr=False)
    cwd: str
    max_message_bytes: int = 1024 * 1024


class BoundedMcpStdio:
    def __init__(self, launch: McpStdioLaunch) -> None:
        if not launch.argv or not 4096 <= launch.max_message_bytes <= 1024 * 1024:
            raise ValueError("invalid_mcp_stdio_launch")
        self.launch = launch
        self._process: Process | None = None
        self._spawn: asyncio.Task[Process] | None = None

    def assert_stopped(self) -> None:
        if self._spawn is not None or (
            self._process is not None and self._process.returncode is None
        ):
            raise RuntimeError("mcp_stdio_worker_cleanup_unconfirmed")

    async def close(self) -> None:
        # A caller cancelled before the process handle is returned must not
        # release the process reservation while spawn is still in progress.
        with anyio.CancelScope(shield=True):
            if self._spawn is not None:
                try:
                    async with asyncio.timeout(5):
                        self._process = await asyncio.shield(self._spawn)
                except OSError:
                    # Native exec failure reaps the failed child before the
                    # open_process task raises; there is no live handle to own.
                    self._process = None
                self._spawn = None
            process = self._process
            if process is None:
                return
            if process.returncode is None:
                if process.stdin is not None:
                    await process.stdin.aclose()
                with anyio.move_on_after(0.25):
                    await process.wait()
                if process.returncode is None:
                    with suppress(ProcessLookupError):
                        process.terminate()
                    with anyio.move_on_after(2):
                        await process.wait()
                if process.returncode is None:
                    with suppress(ProcessLookupError):
                        process.kill()
                    with anyio.fail_after(2):
                        await process.wait()
            await process.aclose()
            self._process = None

    @asynccontextmanager
    async def streams(self, errlog: Any) -> AsyncIterator[Any]:
        read_send, read_receive = anyio.create_memory_object_stream[SessionMessage | Exception](0)
        write_send, write_receive = anyio.create_memory_object_stream[SessionMessage](0)
        try:
            self._spawn = asyncio.create_task(
                anyio.open_process(
                    self.launch.argv,
                    cwd=self.launch.cwd,
                    env=self.launch.environment,
                    stderr=errlog,
                    start_new_session=True,
                )
            )
            self._process = await asyncio.shield(self._spawn)
            self._spawn = None
            process = self._process

            async def receive() -> None:
                assert process.stdout is not None
                pending = bytearray()
                async with read_send:
                    while True:
                        try:
                            chunk = await process.stdout.receive(65536)
                        except anyio.EndOfStream:
                            if pending:
                                raise ValueError("mcp_stdio_truncated_message") from None
                            return
                        pieces = chunk.split(b"\n")
                        for index, piece in enumerate(pieces):
                            if len(pending) + len(piece) > self.launch.max_message_bytes:
                                raise ValueError("mcp_stdio_message_limit_exceeded")
                            pending.extend(piece)
                            if index < len(pieces) - 1:
                                message = types.JSONRPCMessage.model_validate_json(bytes(pending))
                                pending.clear()
                                await read_send.send(SessionMessage(message))

            async def send() -> None:
                assert process.stdin is not None
                async with write_receive:
                    async for message in write_receive:
                        encoded = message.message.model_dump_json(
                            by_alias=True, exclude_none=True
                        ).encode()
                        if len(encoded) > self.launch.max_message_bytes:
                            raise ValueError("mcp_stdio_message_limit_exceeded")
                        await process.stdin.send(encoded + b"\n")

            async with anyio.create_task_group() as group:
                group.start_soon(receive)
                group.start_soon(send)
                try:
                    yield read_receive, write_send
                finally:
                    await self.close()
                    group.cancel_scope.cancel()
        finally:
            await self.close()
            await read_receive.aclose()
            await write_send.aclose()
            await read_send.aclose()
            await write_receive.aclose()
