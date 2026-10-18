"""Owned synthetic load against real production limits, never scanner evidence.

The child emits deterministic bytes; it is not a replacement scanner. HTTP
responses use actual loopback sockets and the unmodified production proxy.
"""
# ruff: noqa: INP001 - standalone benchmark helper, imported by script directory

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sys
import uuid
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.policy import EngagementPolicy


async def log_pressure(output: Path, limit: int = 512 * 1024) -> dict:
    """Overflow stdout AND stderr in separate real bounded-supervisor children."""
    source = Path(__file__).parents[1] / "redjohn/tools/hunt/bounded_worker.py"
    results = []
    for channel in (1, 2):
        directory = output / f"log-pressure-{channel}"
        directory.mkdir(mode=0o700)
        token = uuid.uuid4().hex
        child = "import os; " + f"os.write({channel}, b'x' * {limit + 65536})"
        config = {
            "argv": [sys.executable, "-I", "-S", "-c", child],
            "token": token,
            "digests": {},
            "timeout": 10,
            "max_output_bytes": limit,
        }
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-S",
            str(source),
            json.dumps(config),
            cwd=directory,
            start_new_session=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 15)
        finally:
            if process.returncode is None:
                # Let the production supervisor reap its separately grouped
                # child before escalating; killing only the supervisor first
                # would strand that child on a benchmark cancellation.
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(asyncio.shield(process.wait()), 2)
                except TimeoutError:
                    with suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    await process.wait()
        if len(stdout) > 2 * limit + 65536 or len(stderr) > 65536:
            raise RuntimeError("supervisor_protocol_output_limit")
        row = json.loads(stdout)
        key = "stdout" if channel == 1 else "stderr"
        results.append(
            {
                "channel": key,
                "configured_bytes": limit,
                "observed_bytes": row[key + "_bytes"],
                "retained_bytes": len(row[key].encode()),
                "truncated": row["truncated"],
                "child_exit_code": row["exit_code"],
                "supervisor_exit_code": process.returncode,
                "markers_removed": not list(directory.glob(".redjohn-hunt/*")),
            }
        )
    return {
        "evidence_kind": "synthetic_limit_pressure_real_processes",
        "supervisor_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "channels": results,
        "ok": all(
            r["truncated"]
            and r["observed_bytes"] > limit
            and r["retained_bytes"] == limit
            and r["markers_removed"]
            and r["supervisor_exit_code"] == 0
            for r in results
        ),
    }


async def body_pressure(limit: int = 8 * 1024 * 1024) -> dict:  # noqa: PLR0915 - real socket lifecycle
    """Accept the exact wire cap, reject cap+1 without complete-response proof."""
    tasks = set()
    current = {"bytes": limit}

    async def upstream(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            # Include the HTTP framing in the production proxy's wire quota.
            header = b"HTTP/1.1 200 OK\r\nContent-Length: "
            body_size = current["bytes"] - len(header) - len(b"\r\n\r\n") - len(str(limit))
            response_header = header + str(body_size).encode() + b"\r\n\r\n"
            body_size = current["bytes"] - len(response_header)
            response_header = header + str(body_size).encode() + b"\r\n\r\n"
            writer.write(response_header)
            remaining = body_size
            while remaining:
                block = min(65536, remaining)
                writer.write(b"x" * block)
                await writer.drain()
                remaining -= block
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()

    def accept(reader, writer):
        task = asyncio.create_task(upstream(reader, writer))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    origin = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    policy = EngagementPolicy(
        "owned-body-pressure",
        "benchmark",
        (origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )
    completed = []
    proxy = BrowserEgressProxy(
        policy, max_wire_bytes=limit, on_response=lambda *args: completed.append(args)
    )
    trials = []
    try:
        await proxy.start()
        for wire_bytes in (limit, limit + 1):
            current["bytes"] = wire_bytes
            before = len(completed)
            address = urlsplit(proxy.url)
            reader, writer = await asyncio.open_connection(address.hostname, address.port)
            try:
                writer.write(f"GET {origin}/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
                await writer.drain()
                received = 0
                async with asyncio.timeout(15):
                    while block := await reader.read(65536):
                        received += len(block)
                trials.append(
                    {
                        "upstream_wire_bytes": wire_bytes,
                        "received_bytes": received,
                        "complete_observations": len(completed) - before,
                    }
                )
            finally:
                writer.close()
                await writer.wait_closed()
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()
        if tasks:
            await asyncio.gather(*tasks)
    return {
        "evidence_kind": "synthetic_limit_pressure_real_sockets",
        "configured_wire_bytes": limit,
        "trials": trials,
        "limit_drops": proxy.limit_drops,
        "ok": trials[0]["received_bytes"] == limit
        and trials[0]["complete_observations"] == 1
        and trials[1]["complete_observations"] == 0
        and proxy.limit_drops == 1
        and not proxy._tasks
        and not proxy._writers,
    }
