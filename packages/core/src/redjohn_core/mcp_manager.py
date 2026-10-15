"""MCP Manager: stdio + streamable-HTTP connections via the official ``mcp`` SDK.

Each connection is owned by a dedicated asyncio "actor" task: the anyio-based
MCP transports (stdio_client / streamable_http_client) and the ClientSession
are entered AND exited inside that one task (anyio cancel scopes are bound to
the entering task — exiting elsewhere raises and leaks the subprocess).
Commands (call_tool / close) are passed over a queue to the actor.

Lifecycle: connect -> initialize -> list_tools -> register qualified names
``mcp:<connection>:<tool>``. call_tool applies a timeout inside the actor;
errors surface as typed RJErrors and flip the connection status.
"""

from __future__ import annotations

import asyncio
import shutil
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from .db import Store
from .errors import RJError, not_found
from .logging import get_logger
from .mcp_defaults import (
    BROWSER_TOOLS,
    FILESYSTEM_READ_TOOLS,
    GITHUB_READ_TOOLS,
    NVD_MCP_ID,
    NVD_MCP_NAME,
    VULN_INTEL_MCP_ID,
    VULN_INTEL_MCP_NAME,
    default_templates,
    github_token,
    resolve_node_runtime,
    run_connection,
    toolkit_connection,
    vuln_intel_command,
)
from .models import Agent, MCPConnection, MCPTransport, Run, ServiceState
from .opsec_guard import compute_tool_schema_hash, scan_prompt_injection
from .scope import target_covered
from .settings import Settings

_CallCmd = tuple[str, dict[str, Any], asyncio.Future[str]]
_CloseCmd = tuple[None, None, asyncio.Future[None]]
_Cmd = _CallCmd | _CloseCmd


def _canonical_filesystem_args(args: dict[str, Any]) -> dict[str, Any]:
    args = dict(args)
    if isinstance(args.get("path"), str):
        args["path"] = str(Path(args["path"]).resolve())
    if isinstance(args.get("paths"), list):
        args["paths"] = [str(Path(path).resolve()) for path in args["paths"]]
    return args


class _Managed:
    def __init__(self, conn: MCPConnection, cmd_q: asyncio.Queue[Any], actor: asyncio.Task[None]) -> None:
        self.conn = conn
        self.cmd_q = cmd_q
        self.actor = actor


class MCPManager:
    def __init__(self, store: Store, settings: Settings) -> None:
        self._store = store
        self._settings = settings
        self._live: dict[str, _Managed] = {}
        self._connecting: dict[str, asyncio.Task[None]] = {}
        self._log = get_logger("mcp")
        self._definitions: dict[str, dict[str, Any]] = {}
        self._pinned_schema_hashes: dict[str, str] = {}
        self._run_locks: dict[str, asyncio.Lock] = {}
        self._run_attempts: set[str] = set()
        self._connection_locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------ lifecycle
    async def connect(self, conn: MCPConnection) -> MCPConnection:
        """(Re)initialize a connection and discover its tools. Persists status."""
        lock = self._connection_locks.setdefault(conn.mcp_id, asyncio.Lock())
        async with lock:
            return await self._connect_owned(conn)

    async def _ensure_connected(self, conn: MCPConnection) -> MCPConnection:
        lock = self._connection_locks.setdefault(conn.mcp_id, asyncio.Lock())
        async with lock:
            managed = self._live.get(conn.mcp_id)
            if managed and not managed.actor.done():
                return managed.conn
            return await self._connect_owned(conn)

    async def _connect_owned(self, conn: MCPConnection) -> MCPConnection:
        await self._teardown(conn.mcp_id)
        conn.status = ServiceState.STARTING
        conn.error = None
        cmd_q: asyncio.Queue[Any] = asyncio.Queue()
        ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        actor = asyncio.create_task(self._actor(conn, cmd_q, ready), name=f"mcp:{conn.name}")
        self._connecting[conn.mcp_id] = actor
        try:
            await asyncio.wait_for(ready, timeout=45.0)
        except asyncio.CancelledError:
            actor.cancel()
            await asyncio.gather(actor, return_exceptions=True)
            self._connecting.pop(conn.mcp_id, None)
            raise
        except (TimeoutError, Exception) as exc:
            if conn.status != ServiceState.LIVE:
                conn.status = ServiceState.DOWN
                conn.error = (conn.error or str(exc))[:500]
                self._log.warning("mcp connect failed", extra={"mcp": conn.name, "error": conn.error})
                if not actor.done():
                    actor.cancel()
                try:
                    await asyncio.wait_for(asyncio.shield(actor), timeout=10.0)
                except (TimeoutError, asyncio.CancelledError, Exception):
                    pass
        self._connecting.pop(conn.mcp_id, None)
        if conn.status == ServiceState.LIVE:
            self._live[conn.mcp_id] = _Managed(conn, cmd_q, actor)
        async with self._store.write() as s:
            await self._store.update_mcp_row(s, conn)
        return conn

    async def _actor(
        self,
        conn: MCPConnection,
        cmd_q: asyncio.Queue[Any],
        ready: asyncio.Future[None],
    ) -> None:
        """Owns the MCP session lifecycle; runs entirely in one task."""
        stack = AsyncExitStack()
        calls: set[asyncio.Task[None]] = set()
        try:
            if conn.transport == MCPTransport.STDIO:
                if not conn.command:
                    raise RJError("validation_error", "stdio MCP requires command: list[str]", status=422)
                workdir = None
                if conn.name.startswith("rj-run_"):
                    if Path(conn.command[0]).name in ("npx", "npx.cmd"):
                        npx, runtime_env = await asyncio.to_thread(resolve_node_runtime)
                        if (
                            shutil.which(npx, path=runtime_env["PATH"]) is None
                            or shutil.which("node", path=runtime_env["PATH"]) is None
                        ):
                            raise RJError(
                                "mcp_runtime_unavailable",
                                "Node.js/npm is required for the managed MCP servers. "
                                "Install Node.js 18 or newer and reopen RedJohn.",
                                status=503,
                            )
                        conn.command = [npx, *conn.command[1:]]
                        conn.env = {**conn.env, **runtime_env}
                    run_id = conn.name[3:].rsplit("-", 1)[0]
                    workdir = str(self._settings.work_root / run_id)
                environment = dict(conn.env)
                if conn.mcp_id == NVD_MCP_ID and conn.name == NVD_MCP_NAME:
                    from .nvd_settings import nvd_key
                    from .tool_catalog import tool_command

                    expected = tool_command("nist-nvd")
                    if not expected or conn.command != expected[0]:
                        raise RJError(
                            "validation_error",
                            "Managed NVD command differs from the bundled server",
                            status=422,
                        )
                    environment["NVD_API_KEY"] = nvd_key(self._settings)
                if conn.mcp_id == VULN_INTEL_MCP_ID and conn.name == VULN_INTEL_MCP_NAME:
                    from .nvd_settings import nvd_key

                    expected_cmd, expected_env = vuln_intel_command()
                    if conn.command != expected_cmd:
                        raise RJError(
                            "validation_error",
                            "Managed vuln-intel command differs from the bundled server",
                            status=422,
                        )
                    environment.update(expected_env)
                    if key := nvd_key(self._settings):
                        environment["NVD_API_KEY"] = key
                params = StdioServerParameters(
                    command=conn.command[0],
                    args=conn.command[1:],
                    env=environment or None,
                    cwd=workdir,
                )
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
            else:
                if not conn.url:
                    raise RJError("validation_error", "streamable_http MCP requires url", status=422)
                read, write, _sid = await stack.enter_async_context(
                    streamable_http_client(conn.url, headers=self._remote_headers(conn))
                )
                session = await stack.enter_async_context(ClientSession(read, write))

            await asyncio.wait_for(session.initialize(), timeout=30.0)
            tools = await asyncio.wait_for(session.list_tools(), timeout=30.0)
            exposed = [t for t in tools.tools if self._managed_tool_allowed(conn.name, t.name)]
            conn.tools = sorted(f"mcp:{conn.name}:{t.name}" for t in exposed)
            for tool in exposed:
                qualified = f"mcp:{conn.name}:{tool.name}"
                desc = tool.description or f"MCP tool {tool.name}"
                schema = getattr(tool, "input_schema", None) or getattr(
                    tool, "inputSchema", {"type": "object"}
                )
                schema_hash = compute_tool_schema_hash(tool.name, desc, schema)
                pi_warnings = scan_prompt_injection(desc)
                previous_hash = self._pinned_schema_hashes.get(qualified)
                if previous_hash is not None and previous_hash != schema_hash:
                    raise RJError(
                        "mcp_tool_schema_tampered",
                        f"MCP tool schema hash changed for {qualified} (expected {previous_hash[:12]}, "
                        f"got {schema_hash[:12]}). Possible tool-poisoning / rug-pull attempt.",
                        status=502,
                    )
                self._pinned_schema_hashes[qualified] = schema_hash
                self._definitions[qualified] = {
                    "description": desc,
                    "input_schema": schema,
                    "schema_sha256": schema_hash,
                    "prompt_injection_warnings": pi_warnings,
                }
            conn.status = ServiceState.LIVE
            if not ready.done():
                ready.set_result(None)

            async def perform(tool_name: str, args: dict[str, Any], fut: asyncio.Future[str]) -> None:
                try:
                    result = await asyncio.wait_for(
                        session.call_tool(tool_name, arguments=args),
                        timeout=self._settings.mcp_call_timeout_seconds,
                    )
                    if not fut.done():
                        fut.set_result(self._render_result(result))
                except asyncio.CancelledError:
                    if not fut.done():
                        fut.set_exception(RJError("mcp_unavailable", "MCP connection closed", status=503))
                    raise
                except Exception as exc:
                    if not fut.done():
                        fut.set_exception(exc)

            while True:
                cmd = await cmd_q.get()
                if cmd[0] is None:  # close
                    close_fut = cmd[2]
                    break
                tool_name, args, fut = cmd
                task = asyncio.create_task(perform(tool_name, args, fut))
                calls.add(task)
                task.add_done_callback(calls.discard)
            # close acknowledged after exiting the loop
            if not close_fut.done():
                close_fut.set_result(None)  # type: ignore[possibly-undefined]
        except asyncio.CancelledError:
            if not ready.done():
                ready.set_exception(RJError("mcp_unavailable", "connect cancelled", status=503))
            raise
        except Exception as exc:
            conn.status = ServiceState.DOWN
            conn.error = str(exc)[:500]
            if not ready.done():
                ready.set_exception(exc)
        finally:
            for task in calls:
                task.cancel()
            await asyncio.gather(*calls, return_exceptions=True)
            try:
                await stack.aclose()
            except Exception as exc:
                self._log.warning("mcp teardown error", extra={"mcp": conn.name, "error": str(exc)})

    @staticmethod
    def _render_result(result: Any) -> str:
        texts: list[str] = []
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", None)
            texts.append(text if text is not None else str(block))
        if getattr(result, "is_error", False) or getattr(result, "isError", False):
            raise RJError("tool_error", f"MCP tool returned error: {'; '.join(texts)[:500]}", status=502)
        return "\n".join(texts)

    async def reconnect(self, mcp_id: str) -> MCPConnection:
        conn = await self._store.get_mcp(mcp_id)
        return await self.connect(conn)

    async def disconnect(self, mcp_id: str) -> None:
        async with self._connection_locks.setdefault(mcp_id, asyncio.Lock()):
            await self._teardown(mcp_id)

    async def shutdown(self) -> None:
        for mcp_id in set(self._live) | set(self._connecting):
            await self._teardown(mcp_id)

    async def _teardown(self, mcp_id: str) -> None:
        pending = self._connecting.pop(mcp_id, None)
        if pending:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
        managed = self._live.pop(mcp_id, None)
        if managed:
            for qualified in managed.conn.tools:
                self._definitions.pop(qualified, None)
        if not managed:
            return
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[None] = loop.create_future()
        managed.cmd_q.put_nowait((None, None, fut))
        try:
            await asyncio.wait_for(fut, timeout=15.0)
            await asyncio.wait_for(managed.actor, timeout=15.0)
        except (TimeoutError, Exception) as exc:
            self._log.warning("mcp close error", extra={"error": str(exc)})
            if not managed.actor.done():
                managed.actor.cancel()
                await asyncio.gather(managed.actor, return_exceptions=True)

    # --------------------------------------------------------------- calling
    async def call_tool(self, qualified: str, args: dict[str, Any], *, timeout_seconds: float) -> str:
        parts = qualified.split(":", 2)
        if len(parts) != 3 or parts[0] != "mcp":
            raise RJError("unknown_tool", f"not an MCP tool: {qualified}", status=422)
        _, conn_name, tool_name = parts
        managed = next((m for m in self._live.values() if m.conn.name == conn_name), None)
        if managed is None:
            async with self._store.read() as s:
                conn = await self._store.get_mcp_by_name(s, conn_name)
            if conn is None:
                raise not_found("mcp_connection", conn_name)
            conn = await self.connect(conn)
            if conn.status != ServiceState.LIVE:
                raise RJError(
                    "mcp_unavailable",
                    f"MCP connection {conn_name!r} is {conn.status.value}: {conn.error}",
                    status=503,
                )
            managed = self._live.get(conn.mcp_id)
            if managed is None:
                raise RJError(
                    "mcp_unavailable",
                    f"MCP connection {conn_name!r} was disconnected while connecting",
                    status=503,
                )
        if qualified not in managed.conn.tools:
            raise RJError(
                "unknown_tool", f"tool {tool_name!r} not exposed by connection {conn_name!r}", status=422
            )
        if managed.actor.done():
            raise RJError("mcp_unavailable", f"MCP connection {conn_name!r} actor exited", status=503)
        if conn_name.startswith("rj-run_") and conn_name.endswith("-filesystem"):
            args = await asyncio.to_thread(_canonical_filesystem_args, args)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[str] = loop.create_future()
        managed.cmd_q.put_nowait((tool_name, args, fut))
        try:
            return await asyncio.wait_for(fut, timeout=timeout_seconds)
        except TimeoutError:
            raise RJError(
                "tool_timeout", f"MCP tool {qualified} timed out after {timeout_seconds}s", status=408
            ) from None

    # ---------------------------------------------------------------- status
    def live_connections(self) -> list[MCPConnection]:
        return [m.conn for m in self._live.values()]

    async def register_defaults(self) -> None:
        """Persist default templates without starting processes or contacting services."""
        existing = {conn.name: conn for conn in await self._store.list_mcps()}
        async with self._store.write() as session:
            for conn in default_templates(self._settings):
                if conn.name not in existing:
                    await self._store.insert_mcp(session, conn)
                elif existing[conn.name].mcp_id == conn.mcp_id:
                    # Managed commands follow the installed build after an upgrade.
                    await self._store.update_mcp_row(session, conn)

    async def ensure_run_connections(self, run: Run) -> None:
        # Fixture runs must never download packages, launch a browser or use credentials.
        if self._settings.model_provider == "fixture" or run.run_id in self._run_attempts:
            return
        lock = self._run_locks.setdefault(run.run_id, asyncio.Lock())
        async with lock:
            if run.run_id in self._run_attempts:
                return
            connections = [
                await asyncio.to_thread(run_connection, run, self._settings),
                await asyncio.to_thread(toolkit_connection, run, self._settings),
            ]
            ready = []
            for conn in connections:
                if conn is None:
                    continue
                async with self._store.read() as session:
                    existing = await self._store.get_mcp_by_name(session, conn.name)
                if existing is None:
                    async with self._store.write() as session:
                        await self._store.insert_mcp(session, conn)
                else:
                    conn = existing
                ready.append(conn)
            async with self._store.read() as session:
                nvd = await self._store.get_mcp_by_name(session, NVD_MCP_NAME)
                vuln_intel = await self._store.get_mcp_by_name(session, VULN_INTEL_MCP_NAME)
            if nvd and nvd.mcp_id not in self._live:
                ready.append(nvd)
            if vuln_intel and vuln_intel.mcp_id not in self._live:
                ready.append(vuln_intel)
            await asyncio.gather(*(self._ensure_connected(conn) for conn in ready))
            self._run_attempts.add(run.run_id)

    async def close_run(self, run_id: str) -> None:
        prefix = f"rj-{run_id}-"
        for conn in await self._store.list_mcps():
            if conn.name.startswith(prefix):
                await self.disconnect(conn.mcp_id)
                async with self._store.write() as session:
                    await self._store.delete_mcp(session, conn.mcp_id)
        self._run_attempts.discard(run_id)
        self._run_locks.pop(run_id, None)

    @staticmethod
    def _managed_tool_allowed(connection: str, tool: str) -> bool:
        if connection in (NVD_MCP_NAME, VULN_INTEL_MCP_NAME):
            return True
        if not connection.startswith("rj-run_"):
            return not connection.startswith("redjohn-")  # templates are never agent tools
        if connection.endswith("-filesystem"):
            return tool in FILESYSTEM_READ_TOOLS
        if connection.endswith("-playwright"):
            return tool in BROWSER_TOOLS
        if connection.endswith("-github"):
            return tool in GITHUB_READ_TOOLS
        if connection.endswith("-native"):
            from .native_tool_mcp import WEB_TOOLS
            return tool in WEB_TOOLS
        return False

    @staticmethod
    def _remote_headers(conn: MCPConnection) -> dict[str, str] | None:
        if conn.name.startswith("rj-run_") and conn.name.endswith("-github"):
            token = github_token()
            if not token:
                raise RJError("mcp_credentials_required", "Set RJ_GITHUB_TOKEN for GitHub MCP", status=503)
            return {"Authorization": f"Bearer {token}", "X-MCP-Readonly": "true", "X-MCP-Toolsets": "repos"}
        return None

    def tool_definition(self, qualified: str) -> dict[str, Any] | None:
        return self._definitions.get(qualified)

    @staticmethod
    def tool_visible_to_run(qualified: str, run_id: str) -> bool:
        if not qualified.startswith("mcp:"):
            return True
        name = qualified.split(":", 2)[1]
        return (name in (NVD_MCP_NAME, VULN_INTEL_MCP_NAME) or not name.startswith("redjohn-")) and (
            not name.startswith("rj-run_") or name.startswith(f"rj-{run_id}-")
        )

    @staticmethod
    def is_browser_tool(qualified: str) -> bool:
        return qualified.startswith("mcp:rj-run_") and qualified.split(":", 2)[1].endswith("-playwright")

    def scope_violation(self, qualified: str, args: dict[str, Any], run: Run, agent: Agent) -> str | None:
        if not self.tool_visible_to_run(qualified, run.run_id):
            return "MCP connection belongs to a different pentest session"
        parts = qualified.split(":", 2)
        if len(parts) != 3 or not parts[1].startswith("rj-run_"):
            return None
        name, tool = parts[1:]
        if not self._managed_tool_allowed(name, tool):
            return "Tool is outside this session's managed MCP capabilities"
        if name.endswith("-filesystem"):
            for key in ("path", "paths"):
                paths = args.get(key, [])
                paths = paths if isinstance(paths, list) else [paths]
                for path in paths:
                    if not isinstance(path, str) or not target_covered(
                        str(Path(path).resolve()), agent.allowed_targets
                    ):
                        return "MCP source path is outside the authorized project"
        if name.endswith("-github"):
            from .source_inspection import github_repository

            owner, repository = github_repository(run, agent)
            if args.get("owner") != owner or args.get("repo") != repository:
                return "MCP repository arguments must match the authorized owner/repository"
        if name.endswith("-playwright"):
            if tool == "browser_navigate" and not target_covered(
                str(args.get("url", "")), agent.allowed_targets
            ):
                return "Browser destination is outside the authorized target"
            filename = args.get("filename")
            if filename is not None:
                root = (self._settings.work_root / run.run_id).resolve()
                path = (root / str(filename)).resolve()
                if not path.is_relative_to(root):
                    return "Browser output must remain inside the session workspace"
        if name.endswith("-native") and "url" in args:
            from .scope import url_in_scope
            destination = str(args["url"]).replace("FUZZ", "redjohn-scope-check")
            if not url_in_scope(destination, agent.allowed_targets):
                return "Native tool destination is outside the agent's authorized target"
        return None
