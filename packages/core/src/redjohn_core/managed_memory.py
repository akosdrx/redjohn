"""Profile-owned native OpenViking process supervision.

The language and embedding models are external (OpenAI-compatible) endpoints
configured by the operator; there is no local model runtime. OpenViking's
language calls route through the in-engine proxy to the active provider, and
its embedding calls hit the configured external endpoint directly.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import socket
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .errors import RJError, validation
from .integrations import IntegrationStore, atomic_private_json
from .memory_config import memory_proxy_url, memory_public, save_memory


def free_port() -> int:
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def native_program(service: str = "openviking") -> Path:
    """Resolve the packaged OpenViking supervisor wrapper (never a model daemon)."""
    name = "openviking-server"
    override = os.environ.get("RJ_OPENVIKING_BIN")
    candidates = [Path(override)] if override else [Path(sys.executable).parent.parent / "memory" / name]
    parents = Path(__file__).resolve().parents
    if not override and len(parents) > 4:
        candidates.append(parents[4] / "resources" / "memory" / name)
    if not override and len(parents) > 5:
        candidates.append(parents[5] / "rj-desktop" / "resources" / "memory" / name)
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
    raise RJError(
        "native_memory_runtime_unavailable",
        "The app's native OpenViking runtime is missing. Reinstall the desktop package.",
        status=503,
    )


def ensure_port_available(port: int) -> None:
    with socket.socket() as probe:
        # Match normal HTTP server bind behavior: closed connections in
        # TIME_WAIT do not occupy a listener, while an active listener still
        # rejects this bind. SO_REUSEPORT is deliberately not enabled.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RJError(
                "memory_port_unavailable",
                "The profile's native memory port is occupied by another process. Retry after it exits.",
                status=503,
            ) from exc


@dataclass
class NativeProcess:
    process: asyncio.subprocess.Process
    port: int
    config_hash: str = ""

    async def stop(self) -> None:
        if self.process.returncode is not None:
            return
        # Only a handle created by this engine reaches here. Persisted PIDs
        # never authorize a signal (they can be stale or reused).
        try:
            self.process.terminate()
            async with asyncio.timeout(4):
                await self.process.wait()
        except ProcessLookupError:
            pass
        except TimeoutError:
            try:
                if os.name == "posix":
                    os.killpg(self.process.pid, signal.SIGKILL)
                else:
                    self.process.kill()
                await self.process.wait()
            except ProcessLookupError:
                pass


class ManagedMemoryRuntime:
    """Cancellable native services for one local data profile.

    The packaged wrappers supervise their backend process groups, forward
    termination and watch the owning engine PID so an engine crash cannot
    strand a service. Only tracked child handles are stopped here.
    """

    def __init__(self, settings: Any, progress: Callable[[str], None]) -> None:
        self.settings = settings
        self.progress = progress
        self.processes: dict[str, NativeProcess] = {}
        self._start_lock = asyncio.Lock()

    async def start(self, *, restart: bool = False) -> bool:
        async with self._start_lock:
            config = IntegrationStore(self.settings)
            memory = config.read().get("memory", {})
            managed_url = f"http://127.0.0.1:{memory.get('managed_port')}"
            if self.settings.openviking_url and self.settings.openviking_url != managed_url:
                # Switching to an external service also releases our own
                # unused native children; its process is never touched.
                await self.stop()
                return False
            if not memory.get("server_config"):
                return False  # Not configured yet: no ov.conf / external models set.
            native_program()  # Fail before starting if the runtime is missing.
            self.progress("Starting native OpenViking and preparing the profile account")
            await self._ensure_openviking(restart=restart)
            return True

    async def _spawn(self, service: str, argv: list[str], port: int, config_hash: str = "") -> NativeProcess:
        root = self.settings.profile_dir / "openviking"
        logs = root / "logs"
        logs.mkdir(parents=True, exist_ok=True, mode=0o700)
        logs.chmod(0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(logs / f"{service}.log", flags, 0o600)
        os.fchmod(descriptor, 0o600)
        env = dict(os.environ)
        for name in (
            "RJ_MODEL_API_KEY",
            "RJ_ANTHROPIC_API_KEY",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "RJ_OPENVIKING_API_KEY",
            "RJ_TOKEN",
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
        ):
            env.pop(name, None)
        for name in list(env):
            if name.startswith(("_PYI", "_MEIPASS")):
                env.pop(name, None)
        env.update({"HOME": str(root), "XDG_CACHE_HOME": str(root / "cache")})
        log = os.fdopen(descriptor, "ab", buffering=0)
        try:
            spawn = asyncio.create_task(
                asyncio.create_subprocess_exec(
                    str(native_program(service)),
                    "--owner-pid",
                    str(os.getpid()),
                    *argv,
                    cwd=root,
                    env=env,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=log,
                    stderr=asyncio.subprocess.STDOUT,
                    start_new_session=os.name == "posix",
                )
            )
            try:
                process = await asyncio.shield(spawn)
            except asyncio.CancelledError:
                # Subprocess creation may finish after cancellation. Recover
                # its handle and terminate it before propagating cancellation.
                process = await spawn
                await NativeProcess(process, port, config_hash).stop()
                raise
        finally:
            log.close()
        child = NativeProcess(process, port, config_hash)
        self.processes[service] = child
        return child

    async def _wait_ready(self, service: str, child: NativeProcess, path: str) -> None:
        url = f"http://127.0.0.1:{child.port}{path}"
        try:
            async with asyncio.timeout(45):
                async with httpx.AsyncClient(timeout=2) as client:
                    while True:
                        if child.process.returncode is not None:
                            raise RJError(
                                "memory_process_failed",
                                f"Native {service} exited during startup. "
                                "Check its private memory log and retry.",
                                status=503,
                            )
                        try:
                            response = await client.get(url)
                            if response.is_success:
                                return
                        except httpx.HTTPError:
                            pass
                        await asyncio.sleep(0.25)
        except TimeoutError as exc:
            raise RJError(
                "memory_startup_failed",
                f"Native {service} did not become ready. Check its private memory log and retry.",
                status=503,
            ) from exc

    async def _ensure_openviking(self, *, restart: bool) -> None:
        from .ov.client import OpenVikingAdmin, OVResponseError

        config = IntegrationStore(self.settings)
        data = config.read()
        memory = data.get("memory", {})
        if not memory.get("server_config"):
            raise validation("Generate the OpenViking model configuration first.")
        root = self.settings.profile_dir / "openviking"
        source = root / "ov.conf"
        config_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        port = memory.get("managed_port") or free_port()
        child = self.processes.get("openviking")
        if child and child.process.returncode is None and (restart or child.config_hash != config_hash):
            await child.stop()
        if not child or child.process.returncode is not None:
            ensure_port_available(port)
            server = json.loads(source.read_text())
            server["server"].update({"host": "127.0.0.1", "port": port})
            server["storage"]["workspace"] = str(root / "data")
            if memory.get("model_proxy_secret"):
                # OpenViking's language calls route through the in-engine proxy
                # to the active provider; embeddings hit the external endpoint
                # directly (already written into ov.conf by generate_server_config).
                server["vlm"]["api_base"] = memory_proxy_url(self.settings)
            server.setdefault("encryption", {}).setdefault("local", {})["key_file"] = str(root / "master.key")
            native_config = root / "ov.native.conf"
            atomic_private_json(native_config, server)
            child = await self._spawn(
                "openviking", ["--config", str(native_config), "--port", str(port)], port, config_hash
            )
        memory.update({"managed_port": port, "managed_process": child.process.pid})
        # Remove obsolete lifecycle metadata without contacting any former
        # service or changing model choices, credentials or stored memories.
        for name in ("managed_container", "managed_model_container", "managed_network"):
            memory.pop(name, None)
        data = config.read()
        data.setdefault("memory", {}).update(memory)
        atomic_private_json(config.path, data)
        await self._wait_ready("openviking", child, "/health")
        url = f"http://127.0.0.1:{port}"
        try:
            admin = OpenVikingAdmin(url, config.decrypt(memory["root_secret"]))
            try:
                await admin.create_account(self.settings.openviking_account, "redjohn-admin")
            except OVResponseError as exc:
                if exc.code not in ("ALREADY_EXISTS", "CONFLICT"):
                    raise
            try:
                key = await admin.register_user(
                    self.settings.openviking_account, self.settings.openviking_user
                )
            except OVResponseError as exc:
                if exc.code not in ("ALREADY_EXISTS", "CONFLICT"):
                    raise
                if (
                    memory.get("openviking_url") == url
                    and memory.get("openviking_account") == self.settings.openviking_account
                    and memory.get("openviking_user") == self.settings.openviking_user
                    and memory.get("service_secret")
                ):
                    key = config.decrypt(memory["service_secret"])
                else:
                    key = await admin.mint_user_key(
                        self.settings.openviking_account, self.settings.openviking_user
                    )
            if child.process.returncode is not None:
                raise RJError(
                    "memory_process_failed", "Native OpenViking exited during account setup.", status=503
                )
            save_memory(
                self.settings,
                {
                    "openviking_url": url,
                    "openviking_account": self.settings.openviking_account,
                    "openviking_user": self.settings.openviking_user,
                    "openviking_processing_mode": (
                        self.settings.openviking_processing_mode if memory.get("openviking_url") else ""
                    ),
                    "service_api_key": key,
                },
            )
        except (httpx.HTTPError, OVResponseError) as exc:
            raise RJError(
                "memory_startup_failed",
                "Native OpenViking account setup did not finish. Check its private log and retry.",
                status=503,
            ) from exc
        data = config.read()
        data["memory"]["applied_config_sha256"] = config_hash
        atomic_private_json(config.path, data)

    async def stop(self) -> None:
        children = list(self.processes.values())
        if not children:
            return
        await asyncio.gather(*(child.stop() for child in children))
        self.processes.clear()
        config = IntegrationStore(self.settings)
        if config.path.exists():
            data = config.read()
            memory = data.get("memory", {})
            owned = {child.process.pid for child in children}
            if memory.get("managed_process") in owned:
                memory.pop("managed_process", None)
            atomic_private_json(config.path, data)


async def start_memory(settings: Any, *, runtime: ManagedMemoryRuntime | None = None) -> dict[str, Any]:
    if runtime is None:
        raise validation(
            "Start native memory through the running engine so its child processes are supervised."
        )
    runtime.settings = settings
    await runtime.start(restart=True)
    return memory_public(settings)
