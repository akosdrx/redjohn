"""Internal loopback-fixture transport for the pinned Nuclei supervisor.

This is not an agent tool or an arbitrary shell. Only the checked-in supervisor
source, validated lock-derived argv and its cancellation helper can execute.
It does not claim OS network namespace isolation or production egress support.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import signal
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit


if TYPE_CHECKING:
    import io

    from redjohn.assessment.egress import LinuxEgressBoundary

from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.tools.hunt.nuclei import (
    _CANCEL_SOURCE,
    NucleiLock,
    NucleiOptions,
    nuclei_argv,
    validate_proxy_url,
)


_TOKEN = re.compile(r"[a-f0-9]{32}")


@dataclass(frozen=True)
class NativeExecResult:
    stdout: bytes
    stderr: bytes
    exit_code: int


class _CappedFile:
    def __init__(self, stream: io.BufferedReader, limit: int) -> None:
        self.stream, self.remaining = stream, limit

    def read(self, size: int = -1) -> bytes:
        amount = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
        data = self.stream.read(amount)
        if len(data) > self.remaining:
            raise ValueError("native_session_file_limit")
        self.remaining -= len(data)
        return data

    def close(self) -> None:
        self.stream.close()


class NativeFixtureSession:
    def __init__(
        self,
        policy: EngagementPolicy,
        workspace: Path,
        lock: NucleiLock,
        *,
        max_output_bytes: int = 4 * 1024**2,
        max_binary_bytes: int = 256 * 1024**2,
    ) -> None:
        if policy.egress_mode not in {"local-fixture", "enforced"} or (
            policy.egress_mode == "local-fixture" and policy.profile != "isolated-lab"
        ):
            raise PolicyDenied("native_session_requires_local_fixture_lab")
        for origin in policy.allowed_origins:
            policy.check_scope_url(origin)
        lock.validate()
        if not Path(lock.bundle_root).is_absolute():
            raise ValueError("native_session_bundle_root_must_be_absolute")
        if (
            type(max_output_bytes) is not int
            or not 8192 <= max_output_bytes <= 4 * 1024**2
            or type(max_binary_bytes) is not int
            or not 1 <= max_binary_bytes <= 512 * 1024**2
        ):
            raise ValueError("invalid_native_session_limits")
        self.policy, self.lock = policy, lock
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.workspace.chmod(0o700)
        self.max_output_bytes, self.max_binary_bytes = max_output_bytes, max_binary_bytes
        self._active: dict[str, asyncio.subprocess.Process] = {}
        self._reservations: set[str] = set()
        self._known_tokens: deque[str] = deque(maxlen=128)
        self.closed = False
        self._bound_proxy_url: str | None = None
        self._egress_boundary: LinuxEgressBoundary | None = None
        self._source = (
            Path(__file__).parents[1].joinpath("tools/hunt/bounded_worker.py").read_text()
        )
        self._bundle_paths = {
            str(Path(lock.bundle_root) / name): digest for name, digest in lock.files.items()
        }

    def bind_proxy(self, url: str | None) -> None:
        """Bind one trusted listener from host code, never a job/tool argument."""
        if self.closed or self._active or self._reservations:
            raise PolicyDenied("native_session_proxy_binding_busy")
        validate_proxy_url(url)
        self._bound_proxy_url = url

    def bind_egress_boundary(self, boundary: LinuxEgressBoundary | None) -> None:
        from redjohn.assessment.egress import LinuxEgressBoundary  # noqa: PLC0415

        if self.closed or self._active or self._reservations:
            raise PolicyDenied("native_session_proxy_binding_busy")
        if boundary is not None:
            if not isinstance(boundary, LinuxEgressBoundary):
                raise PolicyDenied("remote_egress_boundary_required")
            boundary.assert_active()
        self._egress_boundary = boundary

    def assert_remote_boundary(self) -> None:
        if self.policy.egress_mode != "enforced" or self._egress_boundary is None:
            raise PolicyDenied("remote_egress_boundary_required")
        self._egress_boundary.assert_active()
        if self._bound_proxy_url != self._egress_boundary.worker_proxy_url:
            raise PolicyDenied("remote_egress_proxy_binding_mismatch")

    def _command(self, command: tuple[str, ...], shell: bool) -> tuple[str, dict[str, Any] | None]:  # noqa: PLR0912
        if (
            self.closed
            or shell is not False
            or len(command) != 4
            or command[:2] != ("python3", "-c")
        ):
            raise PolicyDenied("native_session_trusted_worker_only")
        source, argument = command[2:]
        if source == _CANCEL_SOURCE:
            if not _TOKEN.fullmatch(argument) or argument not in self._known_tokens:
                raise PolicyDenied("native_session_unknown_cancellation")
            return argument, None
        if source != self._source or len(argument) > 131072:
            raise PolicyDenied("native_session_trusted_worker_only")
        config = json.loads(argument)
        if (
            not isinstance(config, dict)
            or set(config)
            != {
                "token",
                "argv",
                "timeout",
                "max_output_bytes",
                "digests",
                "nuclei",
                "snapshot_files",
            }
            or not isinstance(config.get("token"), str)
            or not _TOKEN.fullmatch(config["token"])
        ):
            raise PolicyDenied("native_session_invalid_worker_contract")
        if type(config["nuclei"]) is not bool:
            raise PolicyDenied("native_session_invalid_worker_contract")
        argv = config["argv"]
        if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
            raise PolicyDenied("native_session_invalid_argv")
        options = NucleiOptions(
            timeout_seconds=config["timeout"], max_output_bytes=config["max_output_bytes"]
        )
        options.validate()
        digests = {self.lock.binary_path: self.lock.binary_sha256}
        if config["nuclei"]:
            if len(argv) < 3 or argv[:2] != [self.lock.binary_path, "-u"]:
                raise PolicyDenied("native_session_invalid_argv")
            if urlsplit(argv[2]).scheme == "https" and self._bound_proxy_url is None:
                raise PolicyDenied("native_session_https_requires_verified_proxy")
            paths = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "-t"]
            selections = tuple(
                item
                for item in self.lock.templates
                if str(Path(self.lock.bundle_root) / item.path) in paths
                and self.policy.profile in item.profiles
            )
            if any(item.effect == "authenticated-replay" for item in selections):
                if not all(item.effect == "authenticated-replay" for item in selections):
                    raise PolicyDenied("native_session_mixed_replay_templates")
                self.policy.check_replay_request(argv[2], "POST")
            else:
                self.policy.check_readonly_request(argv[2], "GET")
            try:
                options = NucleiOptions(
                    config["timeout"],
                    int(argv[argv.index("-rl") + 1]),
                    int(argv[argv.index("-timeout") + 1]),
                    config["max_output_bytes"],
                )
                expected = nuclei_argv(
                    argv[2], self.lock, options, selections, proxy_url=self._bound_proxy_url
                )
            except (ValueError, IndexError) as error:
                raise PolicyDenied("native_session_invalid_argv") from error
            if (
                not selections
                or argv != expected
                or paths != [str(Path(self.lock.bundle_root) / item.path) for item in selections]
            ):
                raise PolicyDenied("native_session_invalid_argv")
            digests.update(self._bundle_paths)
        elif argv != [self.lock.binary_path, "-version"]:
            raise PolicyDenied("native_session_healthcheck_only")
        if config["digests"] != digests or config["snapshot_files"] != [
            name for name in digests if name != self.lock.binary_path
        ]:
            raise PolicyDenied("native_session_digest_contract_mismatch")
        if config["token"] in self._active:
            raise PolicyDenied("native_session_duplicate_worker")
        return config["token"], config

    async def _terminate(self, token: str, process: asyncio.subprocess.Process) -> None:
        if self.policy.egress_mode == "enforced" and self._egress_boundary is not None:
            await self._egress_boundary.terminate_workers(process.pid)
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(process.wait(), 2)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
        # Fallback for a supervisor killed before its finally block. The child's
        # process group marker is owned by this private, exact-token workspace.
        marker = self.workspace / ".redjohn-hunt" / (token + ".child")
        if self.policy.egress_mode != "enforced" and marker.is_file() and not marker.is_symlink():
            try:
                child = int(marker.read_text())
                if child > 1:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(child, signal.SIGKILL)
            except ValueError:
                pass
        for suffix in (".pid", ".child"):
            (self.workspace / ".redjohn-hunt" / (token + suffix)).unlink(missing_ok=True)

    async def exec(self, *command: str, timeout: float, shell: bool) -> NativeExecResult:  # noqa: PLR0912, PLR0915 - fenced spawn, drain and cleanup lifecycle
        token, config = self._command(command, shell)
        if type(timeout) not in {int, float} or not 0 < timeout <= 190:
            raise ValueError("native_session_invalid_deadline")
        if self.policy.egress_mode == "enforced":
            self.assert_remote_boundary()
            if command[2] == _CANCEL_SOURCE:
                process = self._active.get(token)
                if process is not None:
                    await self._terminate(token, process)
                return NativeExecResult(b"", b"", 0)
        env = {
            "PATH": os.pathsep.join((str(Path(sys.executable).parent), "/usr/bin", "/bin")),
            "HOME": str(self.workspace),
            "TMPDIR": str(self.workspace),
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if config is not None:
            if len(self._reservations) >= 2 or token in self._reservations:
                raise ValueError("native_session_worker_capacity")
            self._reservations.add(token)
            self._known_tokens.append(token)
        argv = [sys.executable, "-I", "-S", "-c", command[2], command[3]]
        if self.policy.egress_mode == "enforced":
            assert self._egress_boundary is not None
            argv = self._egress_boundary.wrap_argv(argv, cwd=self.workspace)
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *argv,
                cwd=self.workspace,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
        )
        try:
            process = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            process = await spawn
            await asyncio.shield(self._terminate(token, process))
            self._reservations.discard(token)
            raise
        except OSError:
            self._reservations.discard(token)
            raise
        if config is not None:
            self._active[token] = process
        limit = (
            min(self.max_output_bytes, config["max_output_bytes"] * 12 + 8192) if config else 8192
        )

        async def drain(stream: asyncio.StreamReader) -> bytes:
            captured = bytearray()
            while chunk := await stream.read(8192):
                if len(captured) + len(chunk) > limit:
                    raise ValueError("native_session_output_limit")
                captured.extend(chunk)
            return bytes(captured)

        assert process.stdout is not None and process.stderr is not None
        tasks = [asyncio.create_task(drain(stream)) for stream in (process.stdout, process.stderr)]
        try:
            async with asyncio.timeout(timeout):
                stdout, stderr = await asyncio.gather(*tasks)
                await process.wait()
            return NativeExecResult(stdout, stderr, process.returncode or 0)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if config is not None:
                await asyncio.shield(self._terminate(token, process))
                self._active.pop(token, None)
                self._reservations.discard(token)
                self._known_tokens.append(token)
            elif process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                await process.wait()

    async def read(self, path: Path) -> _CappedFile:
        raw = str(Path(path))
        allowed = {**self._bundle_paths, self.lock.binary_path: self.lock.binary_sha256}
        if self.closed or raw not in allowed or Path(raw).is_symlink():
            raise PolicyDenied("native_session_read_denied")
        limit = self.max_binary_bytes if raw == self.lock.binary_path else 65536
        if Path(raw).stat().st_size > limit:
            raise ValueError("native_session_file_limit")
        return _CappedFile(Path(raw).open("rb"), limit)

    async def aclose(self) -> None:
        self.closed = True
        for token, process in tuple(self._active.items()):
            await self._terminate(token, process)
        self._active.clear()
        self._reservations.clear()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()
