"""Kernel-enforced Linux worker egress through one inspected host proxy.

The controller retains networking. Each worker has new user, mount, PID and
network namespaces with only loopback and no network capabilities. A narrow
Unix relay exposes exactly the controller-selected proxy, never a destination
supplied by a worker. Linux SO_PEERCRED and /proc attest the actual namespace
before the trusted helper is allowed to launch its worker.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import platform
import shutil
import signal
import socket
import stat
import struct
import sys
import tempfile
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from redjohn.assessment._owned_process import OwnedProcess


class EgressUnavailable(RuntimeError):  # noqa: N818 - public capability error name
    """The requested kernel isolation could not be established; do not run."""


class EgressCleanupUnverified(EgressUnavailable):
    requires_lease_retention = True
    code = "blocked_namespace_cleanup_unverified"


class LinuxEgressBoundary:
    """Trusted controller API; this class is not exposed as an agent tool.

    Call ``start`` and ``attest`` before enabling a remote job. All actual
    scanner/browser launches must use ``wrap_argv`` or ``executable_wrapper``.
    The same proxy URL works inside and outside the namespace: the helper binds
    that loopback port in its own namespace, forwarding only to the host proxy.
    """

    def __init__(
        self,
        proxy_url: str,
        workspace: Path,
        *,
        read_only_paths: tuple[Path, ...] = (),
        writable_paths: tuple[Path, ...] = (),
        max_connections: int = 64,
        max_stream_bytes: int = 4 * 1024**2,
        timeout_seconds: float = 30,
        controller_preamble: bytes = b"",
    ) -> None:
        parsed = urlsplit(proxy_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("egress_requires_controller_loopback_proxy")
        if (
            not 1 <= max_connections <= 128
            or not 1024 <= max_stream_bytes <= 16 * 1024**2
            or not 0 < timeout_seconds <= 180
            or not isinstance(controller_preamble, bytes)
            or len(controller_preamble) > 256
        ):
            raise ValueError("invalid_egress_limits")
        self.worker_proxy_url = f"http://127.0.0.1:{parsed.port}"
        self._proxy_port = parsed.port
        self.workspace = Path(workspace).resolve()
        self.read_only_paths = tuple(Path(path).resolve() for path in read_only_paths)
        self.writable_paths = tuple(Path(path).resolve() for path in writable_paths)
        self.max_connections = max_connections
        self.max_stream_bytes = max_stream_bytes
        self.timeout_seconds = timeout_seconds
        self._controller_preamble = controller_preamble
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._peers: dict[int, str] = {}
        # Authorization ends with the control socket; ownership ends only after
        # observed process death. Never lose a live peer by closing its socket.
        self._owned_peers: dict[int, str] = {}
        self._attestation_owner = OwnedProcess()
        self._cleanup_unverified = False
        self._closing_server: asyncio.AbstractServer | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._attestations: deque[dict[str, Any]] = deque(maxlen=64)
        self._rejection_reasons: deque[str] = deque(maxlen=16)
        self._verified = False
        self._bwrap: str | None = None
        self._assets: tempfile.TemporaryDirectory[str] | None = None
        self._socket_path: Path | None = None
        self._helper_path: Path | None = None
        self._wrappers: set[Path] = set()
        self.relay_connections = 0
        self.rejected_connections = 0
        self.forwarded_bytes = 0

    @property
    def active(self) -> bool:
        return self._server is not None and self._verified

    def assert_active(self) -> None:
        """Reject remote execution without this live, kernel-attested boundary."""
        if not self.active:
            raise EgressUnavailable("egress_boundary_not_attested")

    @property
    def attestations(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(value) for value in self._attestations)

    @property
    def rejection_reasons(self) -> tuple[str, ...]:
        return tuple(self._rejection_reasons)

    @property
    def environment(self) -> dict[str, str]:
        return {
            "HOME": str(self.workspace),
            # This path is a per-worker tmpfs, not the host's /tmp. Chromium
            # creates Unix sockets here; deep host workspace names can exceed
            # Linux's socket-path limit and crash an otherwise valid sandbox.
            "TMPDIR": "/tmp",  # noqa: S108 - namespace-private tmpfs
            "TMP": "/tmp",  # noqa: S108 - namespace-private tmpfs
            "TEMP": "/tmp",  # noqa: S108 - namespace-private tmpfs
            "LANG": "C.UTF-8",
        }

    async def start(self) -> None:
        if self._server is not None:
            return
        if platform.system() != "Linux":
            raise EgressUnavailable("blocked_linux_network_namespace_required")
        self._bwrap = shutil.which("bwrap")
        if self._bwrap is None:
            raise EgressUnavailable("blocked_bubblewrap_missing")
        if not hasattr(socket, "SO_PEERCRED"):
            raise EgressUnavailable("blocked_peer_credentials_unavailable")
        for path in self.read_only_paths + self.writable_paths:
            if not path.exists() or str(path) in {"/", "/home", "/run", "/tmp", "/proc", "/dev"}:  # noqa: S108 - denied mounts
                raise ValueError("egress_unsafe_mount")
            if path.is_file() and not stat.S_ISREG(path.stat().st_mode):
                raise ValueError("egress_unsafe_mount")
        self.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.workspace.chmod(0o700)
        # Launch shims run on the host: workers must never be able to modify
        # them, even though they can write their own private workspace.
        # A short host-temp path also stays below Linux's Unix-socket path
        # limit. Host /tmp itself is absent from the worker mount namespace.
        self._assets = tempfile.TemporaryDirectory(prefix=".redjohn-egress-")
        assets = Path(self._assets.name)
        assets.chmod(0o700)
        if any(path == assets or path in assets.parents for path in self.writable_paths):
            self._assets.cleanup()
            self._assets = None
            raise ValueError("egress_host_assets_must_not_be_worker_writable")
        self._socket_path = assets / "egress.sock"
        self._helper_path = assets / "egress-worker.py"
        source = Path(__file__).with_name("_egress_worker.py").read_bytes()
        self._helper_path.write_bytes(source)
        self._helper_path.chmod(0o600)
        self._server = await asyncio.start_unix_server(self._accept, path=self._socket_path)
        self._socket_path.chmod(0o600)

    def _kernel_attestation(self, writer: asyncio.StreamWriter) -> dict[str, Any]:
        connection = writer.get_extra_info("socket")
        if connection is None:
            raise EgressUnavailable("egress_peer_socket_missing")
        pid, uid, _gid = struct.unpack(
            "3i",
            connection.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERCRED"), 12),  # noqa: B009 - platform-specific constant
        )
        if pid <= 0 or uid != os.getuid():
            raise EgressUnavailable("egress_peer_identity_denied")
        proc = Path("/proc") / str(pid)
        namespaces = {
            name: str((proc / "ns" / name).readlink()) for name in ("net", "mnt", "pid", "user")
        }
        if any(
            value == str((Path("/proc/self/ns") / name).readlink())
            for name, value in namespaces.items()
        ):
            raise EgressUnavailable("egress_worker_namespace_not_isolated")
        interfaces = tuple(
            line.partition(":")[0].strip()
            for line in (proc / "net/dev").read_text().splitlines()[2:]
        )
        if interfaces != ("lo",):
            raise EgressUnavailable("egress_worker_external_interface_present")
        status = {
            line.partition(":")[0]: line.partition(":")[2].strip()
            for line in (proc / "status").read_text().splitlines()
        }
        if int(status.get("CapEff", "-1"), 16) != 0 or status.get("NoNewPrivs") != "1":
            raise EgressUnavailable("egress_worker_privileges_present")
        return {
            "pid": pid,
            "uid": uid,
            "namespaces": namespaces,
            "interfaces": interfaces,
            "effective_capabilities": "0",
            "no_new_privileges": True,
            "proxy_url": self.worker_proxy_url,
        }

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._tasks) >= self.max_connections:
            self.rejected_connections += 1
            writer.close()
            return
        self._writers.add(writer)
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(  # noqa: PLR0912, PLR0915 - bounded gate then stream lifecycle
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_pid: int | None = None
        control = False
        outside: asyncio.StreamWriter | None = None
        try:
            operation = await asyncio.wait_for(reader.readexactly(1), 5)
            attestation = self._kernel_attestation(writer)
            peer_pid = attestation["pid"]
            if operation == b"A":
                if peer_pid in self._peers:
                    raise EgressUnavailable("egress_duplicate_attestation")  # noqa: TRY301
                self._owned_peers = {
                    pid: namespace
                    for pid, namespace in self._owned_peers.items()
                    if not self._peer_dead(pid, namespace)
                }
                if len(self._owned_peers) >= 128:
                    raise EgressUnavailable("egress_owned_peer_limit")  # noqa: TRY301
                self._peers[peer_pid] = attestation["namespaces"]["net"]
                self._owned_peers[peer_pid] = attestation["namespaces"]["net"]
                self._attestations.append(attestation)
                control = True
                writer.write(b"Y")
                await writer.drain()
                # One live control socket owns this helper's forwarding permit.
                await reader.read(1)
                return
            if operation != b"S" or self._peers.get(peer_pid) != attestation["namespaces"]["net"]:
                raise EgressUnavailable("egress_unattested_forwarder")  # noqa: TRY301
            outside_reader, outside_stream = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self._proxy_port), 5
            )
            outside = outside_stream
            if self._controller_preamble:
                # Host-only framing after the authenticated kernel peer gate.
                # The raw service worker never receives this per-job secret.
                outside_stream.write(self._controller_preamble)
                await outside_stream.drain()
            self.relay_connections += 1
            self._writers.add(outside_stream)
            transferred = 0

            async def copy(source: asyncio.StreamReader, target: asyncio.StreamWriter) -> None:
                nonlocal transferred
                while True:
                    data = await source.read(min(65536, self.max_stream_bytes - transferred + 1))
                    if not data:
                        return
                    transferred += len(data)
                    if transferred > self.max_stream_bytes:
                        raise EgressUnavailable("egress_stream_byte_limit")  # noqa: TRY301
                    self.forwarded_bytes += len(data)
                    target.write(data)
                    await target.drain()

            copies = [
                asyncio.create_task(copy(reader, outside_stream)),
                asyncio.create_task(copy(outside_reader, writer)),
            ]
            try:
                async with asyncio.timeout(self.timeout_seconds):
                    done, pending = await asyncio.wait(copies, return_when=asyncio.FIRST_COMPLETED)
                    for finished in done:
                        finished.result()
                    for pending_copy in pending:
                        pending_copy.cancel()
            finally:
                for pending_copy in copies:
                    if not pending_copy.done():
                        pending_copy.cancel()
                await asyncio.gather(*copies, return_exceptions=True)
        except (
            OSError,
            ValueError,
            EgressUnavailable,
            TimeoutError,
            asyncio.IncompleteReadError,
        ) as error:
            self.rejected_connections += 1
            self._rejection_reasons.append(f"{type(error).__name__}:{error}"[:512])
        finally:
            if control and peer_pid is not None:
                self._peers.pop(peer_pid, None)
            for stream in (writer, outside):
                if stream is not None:
                    self._writers.discard(stream)
                    stream.close()
                    with contextlib.suppress(OSError):
                        await stream.wait_closed()

    def _command(self, argv: tuple[str, ...] | list[str], *, cwd: Path | None = None) -> list[str]:
        if (
            self._server is None
            or self._bwrap is None
            or self._socket_path is None
            or self._helper_path is None
        ):
            raise EgressUnavailable("egress_boundary_not_started")
        if not argv or not Path(argv[0]).is_absolute() or any("\x00" in value for value in argv):
            raise ValueError("egress_requires_explicit_executable")
        directory = self.workspace if cwd is None else Path(cwd).resolve()
        if not directory.is_dir() or not any(
            directory == root or root in directory.parents
            for root in (self.workspace, *self.writable_paths)
        ):
            raise ValueError("egress_working_directory_not_mounted")
        command = [
            self._bwrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--cap-drop",
            "ALL",
            "--clearenv",
        ]
        mounted: set[Path] = set()
        for raw in ("/usr", "/bin", "/sbin", "/lib", "/lib64"):
            path = Path(raw)
            if path.is_symlink():
                command.extend(("--symlink", str(path.readlink()), raw))
            elif path.exists():
                command.extend(("--ro-bind", raw, raw))
                mounted.add(path)
        # Establish the private tmpfs before mounting explicitly reviewed files.
        # Otherwise a reviewed template under host /tmp is hidden by the later
        # tmpfs and the scanner incorrectly reports a missing executable/tool.
        command.extend(("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/run"))  # noqa: S108 - isolated tmpfs
        runtime_paths = (Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve())
        for path in runtime_paths + self.read_only_paths:
            if any(path == root or root in path.parents for root in mounted):
                continue
            command.extend(("--ro-bind", str(path), str(path)))
            mounted.add(path)
        # Chromium's ARM64 cpuinfo library requires this public topology data.
        # Mount only that subtree read-only, never all of /sys or other devices.
        for raw in (
            "/etc/ssl/certs",
            "/etc/fonts",
            "/etc/ld.so.cache",
            "/sys/devices/system/cpu",
        ):
            if Path(raw).exists():
                command.extend(("--ro-bind", raw, raw))
        for path in (self.workspace, *self.writable_paths):
            command.extend(("--bind", str(path), str(path)))
        command.extend(("--ro-bind", str(self._socket_path), "/run/redjohn-egress.sock"))
        command.extend(("--ro-bind", str(self._helper_path), "/run/redjohn-egress-worker.py"))
        for name, value in self.environment.items():
            command.extend(("--setenv", name, value))
        command.extend(("--setenv", "PATH", "/usr/bin:/bin", "--chdir", str(directory), "--"))
        command.extend(
            (
                sys.executable,
                "-I",
                "-S",
                "/run/redjohn-egress-worker.py",
                json.dumps({"port": self._proxy_port, "argv": list(argv)}, separators=(",", ":")),
            )
        )
        return command

    def wrap_argv(self, argv: tuple[str, ...] | list[str], *, cwd: Path | None = None) -> list[str]:
        if not self.active:
            raise EgressUnavailable("egress_boundary_not_attested")
        return self._command(argv, cwd=cwd)

    async def attest(self) -> dict[str, Any]:
        if self._server is None:
            raise EgressUnavailable("egress_boundary_not_started")
        before = len(self._attestations)
        command = self._command([sys.executable, "-I", "-S", "-c", "print('redjohn-egress-ready')"])
        try:
            stdout, stderr, code = await self._attestation_owner.run(command, timeout=15)
        except BaseException:
            await OwnedProcess.join(asyncio.create_task(self.terminate_owned_workers()))
            raise
        if (
            code != 0
            or stdout.strip() != b"redjohn-egress-ready"
            or len(self._attestations) <= before
        ):
            detail = stderr.decode(errors="replace")[:512].strip()
            if self._rejection_reasons:
                detail += ";" + self._rejection_reasons[-1]
            raise EgressUnavailable(f"blocked_namespace_attestation_failed:{detail}")
        self._verified = True
        return dict(self._attestations[-1])

    def executable_wrapper(self, executable: str | Path) -> Path:
        """Return a private launch shim for Playwright's executable_path.

        Set launch env from ``environment`` so Chromium's temporary sockets use
        the short namespace-private tmpfs. The host workspace stays private.
        """
        if not self.active:
            raise EgressUnavailable("egress_boundary_not_attested")
        executable = str(Path(executable).resolve())
        prefix = self._command([executable])
        # The final argument is the helper JSON; append browser arguments inside
        # that JSON rather than permitting shell expansion or bwrap options.
        body = (
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            f"command = {prefix!r}\n"
            "config = json.loads(command[-1])\n"
            "preserved = []\n"
            "if '--remote-debugging-pipe' in sys.argv[1:]:\n"
            "    for descriptor in (3, 4):\n"
            "        os.fstat(descriptor)\n"
            "        os.set_inheritable(descriptor, True)\n"
            "        preserved.append(descriptor)\n"
            "for name in os.listdir('/proc/self/fd'):\n"
            "    descriptor = int(name)\n"
            "    if descriptor > 2 and descriptor not in preserved:\n"
            "        try: os.close(descriptor)\n"
            "        except OSError: pass\n"
            "config['pass_fds'] = preserved\n"
            "config['argv'].extend(sys.argv[1:])\n"
            "command[-1] = json.dumps(config, separators=(',', ':'))\n"
            "os.execv(command[0], command)\n"
        )
        if self._assets is None:
            raise EgressUnavailable("egress_boundary_not_started")
        path = Path(self._assets.name) / f"launch-{len(self._wrappers)}.py"
        path.write_text(body)
        path.chmod(0o700)
        self._wrappers.add(path)
        return path

    @staticmethod
    def _same_namespace(pid: int, namespace: str) -> bool:
        try:
            return str((Path("/proc") / str(pid) / "ns/net").readlink()) == namespace
        except OSError:
            return False

    @staticmethod
    def _peer_dead(pid: int, namespace: str) -> bool:
        try:
            current = str((Path("/proc") / str(pid) / "ns/net").readlink())
        except FileNotFoundError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                return False
            return False
        except OSError:
            return False
        return current != namespace

    def worker_cleanup_verified(self) -> bool:
        return (
            self._attestation_owner.resource_cleanup_verified()
            and not self._cleanup_unverified
            and all(self._peer_dead(pid, namespace) for pid, namespace in self._owned_peers.items())
        )

    def resource_cleanup_verified(self) -> bool:
        return (
            self.worker_cleanup_verified()
            and self._server is None
            and self._closing_server is None
            and not self._tasks
            and not self._writers
            and not self._owned_peers
            and self._assets is None
            and not self._wrappers
            and (self._close_task is None or self._close_task.done())
        )

    @staticmethod
    def _descends_from(pid: int, root_pid: int) -> bool:
        visited: set[int] = set()
        for _level in range(64):
            if pid == root_pid:
                return True
            if pid <= 1 or pid in visited:
                return False
            visited.add(pid)
            try:
                status = (Path("/proc") / str(pid) / "status").read_text()
                parent = next(line for line in status.splitlines() if line.startswith("PPid:"))
                pid = int(parent.split(":", 1)[1].strip())
            except (OSError, ValueError, StopIteration):
                return False
        return False

    async def _terminate_peers(self, peers: dict[int, str]) -> None:
        # Signal the helper first so its supervisor child can execute finally
        # cleanup in the same PID namespace, then kill only still-owned peers.
        for pid, namespace in peers.items():
            if self._same_namespace(pid, namespace):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGTERM)
        for _attempt in range(40):
            if not any(self._same_namespace(pid, namespace) for pid, namespace in peers.items()):
                break
            await asyncio.sleep(0.05)
        for pid, namespace in peers.items():
            if self._same_namespace(pid, namespace):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
        for _attempt in range(20):
            if all(self._peer_dead(pid, namespace) for pid, namespace in peers.items()):
                self._cleanup_unverified = False
                return
            await asyncio.sleep(0.05)
        self._cleanup_unverified = True
        raise EgressCleanupUnverified("namespace_peer_death_unverified")

    async def terminate_owned_workers(self) -> None:
        await self._attestation_owner.stop()
        peers = dict(self._owned_peers)
        await self._terminate_peers(peers)
        for pid, namespace in peers.items():
            if self._owned_peers.get(pid) == namespace:
                self._owned_peers.pop(pid, None)

    async def terminate_workers(self, root_pid: int) -> None:
        """Stop attested helpers descending from one tracked host launcher PID.

        Namespace-local marker PIDs must never be interpreted on the host.
        This controller-only method instead verifies real host parentage and
        the helper's still-live attested network namespace before signalling.
        """
        if type(root_pid) is not int or root_pid <= 1:
            raise ValueError("invalid_egress_launcher_pid")
        peers = {
            pid: namespace
            for pid, namespace in tuple(self._owned_peers.items())
            if self._descends_from(pid, root_pid)
        }
        await self._terminate_peers(peers)

    async def _close_owned(self) -> None:
        await self.terminate_owned_workers()
        self._verified = False
        server = self._server or self._closing_server
        self._closing_server, self._server = server, None
        if server is not None:
            server.close()
        for writer in tuple(self._writers):
            writer.close()
        for task in tuple(self._tasks):
            if not task.cancelling():
                task.cancel()
        # Python 3.12+ also waits for accepted connections. Close their
        # transports before awaiting the listener, or a live worker's control
        # socket would deadlock shutdown until the worker finished naturally.
        try:
            async with asyncio.timeout(5):
                if self._tasks:
                    await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
                if server is not None:
                    await server.wait_closed()
        except TimeoutError:
            self._cleanup_unverified = True
            raise EgressCleanupUnverified("namespace_listener_cleanup_unverified") from None
        self._closing_server = None
        await self.terminate_owned_workers()
        self._peers.clear()
        for path in self._wrappers:
            path.unlink(missing_ok=True)
        self._wrappers.clear()
        if self._assets is not None:
            self._assets.cleanup()
            self._assets = None
        self._socket_path = self._helper_path = None

    async def close(self) -> None:
        if self._close_task is None or self._close_task.done():
            self._close_task = asyncio.create_task(self._close_owned())
        await OwnedProcess.join(self._close_task)
