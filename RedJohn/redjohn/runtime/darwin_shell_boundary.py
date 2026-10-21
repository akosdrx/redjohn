"""Attested Seatbelt networking for an assessment-owned local SDK Shell.

The SDK's filesystem policy remains the base profile. Seatbelt restricts this
process and its descendants to one controller-owned IPv4 TCP proxy endpoint;
there is no direct DNS, UDP, IPv6, Unix socket or Mach/XPC escape path.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import json
import os
import shutil
import signal
import socket
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from redjohn.assessment.egress import EgressUnavailable


if TYPE_CHECKING:
    from redjohn.assessment.resources import ResourceGovernor, ResourceLease


def _is_darwin() -> bool:
    # Keep runtime capability detection independent of mypy's target platform:
    # Linux CI must type-check this optional backend's complete implementation.
    return sys.platform == "darwin"


class DarwinShellEgressBoundary:
    """One verified profile, never a fallback to an unconfined process."""

    def __init__(
        self,
        proxy_url: str,
        workspace: Path,
        *,
        filesystem_profile: str,
        governor: ResourceGovernor,
    ) -> None:
        endpoint = urlsplit(proxy_url)
        if (
            endpoint.scheme != "http"
            or endpoint.hostname != "127.0.0.1"
            or not endpoint.port
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.path not in {"", "/"}
            or endpoint.query
            or endpoint.fragment
        ):
            raise EgressUnavailable("darwin_shell_proxy_endpoint_invalid")
        self.proxy_port = endpoint.port
        self.workspace = workspace.resolve()
        self.governor = governor
        self.profile = "\n".join(
            (
                filesystem_profile,
                "(deny network*)",
                # tcp4 is deliberate: `ip`/`tcp` would also allow an unrelated
                # IPv6 listener using the controller proxy's numeric port.
                f'(allow network-outbound (remote tcp4 "localhost:{self.proxy_port}"))',
                "(deny mach*)",
                "(deny appleevent-send)",
                "(deny ipc*)",
                "(deny process-info*)",
                "(deny signal (target others))",
            )
        )
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".redjohn-shell-tmp-", dir=self.workspace
        )
        temporary = Path(self._temporary.name).resolve()
        self.environment = {
            "HOME": str(self.workspace),
            "WORKSPACE": str(self.workspace),
            "TMPDIR": str(temporary),
            "TMP": str(temporary),
            "TEMP": str(temporary),
            "LANG": "C.UTF-8",
        }
        self._sandbox_exec: str | None = None
        self._started = False
        self._verified = False
        self._probe: asyncio.subprocess.Process | None = None
        self._probe_lease: ResourceLease | None = None
        self._attestation: dict[str, Any] = {}

    async def start(self) -> None:
        if not _is_darwin():
            raise EgressUnavailable("darwin_shell_requires_macos")
        self._sandbox_exec = shutil.which("sandbox-exec", path="/usr/bin:/bin")
        if self._sandbox_exec is None:
            raise EgressUnavailable("darwin_shell_seatbelt_unavailable")
        self._started = True

    @property
    def attestations(self) -> tuple[dict[str, Any], ...]:
        return (dict(self._attestation),) if self._verified else ()

    def assert_active(self) -> None:
        if not self._started or not self._verified:
            raise EgressUnavailable("darwin_shell_boundary_not_attested")

    def wrap_argv(self, argv: tuple[str, ...] | list[str], *, cwd: Path | None = None) -> list[str]:
        self.assert_active()
        if cwd is not None and cwd.resolve() != self.workspace:
            raise EgressUnavailable("darwin_shell_workspace_changed")
        assert self._sandbox_exec is not None
        return [self._sandbox_exec, "-p", self.profile, *argv]

    async def _cleanup_probe(self) -> None:
        if self._probe is not None:
            if self._probe.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self._probe.pid, signal.SIGKILL)
            async with asyncio.timeout(5):
                await self._probe.wait()
            self._probe = None
        if self._probe_lease is not None:
            self._probe_lease.release()
            self._probe_lease = None

    async def attest(self) -> dict[str, Any]:
        if not self._started or self._sandbox_exec is None:
            raise EgressUnavailable("darwin_shell_boundary_not_started")
        if self._verified:
            return dict(self._attestation)
        self._probe_lease = self.governor.acquire("worker", estimated_bytes=64 * 1024 * 1024)
        try:
            # Keep the owned Unix socket below Darwin's sockaddr_un path limit,
            # independently of a possibly deep operator workspace location.
            with tempfile.TemporaryDirectory(prefix="rj-seatbelt-", dir="/tmp") as secret:
                canary = Path(secret).resolve() / "private-canary"
                canary.write_text("controller-only")
                with socket.socket() as denied, socket.socket(socket.AF_UNIX) as unix:
                    denied.bind(("127.0.0.1", 0))
                    denied.listen(1)
                    unix_path = Path(secret).resolve() / "probe.sock"
                    unix.bind(str(unix_path))
                    unix.listen(1)
                    denied_port = denied.getsockname()[1]
                    source = self._probe_source(denied_port, canary, unix_path)
                    self._probe = await asyncio.create_subprocess_exec(
                        self._sandbox_exec,
                        "-p",
                        self.profile,
                        str(Path(sys.executable).resolve()),
                        "-I",
                        "-c",
                        source,
                        cwd=self.workspace,
                        env={**self.environment, "PATH": "/usr/bin:/bin"},
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        start_new_session=True,
                    )
                    async with asyncio.timeout(10):
                        stdout, _stderr = await self._probe.communicate()
                    if self._probe.returncode != 0 or len(stdout) > 4096:
                        raise EgressUnavailable("darwin_shell_seatbelt_probe_failed")
                    try:
                        result = json.loads(stdout)
                    except (ValueError, UnicodeError) as exc:
                        raise EgressUnavailable("darwin_shell_seatbelt_probe_invalid") from exc
                    expected = {
                        "proxy": 0,
                        "direct": errno.EPERM,
                        "other_loopback": errno.EPERM,
                        "ipv6_proxy_port": errno.EPERM,
                        "udp_proxy_port": errno.EPERM,
                        "unix_socket": errno.EPERM,
                        "private_file": errno.EPERM,
                        "child_direct": errno.EPERM,
                    }
                    if result != expected:
                        raise EgressUnavailable("darwin_shell_seatbelt_negative_control_failed")
                    self._attestation = {
                        "method": "darwin_seatbelt_negative_controls",
                        "proxy_endpoint": f"127.0.0.1:{self.proxy_port}",
                        "checks": result,
                    }
                    self._verified = True
        finally:
            # Keep the reservation if process death cannot be confirmed. close()
            # retries cleanup rather than reporting an unknown worker as freed.
            await self._cleanup_probe()
        return dict(self._attestation)

    def _probe_source(self, denied_port: int, canary: Path, unix_path: Path) -> str:
        child = f"import socket;print(socket.socket().connect_ex(('127.0.0.1',{denied_port})))"
        return f"""
import errno,json,pathlib,socket,subprocess,sys,tempfile
result={{}}
for key,family,address in [
 ('proxy',socket.AF_INET,('127.0.0.1',{self.proxy_port})),
 ('direct',socket.AF_INET,('127.0.0.1',{denied_port})),
 ('other_loopback',socket.AF_INET,('127.0.0.2',{self.proxy_port})),
 ('ipv6_proxy_port',socket.AF_INET6,('::1',{self.proxy_port})),
]:
 sock=socket.socket(family,socket.SOCK_STREAM);sock.settimeout(1)
 try:result[key]=sock.connect_ex(address)
 except OSError as exc:result[key]=exc.errno
 finally:sock.close()
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try:result['udp_proxy_port']=sock.sendto(b'owned',('127.0.0.1',{self.proxy_port}))
except OSError as exc:result['udp_proxy_port']=exc.errno
finally:sock.close()
sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try:result['unix_socket']=sock.connect_ex({str(unix_path)!r})
except OSError as exc:result['unix_socket']=exc.errno
finally:sock.close()
try:pathlib.Path({str(canary)!r}).read_bytes();result['private_file']=0
except OSError as exc:result['private_file']=exc.errno
child=subprocess.run([sys.executable,'-I','-c',{child!r}],
 capture_output=True,text=True,timeout=3)
result['child_direct']=int(child.stdout.strip()) if child.returncode==0 else -1
print(json.dumps(result))
"""

    async def close(self) -> None:
        self._verified = False
        self._started = False
        await self._cleanup_probe()
        self._temporary.cleanup()
