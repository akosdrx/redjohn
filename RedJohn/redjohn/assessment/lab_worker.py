"""A fixed header-regression template, enforced namespace, and bounded worker.

No API accepts source code, shell commands, arbitrary argv, or a worker-selected
target. Missing namespace or precontained kernel memory support fails closed.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import hashlib
import json
import os
import signal
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary
from redjohn.assessment.lab_contract import (
    EXPECTED,
    HEADER,
    LabDenied,
    LabPlan,
    OwnedFixtureBinding,
)
from redjohn.assessment.os_memory import LinuxMemoryBoundary
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.resources import ResourceAdmissionError


if TYPE_CHECKING:
    from collections.abc import Callable

    from redjohn.assessment.policy import EngagementPolicy

_SOURCE = '''"""RedJohn fixed owned-lab header assertion; no RCE assertion."""
import errno,hashlib,http.client,json,os,resource,sys
resource.setrlimit(resource.RLIMIT_CPU,(2,2))
resource.setrlimit(resource.RLIMIT_AS,(134217728,134217728))
resource.setrlimit(resource.RLIMIT_FSIZE,(65536,65536))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
try:
    os.chmod(__file__,0o600)
except OSError as exc:
    if exc.errno!=errno.EROFS: raise RuntimeError('payload_mount_not_readonly')
    readonly=True
else:
    raise RuntimeError('regression_payload_not_readonly')
config=CONFIG_VALUE
client=http.client.HTTPConnection('127.0.0.1',config['port'],timeout=2)
try:
    target='http://127.0.0.1:'+str(config['port'])+config['carrier']
    client.request('GET',target,headers={'User-Agent':'RedJohn-owned-lab/1'})
    response=client.getresponse()
    value=response.getheader('x-content-type-options')
    if value is not None and len(value.encode())>128:
        raise RuntimeError('header_budget')
    body=response.read(65537)
    if len(body)>65536:
        raise RuntimeError('body_budget')
    print(json.dumps({'schema':1,'status':response.status,'observed':value,
        'header_present':value=='nosniff','body_bytes':len(body),
        'body_sha256':hashlib.sha256(body).hexdigest(),'payload_readonly':readonly,
        'cpu_limit_seconds':resource.getrlimit(resource.RLIMIT_CPU)[0],
        'address_space_limit_bytes':resource.getrlimit(resource.RLIMIT_AS)[0]}),flush=True)
finally:
    client.close()
'''
TEMPLATE_SHA256 = hashlib.sha256(_SOURCE.encode()).hexdigest()

_NEGATIVE = """import errno,http.client,json,os,socket,sys
port,target_port,artifact=sys.argv[1:]
try:
    sock=socket.create_connection(('127.0.0.1',int(target_port)),timeout=.5)
except OSError:
    direct_blocked=True
else:
    sock.close();raise RuntimeError('direct_fixture_connection_allowed')
client=http.client.HTTPConnection('127.0.0.1',int(port),timeout=2)
try:
    client.request('GET','http://127.0.0.1:'+port+'/outside-reviewed-carrier')
    response=client.getresponse()
    if response.status!=403: raise RuntimeError('offscope_carrier_allowed')
    response.read(1024)
finally:
    client.close()
try:
    os.chmod(artifact,0o600)
except OSError as exc:
    if exc.errno!=errno.EROFS: raise RuntimeError('payload_mount_not_readonly')
    readonly=True
else:
    raise RuntimeError('payload_writable')
print(json.dumps({'direct_blocked':True,'offscope_status':403,'payload_readonly':True}))
"""


def regression_source(port: int, carrier: str) -> str:
    if (
        type(port) is not int
        or not 1 <= port <= 65535
        or not (
            carrier.startswith("/rj-lab/")
            and len(carrier) == 72
            and all(c in "0123456789abcdef" for c in carrier[8:])
        )
    ):
        raise LabDenied("lab_invalid_public_carrier")
    source = _SOURCE.replace("CONFIG_VALUE", repr({"port": port, "carrier": carrier}))
    ast.parse(source)
    return source


def validate_source(source: str, port: int, carrier: str) -> str:
    if not isinstance(source, str) or source != regression_source(port, carrier):
        raise LabDenied("lab_artifact_template_mismatch")
    return hashlib.sha256(source.encode()).hexdigest()


class LabWorker:
    def __init__(self, root: Path, *, memory_config: dict[str, Any], owner_budget: int) -> None:
        self.root, self.memory_config, self.owner_budget = root, memory_config, owner_budget
        self.process: asyncio.subprocess.Process | None = None
        self.boundary: LinuxEgressBoundary | None = None
        self.proxy: BrowserEgressProxy | None = None
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._cleanup_lock = asyncio.Lock()
        self._pending_spawn: asyncio.Task[asyncio.subprocess.Process] | None = None
        self._late_reaper: asyncio.Task[None] | None = None
        self._cleanup_verified = True

    def resource_cleanup_verified(self) -> bool:
        return self._cleanup_verified and self._pending_spawn is None and self.process is None

    async def execute(  # noqa: PLR0915 - one bounded owned lifecycle, no arbitrary commands
        self,
        policy: EngagementPolicy,
        plan: LabPlan,
        fixture: OwnedFixtureBinding,
        *,
        admit: Callable[[], None],
        timeout: float,
    ) -> dict[str, Any]:
        plan.authorize(policy)
        if plan.template_sha256 != TEMPLATE_SHA256:
            raise LabDenied("lab_template_version_mismatch")
        proof = fixture.require_live()
        if (
            proof.url != plan.url
            or proof.fixture_ref != plan.fixture_ref
            or proof.asset_ref != plan.asset_ref
        ):
            raise LabDenied("lab_fixture_context_mismatch")
        fence = LinuxMemoryBoundary.current(self.memory_config, self.owner_budget)
        if fence is None:
            raise EgressUnavailable("blocked_lab_precontained_kernel_memory_required")
        if not self.resource_cleanup_verified():
            raise ResourceAdmissionError("lab_previous_cleanup_unverified")
        self._cleanup_verified = False
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(prefix="lab-", dir=self.root)
        base = Path(self._temporary.name)
        workspace, payload = base / "workspace", base / "payload"
        workspace.mkdir(mode=0o700)
        payload.mkdir(mode=0o700)
        transport: list[dict[str, Any]] = []
        sent = False
        carrier = "/rj-lab/" + plan.key

        def rewrite(url: str, method: str) -> str:
            assert self.proxy is not None
            if method != "GET" or url != self.proxy.url + carrier:
                raise PolicyDenied("lab_public_carrier_mismatch")
            fixture.require_live()
            return plan.url

        def admission(url: str) -> None:
            nonlocal sent
            if sent or url != plan.url:
                raise PolicyDenied("lab_single_request_required")
            fixture.require_live()
            admit()
            sent = True

        def complete(url: str, method: str, status: int, headers: dict[str, str]) -> None:
            if url != plan.url or method != "GET" or len(transport) >= 1:
                raise PolicyDenied("lab_transport_context_mismatch")
            value = headers.get(HEADER)
            if value is not None and len(value.encode()) > 128:
                raise LabDenied("lab_header_budget")
            transport.append(
                {
                    "url": url,
                    "method": method,
                    "status": status,
                    "observed": value,
                    "response_complete": True,
                    "fixture_key": proof.key,
                }
            )

        self.proxy = BrowserEgressProxy(
            policy,
            max_connections=1,
            timeout_seconds=min(timeout, 10),
            max_wire_bytes=131072,
            rewrite_url=rewrite,
            request_admission=admission,
            on_complete=complete,
        )
        try:
            await self.proxy.start()
            port = urlsplit(self.proxy.url).port
            assert port is not None
            source = regression_source(port, carrier)
            artifact = payload / "regression.py"
            artifact.write_text(source)
            artifact.chmod(0o400)
            artifact_sha = validate_source(artifact.read_text(), port, carrier)
            self.boundary = LinuxEgressBoundary(
                self.proxy.url,
                workspace,
                read_only_paths=(payload,),
                max_connections=1,
                max_stream_bytes=131072,
                timeout_seconds=min(timeout, 10),
            )
            await self.boundary.start()
            await self.boundary.attest()
            target_port = urlsplit(plan.url).port
            assert target_port is not None
            negative = await self._execute(
                self.boundary.wrap_argv(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        _NEGATIVE,
                        str(port),
                        str(target_port),
                        str(artifact),
                    ]
                ),
                workspace,
                timeout=min(timeout, 5),
            )
            if negative != {
                "direct_blocked": True,
                "offscope_status": 403,
                "payload_readonly": True,
            }:
                raise LabDenied("lab_negative_control_failed")
            command = self.boundary.wrap_argv([sys.executable, "-I", "-S", str(artifact)])
            result = await self._execute(command, workspace, timeout=timeout)
            if (
                not isinstance(result, dict)
                or set(result)
                != {
                    "schema",
                    "status",
                    "observed",
                    "header_present",
                    "body_bytes",
                    "body_sha256",
                    "payload_readonly",
                    "cpu_limit_seconds",
                    "address_space_limit_bytes",
                }
                or result.get("schema") != 1
                or type(result.get("status")) is not int
                or type(result.get("body_bytes")) is not int
                or not 0 <= result["body_bytes"] <= 65536
                or result.get("payload_readonly") is not True
                or result.get("cpu_limit_seconds") != 2
                or result.get("address_space_limit_bytes") != 134217728
                or len(transport) != 1
                or result["status"] != transport[0]["status"]
                or result["observed"] != transport[0]["observed"]
                or result["header_present"] is not (result["observed"] == EXPECTED)
            ):
                raise LabDenied("lab_worker_transport_assertion_mismatch")
            return {
                "assertion": result,
                "transport": transport[0],
                "artifact_sha256": artifact_sha,
                "template_sha256": TEMPLATE_SHA256,
                "namespace": list(self.boundary.attestations),
                "owner_memory": fence.snapshot(),
                "request_sent": sent,
                "negative_controls": negative,
            }
        finally:
            await self._join_cleanup()

    async def _join_cleanup(self) -> None:
        task = asyncio.create_task(self.cleanup())
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True
        task.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _execute(
        self, command: list[str], workspace: Path, *, timeout: float
    ) -> dict[str, Any]:
        spawn = self._pending_spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *command,
                cwd=workspace,
                env={"PATH": "/usr/bin:/bin", "HOME": str(workspace)},
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        )
        try:
            self.process = await asyncio.wait_for(asyncio.shield(spawn), min(timeout, 2.0))
        except (asyncio.CancelledError, TimeoutError):
            self._schedule_late_reaper()
            raise
        self._pending_spawn = None

        process = self.process

        async def drain(stream: asyncio.StreamReader | None) -> bytes:
            assert stream is not None
            data = bytearray()
            while chunk := await stream.read(1024):
                if len(data) + len(chunk) > 8192:
                    raise LabDenied("lab_worker_output_budget")
                data.extend(chunk)
            return bytes(data)

        tasks = [asyncio.create_task(drain(stream)) for stream in (process.stdout, process.stderr)]
        try:
            async with asyncio.timeout(timeout):
                output, _stderr = await asyncio.gather(*tasks)
                code = await process.wait()
            if code != 0:
                raise LabDenied("lab_worker_failed")
            result = json.loads(output)
            if not isinstance(result, dict):
                raise LabDenied("lab_worker_output_schema")
            return result
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _cancel(self) -> None:
        pending = self._pending_spawn
        if pending is not None:
            try:
                self.process = await asyncio.wait_for(asyncio.shield(pending), 0.25)
            except TimeoutError as exc:
                self._schedule_late_reaper()
                raise ResourceAdmissionError("lab_process_delivery_cleanup_unverified") from exc
            self._pending_spawn = None
        process = self.process
        if process is not None:
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(process.wait(), 1)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                try:
                    await asyncio.wait_for(process.wait(), 1)
                except TimeoutError as exc:
                    raise ResourceAdmissionError("lab_process_reap_unverified") from exc
            if self.boundary is not None:
                await self.boundary.terminate_workers(process.pid)
            if self.process is process:
                self.process = None

    async def cancel(self) -> None:
        async with self._cleanup_lock:
            await self._cancel()

    def _schedule_late_reaper(self) -> None:
        if self._late_reaper is not None and not self._late_reaper.done():
            return

        async def reap() -> None:
            pending = self._pending_spawn
            if pending is not None:
                try:
                    await asyncio.shield(pending)
                    await self.cleanup()
                except (OSError, ResourceAdmissionError, asyncio.CancelledError):
                    # The unchanged guard retains the original reservation.
                    self._cleanup_verified = False

        self._late_reaper = asyncio.create_task(reap())

    async def cleanup(self) -> None:
        async with self._cleanup_lock:
            await self._cancel()
            if self.boundary is not None:
                await self.boundary.close()
                self.boundary = None
            if self.proxy is not None:
                await self.proxy.close()
                self.proxy = None
            if self._temporary is not None:
                self._temporary.cleanup()
                self._temporary = None
            self._cleanup_verified = True
