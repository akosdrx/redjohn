"""Private lifecycle for explicitly selected, content-pinned CLI workers.

Reuses RedJohn's bounded supervisor and attested network namespace. This is
not an agent-facing command runner: callers construct a fixed typed argv.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import signal
import ssl
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary


if TYPE_CHECKING:
    from redjohn.assessment.browser_proxy import BrowserEgressProxy
    from redjohn.assessment.policy import EngagementPolicy


TOOL_VERSIONS = {
    "httpx": "1.12.0",
    "katana": "1.8.0",
    "vulnx": "2.0.2",
    "arjun": "2.2.7",
    "sqlmap": "1.10.10",
    "dalfox": "3.2.4",
    "tinja": "1.2.0",
    "schemathesis": "4.31.1",
}
OUTPUT_LIMIT = 512 * 1024


@dataclass(frozen=True)
class BinaryPin:
    path: Path
    sha256: str
    version: str

    @classmethod
    def from_mapping(cls, tool: str, value: object) -> BinaryPin:
        if (
            not isinstance(value, dict)
            or set(value) != {"path", "sha256", "version"}
            or not all(isinstance(x, str) for x in value.values())
            or not Path(value["path"]).is_absolute()
            or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
            or value["version"] != TOOL_VERSIONS[tool]
        ):
            raise ValueError(f"invalid_{tool}_binary_pin")
        return cls(Path(value["path"]), value["sha256"], value["version"])


class PinnedToolRunner:
    def __init__(self, tool: str, binary: BinaryPin, root: Path) -> None:
        self.tool, self.binary, self.root = tool, binary, root
        self.workspace: Path | None = None
        self.boundary: LinuxEgressBoundary | None = None
        self.process: asyncio.subprocess.Process | None = None
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._token = ""
        self._ca_file: Path | None = None

    def _prepare_payload(self) -> tuple[Path, ...]:
        return (self.binary.path,)

    def _worker_argv(self, argv: list[str]) -> list[str]:
        return argv

    def _tool_environment(self) -> dict[str, str]:
        return {}

    async def prepare(self, policy: EngagementPolicy, proxy: BrowserEgressProxy) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(prefix="job-", dir=self.root)
        self.workspace = Path(self._temporary.name).resolve()
        self.workspace.chmod(0o700)
        # Only public certificates are exported, never the proxy private key.
        https = any(origin.startswith("https://") for origin in policy.allowed_origins)
        certificates = proxy.client_tls_context.get_ca_certs(binary_form=True) if https else []
        pem = "".join(ssl.DER_cert_to_PEM_cert(item) for item in certificates)
        if (https and not pem) or len(pem) > 128 * 1024:
            raise ValueError("pinned_tool_proxy_ca_unavailable")
        self._ca_file = self.workspace / "proxy-ca.pem"
        self._ca_file.write_text(pem)
        self._ca_file.chmod(0o600)
        (self.workspace / "empty-ca-directory").mkdir(mode=0o700)
        payload_paths = self._prepare_payload()
        if policy.egress_mode == "enforced":
            self.boundary = LinuxEgressBoundary(
                proxy.url, self.workspace, read_only_paths=payload_paths
            )
            await self.boundary.start()
            await self.boundary.attest()
        elif policy.egress_mode != "local-fixture" or policy.profile != "isolated-lab":
            raise EgressUnavailable("pinned_tool_kernel_egress_required")

    async def cancel(self) -> None:
        process = self.process
        if process is None:
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 2)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()
        if self.boundary is not None:
            await self.boundary.terminate_workers(process.pid)
        elif self.workspace is not None:
            marker = self.workspace / ".redjohn-hunt" / (self._token + ".child")
            if marker.is_file():
                with contextlib.suppress(OSError, ValueError):
                    os.killpg(int(marker.read_text()), signal.SIGKILL)
        self.process = None

    async def execute(
        self, argv: list[str], timeout: float, *, api_url: str | None = None
    ) -> dict[str, Any]:
        if self.workspace is None or self._ca_file is None or argv[0] != str(self.binary.path):
            raise ValueError("pinned_tool_not_prepared")
        environment = {
            "GOMEMLIMIT": "128MiB",
            "GOMAXPROCS": "1",
            "SSL_CERT_FILE": str(self._ca_file),
            "SSL_CERT_DIR": str(self.workspace / "empty-ca-directory"),
            **self._tool_environment(),
        }
        if api_url is not None:
            if self.tool != "vulnx":
                raise ValueError("api_override_is_vulnx_only")
            environment["VULNX_API_URL"] = api_url
        self._token = uuid.uuid4().hex
        config = {
            "argv": self._worker_argv(argv),
            "token": self._token,
            "digests": {
                str(self.binary.path): self.binary.sha256,
                str(self._ca_file): hashlib.sha256(self._ca_file.read_bytes()).hexdigest(),
            },
            "timeout": timeout,
            "max_output_bytes": OUTPUT_LIMIT,
            "tool_environment": environment,
        }
        if self.tool in {"arjun", "sqlmap", "dalfox", "tinja", "schemathesis"}:
            config["max_file_bytes"] = 1024 * 1024
        source = Path(__file__).parents[1].joinpath("tools/hunt/bounded_worker.py").read_text()
        command = [sys.executable, "-I", "-S", "-c", source, json.dumps(config)]
        if self.boundary is not None:
            command = self.boundary.wrap_argv(command, cwd=self.workspace)
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *command,
                cwd=self.workspace,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(self.workspace),
                    "TMPDIR": str(self.workspace),
                    "LANG": "C.UTF-8",
                    "SSL_CERT_FILE": str(self._ca_file),
                    "SSL_CERT_DIR": str(self.workspace / "empty-ca-directory"),
                },
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        )
        try:
            self.process = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            self.process = await spawn
            await asyncio.shield(self.cancel())
            raise

        async def drain(stream: asyncio.StreamReader | None) -> bytes:
            assert stream is not None
            data = bytearray()
            while chunk := await stream.read(8192):
                if len(data) + len(chunk) > OUTPUT_LIMIT * 12 + 8192:
                    raise ValueError("pinned_tool_supervisor_output_limit")
                data.extend(chunk)
            return bytes(data)

        tasks = [
            asyncio.create_task(drain(stream))
            for stream in (self.process.stdout, self.process.stderr)
        ]
        try:
            async with asyncio.timeout(timeout + 5):
                stdout, _stderr = await asyncio.gather(*tasks)
                await self.process.wait()
            raw = json.loads(stdout)
            if not isinstance(raw, dict):
                raise TypeError("pinned_tool_supervisor_schema_error")
            return raw
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.shield(self.cancel())

    async def healthcheck(self) -> dict[str, str]:
        if self.tool in {"arjun", "sqlmap", "dalfox", "tinja", "schemathesis"}:
            raw = await self.execute([str(self.binary.path), "--version"], 5)
            text = raw.get("stdout", "") + raw.get("stderr", "")
            if (
                raw.get("error")
                or raw.get("exit_code") != 0
                or raw.get("truncated")
                or re.search(r"(?<![\d.])" + re.escape(self.binary.version) + r"(?![\d.])", text)
                is None
            ):
                raise ValueError(f"{self.tool}_binary_or_version_mismatch")
            return {"tool_version": self.binary.version, "binary_sha256": self.binary.sha256}
        flags = (
            ["version", "--disable-update-check"]
            if self.tool == "vulnx"
            else ["-version", "-duc", "-nc"]
        )
        raw = await self.execute([str(self.binary.path), *flags], 5)
        text = raw.get("stdout", "") + raw.get("stderr", "")
        version = re.escape(self.binary.version)
        if (
            raw.get("error")
            or raw.get("exit_code") != 0
            or raw.get("truncated")
            or re.search(
                rf"(?im)\b(?:current\s+)?(?:{self.tool}\s+)?version\s*:?\s*v?{version}(?:\s|$)",
                text,
            )
            is None
        ):
            raise ValueError(f"{self.tool}_binary_or_version_mismatch")
        return {"tool_version": self.binary.version, "binary_sha256": self.binary.sha256}

    async def cleanup(self) -> None:
        await self.cancel()
        if self.boundary is not None:
            await self.boundary.close()
            self.boundary = None
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None
        self.workspace = None
