"""One fixed, owned, deadline-bounded immutable Trivy input preparer.

Unknown process delivery, unreaped children and uncertain path cleanup quarantine
this component. Only the shared scheduler can retain/release its EXISTING lease.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import os
import re
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.os_memory import _current_owner_guard, current_memory_fence
from redjohn.assessment.resources import ResourceAdmissionError
from redjohn.assessment.trivy_database import DatabaseSnapshot, bounded_document


if TYPE_CHECKING:
    from redjohn.assessment.trivy_sbom import TrivySBOMConfig


class TrivyCopyUnavailable(ResourceAdmissionError):  # noqa: N818 - admission protocol
    code = "blocked_trivy_copy_owner_unavailable"


class TrivyCopyCleanupUnverified(ResourceAdmissionError):  # noqa: N818 - retention protocol
    code = "blocked_trivy_copy_cleanup_unverified"
    requires_lease_retention = True

    def __init__(
        self,
        process: asyncio.subprocess.Process | None,
        fence: tuple[str, int],
        proof: dict[str, Any],
        pending_spawn: asyncio.Task[asyncio.subprocess.Process] | None = None,
    ) -> None:
        self.process, self.fence = process, fence
        self.pending_spawn, self.partial_proof = pending_spawn, dict(proof)
        super().__init__("trivy_copy_owned_resources_not_reconciled")


def _owner_fence() -> tuple[str, int]:
    fence = current_memory_fence()
    if fence is None:
        raise TrivyCopyUnavailable("trivy_copy_attested_current_owner_required")
    _current_owner_guard(Path(fence[0]))
    return fence


class OwnedDatabaseCopier:
    def __init__(self, *, timeout_seconds: float = 30) -> None:
        if (
            type(timeout_seconds) not in {int, float}
            or not math.isfinite(timeout_seconds)
            or not 0.05 <= timeout_seconds <= 30
        ):
            raise ValueError("trivy_copy_deadline_required")
        self.timeout_seconds = timeout_seconds
        self.process: asyncio.subprocess.Process | None = None
        self.fence: tuple[str, int] | None = None
        self.destination: Path | None = None
        self.nonce = ""
        self.proof: dict[str, Any] = {
            "cleanup_verified": True,
            "reservation_retention_wired": False,
        }
        self.cleanup_unverified = False
        self._pending_spawn: asyncio.Task[asyncio.subprocess.Process] | None = None
        self._drains: list[asyncio.Task[bytes]] = []
        self._operation_task: asyncio.Task[dict[str, Any]] | None = None
        self._cleanup_task: asyncio.Task[None] | None = None
        self._late_reaper: asyncio.Task[None] | None = None
        self._late_callback_for: asyncio.Task[asyncio.subprocess.Process] | None = None
        self._generation = 0
        self._admission = asyncio.Lock()
        self._stop_lock = asyncio.Lock()

    def resource_cleanup_verified(self) -> bool:
        return (
            self.process is None
            and self._pending_spawn is None
            and not self._drains
            and self.destination is None
            and not self.cleanup_unverified
            and (self._operation_task is None or self._operation_task.done())
            and (self._cleanup_task is None or self._cleanup_task.done())
            and (self._late_reaper is None or self._late_reaper.done())
        )

    @property
    def requires_lease_retention(self) -> bool:
        return not self.resource_cleanup_verified()

    def _command(self, payload: dict[str, Any]) -> list[str]:
        # The installation root is trusted host code, never an operator option.
        root = str(Path(__file__).parents[2])
        bootstrap = (
            f"import sys;sys.path.insert(0,{root!r});"
            "from redjohn.assessment._trivy_database_copy_worker import main;"
            "raise SystemExit(main())"
        )
        encoded = json.dumps(payload, separators=(",", ":"))
        if len(encoded.encode()) > 32768:
            raise ValueError("trivy_copy_configuration_byte_limit")
        return [sys.executable, "-I", "-S", "-c", bootstrap, encoded]

    @staticmethod
    async def _drain(reader: asyncio.StreamReader | None, limit: int) -> bytes:
        assert reader is not None
        value = bytearray()
        while chunk := await reader.read(4096):
            if len(value) + len(chunk) > limit:
                raise ValueError("trivy_copy_output_byte_limit")
            value.extend(chunk)
        return bytes(value)

    def _adopt(self, process: asyncio.subprocess.Process) -> None:
        self.process, self._pending_spawn = process, None
        self.proof["pid"] = process.pid
        self._drains = [
            asyncio.create_task(self._drain(process.stdout, 192 * 1024)),
            asyncio.create_task(self._drain(process.stderr, 4096)),
        ]

    async def _execute(
        self, operation: str, configuration: dict[str, Any], seconds: float, *, ca_pem: str = ""
    ) -> dict[str, Any]:
        assert self.fence is not None and self.destination is not None
        if self.process is not None or self._pending_spawn is not None:
            self._quarantine("previous_process_not_reconciled")
        payload = {
            "operation": operation,
            "configuration": configuration,
            "destination": str(self.destination),
            "nonce": self.nonce,
            "ca_pem": ca_pem,
            "fence_path": self.fence[0],
            "fence_inode": self.fence[1],
            "uid": os.getuid(),
            "parent": os.getpid(),
        }
        deadline = asyncio.get_running_loop().time() + seconds
        self._generation += 1
        # Record pending ownership BEFORE the first await, including Process delivery.
        self._pending_spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *self._command(payload),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                start_new_session=True,
            )
        )
        async with asyncio.timeout_at(deadline):
            self._adopt(await asyncio.shield(self._pending_spawn))
            assert self.process is not None
            output, _diagnostic = await asyncio.gather(*self._drains)
            await self.process.wait()
        if self.process.returncode != 0:
            raise TrivyCopyUnavailable("trivy_copy_fixed_helper_failed")
        return bounded_document(output, 192 * 1024)

    def _quarantine(self, cause: str) -> None:
        self.cleanup_unverified = True
        self.proof.update(
            cleanup_verified=False,
            quarantined=True,
            cause=cause,
            requires_existing_scheduler_lease_retention=True,
        )
        assert self.fence is not None
        raise TrivyCopyCleanupUnverified(self.process, self.fence, self.proof, self._pending_spawn)

    async def _reaped(self, seconds: float) -> bool:
        assert self.process is not None
        try:
            await asyncio.wait_for(asyncio.shield(self.process.wait()), seconds)
        except TimeoutError:
            return False
        return True

    def _schedule_late_reap(self, pending: asyncio.Task[asyncio.subprocess.Process]) -> None:
        if self._late_callback_for is pending:
            return
        self._late_callback_for = pending

        def delivered(_task: asyncio.Task[asyncio.subprocess.Process]) -> None:
            self._late_reaper = asyncio.create_task(self._late_stop(pending))

        pending.add_done_callback(delivered)

    async def _late_stop(self, pending: asyncio.Task[asyncio.subprocess.Process]) -> None:
        # Ownership/proof remains attached; no lease or path is released here.
        with contextlib.suppress(TrivyCopyCleanupUnverified):
            await self._stop_owned(expected_pending=pending)

    async def _stop_owned(
        self,
        *,
        expected_pending: asyncio.Task[asyncio.subprocess.Process] | None = None,
        expected_generation: int | None = None,
    ) -> None:
        async with self._stop_lock:
            if expected_generation is not None and self._generation != expected_generation:
                return
            if expected_pending is not None and self._pending_spawn is not expected_pending:
                return
            if self._pending_spawn is not None:
                pending = self._pending_spawn
                try:
                    delivered_process = await asyncio.wait_for(asyncio.shield(pending), 0.25)
                except TimeoutError:
                    self._schedule_late_reap(pending)
                    self._quarantine("process_delivery_unverified")
                except asyncio.CancelledError:
                    self._schedule_late_reap(pending)
                    self._quarantine("process_delivery_cancelled")
                except (OSError, ValueError):
                    self._pending_spawn = None
                else:
                    self._adopt(delivered_process)
            process = self.process
            if process is not None:
                if process.returncode is None:
                    with contextlib.suppress(OSError):
                        os.killpg(process.pid, signal.SIGTERM)
                    if not await self._reaped(0.25):
                        with contextlib.suppress(OSError):
                            os.killpg(process.pid, signal.SIGKILL)
                        if not await self._reaped(1):
                            self._quarantine("process_reap_unverified")
                for task in self._drains:
                    task.cancel()
                await asyncio.gather(*self._drains, return_exceptions=True)
                self._drains = []
                self.process = None
            self.proof["process_cleanup_verified"] = True

    @staticmethod
    async def _join(task: asyncio.Task[Any]) -> Any:
        while True:
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                if task.done():
                    return task.result()

    async def _remove_owned_paths(self) -> None:
        await self._stop_owned()
        if self.destination is None:
            return
        try:
            result = await self._execute("cleanup", {}, 5)
        except (OSError, ValueError, TimeoutError, TrivyCopyUnavailable):
            self._quarantine("private_path_cleanup_unverified")
        finally:
            await self._stop_owned()
        if result != {"cleaned": True, "nonce": self.nonce}:
            self._quarantine("private_path_cleanup_unbound")
        self.destination = None
        self.cleanup_unverified = False
        self.proof.update(cleanup_verified=True, quarantined=False)

    def _validate_report(
        self, value: dict[str, Any], operation: str, revision: str, database: DatabaseSnapshot
    ) -> None:
        if (
            set(value)
            != {
                "prepared",
                "operation",
                "configuration_revision",
                "database_bytes",
                "database_sha256",
                "metadata_sha256",
                "provenance_sha256",
                "data_sources",
                "valid_until",
                "packages",
                "artifact_sha256",
                "engine_bytes",
            }
            or value["prepared"] is not True
            or value["operation"] != operation
            or value["configuration_revision"] != revision
            or type(value["database_bytes"]) is not int
            or value["database_bytes"] != database.database_bytes
            or value["database_sha256"] != database.database_sha256
            or value["metadata_sha256"] != database.metadata_sha256
            or value["provenance_sha256"] != database.provenance_sha256
            or not isinstance(value["data_sources"], list)
            or not 1 <= len(value["data_sources"]) <= 16
            or any(
                not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", name) is None
                for name in value["data_sources"]
            )
            or len(set(value["data_sources"])) != len(value["data_sources"])
            or type(value["valid_until"]) not in {int, float}
            or not math.isfinite(value["valid_until"])
            or not time.time() < value["valid_until"] <= time.time() + 7 * 86400 + 300
            or not isinstance(value["packages"], list)
            or len(value["packages"]) > 128
            or type(value["engine_bytes"]) is not int
            or not 0 <= value["engine_bytes"] <= 256 * 1024**2
        ):
            raise TrivyCopyUnavailable("trivy_copy_unbound_prepare_report")

    async def _prepare(
        self,
        operation: str,
        configuration: dict[str, Any],
        revision: str,
        database: DatabaseSnapshot,
        ca_pem: str,
    ) -> dict[str, Any]:
        started = time.monotonic()
        prepared = False
        try:
            value = await self._execute(
                operation, configuration, self.timeout_seconds, ca_pem=ca_pem
            )
            self._validate_report(value, operation, revision, database)
            self.proof.update(prepared=True, valid_until=value["valid_until"])
            prepared = True
            return value
        finally:
            try:
                await self._stop_owned()
                if not prepared:
                    await self._remove_owned_paths()
            finally:
                self.proof["duration_seconds"] = time.monotonic() - started

    async def _admit(
        self,
        operation: str,
        configuration: dict[str, Any],
        revision: str,
        database: DatabaseSnapshot,
        destination: Path,
        ca_pem: str = "",
    ) -> dict[str, Any]:
        async with self._admission:
            if not self.resource_cleanup_verified():
                raise TrivyCopyUnavailable("trivy_copy_previous_resources_not_reconciled")
            self.fence = _owner_fence()
            self.destination, self.nonce = destination, uuid.uuid4().hex
            self.proof = {
                "cleanup_verified": False,
                "reservation_retention_wired": False,
                "owner_fence": self.fence,
                "deadline_seconds": self.timeout_seconds,
                "database_sha256": database.database_sha256,
                "database_bytes": database.database_bytes,
            }
            task = asyncio.create_task(
                self._prepare(operation, configuration, revision, database, ca_pem)
            )
            self._operation_task = task
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if not task.done() and not task.cancelling():
                task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._join(task)
            await self.cleanup()
            raise

    async def snapshot(self, config: DatabaseSnapshot, destination: Path) -> tuple[str, ...]:
        config.validate()  # Pure structural validation; no operator IO.
        value = await self._admit(
            "database", config.to_dict(), config.revision, config, destination
        )
        return tuple(value["data_sources"])

    async def prepare(
        self, config: TrivySBOMConfig, destination: Path, ca_pem: bytes
    ) -> dict[str, Any]:
        return await self._admit(
            "sbom",
            config.to_dict(),
            config.revision,
            config.database,
            destination,
            ca_pem.decode("ascii"),
        )

    async def stop(self) -> None:
        if self._cleanup_task is not None and not self._cleanup_task.done():
            await self._join(self._cleanup_task)
            return
        task = asyncio.create_task(self._stop_owned(expected_generation=self._generation))
        await self._join(task)

    async def cleanup(self) -> None:
        operation = self._operation_task
        if operation is not None and not operation.done():
            if not operation.cancelling():
                operation.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._join(operation)
        async with self._admission:
            if self._cleanup_task is None or self._cleanup_task.done():
                self._cleanup_task = asyncio.create_task(self._remove_owned_paths())
            task = self._cleanup_task
        await self._join(task)

    async def cancel(self) -> None:
        operation = self._operation_task
        if operation is not None and not operation.done():
            if not operation.cancelling():
                operation.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._join(operation)
        await self.stop()
