"""Internal subprocess ownership; callers still construct fixed reviewed commands.

No policy, command dispatch, environment inheritance or agent-facing API lives
here. Pending launch handles are owned resources, even before a PID is known.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import os
import signal
from typing import TYPE_CHECKING, Any

from redjohn.assessment.resources import ResourceAdmissionError


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path


class OwnedProcessCleanupUnverified(ResourceAdmissionError):  # noqa: N818 - ownership protocol
    code = "blocked_owned_process_cleanup_unverified"
    requires_lease_retention = True

    def __init__(self, owner: OwnedProcess, cause: str) -> None:
        self.owner = owner
        self.process, self.pending_spawn = owner.process, owner.pending
        self.partial_proof = {**owner.proof, "cleanup_verified": False, "cause": cause}
        super().__init__(cause)


class OwnedProcess:
    def __init__(self) -> None:
        self.process: asyncio.subprocess.Process | None = None
        self.pending: asyncio.Task[asyncio.subprocess.Process] | None = None
        self.drains: list[asyncio.Task[bytes]] = []
        self.cleanup_unverified = False
        self.proof: dict[str, Any] = {"cleanup_verified": True, "forced_kill": False}
        self._active = False
        self._generation = 0
        self._limits = (4096, 4096)
        self._run_lock, self._stop_lock = asyncio.Lock(), asyncio.Lock()
        self._late_for: asyncio.Task[asyncio.subprocess.Process] | None = None
        self._late_reaper: asyncio.Task[None] | None = None

    def resource_cleanup_verified(self) -> bool:
        return (
            self.process is None
            and self.pending is None
            and not self.drains
            and not self._active
            and not self.cleanup_unverified
            and (self._late_reaper is None or self._late_reaper.done())
        )

    def quarantine(self, cause: str) -> None:
        self.cleanup_unverified = True
        self.proof.update(cleanup_verified=False, quarantined=True)
        raise OwnedProcessCleanupUnverified(self, cause)

    @staticmethod
    async def join(task: asyncio.Task[Any]) -> Any:
        while True:
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                if task.done():
                    return task.result()

    @staticmethod
    async def _drain(stream: asyncio.StreamReader | None, maximum: int) -> bytes:
        assert stream is not None
        result = bytearray()
        while chunk := await stream.read(8192):
            if len(result) + len(chunk) > maximum:
                raise ValueError("owned_process_output_limit")
            result.extend(chunk)
        return bytes(result)

    def _adopt(self, process: asyncio.subprocess.Process) -> None:
        self.process, self.pending = process, None
        self.proof["pid"] = process.pid
        self.drains = [
            asyncio.create_task(self._drain(stream, maximum))
            for stream, maximum in zip((process.stdout, process.stderr), self._limits, strict=True)
        ]

    def _late(self, pending: asyncio.Task[asyncio.subprocess.Process]) -> None:
        if self._late_for is pending:
            return
        self._late_for = pending

        def delivered(_task: asyncio.Task[asyncio.subprocess.Process]) -> None:
            self._late_reaper = asyncio.create_task(self._late_stop(pending))

        pending.add_done_callback(delivered)

    async def _late_stop(self, pending: asyncio.Task[asyncio.subprocess.Process]) -> None:
        with contextlib.suppress(OwnedProcessCleanupUnverified):
            await self._stop(expected_pending=pending)

    async def _reaped(self, seconds: float) -> bool:
        assert self.process is not None
        try:
            await asyncio.wait_for(asyncio.shield(self.process.wait()), seconds)
        except TimeoutError:
            return False
        return True

    async def _stop(
        self,
        *,
        expected_generation: int | None = None,
        expected_pending: asyncio.Task[asyncio.subprocess.Process] | None = None,
    ) -> None:
        async with self._stop_lock:
            if expected_generation is not None and self._generation != expected_generation:
                return
            if expected_pending is not None and self.pending is not expected_pending:
                return
            if self.pending is not None:
                pending = self.pending
                try:
                    delivered = await asyncio.wait_for(asyncio.shield(pending), 0.25)
                except TimeoutError:
                    self._late(pending)
                    self.quarantine("owned_process_delivery_unverified")
                except asyncio.CancelledError:
                    self._late(pending)
                    self.quarantine("owned_process_delivery_cancelled")
                except (OSError, ValueError):
                    self.pending = None
                else:
                    self._adopt(delivered)
            process = self.process
            if process is not None:
                if process.returncode is None:
                    with contextlib.suppress(OSError):
                        os.killpg(process.pid, signal.SIGTERM)
                    if not await self._reaped(2):
                        self.proof["forced_kill"] = True
                        with contextlib.suppress(OSError):
                            os.killpg(process.pid, signal.SIGKILL)
                        if not await self._reaped(1):
                            self.quarantine("owned_process_reap_unverified")
                for task in self.drains:
                    task.cancel()
                await asyncio.gather(*self.drains, return_exceptions=True)
                self.drains = []
                self.process = None
            self.cleanup_unverified = False
            self.proof.update(cleanup_verified=True, quarantined=False)

    async def stop(self) -> None:
        await self.join(asyncio.create_task(self._stop(expected_generation=self._generation)))

    async def run(
        self,
        command: Sequence[str],
        *,
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        stdout_limit: int = 4096,
        stderr_limit: int = 4096,
    ) -> tuple[bytes, bytes, int]:
        if (
            type(timeout) not in {float, int}
            or not math.isfinite(timeout)
            or not 0 < timeout <= 605
            or any(
                type(limit) is not int or not 1 <= limit <= 8 * 1024**2
                for limit in (stdout_limit, stderr_limit)
            )
        ):
            raise ValueError("owned_process_finite_bounds_required")
        if self._run_lock.locked():
            raise ResourceAdmissionError("owned_process_already_running")
        async with self._run_lock:
            if not self.resource_cleanup_verified():
                self.quarantine("owned_process_previous_ownership_unresolved")
            self._active = True
            self._generation += 1
            self._limits = stdout_limit, stderr_limit
            self.proof = {
                "cleanup_verified": False,
                "forced_kill": False,
                "deadline_seconds": timeout,
            }
            deadline = asyncio.get_running_loop().time() + timeout
            try:
                self.pending = asyncio.create_task(
                    asyncio.create_subprocess_exec(
                        *command,
                        cwd=cwd,
                        env=env,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        start_new_session=True,
                    )
                )
                async with asyncio.timeout_at(deadline):
                    self._adopt(await asyncio.shield(self.pending))
                    assert self.process is not None
                    stdout, stderr = await asyncio.gather(*self.drains)
                    code = await self.process.wait()
                return stdout, stderr, code
            finally:
                try:
                    await self.stop()
                finally:
                    self._active = False
