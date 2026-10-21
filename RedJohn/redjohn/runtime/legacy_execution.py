"""Bounded admission and durable outcome accounting for the SDK bridge.

This is an admission journal, not a second scanner queue. Scanner work remains
in assessment.Scheduler. Raw credentials, shell text and MCP arguments are never
stored here. An interrupted operation is reconciled as unknown, never replayed.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import math
import os
import re
import sqlite3
import time
import uuid
from typing import TYPE_CHECKING, Any, TypeVar

from redjohn.assessment.resources import ResourceAdmissionError, ResourceGovernor


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path

    from redjohn.assessment.browser import BrowserDiscoveryService
    from redjohn.assessment.control import AssessmentControl
    from redjohn.assessment.resources import ResourceLease
    from redjohn.runtime.legacy_shell_boundary import LegacyShellBoundary


T = TypeVar("T")
LEGACY_EXECUTION_CONTEXT_KEY = "legacy_execution"


class LegacyExecution:
    """One scan's bounded SDK operations share its assessment resource envelope."""

    def __init__(
        self,
        path: Path,
        governor: ResourceGovernor,
        *,
        control: AssessmentControl | None = None,
        max_history: int = 1024,
        sandbox_session: Any = None,
        shell_timeout_seconds: float = 600,
        shell_transport: BrowserDiscoveryService | None = None,
    ) -> None:
        if type(max_history) is not int or not 1 <= max_history <= 16384:
            raise ValueError("invalid_legacy_history_limit")
        if (
            isinstance(shell_timeout_seconds, bool)
            or not math.isfinite(shell_timeout_seconds)
            or not 0 < shell_timeout_seconds <= 600
        ):
            raise ValueError("invalid_shell_timeout")
        self.governor, self.control, self.max_history = governor, control, max_history
        self.owner = uuid.uuid4().hex
        self._active: set[asyncio.Task[Any]] = set()
        self._model_leases: dict[str, ResourceLease] = {}
        self._closed = False
        self._closing = False
        self._shell_timeout = shell_timeout_seconds
        self._shell_transport = shell_transport
        self._shell_boundary: LegacyShellBoundary | None = None
        self._mcp_target: Any = None
        self._shell_boundary_lock = asyncio.Lock()
        self._failed_cleanup: dict[str, tuple[ResourceLease, Callable[[], Awaitable[None]]]] = {}
        self._sandbox_session = sandbox_session
        self._shell: dict[int, tuple[str, ResourceLease, asyncio.Task[None]]] = {}
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_fd = os.open(
            path.with_suffix(".legacy.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        self._lock_file = os.fdopen(lock_fd, "a+b")
        try:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._lock_file.close()
            raise ResourceAdmissionError("legacy_coordinator_already_running") from None
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        path.chmod(0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS rj_legacy_execution("
            "id TEXT PRIMARY KEY, owner TEXT NOT NULL, kind TEXT NOT NULL, "
            "label_digest TEXT NOT NULL, started_at REAL NOT NULL, ended_at REAL, "
            "status TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '')"
        )
        # Exclusive ownership proves these belong to a dead prior coordinator.
        # The request/outcome may already have taken effect: do not reissue it.
        self.db.execute(
            "UPDATE rj_legacy_execution SET status='inconclusive', "
            "error_code='coordinator_restart_unknown_outcome', ended_at=? "
            "WHERE status='running'",
            (time.time(),),
        )

    def check_policy(self) -> None:
        if self._closed or self._closing:
            raise ResourceAdmissionError("legacy_execution_closed")
        if self.control is None:
            return
        current = self.control.store.policy(self.control.policy.engagement_id, self.control.caller)
        current.authorize(self.control.caller, self.control.policy.revision)
        if current != self.control.policy or self.control.store.is_stopped(current):
            raise ResourceAdmissionError("legacy_engagement_not_running")
        if current.deadline and time.time() >= current.deadline:
            raise ResourceAdmissionError("legacy_engagement_deadline_exceeded")

    async def run(  # noqa: PLR0912, PLR0915 - single durable cleanup boundary
        self,
        label: str,
        operation: Callable[[], Awaitable[T]],
        *,
        timeout: float = 60,
        cleanup: Callable[[], Awaitable[None]] | None = None,
        estimated_bytes: int = 1024 * 1024,
    ) -> T:
        if isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise ValueError("invalid_legacy_operation_timeout")
        self.check_policy()
        if self.control is not None and self.control.policy.deadline:
            timeout = min(timeout, max(0.001, self.control.policy.deadline - time.time()))
        # This lease is the same pool as scheduler/browser workers, not a per-tool
        # semaphore that can independently exceed the scan's memory reservation.
        lease = self.governor.acquire("worker", estimated_bytes=estimated_bytes)
        operation_id = uuid.uuid4().hex
        task = asyncio.current_task()
        assert task is not None
        try:
            self.db.execute(
                "INSERT INTO rj_legacy_execution VALUES(?,?,?,?,?,NULL,'running','')",
                (
                    operation_id,
                    self.owner,
                    "sdk",
                    hashlib.sha256(label.encode()).hexdigest(),
                    time.time(),
                ),
            )
        except Exception:
            lease.release()
            raise
        self._active.add(task)
        state, code = "succeeded", ""
        try:
            async with asyncio.timeout(timeout):
                value = await operation()
                if isinstance(value, dict) and value.get("success") is False:
                    state, code = "inconclusive", "legacy_tool_failed_outcome"
                return value
        except TimeoutError:
            state, code = "timed_out", "legacy_operation_timeout"
            raise
        except asyncio.CancelledError:
            state, code = "cancelled", "legacy_operation_cancelled"
            raise
        except Exception:
            state, code = "failed", "legacy_operation_failed"
            raise
        finally:
            try:
                if state != "succeeded" and cleanup is not None:
                    try:
                        async with asyncio.timeout(15):
                            await cleanup()
                    except BaseException:
                        state, code = "inconclusive", "legacy_cleanup_failed"
                        self._failed_cleanup[lease.lease_id] = lease, cleanup
                        raise
            finally:
                try:
                    self._finish(operation_id, state, code)
                finally:
                    self._active.discard(task)
                    if lease.lease_id not in self._failed_cleanup:
                        lease.release()

    def _finish(self, operation_id: str, state: str, code: str = "") -> None:
        self.db.execute(
            "UPDATE rj_legacy_execution SET status=?,error_code=?,ended_at=? WHERE id=?",
            (state, code, time.time(), operation_id),
        )
        self.db.execute(
            "DELETE FROM rj_legacy_execution WHERE status!='running' AND id NOT IN "
            "(SELECT id FROM rj_legacy_execution ORDER BY started_at DESC LIMIT ?)",
            (self.max_history,),
        )

    async def shell(  # noqa: PLR0912, PLR0915 - process handle and cleanup ownership stay atomic
        self, name: str, arguments: dict[str, Any], operation: Callable[[], Awaitable[Any]]
    ) -> Any:
        """Retain the worker lease after a yielded SDK process until it terminates.

        This adds lifetime/resource control to the existing SDK sandbox. It does
        not attest a new network boundary or authorize an out-of-scope target.
        The SDK exposes only terminate-all; a deadline stops the scan's complete
        Shell bulkhead rather than leaving a timed-out sibling process alive.
        """
        self.check_policy()
        if self.control is not None:
            await self._ensure_shell_boundary()
            # Lazy boundary attestation can yield while an operator stops or
            # revises the engagement; recheck before the selected command starts.
            self.check_policy()
        terminate = getattr(self._sandbox_session, "pty_terminate_all", None)
        if not callable(terminate):
            raise ResourceAdmissionError("sdk_process_cleanup_unavailable")
        requested = arguments.get("yield_time_ms", 10000)
        arguments["yield_time_ms"] = (
            min(max(requested, 0), 10000) if type(requested) is int else 10000
        )
        if name == "write_stdin":
            process_id = arguments.get("session_id")
            if type(process_id) is not int or process_id not in self._shell:
                raise ResourceAdmissionError("sdk_process_lease_not_found")
            try:
                async with asyncio.timeout(15):
                    result = await operation()
            except BaseException:
                await self._stop_shell("cancelled", "sdk_stdin_interrupted")
                raise
            header = str(result).partition("Output:")[0]
            if "Process running with session ID" not in header:
                self._release_shell(process_id, "succeeded")
            return result
        lease = self.governor.acquire(
            "worker", estimated_bytes=self.governor.envelope.worker_memory_budget
        )
        operation_id = uuid.uuid4().hex
        retained = False
        launched_at = time.monotonic()
        try:
            self.db.execute(
                "INSERT INTO rj_legacy_execution VALUES(?,?,?,?,?,NULL,'running','')",
                (
                    operation_id,
                    self.owner,
                    "shell",
                    hashlib.sha256(name.encode()).hexdigest(),
                    time.time(),
                ),
            )
            async with asyncio.timeout(15):
                result = await operation()
            # Parse only the SDK-owned header. Target stdout must never invent a
            # fake process handle or release a real resource reservation.
            header = str(result).partition("Output:")[0]
            running = re.search(r"^Process running with session ID (\d+)$", header, re.M)
            if running:
                process_id = int(running.group(1))
                watchdog = asyncio.create_task(
                    self._shell_deadline(launched_at), name="redjohn-shell-deadline"
                )
                self._shell[process_id] = operation_id, lease, watchdog
                retained = True
            else:
                self._finish(operation_id, "succeeded" if "code 0" in header else "inconclusive")
        except BaseException:
            try:
                await self._stop_shell("cancelled", "sdk_exec_interrupted")
            except BaseException:
                # The SDK may have spawned a child before yielding its handle.
                # Keep this admission too until terminate-all succeeds; absence
                # of a returned handle does not prove absence of a process.
                retained = True
                self._failed_cleanup[lease.lease_id] = (
                    lease,
                    self._sandbox_session.pty_terminate_all,
                )
                self._finish(operation_id, "inconclusive", "sdk_process_cleanup_failed")
                raise
            else:
                self._finish(operation_id, "inconclusive", "sdk_exec_interrupted")
            raise
        finally:
            if not retained:
                lease.release()
        return result

    async def _shell_deadline(self, launched_at: float) -> None:
        maximum = max(0.0, self._shell_timeout - (time.monotonic() - launched_at))
        if self.control is not None and self.control.policy.deadline:
            maximum = min(maximum, max(0, self.control.policy.deadline - time.time()))
        await asyncio.sleep(maximum)
        await self._stop_shell("timed_out", "sdk_process_deadline_exceeded")

    async def _ensure_shell_boundary(self) -> None:
        from redjohn.assessment.egress import EgressUnavailable  # noqa: PLC0415
        from redjohn.runtime.legacy_shell_boundary import LegacyShellBoundary  # noqa: PLC0415

        async with self._shell_boundary_lock:
            if self._shell_boundary is not None:
                self._shell_boundary.assert_active()
                return
            transport = self._shell_transport
            if transport is None or transport.request_admission is None or self.control is None:
                raise EgressUnavailable("legacy_shell_shared_policy_transport_unavailable")
            boundary = LegacyShellBoundary(
                self._sandbox_session,
                self.control,
                admission=transport.request_admission,
                tls_config=transport.tls_config,
                on_response=transport.on_response,
            )
            self._shell_boundary = boundary
            try:
                await boundary.start()
            except BaseException as start_error:
                try:
                    await boundary.close()
                except BaseException as cleanup_error:
                    # Retain the cleanup owner and its reservation if an
                    # interrupted attestation may still have a child process.
                    # The next call must assert_active(), never run unconfined.
                    raise start_error from cleanup_error
                else:
                    self._shell_boundary = None
                raise

    def bind_mcp_registry(self, registry: Any) -> None:
        """Host-only composition; target calls enqueue into the existing scheduler."""
        if self.control is None or self.control.scheduler is None:
            return
        from redjohn.runtime.mcp_target import McpTargetAdapter, _target_config  # noqa: PLC0415

        if any(_target_config(registry.get(name).config) for name in registry.names()):
            self._mcp_target = McpTargetAdapter(self, registry)

    def _release_shell(self, process_id: int, state: str, code: str = "") -> None:
        if (owned := self._shell.pop(process_id, None)) is None:
            return
        operation_id, lease, watchdog = owned
        if watchdog is not asyncio.current_task():
            watchdog.cancel()
        try:
            self._finish(operation_id, state, code)
        finally:
            lease.release()

    async def _stop_shell(self, state: str, code: str) -> None:
        try:
            async with asyncio.timeout(15):
                await self._sandbox_session.pty_terminate_all()
        except BaseException:
            # Retain leases if termination was not proved; another admission must
            # not treat an unconfirmed cleanup as freed memory.
            for operation_id, _lease, _watchdog in self._shell.values():
                self._finish(operation_id, "inconclusive", "sdk_process_cleanup_failed")
            raise
        for process_id in list(self._shell):
            self._release_shell(process_id, state, code)

    def model_start(self, agent_id: str) -> None:
        self.model_end(agent_id)
        self.check_policy()
        self._model_leases[agent_id] = self.governor.acquire(
            "worker", estimated_bytes=1024 * 1024, owner_process_only=True
        )

    def model_end(self, agent_id: str) -> None:
        if (lease := self._model_leases.pop(agent_id, None)) is not None:
            lease.release()

    async def close(self) -> None:
        if self._closed:
            return
        self._closing = True
        current = asyncio.current_task()
        tasks = [task for task in self._active if task is not current]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self._mcp_target is not None:
            await self._mcp_target.close()
            self._mcp_target = None
        if self._shell:
            await self._stop_shell("cancelled", "sdk_run_closed")
        if self._shell_boundary is not None:
            await self._shell_boundary.close()
            self._shell_boundary = None
        for lease_id, (lease, cleanup) in list(self._failed_cleanup.items()):
            async with asyncio.timeout(15):
                await cleanup()
            lease.release()
            self._failed_cleanup.pop(lease_id)
        for agent_id in list(self._model_leases):
            self.model_end(agent_id)
        self.db.close()
        fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
        self._lock_file.close()
        self._closed = True


def legacy_from_context(context: object) -> LegacyExecution | None:
    value = context.get(LEGACY_EXECUTION_CONTEXT_KEY) if isinstance(context, dict) else None
    return value if isinstance(value, LegacyExecution) else None
