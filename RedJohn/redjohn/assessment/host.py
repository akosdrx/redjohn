"""Host-owned lifecycle for the existing assessment scheduler and control API.

There is no second job queue: the bounded pump only claims the same durable
SQLite jobs used by ``assess run``. Model calls never start workers directly.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Self

from redjohn.assessment.configuration import ConfiguredAssessment
from redjohn.assessment.os_memory import LinuxMemoryBoundary, MemoryLimitUnavailableError
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.report import build_report, write_report
from redjohn.assessment.resources import ResourceAdmissionError
from redjohn.assessment.store import CapacityExceeded


if TYPE_CHECKING:
    from pathlib import Path

    from redjohn.assessment.control import AssessmentControl
    from redjohn.assessment.policy import EngagementPolicy


@dataclass(frozen=True)
class HostControllerLimits:
    max_jobs: int = 128
    max_seconds: float = 3600
    shutdown_seconds: float = 15

    def __post_init__(self) -> None:
        if type(self.max_jobs) is not int or not 1 <= self.max_jobs <= 4096:
            raise ValueError("invalid_host_job_budget")
        for value, maximum in ((self.max_seconds, 3600), (self.shutdown_seconds, 30)):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0.1 <= value <= maximum
            ):
                raise ValueError("invalid_host_time_budget")


class HostAssessment:
    """One host-bound API and one bounded pump for one approved engagement."""

    def __init__(
        self,
        config: dict[str, Any],
        output: Path,
        *,
        caller: str,
        limits: HostControllerLimits | None = None,
    ) -> None:
        self.configured = ConfiguredAssessment(config, output, caller=caller)
        self.limits = limits or HostControllerLimits(
            max_jobs=min(128, self.configured.envelope.queue_max_items)
        )
        self._state = "configured"
        self._stop_reason = ""
        self._completed = 0
        self._contention = 0
        self._deadline = 0.0
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._boundary: LinuxMemoryBoundary | None = None
        self._opened = False
        self._closed = False

    @property
    def control(self) -> AssessmentControl:
        return self.configured.runtime.control

    def status(self) -> dict[str, Any]:
        return {
            "mode": "host_bound_persistent_scheduler",
            "state": self._state,
            "stop_reason": self._stop_reason,
            "completed_attempts": self._completed,
            "max_jobs": self.limits.max_jobs,
            "remaining_seconds": round(max(0, self._deadline - time.monotonic()), 3),
            "coordinator_contention": self._contention,
        }

    def _admit_submission(self) -> None:
        if self._opened and time.monotonic() >= self._deadline:
            self._state = self._stop_reason = "deadline_exhausted"
            self._stop.set()
        if (
            self._closed
            or self._stop.is_set()
            or self._state not in {"running", "waiting", "waiting_for_coordinator"}
        ):
            raise ResourceAdmissionError("host_controller_not_running")

    def _audit(self) -> None:
        with self.configured.store.transaction() as db:
            self.configured.store._audit(
                db, self.configured.policy.engagement_id, "host_controller", self.status()
            )

    def _admit_policy(self, current: EngagementPolicy) -> None:
        if current != self.configured.policy:
            raise PolicyDenied("assessment_reapproval_required")

    @staticmethod
    def _close_control(service: AssessmentControl) -> None:
        service.close()
        service.runtime_status = None
        service.submission_admission = None
        service.policy_admission = None

    def _policy_stop_reason(self) -> str:
        policy = self.configured.policy
        current = self.configured.store.policy(policy.engagement_id, self.configured.caller)
        if current != policy:
            return "policy_changed"
        return "engagement_cancelled" if self.configured.store.is_stopped(policy) else ""

    async def __aenter__(self) -> Self:
        if self._opened or self._closed:
            raise RuntimeError("host_assessment_already_used")
        if "os_memory" in self.configured.config:
            self._boundary = LinuxMemoryBoundary.current(
                self.configured.config["os_memory"],
                self.configured.envelope.total_memory_budget,
            )
            if self._boundary is None:
                raise MemoryLimitUnavailableError("inline_controller_requires_precontained_process")
            self._boundary.__enter__()
        try:
            await self.configured.__aenter__()
            self._opened = True
            self.control.runtime_status = self.status
            self.control.submission_admission = self._admit_submission
            self.control.policy_admission = self._admit_policy
            self._deadline = time.monotonic() + self.limits.max_seconds
            if self.configured.policy.deadline:
                self._deadline = min(
                    self._deadline,
                    time.monotonic() + max(0, self.configured.policy.deadline - time.time()),
                )
            self._state = "running"
            self._audit()
            self._task = asyncio.create_task(self._pump(), name="redjohn-assessment-scheduler")
        except BaseException:
            service = self.control if self._opened else None
            try:
                if self._opened:
                    await self.configured.close()
            finally:
                if service is not None:
                    self._close_control(service)
                self._opened, self._closed = False, True
                self._state, self._stop_reason = "failed", "startup_failed"
                self._stop.set()
                if self._boundary is not None:
                    self._boundary.__exit__(None, None, None)
            raise
        return self

    async def _pump(self) -> None:
        try:
            while not self._stop.is_set() and self._completed < self.limits.max_jobs:
                remaining = self._deadline - time.monotonic()
                if remaining <= 0:
                    self._state = "deadline_exhausted"
                    return
                if reason := self._policy_stop_reason():
                    self._state = reason
                    return
                self._state = "running"
                try:
                    finished = await asyncio.wait_for(
                        self.configured.runtime.scheduler.run_batch(max_jobs=1), remaining
                    )
                except CapacityExceeded as exc:
                    if str(exc) != "coordinator_already_running":
                        raise
                    self._contention += 1
                    self._state = "waiting_for_coordinator"
                    finished = []
                except TimeoutError:
                    self._state = "deadline_exhausted"
                    return
                self._completed += len(finished)
                if not finished:
                    if self._state != "waiting_for_coordinator":
                        self._state = "waiting"
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(self._stop.wait(), min(0.25, remaining))
            if self._state != "deadline_exhausted":
                self._state = (
                    "job_budget_exhausted" if self._completed >= self.limits.max_jobs else "stopped"
                )
        except asyncio.CancelledError:
            self._state = "cancelled"
            raise
        except Exception:
            self._state = "failed"
            raise
        finally:
            self._stop_reason = self._state
            self._audit()

    async def close(self, *, cancel_running: bool = False) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        try:
            if self._task is not None:
                if cancel_running:
                    self._task.cancel()
                _, pending = await asyncio.wait({self._task}, timeout=self.limits.shutdown_seconds)
                if pending:
                    self._task.cancel()
                results = await asyncio.wait_for(
                    asyncio.gather(self._task, return_exceptions=True),
                    self.limits.shutdown_seconds,
                )
                if any(
                    isinstance(result, BaseException)
                    and not isinstance(result, asyncio.CancelledError)
                    for result in results
                ):
                    raise ResourceAdmissionError("host_scheduler_failed")
            if self._opened:
                runtime = self.configured.runtime
                metrics = self.configured.metrics(os_boundary=self._boundary)
                metrics["controller"] = self.status()
                write_report(
                    self.configured.output,
                    build_report(
                        self.configured.store,
                        self.configured.policy.engagement_id,
                        metrics=metrics,
                        registry=runtime.registry,
                    ),
                )
        finally:
            try:
                if self._opened:
                    service = self.control
                    try:
                        await self.configured.close()
                    finally:
                        self._close_control(service)
            finally:
                self._opened = False
                if self._boundary is not None:
                    self._boundary.__exit__(None, None, None)
                self._state = "closed"

    async def __aexit__(self, *_args: object) -> None:
        await self.close(cancel_running=bool(_args and _args[0] is not None))
