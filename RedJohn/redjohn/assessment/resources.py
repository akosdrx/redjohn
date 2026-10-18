"""Shared admission control for RedJohn workers and model context.

RSS is measured for the controller's process tree. Summed RSS may count shared
pages more than once; it is deliberately labelled, never presented as heap size.
Admission is cooperative: OS/container hard limits remain a separate backstop.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Self


if TYPE_CHECKING:
    from collections.abc import Callable

    from redjohn.assessment.host_resources import HostResourcePool


MIB = 1024 * 1024


@dataclass(frozen=True)
class ResourceEnvelope:
    total_memory_budget: int = 1024 * MIB
    worker_memory_budget: int = 256 * MIB
    browser_concurrency: int = 1
    cache_max_bytes: int = 32 * MIB
    queue_max_items: int = 128
    artifact_max_bytes: int = 4 * MIB
    max_model_input_tokens: int = 32768
    max_workers: int = 2
    max_pages: int = 2
    max_contexts: int = 2
    soft_watermark: float = 0.80
    high_watermark: float = 0.90
    resume_watermark: float = 0.65

    def __post_init__(self) -> None:
        for name in (
            "total_memory_budget",
            "worker_memory_budget",
            "browser_concurrency",
            "cache_max_bytes",
            "queue_max_items",
            "artifact_max_bytes",
            "max_model_input_tokens",
            "max_workers",
            "max_pages",
            "max_contexts",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.worker_memory_budget > self.total_memory_budget:
            raise ValueError("worker memory exceeds total memory budget")
        if self.cache_max_bytes >= self.total_memory_budget:
            raise ValueError("cache quota must leave room for workers")
        if not 0 < self.resume_watermark < self.soft_watermark < self.high_watermark < 1:
            raise ValueError("watermarks must satisfy 0 < resume < soft < high < 1")


@dataclass(frozen=True)
class ProcessTreeMemory:
    root_pid: int
    rss_bytes: int
    process_count: int
    measured_at: float
    method: str = "process_tree_summed_rss_shared_pages_may_be_counted_multiple_times"
    cgroup_current_bytes: int | None = None
    available: bool = True
    cgroup_inactive_file_bytes: int | None = None

    @property
    def admission_bytes(self) -> int:
        """Conservative resident/working-set pressure, retaining raw telemetry.

        Cgroup current includes reclaimable filesystem cache left by downloads
        and previous jobs. Subtract only the kernel's inactive_file counter;
        active cache and other kernel charges still count. Summed process RSS
        remains a floor, so mapped worker memory cannot disappear from admission.
        Missing memory.stat fails conservatively to the full current charge.
        """
        if self.cgroup_current_bytes is None:
            return self.rss_bytes
        inactive = self.cgroup_inactive_file_bytes or 0
        return max(self.rss_bytes, self.cgroup_current_bytes - max(0, inactive))


def process_tree_memory(pid: int | None = None) -> ProcessTreeMemory:
    """Read the actual process tree on Linux/macOS without a psutil dependency."""
    root = os.getpid() if pid is None else pid
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,ppid=,rss="],
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        )
        rows = [tuple(map(int, line.split())) for line in result.stdout.splitlines()]
    except (OSError, ValueError, subprocess.SubprocessError):
        return ProcessTreeMemory(root, 0, 0, time.time(), available=False)
    children: dict[int, list[int]] = {}
    sizes: dict[int, int] = {}
    for child, parent, rss in rows:
        children.setdefault(parent, []).append(child)
        sizes[child] = rss * 1024
    pending, found = [root], set()
    while pending:
        current = pending.pop()
        if current not in found and current in sizes:
            found.add(current)
            pending.extend(children.get(current, ()))
    cgroup_current = None
    cgroup_inactive_file = None
    # Only use the controller's own cgroup, never a system-wide root cgroup value.
    if root == os.getpid():
        try:
            for entry in Path("/proc/self/cgroup").read_text().splitlines():
                if entry.startswith("0::"):
                    relative = entry.partition("0::")[2].lstrip("/")
                    if not relative:
                        break  # A system-wide root charge is not this process tree.
                    group = Path("/sys/fs/cgroup") / relative
                    cgroup_current = int((group / "memory.current").read_text().strip())
                    counters = dict(
                        line.split() for line in (group / "memory.stat").read_text().splitlines()
                    )
                    cgroup_inactive_file = int(counters["inactive_file"])
                    break
        except (OSError, ValueError, KeyError):
            pass
    return ProcessTreeMemory(
        root,
        sum(sizes[item] for item in found),
        len(found),
        time.time(),
        cgroup_current_bytes=cgroup_current,
        available=bool(found),
        cgroup_inactive_file_bytes=cgroup_inactive_file,
    )


def process_forest_memory(roots: set[int]) -> ProcessTreeMemory:
    """Measure distinct processes once even when controller trees overlap."""
    try:
        output = subprocess.run(
            ["/bin/ps", "-axo", "pid=,ppid=,rss="],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        rows = [tuple(map(int, line.split())) for line in output.stdout.splitlines()]
    except (OSError, ValueError, subprocess.SubprocessError):
        return ProcessTreeMemory(0, 0, 0, time.time(), available=False)
    children: dict[int, list[int]] = {}
    sizes: dict[int, int] = {}
    for pid, parent, rss in rows:
        children.setdefault(parent, []).append(pid)
        sizes[pid] = rss * 1024
    found: set[int] = set()
    pending = list(roots)
    while pending:
        pid = pending.pop()
        if pid in sizes and pid not in found:
            found.add(pid)
            pending.extend(children.get(pid, ()))
    return ProcessTreeMemory(
        0,
        sum(sizes[pid] for pid in found),
        len(found),
        time.time(),
        method="deduplicated_process_forest_summed_rss_shared_pages_may_be_counted_multiple_times",
        available=roots <= found,
    )


class ResourceAdmissionError(RuntimeError):
    code = "resource_admission_denied"


@dataclass
class ResourceLease:
    governor: ResourceGovernor = field(repr=False)
    lease_id: str
    kind: str
    estimated_bytes: int
    released: bool = False

    def release(self) -> None:
        self.governor.release(self)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


class ResourceGovernor:
    """One writer owns worker/page/context capacity and pressure hysteresis."""

    def __init__(
        self,
        envelope: ResourceEnvelope | None = None,
        *,
        memory_reader: Callable[[], ProcessTreeMemory] = process_tree_memory,
        host_pool: HostResourcePool | None = None,
    ) -> None:
        self.envelope = envelope or ResourceEnvelope()
        self._memory_reader = memory_reader
        self._host_pool = host_pool
        self._owner_id = uuid.uuid4().hex
        self._closed = False
        self._lock = threading.RLock()
        self._leases: dict[str, ResourceLease] = {}
        self._pressure = "normal"
        self._last_memory: ProcessTreeMemory | None = None
        self.denied = 0
        self.peak_rss_bytes = 0

    def sample(self) -> ProcessTreeMemory:
        memory = self._memory_reader()
        with self._lock:
            self._last_memory = memory
            self.peak_rss_bytes = max(self.peak_rss_bytes, memory.rss_bytes)
            if not memory.available:
                self._pressure = "measurement_unavailable"
                return memory
            used = memory.admission_bytes
            ratio = used / self.envelope.total_memory_budget
            if ratio >= self.envelope.high_watermark:
                self._pressure = "high"
            elif self._pressure != "normal" and ratio > self.envelope.resume_watermark:
                # Do not oscillate at the soft threshold after a pressure event.
                self._pressure = "high" if self._pressure == "high" else "soft"
            elif ratio >= self.envelope.soft_watermark:
                self._pressure = "soft"
            else:
                self._pressure = "normal"
        return memory

    def acquire(
        self,
        kind: str = "worker",
        estimated_bytes: int = 0,
        *,
        owner_process_only: bool = False,
    ) -> ResourceLease:
        if kind not in {"worker", "scanner", "browser", "page", "context"}:
            raise ValueError("unknown resource kind")
        if type(estimated_bytes) is not int or estimated_bytes < 0:
            raise ValueError("estimated_bytes must be a nonnegative integer")
        if type(owner_process_only) is not bool or (owner_process_only and kind != "worker"):
            raise ValueError("owner_process_only requires an in-process worker")
        with self._lock:
            if self._closed:
                raise ResourceAdmissionError("resource_governor_closed")
            memory = self.sample()
            counts = Counter(lease.kind for lease in self._leases.values())
            worker_count = sum(counts[k] for k in ("worker", "scanner", "browser"))
            limits = {
                "browser": self.envelope.browser_concurrency,
                "page": self.envelope.max_pages,
                "context": self.envelope.max_contexts,
            }
            measured = memory.admission_bytes
            reserved = sum(lease.estimated_bytes for lease in self._leases.values())
            reason = None
            if self._pressure != "normal":
                reason = f"memory pressure: {self._pressure}"
            elif estimated_bytes > self.envelope.worker_memory_budget:
                reason = "worker estimate exceeds worker memory budget"
            elif measured + reserved + estimated_bytes > self.envelope.total_memory_budget:
                reason = "total memory reservation exhausted"
            elif (
                kind in {"worker", "scanner", "browser"}
                and worker_count >= self.envelope.max_workers
            ):
                reason = "worker capacity exhausted"
            elif kind in limits and counts[kind] >= limits[kind]:
                reason = f"{kind} capacity exhausted"
            if reason:
                self.denied += 1
                raise ResourceAdmissionError(reason)
            lease = ResourceLease(self, uuid.uuid4().hex, kind, estimated_bytes)
            if self._host_pool is not None:
                try:
                    self._host_pool.reserve(
                        self._owner_id,
                        lease.lease_id,
                        kind,
                        estimated_bytes,
                        owner_process_only=owner_process_only,
                    )
                except ResourceAdmissionError:
                    self.denied += 1
                    raise
            self._leases[lease.lease_id] = lease
            return lease

    def release(self, lease: ResourceLease) -> None:
        with self._lock:
            if lease.governor is not self:
                raise ValueError("lease belongs to another governor")
            if not lease.released and self._host_pool is not None:
                self._host_pool.release(self._owner_id, lease.lease_id)
            self._leases.pop(lease.lease_id, None)
            lease.released = True

    def close(self) -> None:
        """Called after the runtime has stopped its owned jobs and browsers."""
        with self._lock:
            if self._leases:
                raise ResourceAdmissionError("resource_leases_still_active")
            self._closed = True

    def snapshot(self) -> dict[str, object]:
        from redjohn.assessment.os_memory import active_memory_measurement  # noqa: PLC0415

        with self._lock:
            return {
                "pressure": self._pressure,
                "active": dict(Counter(x.kind for x in self._leases.values())),
                "reserved_bytes": sum(x.estimated_bytes for x in self._leases.values()),
                "peak_rss_bytes": self.peak_rss_bytes,
                "admissions_denied": self.denied,
                "admission_bytes": self._last_memory.admission_bytes if self._last_memory else None,
                "cgroup_current_bytes": self._last_memory.cgroup_current_bytes
                if self._last_memory
                else None,
                "cgroup_inactive_file_bytes": self._last_memory.cgroup_inactive_file_bytes
                if self._last_memory
                else None,
                "admission_measurement": "max_process_tree_rss_cgroup_current_minus_inactive_file",
                "measurement_method": self._last_memory.method
                if self._last_memory
                else "not_sampled",
                "host": self._host_pool.snapshot() if self._host_pool is not None else None,
                "os_memory": active_memory_measurement(),
            }


@dataclass(frozen=True)
class ContextTokenBudget:
    system: int = 0
    tool_schemas: int = 0
    skills: int = 0
    history: int = 0
    inputs: int = 0
    planned_output: int = 0
    measurement: str = "estimated"

    @property
    def total(self) -> int:
        values = (
            self.system,
            self.tool_schemas,
            self.skills,
            self.history,
            self.inputs,
            self.planned_output,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("token counts must be nonnegative integers")
        return sum(values)


class MemoryBudgetManager:
    def __init__(self, envelope: ResourceEnvelope) -> None:
        self.envelope = envelope

    def validate_context(self, budget: ContextTokenBudget) -> int:
        total = budget.total
        if total > self.envelope.max_model_input_tokens:
            raise ResourceAdmissionError("model context and planned output exceed token envelope")
        return total
