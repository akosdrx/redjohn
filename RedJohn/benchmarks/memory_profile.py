"""Bounded diagnostic observations, never an admission or containment mechanism.

Only PID/start identities, classified executable names, and memory counters are
read. Process arguments, environment variables and target/session data are not
collected. RSS sums can double count shared pages. PSS/private figures are only
available for processes whose Linux smaps_rollup is readable.
"""

# ruff: noqa: INP001 - script-local helper imported by the standalone benchmark

from __future__ import annotations

import os
import sys
import time
import tracemalloc
from collections import Counter
from itertools import islice
from pathlib import Path

from redjohn.assessment.os_memory import active_memory_measurement


MAX_PROCESSES = 512
MAX_SAMPLES = 2048
MAX_PROC_ENTRIES = 32768
SAMPLE_INTERVAL_SECONDS = 0.5
RETAIN_INTERVAL_SECONDS = 2


def process_role(name: str, pid: int, controller_pid: int) -> str:
    if pid == controller_pid:
        return "controller"
    name = name.lower()
    if name.startswith(("chrome", "chromium")):
        return "chromium"
    fixed = {
        "node": "node",
        "nuclei": "nuclei",
        "httpx": "httpx",
        "bwrap": "isolation_supervisor",
        "timeout": "isolation_supervisor",
        "setpriv": "isolation_supervisor",
    }
    if name in fixed:
        return fixed[name]
    if name.startswith("python"):
        return "python_descendant"
    return "other_descendant"


def _stat(path: Path) -> tuple[str, int, int, int]:
    value = path.read_text()
    end = value.rindex(")")
    fields = value[end + 2 :].split()
    return (
        value[value.index("(") + 1 : end],
        int(fields[1]),
        int(fields[19]),
        int(fields[21]) * os.sysconf("SC_PAGE_SIZE"),
    )


def _smaps(path: Path) -> dict[str, int]:
    wanted = {"Rss", "Pss", "Private_Clean", "Private_Dirty", "Private_Hugetlb"}
    result = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        key = fields[0].rstrip(":") if fields else ""
        if key in wanted:
            if len(fields) != 3 or fields[2] != "kB":
                raise ValueError("unexpected_smaps_memory_unit")
            result[key] = int(fields[1]) * 1024
    if not {"Rss", "Pss", "Private_Clean", "Private_Dirty"} <= result.keys():
        raise ValueError("incomplete_smaps_rollup")
    return {
        "rss_bytes": result["Rss"],
        "pss_bytes": result["Pss"],
        "private_bytes": sum(result.get(key, 0) for key in wanted if key.startswith("Private_")),
    }


def _process_record(proc_root, pid, row, controller_pid):
    name, _, identity, rss = row
    item = {
        "pid": pid,
        "start_ticks": identity,
        "role": process_role(name, pid, controller_pid),
        "rss_bytes": rss,
        "pss_bytes": None,
        "private_bytes": None,
    }
    try:
        detail = _smaps(proc_root / str(pid) / "smaps_rollup")
        if _stat(proc_root / str(pid) / "stat")[2] != identity:
            status = "process_identity_changed"
        else:
            item.update(detail)
            status = "complete"
    except FileNotFoundError:
        status = "exited_during_observation"
    except PermissionError:
        status = "smaps_permission_denied"
    except (OSError, ValueError, IndexError):
        status = "smaps_unavailable"
    item["status"] = status
    return item


def process_memory_sample(*, proc_root: Path = Path("/proc"), controller_pid: int | None = None):
    """An observed tree, not a claim that reparented processes are contained."""
    result = {
        "sample_monotonic": time.monotonic(),
        "scope": "controller_and_observed_descendants_not_a_containment_proof",
        "processes": [],
        "roles": {},
        "kernel_memory": active_memory_measurement(),
    }
    if sys.platform != "linux":
        return {**result, "status": "unavailable", "reason": "linux_smaps_rollup_required"}
    controller_pid = os.getpid() if controller_pid is None else controller_pid
    paths = list(islice(proc_root.glob("[0-9]*/stat"), MAX_PROC_ENTRIES + 1))
    if len(paths) > MAX_PROC_ENTRIES:
        return {**result, "status": "unavailable", "reason": "process_table_observation_limit"}
    table = {}
    for path in paths:
        try:
            table[int(path.parent.name)] = _stat(path)
        except (OSError, ValueError, IndexError):
            continue  # Other users' processes can disappear or deny access.
    if controller_pid not in table:
        return {**result, "status": "unavailable", "reason": "controller_identity_unavailable"}
    owned = {controller_pid}
    while True:
        children = {pid for pid, (_, parent, _, _) in table.items() if parent in owned}
        if children <= owned:
            break
        owned.update(children)
    overflow = len(owned) > MAX_PROCESSES
    statuses = Counter()
    for pid in sorted(owned)[:MAX_PROCESSES]:
        item = _process_record(proc_root, pid, table[pid], controller_pid)
        statuses[item["status"]] += 1
        result["processes"].append(item)
    for role in sorted({item["role"] for item in result["processes"]}):
        members = [item for item in result["processes"] if item["role"] == role]
        result["roles"][role] = {
            "process_count": len(members),
            **{
                key: sum(item[key] for item in members)
                if all(item[key] is not None for item in members)
                else None
                for key in ("rss_bytes", "pss_bytes", "private_bytes")
            },
        }
    result.update(
        {
            "status": "complete" if not overflow and set(statuses) == {"complete"} else "partial",
            "process_count": len(owned),
            "process_limit_exceeded": overflow,
            "observation_status_counts": dict(statuses),
            "summed_rss_bytes": sum(item["rss_bytes"] for item in result["processes"]),
        }
    )
    return result


class MemoryAttribution:
    """Retain a bounded 2s series and one peak per fixed workload phase."""

    def __init__(self, started: float):
        self.started = started
        self.phase = "setup"
        self.cycle = None
        self.next_retained = started
        self.report = {
            "measurement": "process_observations_not_memory_limit_enforcement",
            "sampling_interval_seconds": SAMPLE_INTERVAL_SECONDS,
            "retained_interval_seconds": RETAIN_INTERVAL_SECONDS,
            "maximum_retained_samples": MAX_SAMPLES,
            "maximum_processes_per_sample": MAX_PROCESSES,
            "samples": [],
            "phase_peaks": {},
            "role_peaks": {},
            "phase_observations": {},
            "checkpoints": [],
            "observation_errors": {},
            "sample_count": 0,
            "retention_limit_reached": False,
        }

    def set_phase(self, phase: str, cycle: int | None = None):
        if phase not in {
            "setup",
            "synthetic_pressure",
            "runtime_setup",
            "browser",
            "httpx",
            "nuclei",
            "cache_pressure",
            "pacing",
            "runtime_close",
            "closed",
            "after_gc",
            "after_tracer_stop",
        }:
            raise ValueError("unknown_memory_measurement_phase")
        self.phase, self.cycle = phase, cycle

    def capture(self):
        phase, cycle = self.phase, self.cycle
        value = process_memory_sample()
        value.update({"phase": phase, "cycle": cycle})
        value["elapsed_seconds"] = value["sample_monotonic"] - self.started
        if tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            value["controller_traced_bytes"] = current
            value["controller_traced_peak_bytes"] = peak
            value["tracer_metadata_bytes"] = tracemalloc.get_tracemalloc_memory()
        return value

    def record(self, value):
        self.report["sample_count"] += 1
        phase = value["phase"]
        observation = self.report["phase_observations"].setdefault(
            phase, {"sample_count": 0, "role_sample_counts": {}}
        )
        observation["sample_count"] += 1
        for role, counters in value.get("roles", {}).items():
            counts = observation["role_sample_counts"]
            counts[role] = counts.get(role, 0) + 1
            peak = self.report["role_peaks"].get(role)
            if peak is None or counters["rss_bytes"] > peak["roles"][role]["rss_bytes"]:
                # Short-lived scanners need not coincide with the phase's
                # overall RSS maximum. Preserve evidence of observed roles.
                self.report["role_peaks"][role] = value
        peaks = self.report["phase_peaks"]
        if phase not in peaks or value.get("summed_rss_bytes", 0) > peaks[phase].get(
            "summed_rss_bytes", 0
        ):
            peaks[phase] = value
        if value["sample_monotonic"] >= self.next_retained:
            if len(self.report["samples"]) < MAX_SAMPLES:
                self.report["samples"].append(value)
            else:
                self.report["retention_limit_reached"] = True
            self.next_retained = value["sample_monotonic"] + RETAIN_INTERVAL_SECONDS

    def checkpoint(self, name: str):
        # Fixed names at setup/warmup/close: never a target-derived label.
        value = self.capture()
        value["checkpoint"] = name
        self.report["checkpoints"].append(value)
        return value

    def error(self, exc: Exception):
        name = type(exc).__name__
        errors = self.report["observation_errors"]
        errors[name] = errors.get(name, 0) + 1
