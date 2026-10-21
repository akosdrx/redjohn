#!/usr/bin/env python3
"""Commit-bound command logs, external RSS samples and strict CI evidence gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import signal
import stat
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "artifacts"
FRONTEND_TRANSPORT_CASES = frozenset({
    "read-only capability defaults closed on absent or malformed permissions",
    "steering preserves agent and message, HTTP rejection stays failure",
    "successful HTTP status cannot turn rejected OTP into verified auth",
    "dropped POST transport is an explicit failure and the next action can retry",
    "report sending encodes requested run and surfaces non-JSON failures",
    "run loading encodes scope and does not hide a failed primary run fetch",
})
SOAK_OWNER_RECEIPT = "mixed-soak-owner/receipt.json"
KERNEL_CONTROL_CASES = frozenset({
    ("test_owned_memory_live.py", name) for name in (
        "test_actual_manually_entered_writable_group_cannot_authorize_inline_profile",
        "test_actual_owner_and_setsid_children_share_one_kernel_memory_budget",
        "test_actual_two_owners_share_immutable_aggregate_kernel_budget",
        "test_actual_supervisor_deadline_or_signal_cleans_setsid_descendant[False]",
        "test_actual_supervisor_deadline_or_signal_cleans_setsid_descendant[True]",
        "test_actual_missing_delegation_blocks_before_owner_exec",
        "test_actual_contained_startup_failure_preserves_kernel_and_cleanup_receipt",
        "test_actual_browser_sdk_mcp_and_native_worker_inherit_the_owner_hard_fence",
        "test_actual_owner_preserves_inherited_terminal_io",
    )
}) | frozenset({("test_os_memory_live.py",
                "test_actual_orphan_is_killed_before_crashed_owner_capacity_is_reclaimed")})
SOAK_CHECKS = frozenset({
    "synthetic_limits_enforced", "all_cycles_completed", "minimum_duration_observed",
    "closed_cache_payload_released", "no_owned_process_reservations",
    "process_count_returns_to_baseline", "listeners_return_to_baseline",
    "descriptors_return_to_baseline", "native_session_empty", "pages_contexts_closed",
    "no_browser_cleanup_errors", "actual_budget_matches_requests", "both_actors_observed",
    "no_forbidden_mutations", "no_observation_errors", "source_identity_preserved",
})
RELEASED_TYPES = (
    "redjohn.assessment.runtime.AssessmentRuntime",
    "redjohn.assessment.browser.BrowserDiscoveryService",
    "playwright._impl._connection.Connection",
    "playwright._impl._browser.Browser",
    "playwright._impl._browser_context.BrowserContext",
    "playwright._impl._page.Page",
)
CONTROLLER_MIXED_PHASES = frozenset({
    "before_synthetic_pressure", "after_synthetic_pressure", "runtime_ready_before_loop",
    "first_browser_job_completed", "first_httpx_job_completed", "first_nuclei_job_completed",
    "after_warmup", "before_runtime_close", "after_runtime_close",
    "after_workload_return_before_gc", "after_diagnostic_gc", "after_tracemalloc_stop",
    "after_allocator_trim",
})
PYMALLOC_COUNTERS = (
    "arenas_current", "arenas_reclaimed", "arenas_highwater", "arena_size_bytes",
    "allocated_block_bytes", "available_block_bytes", "unused_pool_bytes",
)


def _nonnegative_counters(value, fields):
    return isinstance(value, dict) and all(
        type(value.get(key)) is int and value[key] >= 0 for key in fields
    )


def validate_controller_details(observations, *, mixed):
    """Shared gate for complete numeric controller observations, not RSS accounting."""
    if not isinstance(observations, list) or not 1 <= len(observations) <= 16:
        raise ValueError("missing_controller_checkpoint_details")
    names = []
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("malformed_controller_checkpoint_details")
        name = observation.get("checkpoint")
        details = observation.get("controller_details" if mixed else "details")
        if not isinstance(name, str) or not isinstance(details, dict):
            raise ValueError("malformed_controller_checkpoint_details")
        names.append(name)
        mappings, allocator = details.get("mappings"), details.get("glibc_allocator")
        groups = mappings.get("groups") if isinstance(mappings, dict) else None
        modules, counts = details.get("new_modules"), details.get("live_component_types")
        if (not isinstance(mappings, dict) or mappings.get("status") != "observed"
            or not _nonnegative_counters(mappings, ("mapping_count",))
            or mappings["mapping_count"] < 1
            or not isinstance(groups, dict) or not 1 <= len(groups) <= 16
            or any(not _nonnegative_counters(row, (
                "mappings", "Size_bytes", "Rss_bytes", "Pss_bytes",
                "Private_Clean_bytes", "Private_Dirty_bytes"))
                or row["mappings"] < 1 for row in groups.values())
            or not isinstance(allocator, dict) or allocator.get("status") != "observed"
            or not _nonnegative_counters(allocator, (
                "arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks", "fsmblks",
                "uordblks", "fordblks", "keepcost"))
            or not _nonnegative_counters(details, (
                "python_allocated_blocks", "module_count", "linecache_files",
                "linecache_source_bytes", "gc_tracked_objects"))
            or details.get("new_modules_truncated") is not False
            or not isinstance(modules, list) or len(modules) > 2048
            or any(not isinstance(module, str) for module in modules)
            or len(set(modules)) != len(modules)
            # The producer truncates to 512. Reaching that boundary cannot
            # prove absence of a released type outside the retained prefix.
            or not isinstance(counts, dict) or len(counts) >= 512
            or any(not isinstance(key, str) or type(count) is not int or count < 0
                   for key, count in counts.items())):
            raise ValueError("blocked_controller_counter_capability")
        if mixed and name == "after_diagnostic_gc" and any(
            counts.get(component, 0) != 0 for component in RELEASED_TYPES
        ):
            raise ValueError("controller_components_retained_after_gc")
    required = CONTROLLER_MIXED_PHASES if mixed else {"before", "after", "after_gc", "after_trim"}
    if not required <= set(names) or len(set(names)) != len(names):
        raise ValueError("incomplete_or_duplicate_controller_phases")
    return {"checkpoints": names, "released_component_types_checked": list(RELEASED_TYPES) if mixed else []}


def validate_controller_pymalloc(value):
    """Require real CPython counters; reservations do not represent resident pages."""
    if not isinstance(value, dict):
        raise ValueError("blocked_cpython_allocator_diagnostic")
    for phase in ("before_asyncio_run", "after_asyncio_run"):
        counters = value.get(phase)
        if (not isinstance(counters, dict) or counters.get("status") != "observed"
            or not _nonnegative_counters(counters, PYMALLOC_COUNTERS)
            or counters["arena_size_bytes"] < 1):
            raise ValueError("blocked_cpython_allocator_diagnostic")
    return value


def soak_owner_reference():
    """Digest the private supervisor receipt, never substitute sampled RSS."""
    path = OUT / SOAK_OWNER_RECEIPT
    if path.is_symlink():
        raise ValueError("mixed_soak_owner_receipt_not_regular")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("mixed_soak_owner_receipt_not_regular")
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise ValueError("mixed_soak_owner_receipt_byte_limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("mixed_soak_owner_receipt_not_mapping")
    return value, {"path": SOAK_OWNER_RECEIPT,
                   "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def validate_soak_owner(value):
    """Validate actual owner/pool controls without changing cooperative ledgers."""
    if (value.get("product") != "RedJohn"
        or value.get("mode") != "owned_local_process_tree_hard_memory"
        or value.get("outcome") != "owner_exited"
        or type(value.get("owner_returncode")) is not int or value["owner_returncode"] != 0
        or value.get("supervisor_outside_budget") is not True
        or value.get("external_daemon_or_remote_workers_included") is not False
        or value.get("process_cleanup_verified") is not True
        or value.get("owner_cgroup_removed") is not True
        or type(value.get("supervisor_peak_rss_bytes")) is not int
        or value["supervisor_peak_rss_bytes"] < 1):
        raise ValueError("mixed_soak_owner_execution_or_cleanup_unverified")
    memory = value.get("os_memory")
    if not isinstance(memory, dict):
        raise ValueError("mixed_soak_owner_kernel_receipt_missing")
    if (memory.get("method") != "linux_cgroup_v2_before_controller_exec"
        or memory.get("scope") != "fresh_exec_local_owner_and_inherited_descendants"):
        raise ValueError("mixed_soak_owner_preexec_fence_unverified")
    aggregate = memory.get("aggregate")
    if not isinstance(aggregate, dict):
        raise ValueError("mixed_soak_aggregate_kernel_receipt_missing")
    for scope, measured, maximum, pids, oom_group in (
        ("owner", memory, 2048 * 1024**2, 512, 1),
        ("aggregate", aggregate, 4096 * 1024**2, 4096, 0),
    ):
        expected = {"memory_max_bytes": maximum, "swap_max_bytes": 0,
                    "pids_max": pids, "memory_oom_group": oom_group,
                    "oom_events": 0, "oom_kills": 0}
        if (measured.get("enforced") is not True
            or any(type(measured.get(key)) is not int or measured[key] != number
                   for key, number in expected.items())
            or type(measured.get("memory_peak_bytes")) is not int
            or measured["memory_peak_bytes"] < 1):
            raise ValueError("mixed_soak_" + scope + "_kernel_limits_or_oom_invalid")
    namespace = memory.get("owner_namespace")
    if not isinstance(namespace, dict) or any(namespace.get(key) is not True for key in (
        "verified", "capabilities_zero", "no_new_privileges", "direct_control_open_denied",
        "supervisor_proc_root_open_denied",
    )):
        raise ValueError("mixed_soak_owner_namespace_unverified")
    return {"owner": memory, "supervisor_peak_rss_bytes": value["supervisor_peak_rss_bytes"],
            "supervisor_outside_budget": True, "owner_cgroup_removed": True,
            "process_cleanup_verified": True}


def validate_kernel_control_cases(path):
    """A green partial suite cannot omit the actual kernel fault controls."""
    found = set()
    for case in ET.parse(path).getroot().iter("testcase"):
        key = (Path(case.get("file", "")).name, case.get("name"))
        if key not in KERNEL_CONTROL_CASES:
            continue
        props = {item.get("name"): item.get("value")
                 for item in case.findall("properties/property")}
        capabilities = set(props.get("required_runner_capabilities", "").split(","))
        if (key in found or any(case.find(tag) is not None for tag in ("error", "failure", "skipped"))
            or props.get("evidence_kind") != "real_integration"
            or "cgroup_available" not in capabilities):
            raise ValueError("invalid_actual_kernel_control_case:" + str(key[1]))
        found.add(key)
    if found != KERNEL_CONTROL_CASES:
        raise ValueError("missing_actual_kernel_control_cases:" + ",".join(
            name for _, name in sorted(KERNEL_CONTROL_CASES - found)))
    return [name for _, name in sorted(found)]


def _finite_nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _validate_memory_observation(value):
    if not isinstance(value, dict) or value.get("status") not in {"complete", "partial"}:
        raise ValueError("mixed_soak_memory_observation_unavailable")
    rows = value.get("processes")
    if (not isinstance(rows, list) or not 1 <= len(rows) <= 512
        or value.get("process_limit_exceeded") is not False):
        raise ValueError("mixed_soak_process_observation_bounds_invalid")
    controllers = [row for row in rows if isinstance(row, dict) and row.get("role") == "controller"]
    if (len(controllers) != 1 or controllers[0].get("status") != "complete"
        or any(type(controllers[0].get(key)) is not int or controllers[0][key] < 0
               for key in ("rss_bytes", "pss_bytes", "private_bytes"))):
        raise ValueError("mixed_soak_controller_memory_attribution_unavailable")
    measured = value.get("kernel_memory")
    expected = {"memory_max_bytes": 2048 * 1024**2, "swap_max_bytes": 0,
                "pids_max": 512, "memory_oom_group": 1, "oom_events": 0, "oom_kills": 0}
    if (not isinstance(measured, dict) or measured.get("enforced") is not True
        or any(type(measured.get(key)) is not int or measured[key] != number
               for key, number in expected.items())):
        raise ValueError("mixed_soak_observed_controller_kernel_fence_invalid")
    return controllers[0]


def validate_allocator_diagnostic(value, checkpoints):
    """Verify the real Linux call and its observations; a no-op is valid data."""
    if (not isinstance(value, dict) or value.get("status") != "completed"
        or value.get("method") != "glibc_malloc_trim_0"
        or type(value.get("call_count")) is not int or value["call_count"] != 1
        or type(value.get("returncode")) is not int or value["returncode"] not in (0, 1)
        or not isinstance(value.get("glibc_version"), str) or not value["glibc_version"]
        or not _finite_nonnegative(value.get("elapsed_seconds"))
        or value.get("scope") != "controller_allocator_only"
        or value.get("runtime_policy_changed") is not False
        or value.get("library_prepared_before_observation") is not True
        or value.get("before_checkpoint") != "after_tracemalloc_stop"
        or value.get("after_checkpoint") != "after_allocator_trim"):
        raise ValueError("mixed_soak_allocator_diagnostic_missing_or_blocked")
    before, after = value.get("before_observation"), value.get("after_observation")
    previous = checkpoints["after_tracemalloc_stop"]
    def normalize(item):
        return {key: measured for key, measured in item.items()
                if key not in {"phase", "checkpoint"}}
    if (not isinstance(after, dict)
        or normalize(after) != normalize(checkpoints["after_allocator_trim"])):
        raise ValueError("mixed_soak_allocator_after_observation_checkpoint_mismatch")
    controllers = [_validate_memory_observation(item) for item in (previous, before, after)]
    identities = {(item.get("pid"), item.get("start_ticks")) for item in controllers}
    if (len(identities) != 1
        or any(type(item.get(key)) is not int or item[key] <= 0
               for item in controllers for key in ("pid", "start_ticks"))
        or any(not _finite_nonnegative(item.get("sample_monotonic"))
               for item in (previous, before, after))
        or not previous["sample_monotonic"] <= before["sample_monotonic"] <= after["sample_monotonic"]
        or value["elapsed_seconds"] > after["sample_monotonic"] - before["sample_monotonic"]):
        raise ValueError("mixed_soak_allocator_observation_identity_or_order_invalid")
    first, last = controllers[1:]
    fields = ("rss_bytes", "pss_bytes", "private_bytes")
    return {"status": "completed", "method": value["method"], "returncode": value["returncode"],
            "call_count": 1, "library_prepared_before_observation": True,
            "before_checkpoint": "after_tracemalloc_stop", "after_checkpoint": "after_allocator_trim",
            "glibc_version": value["glibc_version"], "elapsed_seconds": value["elapsed_seconds"],
            "controller_before": {key: first[key] for key in fields},
            "controller_after": {key: last[key] for key in fields},
            "controller_after_minus_before": {key: last[key] - first[key] for key in fields},
            "scope": "controller_allocator_only", "runtime_policy_changed": False}


def validate_soak_observations(value, *, require_controller_details=False):
    """Require the explicit loop window and bounded, usable diagnostic evidence."""
    checks = value.get("checks", {})
    if not isinstance(checks, dict) or any(checks.get(name) is not True for name in SOAK_CHECKS):
        raise ValueError("mixed_soak_required_invariants_incomplete")
    requested, minimum = value.get("requested_cycles"), value.get("minimum_elapsed_seconds")
    if (type(requested) is not int or not 2 <= requested <= 1000
        or not _finite_nonnegative(minimum)
        or (os.environ.get("REDJOHN_SOAK_CYCLES") is not None
            and requested != int(os.environ["REDJOHN_SOAK_CYCLES"]))
        or (os.environ.get("REDJOHN_SOAK_MINIMUM_SECONDS") is not None
            and minimum != float(os.environ["REDJOHN_SOAK_MINIMUM_SECONDS"]))):
        raise ValueError("mixed_soak_requested_window_mismatch")
    workload = value.get("workload", {})
    timing, cycles = workload.get("timing", {}), workload.get("cycles")
    if (not isinstance(cycles, list) or not requested <= len(cycles) <= 1000
        or timing.get("loop_returned_normally") is not True
        or type(timing.get("completed_cycles")) is not int
        or timing["completed_cycles"] != len(cycles)
        or any(not _finite_nonnegative(timing.get(key)) for key in (
            "loop_started_monotonic", "loop_ended_monotonic", "loop_elapsed_seconds",
            "loop_nonpacing_seconds", "pacing_seconds", "runtime_setup_elapsed_seconds"))
        or timing["loop_elapsed_seconds"] < minimum
        or not math.isclose(timing["loop_ended_monotonic"] - timing["loop_started_monotonic"],
                            timing["loop_elapsed_seconds"], rel_tol=0, abs_tol=1e-6)
        or not math.isclose(timing["loop_nonpacing_seconds"] + timing["pacing_seconds"],
                            timing["loop_elapsed_seconds"], rel_tol=0, abs_tol=1e-6)):
        raise ValueError("mixed_soak_explicit_workload_window_incomplete")
    profile = value.get("memory_attribution")
    if (not isinstance(profile, dict) or value.get("observation_errors") != {}
        or profile.get("observation_errors") != {}
        or "initial_observation_error" in value or "final_observation_error" in value
        or profile.get("maximum_retained_samples") != 2048
        or profile.get("maximum_processes_per_sample") != 512
        or profile.get("retention_limit_reached") is not False):
        raise ValueError("mixed_soak_memory_profile_missing_or_failed")
    samples, checkpoints = profile.get("samples"), profile.get("checkpoints")
    if (not isinstance(samples, list) or not 1 <= len(samples) <= 2048
        or type(profile.get("sample_count")) is not int
        or profile["sample_count"] < len(samples)
        or not isinstance(checkpoints, list) or len(checkpoints) != 10):
        raise ValueError("mixed_soak_memory_profile_retention_invalid")
    names = {item.get("checkpoint") for item in checkpoints if isinstance(item, dict)}
    if names != {"before_synthetic_pressure", "after_synthetic_pressure",
                 "runtime_ready_before_loop", "after_warmup", "before_runtime_close",
                 "after_runtime_close", "after_workload_return_before_gc",
                 "after_diagnostic_gc", "after_tracemalloc_stop", "after_allocator_trim"}:
        raise ValueError("mixed_soak_memory_checkpoints_incomplete")
    phases, roles = profile.get("phase_peaks"), profile.get("role_peaks")
    if (not isinstance(phases, dict) or not 1 <= len(phases) <= 13
        or not isinstance(roles, dict) or not 1 <= len(roles) <= 8):
        raise ValueError("mixed_soak_phase_or_role_peaks_incomplete")
    for observed in (*samples, *checkpoints, *phases.values(), *roles.values()):
        _validate_memory_observation(observed)
    diagnostic = validate_allocator_diagnostic(value.get("allocation_diagnostic"),
        {item["checkpoint"]: item for item in checkpoints})
    allocation = value.get("allocation_observations", {})
    if (allocation.get("closed_cache_payload_bytes") != 0
        or not _finite_nonnegative(allocation.get("retained_memory_observation_json_bytes"))):
        raise ValueError("mixed_soak_allocation_attribution_incomplete")
    controller = None
    requested_details = value.get("controller_details_requested", False)
    if type(requested_details) is not bool:
        raise ValueError("mixed_soak_controller_details_request_invalid")
    if require_controller_details or requested_details:
        if requested_details is not True:
            raise ValueError("mixed_soak_requested_controller_details_missing")
        controller = validate_controller_details(profile.get("controller_diagnostics"), mixed=True)
        controller["python_allocator_diagnostic"] = validate_controller_pymalloc(
            value.get("python_allocator_diagnostic")
        )
    return {"timing": timing, "actual_cycles": len(cycles), "sample_count": profile["sample_count"],
            "retained_samples": len(samples), "checkpoints": sorted(names),
            "observed_phases": sorted(phases), "observed_roles": sorted(roles),
            "allocation_observations": allocation, "allocation_diagnostic": diagnostic,
            "controller_diagnostics": controller}


def write(name, value):
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def require_clean_worktree():
    """Fail evidence collection unless the complete checkout is commit-bound.

    ``git ls-files`` alone silently omits untracked source, so a hashed source
    manifest could describe a different tree than the one that ran.  Ignored
    build/runtime paths are excluded by Git and therefore remain allowed.
    """
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if status.returncode != 0:
        detail = status.stderr.strip().splitlines()[:1]
        raise RuntimeError("worktree_status_unavailable" + (": " + detail[0] if detail else ""))
    entries = status.stdout.splitlines()
    if entries:
        sample = ", ".join(entry[:200] for entry in entries[:10])
        raise RuntimeError(
            f"dirty_worktree_blocks_evidence: {len(entries)} path(s): {sample}"
        )
    return {"clean": True, "path_count": 0}


def identity():
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    expected = os.environ.get("GITHUB_SHA")
    if expected and sha != expected:
        raise RuntimeError("checkout_commit_does_not_match_event")
    return {
        "commit_sha": sha,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "run_url": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/"
        + os.environ.get("GITHUB_RUN_ID", ""),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
        "machine": platform.machine(),
        "python": sys.version,
        "platform": platform.platform(),
        "image_version": os.environ.get("ImageVersion"),
    }


def process_table():
    """PID/PPID/starttime/RSS only; never export process arguments or environment."""
    rows = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            pid = int(path.parent.name)
            text = path.read_text()
            fields = text[text.rfind(")") + 2 :].split()
            rows[pid] = (int(fields[1]), fields[19], int(fields[21]) * os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError, IndexError):
            continue
    return rows


def run(name, cwd, argv):
    OUT.mkdir(exist_ok=True)
    meta = identity()
    started = time.monotonic()
    peak = count = samples = 0
    seen = {}
    log_path = OUT / (name + ".log")
    process = subprocess.Popen(
        argv, cwd=ROOT / cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    def forward():
        with log_path.open("wb") as log:
            assert process.stdout is not None
            for block in iter(lambda: process.stdout.read1(65536), b""):
                log.write(block)
                log.flush()
                sys.stdout.buffer.write(block)
                sys.stdout.buffer.flush()

    reader = threading.Thread(target=forward, daemon=True)
    reader.start()

    def stop(_signum, _frame):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    old = {s: signal.signal(s, stop) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        while process.poll() is None:
            table = process_table()
            owned = {process.pid}
            while True:
                more = {pid for pid, (ppid, _birth, _rss) in table.items() if ppid in owned}
                if more <= owned:
                    break
                owned |= more
            active = {pid: table[pid] for pid in owned if pid in table}
            seen.update({pid: row[1] for pid, row in active.items()})
            samples += 1
            peak = max(peak, sum(row[2] for row in active.values()))
            count = max(count, len(active))
            time.sleep(0.2)
        code = process.wait()
        table = process_table()
        leaked = [pid for pid, birth in seen.items() if pid != process.pid
                  and pid in table and table[pid][1] == birth]
        if leaked:
            stop(None, None)
            time.sleep(0.3)
            for pid in leaked:
                current = process_table().get(pid)
                if current and current[1] == seen[pid]:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        reader.join(timeout=5)
        value = {
            **meta, "command": argv, "cwd": cwd, "exit_code": code,
            "duration_seconds": time.monotonic() - started,
            "process_tree_peak_rss_bytes": peak, "max_process_count": count,
            "samples": samples, "leaked_descendant_pids_before_cleanup": leaked,
            "rss_method": "external /proc RSS sum; shared pages may be counted more than once; not a hard OS limit",
        }
        if name == "mixed-soak":
            try:
                _, value["kernel_owner_receipt"] = soak_owner_reference()
            except (OSError, ValueError) as exc:
                value["kernel_owner_receipt_error"] = type(exc).__name__
        write(name + ".json", value)
        return code or (1 if leaked or reader.is_alive() else 0)
    finally:
        for s, handler in old.items():
            signal.signal(s, handler)


def junit_summary(path):
    cases = ET.parse(path).getroot().findall(".//testcase")
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    kinds = {}
    skips = []
    for case in cases:
        status = next((key for tag, key in (("error", "errors"), ("failure", "failed"),
                                            ("skipped", "skipped")) if case.find(tag) is not None), "passed")
        counts[status] += 1
        props = {p.get("name"): p.get("value") for p in case.findall("properties/property")}
        # Node's built-in reporter has no custom properties. These six reviewed
        # cases use fetch doubles, and must never be counted as real HTTP E2E.
        frontend_origin = (Path(case.get("file", "")).name == "server-source.test.mjs"
                           or Path(path).name == "frontend.junit.xml")
        frontend_double = frontend_origin and case.get("name") in FRONTEND_TRANSPORT_CASES
        kind = props.get("evidence_kind", "mock_contract" if frontend_double else "unit_contract_or_mixed")
        kinds.setdefault(kind, {key: 0 for key in counts})[status] += 1
        if status == "skipped":
            skips.append({"test": case.get("name"), "reason": case.find("skipped").get("message")})
    return {"counts": counts, "evidence_kinds": kinds, "skips": skips}


REQUIRED = ("artifact-native-evidence", "artifact-runtime-install", "artifact-database-install", "python-install", "capability-catalog", "linux-dependencies", "scanner-install", "source-scanner-install", "network-scanner-install", "service-scanner-install", "preparation-tool-install", "linux-setup",
            "frontend-install", "pip-check", "python-lint", "python-types", "ci-contracts", "frontend-types",
            "frontend-build", "frontend-tests", "go-vet", "go-tests", "go-build", "python-wheel", "python-wheel-license",
            "python-regression", "python-integration", "mixed-soak", "sandbox-setup", "sandbox-cleanup")


def summarize():
    result = {**identity(), "commands": {}, "junit": {}, "blockers": []}
    result["platform_not_applicable"] = {}
    for suite_name in ("regression", "integration"):
        applicability = OUT / ("non-applicable-" + suite_name + ".json")
        if applicability.is_file():
            result["platform_not_applicable"][suite_name] = json.loads(applicability.read_text())["cases"]
    for name in REQUIRED:
        path = OUT / (name + ".json")
        if not path.is_file():
            result["blockers"].append("missing_command:" + name)
            continue
        value = json.loads(path.read_text())
        result["commands"][name] = value
        if value["commit_sha"] != result["commit_sha"] or value["exit_code"] != 0 or value["leaked_descendant_pids_before_cleanup"]:
            result["blockers"].append("failed_command:" + name)
    for name in ("regression", "integration", "frontend"):
        path = OUT / (name + ".junit.xml")
        if not path.is_file():
            result["blockers"].append("missing_junit:" + name)
            continue
        value = junit_summary(path)
        result["junit"][name] = value
        if not value["counts"]["passed"] or any(value["counts"][key] for key in ("failed", "errors", "skipped")):
            result["blockers"].append("incomplete_suite:" + name)
    soak = OUT / "mixed-soak/mixed-soak.json"
    if not soak.is_file():
        result["blockers"].append("missing_mixed_soak_evidence")
    else:
        value = json.loads(soak.read_text())
        result["mixed_soak"] = {key: value.get(key) for key in
            ("commit_sha", "ok", "elapsed_seconds", "requested_cycles", "checks", "error")}
        if value.get("commit_sha") != result["commit_sha"] or value.get("ok") is not True:
            result["blockers"].append("incomplete_mixed_soak")
        try:
            command = result["commands"].get("mixed-soak", {}).get("command", [])
            if not isinstance(command, list) or any(not isinstance(arg, str) for arg in command):
                raise ValueError("mixed_soak_command_arguments_invalid")
            result["mixed_soak_observations"] = validate_soak_observations(
                value, require_controller_details="--controller-details" in command,
            )
        except (TypeError, ValueError, AttributeError) as exc:
            result["blockers"].append("incomplete_mixed_soak_observations:" + str(exc))
    try:
        value, reference = soak_owner_reference()
        command = result["commands"].get("mixed-soak", {})
        if command.get("kernel_owner_receipt") != reference:
            raise ValueError("mixed_soak_owner_receipt_not_bound_to_command_commit")
        result["mixed_soak_kernel_memory"] = {**validate_soak_owner(value), **reference}
    except (OSError, ValueError) as exc:
        result["blockers"].append("invalid_mixed_soak_kernel_memory:" + str(exc))
    try:
        result["kernel_control_cases"] = validate_kernel_control_cases(OUT / "integration.junit.xml")
    except (OSError, ValueError, ET.ParseError) as exc:
        result["blockers"].append("incomplete_kernel_control_evidence:" + str(exc))
    cap = OUT / "capabilities.json"
    if not cap.is_file() or not json.loads(cap.read_text()).get("available"):
        result["blockers"].append("blocked_runner_capability")
    policy_cleanup = OUT / "apparmor-cleanup.json"
    if not policy_cleanup.is_file() or not json.loads(policy_cleanup.read_text()).get("success"):
        result["blockers"].append("failed_owned_apparmor_cleanup")
    cleanup = OUT / "cgroup-cleanup.json"
    if not cleanup.is_file():
        result["blockers"].append("missing_cleanup_evidence")
    else:
        data = json.loads(cleanup.read_text())
        if not data.get("removed") or data.get("leaked_processes"):
            result["blockers"].append("failed_owned_process_cleanup")
    go_cases = {}
    go_packages = set()
    go_log = OUT / "go-tests.log"
    if go_log.exists():
        for line in go_log.read_text().splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("Package"):
                go_packages.add(row["Package"])
            if row.get("Test") and row.get("Action") in {"pass", "fail", "skip"}:
                go_cases[(row["Package"], row["Test"])] = row
    result["go_tests"] = {status: sum(row["Action"] == action for row in go_cases.values())
                          for status, action in (("passed", "pass"), ("failed", "fail"), ("skipped", "skip"))}
    result["go_test_coverage"] = "test_functions_executed" if go_cases else "no_test_functions_defined"
    result["go_packages_checked"] = sorted(go_packages)
    suite = ET.Element("testsuite", name="Go TUI", tests=str(len(go_cases)))
    for (package, name), row in sorted(go_cases.items()):
        case = ET.SubElement(suite, "testcase", classname=package, name=name, time=str(row.get("Elapsed", 0)))
        if row["Action"] in {"fail", "skip"}:
            ET.SubElement(case, "failure" if row["Action"] == "fail" else "skipped")
    if go_cases or go_packages:
        ET.ElementTree(suite).write(OUT / "go.junit.xml", encoding="utf-8", xml_declaration=True)
        if not result["go_tests"]["passed"] or result["go_tests"]["failed"] or result["go_tests"]["skipped"]:
            result["blockers"].append("incomplete_go_tests")
    else:
        result["blockers"].append("missing_go_results")
    result["success"] = not result["blockers"]
    write("summary.json", result)
    evidence = {str(path.relative_to(OUT)): {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size} for path in sorted(OUT.rglob("*"))
                if path.is_file() and path.suffix in {".xml", ".json", ".log", ".txt"}
                and path.name != "evidence-index.json"}
    write("evidence-index.json", {**identity(), "files": evidence})
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as report:
            report.write(f"## RedJohn {result['machine']} — `{result['commit_sha']}`\n\n")
            report.write("| Suite | Passed | Failed | Errors | Skipped |\n|---|---:|---:|---:|---:|\n")
            for name, value in result["junit"].items():
                c = value["counts"]
                report.write(f"| {name} | {c['passed']} | {c['failed']} | {c['errors']} | {c['skipped']} |\n")
            report.write("\n" + ("Complete." if result["success"] else "Incomplete: " + ", ".join(result["blockers"])) + "\n")
    print(json.dumps({key: result[key] for key in
                     ("commit_sha", "machine", "success", "blockers", "junit", "go_tests", "go_test_coverage")}))
    return 0 if result["success"] else 1


def snapshot():
    require_clean_worktree()
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    hashes = {}
    for raw in paths:
        if raw:
            path = ROOT / os.fsdecode(raw)
            if path.is_file() and not path.is_symlink():
                hashes[os.fsdecode(raw)] = hashlib.sha256(path.read_bytes()).hexdigest()
    write("source.json", {**identity(), "sha256": hashes})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    command = sub.add_parser("run")
    command.add_argument("--name", required=True)
    command.add_argument("--cwd", default=".")
    command.add_argument("argv", nargs=argparse.REMAINDER)
    sub.add_parser("summary")
    sub.add_parser("snapshot")
    sub.add_parser("preflight")
    args = parser.parse_args()
    if args.action == "run":
        return run(args.name, args.cwd, args.argv[1:] if args.argv[:1] == ["--"] else args.argv)
    if args.action == "snapshot":
        snapshot()
        return 0
    if args.action == "preflight":
        print(json.dumps(require_clean_worktree(), sort_keys=True))
        return 0
    return summarize()


if __name__ == "__main__":
    raise SystemExit(main())
