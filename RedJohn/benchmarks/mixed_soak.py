#!/usr/bin/env python3
"""Real owned HTTPS Chromium/httpx/Nuclei soak through one durable scheduler.

Never accepts a target or arbitrary command. Missing pinned engines fail the
run. Synthetic byte/queue pressure is reported separately from scanner proof.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc
from collections import Counter
from contextlib import suppress
from pathlib import Path

from browser_soak import _source_hashes, sample
from limit_pressure import body_pressure, log_pressure
from memory_profile import SAMPLE_INTERVAL_SECONDS, MemoryAttribution, allocator_trim_diagnostic

from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.discovery_tools import DiscoveryToolConfig
from redjohn.assessment.host_resources import HostResourcePool
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore, CapacityExceeded
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.tools.hunt.nuclei import NucleiLock


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate(cycles: int, warmup: int, interval: float, minimum: float) -> float:
    if type(cycles) is not int or not 2 <= cycles <= 1000 or not 0 <= warmup < cycles:
        raise ValueError("require_2_to_1000_cycles_and_smaller_nonnegative_warmup")
    if not all(math.isfinite(x) and 0 <= x <= 3600 for x in (interval, minimum)):
        raise ValueError("invalid_soak_timing")
    deadline = max(minimum, cycles * max(interval, 10)) + 180
    if deadline > 3900:
        raise ValueError("soak_exceeds_65_minute_deadline")
    return deadline


def queue_pressure(store: AssessmentStore, policy: EngagementPolicy, sid: str) -> dict:
    specs = [
        JobSpec(
            sid,
            "headers",
            "headers_audit",
            retest_revision=f"queue-{i}",
            policy_revision=policy.revision,
        )
        for i in range(store.queue_max_items)
    ]
    ids = store.submit(policy, specs)
    require(len(ids) == store.queue_max_items, "queue_did_not_fill")
    duplicate = store.submit(policy, [specs[0]]) == ids[:1]
    try:
        store.submit(
            policy,
            [
                JobSpec(
                    sid,
                    "headers",
                    "headers_audit",
                    retest_revision="overflow",
                    policy_revision=policy.revision,
                )
            ],
        )
        rejected = False
    except CapacityExceeded as exc:
        rejected = str(exc) == "queue_capacity_exhausted"
    # A second actual SQLite connection proves this was durable, not RAM state.
    reopened = AssessmentStore(store.path, queue_max_items=store.queue_max_items)
    try:
        pending = reopened.db.execute(
            "SELECT count(*) FROM rj_job WHERE engagement=? AND execution_status='queued'",
            (policy.engagement_id,),
        ).fetchone()[0]
    finally:
        reopened.close()
    cancelled = sum(store.cancel(policy.engagement_id, job_id) for job_id in ids)
    return {
        "evidence_kind": "synthetic_queue_pressure_real_sqlite",
        "configured_items": store.queue_max_items,
        "persisted_pending": pending,
        "cancelled_before_execution": cancelled,
        "overflow_rejected": rejected,
        "duplicate_preserved": duplicate,
        "ok": pending == cancelled == store.queue_max_items and duplicate and rejected,
    }


def cache_pressure(cache, cycle: int) -> dict:
    # Actual serialized payload pressure against the runtime's configured cache.
    value = "x" * (cache.max_bytes // 4)
    accepted = all(cache.set(f"soak-{cycle}-{i}", value, 60) for i in range(6))
    stats = cache.stats()
    oversized_rejected = not cache.set("oversized", "x" * cache.max_bytes, 60)
    bypass = cache.get(f"soak-{cycle}-5", default=None, retest=True) is None
    return {
        "serialized_bytes": stats["bytes"],
        "items": stats["items"],
        "metrics": stats,
        "configured_bytes": cache.max_bytes,
        "ok": accepted and stats["bytes"] <= cache.max_bytes and oversized_rejected and bypass,
    }


def heap_sample() -> dict:
    current, peak = tracemalloc.get_traced_memory()
    top = tracemalloc.take_snapshot().statistics("lineno")[:12]
    return {
        "controller_traced_bytes": current,
        "controller_traced_peak_bytes": peak,
        "tracer_metadata_bytes": tracemalloc.get_tracemalloc_memory(),
        "gc_generation_counts": list(gc.get_count()),
        "largest_allocations": [
            {"location": str(x.traceback), "bytes": x.size, "count": x.count} for x in top
        ],
    }


def benchmark_sources() -> dict:
    return {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in ("mixed_soak.py", "browser_soak.py", "limit_pressure.py", "memory_profile.py")
    }


async def _job(app, surface: Surface, spec: JobSpec) -> dict:
    store, policy = app.store, app.policy
    sid = store.upsert_surface(policy.engagement_id, surface)
    require(sid == spec.surface_id, "job_surface_identity_mismatch")
    job_id = store.submit(policy, [spec])[0]
    require(await app.scheduler.run_batch(max_jobs=1) == [job_id], "scheduled_job_not_run")
    row = store.db.execute("SELECT * FROM rj_job WHERE id=?", (job_id,)).fetchone()
    result = json.loads(row["result"]) if row["result"] else {}
    require(
        row["execution_status"] == "succeeded",
        f"job_failed:{spec.capability}:{result.get('error')}",
    )
    return {
        "job_id": job_id,
        "capability": spec.capability,
        "coverage": row["coverage_status"],
        "findings": len(result.get("findings", [])),
        "queue_wait_seconds": row["started_at"] - row["created_at"],
        "duration_seconds": row["ended_at"] - row["started_at"],
        "result_summary": result.get("summary", {}),
    }


async def workload(  # noqa: PLR0915 - actual ordered scheduler stages and cleanup
    output: Path,
    lock_document: dict,
    httpx_document: dict,
    *,
    cycles: int,
    warmup: int,
    interval: float,
    minimum: float,
    deadline: float,
    progress: dict,
    memory: MemoryAttribution,
) -> dict:
    lock = NucleiLock.from_mapping(lock_document)
    httpx = DiscoveryToolConfig.from_mapping("httpx", httpx_document)
    envelope = ResourceEnvelope(total_memory_budget=2 * 1024**3, cache_max_bytes=8 * 1024**2)
    with TLSFixtureServer() as fixture:
        policy = EngagementPolicy(
            f"mixed-soak-{time.time_ns()}",
            "local-operator",
            (fixture.origin,),
            allowed_ips=("127.0.0.1/32",),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice", "bob"),
            request_budget=min(100000, max(cycles, math.ceil(minimum / max(interval, 1)) + 1) * 32),
            deadline=time.time() + deadline,
        )
        store = AssessmentStore(
            output / ".state/agents.db", queue_max_items=envelope.queue_max_items
        )
        records, caches = [], []
        progress.update(
            {
                "cycles": records,
                "cache_pressure": caches,
                "nuclei_version": lock.binary_version,
                "nuclei_binary_sha256": lock.binary_sha256,
                "template_sha256": lock.bundle_sha256,
                "httpx_binary": httpx_document["binary"],
            }
        )
        app, session = None, None
        tick = time.monotonic()
        timing = {"setup_started_monotonic": tick, "pacing_seconds": 0.0, "pacing_calls": 0}
        progress["timing"] = timing
        memory.set_phase("runtime_setup")
        try:
            async with (
                NativeFixtureSession(policy, output / "worker", lock) as session,
                AssessmentRuntime(
                    store,
                    policy,
                    caller=policy.owner_id,
                    envelope=envelope,
                    host_pool_path=output / ".state/host-resources.sqlite3",
                    browser_limits=BrowserLimits(readiness_selector="body[data-actor]"),
                    browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                    actor_states={a: fixture.actor_state(a) for a in ("alice", "bob")},
                    nuclei_lock=lock_document,
                    session=session,
                    httpx_config=httpx_document,
                ) as app,
            ):
                policy = app.policy
                seed = Surface(
                    fixture.origin + "/", source="imported", workflow_state="approved_seed"
                )
                sid = store.upsert_surface(policy.engagement_id, seed)
                queue = queue_pressure(store, policy, sid)
                progress["queue_pressure"] = queue
                require(queue["ok"], "persistent_queue_pressure_failed")
                cycle = 0
                warmup_heap = heap_sample()
                warmup_snapshot = tracemalloc.take_snapshot()
                progress["heap_after_warmup"] = warmup_heap
                loop_started = time.monotonic()
                timing["loop_started_monotonic"] = loop_started
                timing["runtime_setup_elapsed_seconds"] = loop_started - tick
                memory.checkpoint("runtime_ready_before_loop")
                while cycle < cycles or time.monotonic() - loop_started < minimum:
                    require(cycle < 1000, "duration_exceeds_maximum_cycle_count")
                    started = time.monotonic()
                    # Fixed mode deliberately enables a strict CSP. Preserve
                    # that control for scanners; browser inventory needs the
                    # fixture's inline SPA script to establish actor readiness.
                    fixture.fixed = False
                    browser = Surface(
                        fixture.origin + "/",
                        actor_id="alice" if cycle % 2 == 0 else "bob",
                        source="imported",
                        workflow_state="approved_seed",
                    )
                    bid = store.upsert_surface(policy.engagement_id, browser)
                    memory.set_phase("browser", cycle)
                    observed = await _job(
                        app,
                        browser,
                        JobSpec(
                            bid,
                            "discovery",
                            "browser_discover",
                            retest_revision=str(cycle),
                            policy_revision=policy.revision,
                        ),
                    )
                    fixture.fixed = bool(cycle % 2)
                    probe = Surface(
                        fixture.origin + "/api/items",
                        source="imported",
                        workflow_state="approved_seed",
                    )
                    pid = store.upsert_surface(policy.engagement_id, probe)
                    memory.set_phase("httpx", cycle)
                    probed = await _job(
                        app,
                        probe,
                        JobSpec(
                            pid,
                            "discovery",
                            "httpx_probe",
                            tool_version=httpx.version,
                            template_version=httpx.revision,
                            retest_revision=str(cycle),
                            policy_revision=policy.revision,
                        ),
                    )
                    require(probed["coverage"] == "completed", "httpx_incomplete")
                    # The actual httpx response must have committed observed inventory.
                    inventory = next(
                        row
                        for row in store.surfaces(policy.engagement_id, limit=100)
                        if row["url"] == probe.url
                        and row["source"] == "observed"
                        and row["actor_id"] == "anonymous"
                    )
                    surface = store.surface(policy.engagement_id, inventory["id"])
                    spec = JobSpec(
                        inventory["id"],
                        "known_vulnerability",
                        "nuclei_scan",
                        tool_version=lock.binary_version,
                        template_version=lock.bundle_sha256,
                        retest_revision=str(cycle),
                        policy_revision=policy.revision,
                    )
                    memory.set_phase("nuclei", cycle)
                    scanned = await _job(app, surface, spec)
                    expected = 0 if fixture.fixed else 1
                    require(
                        scanned["coverage"] == "completed" and scanned["findings"] == expected,
                        "nuclei_positive_fixed_oracle_failed",
                    )
                    requests_before = sum(fixture.counts.values())
                    require(
                        store.submit(policy, [spec]) == [scanned["job_id"]]
                        and await app.scheduler.run_batch(max_jobs=1) == []
                        and sum(fixture.counts.values()) == requests_before,
                        "dedupe_replayed_network",
                    )
                    memory.set_phase("cache_pressure", cycle)
                    caches.append(cache_pressure(app.control.cache, cycle))
                    records.append(
                        {
                            "cycle": cycle,
                            "fixed": fixture.fixed,
                            "seconds": time.monotonic() - started,
                            "jobs": [observed, probed, scanned],
                            "resources": await asyncio.to_thread(sample),
                            "http_requests_so_far": requests_before,
                        }
                    )
                    require(caches[-1]["ok"], "cache_pressure_failed")
                    if cycle + 1 == warmup:
                        warmup_heap = heap_sample()
                        warmup_snapshot = tracemalloc.take_snapshot()
                        progress["heap_after_warmup"] = warmup_heap
                        memory.checkpoint("after_warmup")
                    print(  # noqa: T201 - bounded standalone progress, no target/session data
                        json.dumps(
                            {
                                "cycle": cycle + 1,
                                "cycles": cycles,
                                "elapsed_seconds": round(time.monotonic() - tick, 3),
                                "loop_elapsed_seconds": round(time.monotonic() - loop_started, 3),
                            }
                        ),
                        flush=True,
                    )
                    cycle += 1
                    if cycle < cycles or time.monotonic() - loop_started < minimum:
                        memory.set_phase("pacing", cycle - 1)
                        pacing_started = time.monotonic()
                        try:
                            await asyncio.sleep(max(0, interval - (pacing_started - started)))
                        finally:
                            timing["pacing_seconds"] += time.monotonic() - pacing_started
                            timing["pacing_calls"] += 1
                timing["loop_ended_monotonic"] = time.monotonic()
                timing["loop_elapsed_seconds"] = timing["loop_ended_monotonic"] - loop_started
                timing["loop_nonpacing_seconds"] = (
                    timing["loop_elapsed_seconds"] - timing["pacing_seconds"]
                )
                timing["completed_cycles"] = cycle
                timing["loop_returned_normally"] = True
                db_used = store.db.execute(
                    "SELECT requests_used FROM rj_engagement WHERE id=?", (policy.engagement_id,)
                ).fetchone()[0]
                governor = app.governor.snapshot()
                progress["cache_before_close"] = app.control.cache.stats()
                memory.set_phase("runtime_close")
                memory.checkpoint("before_runtime_close")
            memory.set_phase("closed")
            memory.checkpoint("after_runtime_close")
            progress["cache_after_close"] = app.control.cache.stats()
            differences = tracemalloc.take_snapshot().compare_to(warmup_snapshot, "lineno")
            progress["allocation_changes_after_warmup"] = [
                {
                    "location": str(item.traceback),
                    "bytes_diff": item.size_diff,
                    "count_diff": item.count_diff,
                }
                for item in differences[:12]
            ]
            del differences, warmup_snapshot
            health = app.browser.healthcheck()
            progress.update(
                {
                    "cycles": records,
                    "cache_pressure": caches,
                    "queue_pressure": queue,
                    "browser_health_after_close": health,
                    "governor_before_close": governor,
                    "requests_used": db_used,
                    "actual_fixture_requests": sum(fixture.counts.values()),
                    "fixture_counts": dict(fixture.counts),
                    "observed_actors": sorted({r["actor"] for r in fixture.observed_actors}),
                    "heap_after_warmup": warmup_heap,
                    "heap_after_close": heap_sample(),
                    "nuclei_version": lock.binary_version,
                    "nuclei_binary_sha256": lock.binary_sha256,
                    "template_sha256": lock.bundle_sha256,
                    "httpx_binary": httpx_document["binary"],
                    "native_session_empty": not session._active and not session._reservations,
                }
            )
            return progress
        finally:
            # Context-manager cleanup has run before this block, including on
            # a failed later cycle. Preserve already completed sanitized proof;
            # private SQLite/vault files are deliberately not CI artifacts.
            try:
                if "loop_started_monotonic" in timing and not timing.get("loop_returned_normally"):
                    timing["loop_aborted_monotonic"] = time.monotonic()
                    timing["loop_elapsed_seconds"] = (
                        timing["loop_aborted_monotonic"] - timing["loop_started_monotonic"]
                    )
                    timing["loop_returned_normally"] = False
                progress["actual_fixture_requests"] = sum(fixture.counts.values())
                progress["fixture_counts"] = dict(fixture.counts)
                progress["observed_actors"] = sorted({r["actor"] for r in fixture.observed_actors})
                if app is not None:
                    progress["browser_health_after_close"] = app.browser.healthcheck()
                if session is not None:
                    progress["native_session_empty"] = (
                        not session._active and not session._reservations
                    )
                progress["heap_after_close"] = heap_sample()
            finally:
                store.close()


async def run(  # noqa: PLR0915 - benchmark evidence retained even on workload failure
    output: Path,
    lock_document: dict,
    httpx_document: dict,
    *,
    cycles: int = 30,
    warmup: int = 3,
    interval: float = 10,
    minimum: float = 300,
) -> dict:
    deadline = validate(cycles, warmup, interval, minimum)
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(output.iterdir()), "output_directory_must_be_empty")
    sources = _source_hashes()
    original_pool = os.environ.get("REDJOHN_RESOURCE_POOL_PATH")
    pool = output / ".state/host-resources.sqlite3"
    started = time.monotonic()
    result = {
        "product": "RedJohn",
        "measurement": "actual_mixed_https_scheduler_soak",
        "commit_sha": os.environ.get("GITHUB_SHA"),
        "platform": platform.platform(),
        "python": sys.version,
        "ok": False,
        "runtime_source_hashes": sources,
        "benchmark_source_hashes": benchmark_sources(),
        "requested_cycles": cycles,
        "warmup_cycles": warmup,
        "minimum_elapsed_seconds": minimum,
        "cycle_interval_seconds": interval,
        "deadline_seconds": deadline,
        "model_calls": 0,
        "model_tokens": 0,
        "model_cost": 0,
        "baseline": "baseline_unavailable",
        "coverage_limits": [
            "owned_loopback_fixture_only",
            "controller_tracemalloc_excludes_native_children",
            "summed_RSS_can_double_count_shared_pages",
            "no_original_RCE_fixture",
            "synthetic_pressure_is_not_scanner_detection_evidence",
            "no_cloud_or_public_OAST_or_live_LLM",
            "memory_observer_and_allocation_snapshots_add_measured_controller_overhead",
            "post_cleanup_glibc_trim_is_a_diagnostic_not_runtime_allocator_policy",
        ],
    }
    stop = asyncio.Event()
    samples, observation_errors = [], Counter()
    memory = MemoryAttribution(started)
    result["memory_attribution"] = memory.report

    async def observe():
        next_legacy = started
        while not stop.is_set():
            try:
                memory.record(await asyncio.to_thread(memory.capture))
                if time.monotonic() >= next_legacy:
                    samples.append(await asyncio.to_thread(sample))
                    next_legacy = time.monotonic() + 2
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                observation_errors[type(exc).__name__] += 1
                memory.error(exc)
            # All accepted durations <=3900s; two seconds yields <=1951 samples.
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), SAMPLE_INTERVAL_SECONDS)

    require(not tracemalloc.is_tracing(), "benchmark_requires_own_tracemalloc_lifetime")
    try:
        before = await asyncio.to_thread(sample)
    except Exception as exc:  # noqa: BLE001 - explicit unavailable observation, no state changed
        result["initial_observation_error"] = {
            "type": type(exc).__name__,
            "message": str(exc)[:512],
        }
        result["elapsed_seconds"] = time.monotonic() - started
        (output / "mixed-soak.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    os.environ["REDJOHN_RESOURCE_POOL_PATH"] = str(pool)
    observer = None
    try:
        tracemalloc.start(5)
        memory.checkpoint("before_synthetic_pressure")
        observer = asyncio.create_task(observe())
        async with asyncio.timeout(deadline):
            memory.set_phase("synthetic_pressure")
            result["log_pressure"] = await log_pressure(output)
            result["body_pressure"] = await body_pressure()
            memory.checkpoint("after_synthetic_pressure")
            result["workload"] = {}
            await workload(
                output,
                lock_document,
                httpx_document,
                cycles=cycles,
                warmup=warmup,
                interval=interval,
                minimum=minimum,
                deadline=deadline,
                progress=result["workload"],
                memory=memory,
            )
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)[:1024]}
        raise
    finally:
        stop.set()
        try:
            if observer is not None:
                await observer
            result["sample_after"] = await asyncio.to_thread(sample)
            memory.set_phase("closed")
            memory.checkpoint("after_workload_return_before_gc")
            result["heap_before_diagnostic_gc"] = heap_sample()
            # Diagnostic only, after normal runtime/child/FD cleanup. Retain the
            # pre-GC measurements; collection must not conceal runtime leaks.
            result["diagnostic_gc_collected_objects"] = gc.collect()
            memory.set_phase("after_gc")
            memory.checkpoint("after_diagnostic_gc")
            result["heap_after_diagnostic_gc"] = heap_sample()
            result["resources_after_close"] = HostResourcePool(pool).snapshot()
            result["sources_unchanged"] = (
                sources == _source_hashes()
                and result["benchmark_source_hashes"] == benchmark_sources()
            )
        except Exception as exc:  # noqa: BLE001 - evidence failure must not mask the workload error
            result["final_observation_error"] = {
                "type": type(exc).__name__,
                "message": str(exc)[:512],
            }
        finally:
            tracemalloc.stop()
            if original_pool is None:
                os.environ.pop("REDJOHN_RESOURCE_POOL_PATH", None)
            else:
                os.environ["REDJOHN_RESOURCE_POOL_PATH"] = original_pool
        try:
            memory.set_phase("after_tracer_stop")
            memory.checkpoint("after_tracemalloc_stop")
            diagnostic = allocator_trim_diagnostic(memory.capture)
            result["allocation_diagnostic"] = diagnostic
            memory.set_phase("after_allocator_trim")
            memory.checkpoint(
                "after_allocator_trim", observation=diagnostic.get("after_observation")
            )
        except Exception as exc:  # noqa: BLE001 - do not mask an earlier workload failure
            result.setdefault(
                "final_observation_error",
                {
                    "type": type(exc).__name__,
                    "message": str(exc)[:512],
                },
            )
        result["elapsed_seconds"] = time.monotonic() - started
        result["sample_before"] = before
        result["samples"] = samples
        result["observation_errors"] = dict(observation_errors)
        metrics = result.get("workload", {})
        if (
            metrics.get("cycles")
            and "error" not in result
            and "final_observation_error" not in result
        ):
            h = metrics["browser_health_after_close"]
            measured = metrics["cycles"][warmup:]
            durations = [r["seconds"] for r in measured]
            result["p50_cycle_seconds"] = statistics.median(durations)
            result["p95_cycle_seconds"] = sorted(durations)[math.ceil(len(durations) * 0.95) - 1]
            result["allocation_observations"] = {
                "controller_traced_growth_after_warmup_bytes": metrics["heap_after_close"][
                    "controller_traced_bytes"
                ]
                - metrics["heap_after_warmup"]["controller_traced_bytes"],
                "retained_cycle_cache_result_json_bytes": len(
                    json.dumps(
                        {"cycles": metrics["cycles"], "cache_pressure": metrics["cache_pressure"]}
                    ).encode()
                ),
                "retained_memory_observation_json_bytes": len(json.dumps(memory.report).encode()),
                "tracer_metadata_before_gc_bytes": result["heap_before_diagnostic_gc"][
                    "tracer_metadata_bytes"
                ],
                "controller_traced_after_diagnostic_gc_bytes": result["heap_after_diagnostic_gc"][
                    "controller_traced_bytes"
                ],
                "closed_cache_payload_bytes": metrics["cache_after_close"]["bytes"],
                "interpretation": (
                    "Compare allocation sites and bounded retained measurement/cache bytes; "
                    "Pre/post diagnostic GC, Linux PSS/private counters, tracer metadata, "
                    "and closed-cache payloads are separate observations, "
                    "not additive RSS attribution. "
                    "Controller tracemalloc cannot fully attribute native/browser RSS growth. "
                    "No leak-free claim."
                ),
            }
            result["checks"] = {
                "synthetic_limits_enforced": result["log_pressure"]["ok"]
                and result["body_pressure"]["ok"],
                "all_cycles_completed": len(metrics["cycles"]) >= cycles,
                "minimum_duration_observed": metrics["timing"]["loop_returned_normally"]
                and metrics["timing"]["loop_elapsed_seconds"] >= minimum,
                "closed_cache_payload_released": metrics["cache_after_close"]["bytes"]
                == metrics["cache_after_close"]["items"]
                == 0,
                "no_owned_process_reservations": result["resources_after_close"]["owners"] == 0
                and result["resources_after_close"]["active"] == {},
                "process_count_returns_to_baseline": result["sample_after"]["process_count"]
                == before["process_count"],
                "listeners_return_to_baseline": before["tcp_listeners"] is not None
                and result["sample_after"]["tcp_listeners"] == before["tcp_listeners"],
                "descriptors_return_to_baseline": before["file_descriptors"] is not None
                and result["sample_after"]["file_descriptors"] is not None
                and result["sample_after"]["file_descriptors"] <= before["file_descriptors"],
                "native_session_empty": metrics["native_session_empty"],
                "pages_contexts_closed": h["pages_created"] == h["pages_closed"]
                and h["contexts_created"] == h["contexts_closed"]
                and h["active_pages"] == h["active_contexts"] == h["active_proxy_connections"] == 0,
                "no_browser_cleanup_errors": h["cleanup_errors"] == 0,
                "actual_budget_matches_requests": metrics["actual_fixture_requests"]
                == metrics["requests_used"],
                "both_actors_observed": {"alice", "bob"} <= set(metrics["observed_actors"]),
                "no_forbidden_mutations": metrics["fixture_counts"].get("unexpected_post", 0) == 0
                and metrics["fixture_counts"].get("/logout", 0) == 0,
                "no_observation_errors": not observation_errors,
                "source_identity_preserved": result["sources_unchanged"],
            }
            result["ok"] = all(result["checks"].values()) and "error" not in result
        file = output / "mixed-soak.json"
        file.write_text(json.dumps(result, indent=2) + "\n")
        file.chmod(0o600)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nuclei-lock", type=Path, required=True)
    parser.add_argument("--httpx-receipt", type=Path, required=True)
    parser.add_argument("--cycles", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--interval-seconds", type=float, default=10)
    parser.add_argument("--minimum-seconds", type=float, default=300)
    args = parser.parse_args()
    receipt = json.loads(args.httpx_receipt.read_text())
    httpx = {
        "binary": {
            "path": str(args.httpx_receipt.resolve().parent / "httpx"),
            "sha256": receipt["binary_sha256"],
            "version": receipt["version"],
        }
    }
    result = asyncio.run(
        run(
            args.output,
            json.loads(args.nuclei_lock.read_text()),
            httpx,
            cycles=args.cycles,
            warmup=args.warmup,
            interval=args.interval_seconds,
            minimum=args.minimum_seconds,
        )
    )
    print(  # noqa: T201 - standalone CLI summary
        json.dumps({key: result.get(key) for key in ("ok", "elapsed_seconds", "checks")})
    )
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
