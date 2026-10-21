#!/usr/bin/env python3
"""Observe repeated real local HTTPS Chromium jobs through the existing scheduler.

No target URL, engine output, clock, result or resource observation is mocked.
The paced workload preserves the normal origin quota and explicitly retests
the same fixture using two actor contexts. No Nuclei lock or optional scanner
starts. Scanner, cache-pressure and maximum-queue soaks are separate.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import platform
import selectors
import shutil
import sqlite3
import statistics
import subprocess
import sys
import time
from collections import Counter
from contextlib import suppress
from dataclasses import asdict
from pathlib import Path
from typing import Any

import redjohn
from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.host_resources import HostResourcePool
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import process_tree_memory
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer


def _command(argv: list[str]) -> tuple[str, int, int, int]:
    # Callers supply only fixed ps/lsof options and observed numeric PIDs.
    process = subprocess.Popen(  # noqa: S603 - no user/target command or arguments
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    deadline = time.monotonic() + 3
    stdout = bytearray()
    stderr_bytes = 0
    try:
        assert process.stdout is not None and process.stderr is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sampler_deadline")
                for key, _ in selector.select(remaining):
                    piece = os.read(key.fd, 65536)
                    if not piece:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is process.stdout:
                        stdout.extend(piece)
                    else:
                        stderr_bytes += len(piece)
                    if len(stdout) + stderr_bytes > 2 * 1024**2:
                        raise RuntimeError("sampler_output_limit")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return stdout.decode("utf-8", "strict"), code, process.pid, stderr_bytes
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def _linux_fds(pids: set[int]) -> dict[str, int | None]:
    descriptors, sockets, missing = 0, set(), 0
    for pid in pids:
        try:
            for fd in Path(f"/proc/{pid}/fd").iterdir():
                try:
                    target = fd.readlink().as_posix()
                except FileNotFoundError:
                    continue
                descriptors += 1
                if target.startswith("socket:["):
                    sockets.add(target[8:-1])
        except (OSError, ValueError):
            missing += 1
    try:
        listeners = {
            fields[9]
            for file in ("/proc/net/tcp", "/proc/net/tcp6")
            for line in Path(file).read_text().splitlines()[1:]
            if len(fields := line.split()) > 9 and fields[3] == "0A"
        }
        listening: int | None = len(sockets & listeners)
    except OSError:
        listening = None
    return {
        "file_descriptors": descriptors if not missing else None,
        "tcp_listeners": listening if not missing else None,
        "inaccessible_processes": missing,
    }


def _mac_fds(pids: set[int]) -> dict[str, int | None]:
    executable = shutil.which("lsof")
    if executable is None:
        return {"file_descriptors": None, "tcp_listeners": None}
    owners = ",".join(str(pid) for pid in sorted(pids))
    descriptors, code, _, _ = _command([executable, "-nP", "-a", "-p", owners, "-Fpf"])
    listeners, listen_code, _, listen_errors = _command(
        [
            executable,
            "-nP",
            "-a",
            "-p",
            owners,
            "-iTCP",
            "-sTCP:LISTEN",
            "-Fpf",
        ]
    )

    def count(value: str) -> int:
        return sum(line.startswith("f") and line[1:2].isdigit() for line in value.splitlines())

    no_listeners = listen_code == 1 and not listeners and not listen_errors
    return {
        "file_descriptors": count(descriptors) if code == 0 else None,
        "tcp_listeners": count(listeners) if listen_code == 0 or no_listeners else None,
    }


def sample() -> dict[str, Any]:
    started = time.monotonic()
    raw, code, sampler_pid, _ = _command(["/bin/ps", "-axo", "pid=,ppid=,rss="])
    if code:
        raise RuntimeError("process_observation_unavailable")
    rows = [tuple(map(int, line.split())) for line in raw.splitlines()]
    pids = {os.getpid()}
    while True:
        children = {pid for pid, parent, _ in rows if parent in pids and pid != sampler_pid}
        if children <= pids:
            break
        pids.update(children)
    result: dict[str, Any] = {
        "sample_monotonic": started,
        "process_count": len(pids),
        "summed_rss_bytes": sum(rss * 1024 for pid, _, rss in rows if pid in pids),
    }
    result.update(_linux_fds(pids) if sys.platform == "linux" else _mac_fds(pids))
    result["sampling_seconds"] = time.monotonic() - started
    return result


async def _workload(
    output: Path, *, cycles: int, interval: float, deadline_seconds: float
) -> dict[str, Any]:
    with TLSFixtureServer() as fixture:
        policy = EngagementPolicy(
            engagement_id=f"browser-soak-{time.time_ns()}",
            owner_id="local-operator",
            allowed_origins=(fixture.origin,),
            allowed_ips=("127.0.0.1/32",),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice", "bob"),
            request_budget=max(128, cycles * 12),
            deadline=time.time() + deadline_seconds,
        )
        store = AssessmentStore(output / ".state/agents.db")
        try:
            async with AssessmentRuntime(
                store,
                policy,
                caller=policy.owner_id,
                browser_limits=BrowserLimits(readiness_selector="body[data-actor]"),
                browser_tls=BrowserTLSConfig(upstream_ca_file=str(fixture.ca_file)),
                actor_states={actor: fixture.actor_state(actor) for actor in ("alice", "bob")},
            ) as app:
                durations, memory, cycle_resources = [], [], []
                for index in range(cycles):
                    tick = time.monotonic()
                    actor = "alice" if index % 2 == 0 else "bob"
                    sid = store.upsert_surface(
                        policy.engagement_id,
                        Surface(
                            fixture.origin + "/",
                            actor_id=actor,
                            source="imported",
                            workflow_state="approved_seed",
                        ),
                    )
                    store.submit(
                        policy,
                        [
                            JobSpec(
                                sid,
                                "discovery",
                                "browser_discover",
                                retest_revision=str(index),
                                policy_revision=policy.revision,
                            )
                        ],
                    )
                    await app.scheduler.run_batch(max_jobs=1)
                    durations.append(time.monotonic() - tick)
                    memory.append(asdict(await asyncio.to_thread(process_tree_memory)))
                    cycle_resources.append(await asyncio.to_thread(sample))
                    if index < cycles - 1:
                        await asyncio.sleep(max(0, interval - (time.monotonic() - tick)))
                cache = app.control.cache.stats()
            return {
                "cycle_seconds": durations,
                "process_memory_samples": memory,
                "cycle_resource_samples": cycle_resources,
                "browser_health_after_close": app.browser.healthcheck(),
                "http_requests": sum(fixture.counts.values()),
                "fixture_request_counts": dict(fixture.counts),
                "observed_http_actors": sorted({row["actor"] for row in fixture.observed_actors}),
                "cache": cache,
                "model_calls": 0,
            }
        finally:
            store.close()


def _cleanup_checks(
    output: Path, metrics: dict[str, Any], host: dict[str, Any], cycles: int
) -> dict[str, bool]:
    with sqlite3.connect(f"file:{output / '.state/agents.db'}?mode=ro", uri=True) as db:
        states = db.execute(
            "SELECT execution_status, COUNT(*) FROM rj_job "
            "WHERE capability='browser_discover' GROUP BY execution_status"
        ).fetchall()
    health = metrics["browser_health_after_close"]
    return {
        "all_browser_cycles_succeeded": dict(states) == {"succeeded": cycles},
        "pages_closed": health["pages_created"] == health["pages_closed"],
        "contexts_closed": health["contexts_created"] == health["contexts_closed"],
        "no_active_browser_objects": health["active_pages"] == health["active_contexts"] == 0,
        "no_proxy_connections": health["active_proxy_connections"] == 0,
        "no_browser_cleanup_errors": health["cleanup_errors"] == 0,
        "no_host_reservations": host["owners"] == 0 and host["active"] == {},
        "no_fixture_post": metrics["fixture_request_counts"].get("unexpected_post", 0) == 0,
        "both_actor_cookies_observed": cycles == 1
        or {"alice", "bob"} <= set(metrics["observed_http_actors"]),
    }


def _deadline_budget(cycles: int, warmup: int, interval: float) -> float:
    if not 1 <= cycles <= 1000 or not 0 <= warmup < cycles:
        raise ValueError("require_1_to_1000_cycles_and_a_smaller_nonnegative_warmup")
    if not math.isfinite(interval) or not 0 <= interval <= 60:
        raise ValueError("interval_must_be_finite_and_between_0_and_60")
    deadline_seconds = max(60, cycles * (interval + 2) + 30)
    if deadline_seconds > 3600:
        raise ValueError("workload_exceeds_one_hour_budget")
    return deadline_seconds


def _source_hashes() -> dict[str, str]:
    assert redjohn.__file__ is not None
    root = Path(redjohn.__file__).resolve().parent
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*.py"))
    }


async def _observe(
    samples: list[dict[str, Any]], errors: Counter[str], stop: asyncio.Event
) -> None:
    while not stop.is_set():
        try:
            samples.append(await asyncio.to_thread(sample))
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            errors[type(exc).__name__] += 1
        if len(samples) >= 1500:
            return
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=0.5)


async def run(output: Path, *, cycles: int, warmup: int, interval: float = 5) -> dict[str, Any]:
    deadline_seconds = _deadline_budget(cycles, warmup, interval)
    sampler_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    source_hashes = _source_hashes()
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("output_directory_must_be_empty")
    pool = output / ".state/host-resources.sqlite3"
    original_pool = os.environ.get("REDJOHN_RESOURCE_POOL_PATH")
    samples: list[dict[str, Any]] = []
    sampling_errors: Counter[str] = Counter()
    stop_observer = asyncio.Event()

    before = await asyncio.to_thread(sample)
    started = time.monotonic()
    observer = asyncio.create_task(_observe(samples, sampling_errors, stop_observer))
    os.environ["REDJOHN_RESOURCE_POOL_PATH"] = str(pool)
    try:
        metrics = await asyncio.wait_for(
            _workload(output, cycles=cycles, interval=interval, deadline_seconds=deadline_seconds),
            timeout=deadline_seconds + 5,
        )
    finally:
        try:
            stop_observer.set()
            await observer
        finally:
            if original_pool is None:
                os.environ.pop("REDJOHN_RESOURCE_POOL_PATH", None)
            else:
                os.environ["REDJOHN_RESOURCE_POOL_PATH"] = original_pool
    after = await asyncio.to_thread(sample)
    health = metrics["browser_health_after_close"]
    host = HostResourcePool(pool).snapshot()
    observations = metrics["process_memory_samples"][warmup:]
    rss = [row["rss_bytes"] for row in observations if row["available"]]
    durations = metrics["cycle_seconds"][warmup:]
    checks = _cleanup_checks(output, metrics, host, cycles)
    checks["process_observation_complete"] = not sampling_errors
    checks["sampler_source_unchanged"] = (
        sampler_hash == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    )
    checks["runtime_sources_unchanged"] = source_hashes == _source_hashes()
    result = {
        "product": "RedJohn",
        "measurement": "real_local_https_browser_repeated_workload",
        "platform": platform.platform(),
        "python": sys.version,
        "sampler_sha256": sampler_hash,
        "runtime_source_hashes": source_hashes,
        "cycles": cycles,
        "warmup_cycles": warmup,
        "minimum_cycle_interval_seconds": interval,
        "deadline_budget_seconds": deadline_seconds,
        "elapsed_seconds": time.monotonic() - started,
        "target_sample_sleep_seconds": 0.5,
        "sampling_method": (
            "ps tree excluding observer child; proc fd/socket inodes on Linux, "
            "lsof on macOS; RSS can count shared pages multiple times"
        ),
        "observation_coverage": {
            "sampling_errors": dict(sampling_errors),
            "file_descriptors": "observed"
            if before["file_descriptors"] is not None and after["file_descriptors"] is not None
            else "unavailable",
            "tcp_listeners": "observed"
            if before["tcp_listeners"] is not None and after["tcp_listeners"] is not None
            else "unavailable",
        },
        "sample_before": before,
        "samples": samples,
        "sample_after": after,
        "post_warmup_cycle_rss_bytes": rss,
        "post_warmup_cycle_resource_samples": metrics["cycle_resource_samples"][warmup:],
        "post_warmup_cycle_process_counts": [row["process_count"] for row in observations],
        "p50_seconds": statistics.median(durations),
        "p95_seconds": sorted(durations)[math.ceil(len(durations) * 0.95) - 1],
        "peak_sampled_tree_rss_bytes": max(
            row["summed_rss_bytes"] for row in [before, *samples, after]
        ),
        "http_requests": metrics["http_requests"],
        "model_calls": metrics["model_calls"],
        "browser_health_after_close": health,
        "cache": metrics["cache"],
        "resources_after_close": host,
        "checks": checks,
        "ok": all(checks.values()),
        "baseline": "baseline_unavailable",
        "coverage_limits": [
            "HTTPS_browser_fixture_only",
            "no_Nuclei_or_optional_scanner_started",
            "not_a_scanner_soak",
            "cache_pressure_and_maximum_queue_not_exercised",
            "no_vulnerability_oracle_or_RCE_proof",
            "no_long_duration_claim",
            "process_observation_can_race_child_exit",
        ],
    }
    file = output / "browser-soak.json"
    file.write_text(json.dumps(result, indent=2) + "\n")
    file.chmod(0o600)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--interval-seconds", type=float, default=5)
    args = parser.parse_args()
    result = asyncio.run(
        run(args.output, cycles=args.cycles, warmup=args.warmup, interval=args.interval_seconds)
    )
    print(  # noqa: T201 - standalone benchmark emits a bounded JSON summary
        json.dumps(
            {
                key: result[key]
                for key in (
                    "ok",
                    "cycles",
                    "elapsed_seconds",
                    "peak_sampled_tree_rss_bytes",
                    "checks",
                    "coverage_limits",
                )
            },
            indent=2,
        )
    )
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
