"""Reproducible local cache workload; no network, scanner, browser or model calls."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
import tracemalloc
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redjohn.assessment.cache import SmartCache
from redjohn.assessment.resources import process_tree_memory


def benchmark(*, cycles: int = 20, lookups_per_cycle: int = 2000) -> dict[str, Any]:
    if not 2 <= cycles <= 1000 or not 1 <= lookups_per_cycle <= 100000:
        raise ValueError("benchmark workload exceeds configured bounds")
    cache = SmartCache(512 * 1024, max_items=64)
    durations, memory_samples = [], []
    tracemalloc.start()
    started = time.perf_counter()
    try:
        for key in range(64):
            cache.set(str(key), {"parsed_js": "x" * 4096, "version": "fixture-1"}, 3600)
        warm = process_tree_memory()
        for _cycle in range(cycles):
            phase_start = time.perf_counter()
            for index in range(lookups_per_cycle):
                value = cache.get(str(index % 64))
                if not isinstance(value, dict) or value.get("version") != "fixture-1":
                    raise RuntimeError("benchmark cache fixture unexpectedly missing")
            durations.append(time.perf_counter() - phase_start)
            memory_samples.append(process_tree_memory())
        current, peak = tracemalloc.get_traced_memory()
        cache_stats = cache.stats()
        freed_bytes = cache.trim()
    finally:
        tracemalloc.stop()
        cache.close()
    after = process_tree_memory()
    available = [sample.rss_bytes for sample in memory_samples if sample.available]
    return {
        "benchmark": "actual_local_json_cache_workload",
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "cycles": cycles,
        "lookups_per_cycle": lookups_per_cycle,
        "warm_entries": 64,
        "cache_max_bytes": 512 * 1024,
        "cache": cache_stats,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
        "cycle_p50_seconds": round(statistics.median(durations), 6),
        "cycle_p95_seconds": round(sorted(durations)[math.ceil(cycles * 0.95) - 1], 6),
        "warm_memory": asdict(warm),
        "peak_sampled_process_tree_rss_bytes": max(available) if available else None,
        "last_memory": asdict(memory_samples[-1]),
        "after_trim_memory": asdict(after),
        "trim_released_cache_bytes": freed_bytes,
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
        "old_implementation_baseline": "baseline_unavailable",
        "llm_calls": 0,
        "http_requests": 0,
        "limitations": [
            "Local JSON cache workload, not browser or full-platform soak",
            "No old/new comparison; no detector coverage or speedup claim",
            "Summed RSS may double-count shared pages and include the ps helper",
            "RSS need not fall immediately after Python objects are released",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycles", type=int, default=20)
    parser.add_argument("--lookups-per-cycle", type=int, default=2000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(
        benchmark(cycles=args.cycles, lookups_per_cycle=args.lookups_per_cycle), indent=2
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result + "\n", encoding="utf-8")
    print(result)  # noqa: T201 - explicit benchmark CLI output


if __name__ == "__main__":
    main()
