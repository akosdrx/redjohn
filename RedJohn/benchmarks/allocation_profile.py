"""Compact allocation summaries and single-threaded CPython diagnostics.

Only numeric counters and Python source locations are retained. A complete
tracemalloc snapshot is transient, never kept across the benchmark window.
"""

# ruff: noqa: INP001 - standalone benchmark helper

from __future__ import annotations

import os
import re
import sys
import tempfile
import threading
import tracemalloc


MAX_ALLOCATION_SITES = 16384


def allocation_sites(snapshot=None):
    """Match non-cumulative stdlib lineno statistics using the public API.

    Snapshot.statistics caches keys for complete stacks even for a lineno
    grouping. This streaming aggregation retains one numeric pair per site.
    """
    snapshot = tracemalloc.take_snapshot() if snapshot is None else snapshot
    sites = {}
    for trace in snapshot.traces:
        frame = trace.traceback[-1]
        key = (frame.filename, frame.lineno)
        if key not in sites:
            if len(sites) >= MAX_ALLOCATION_SITES:
                raise ValueError("allocation_site_observation_limit")
            sites[key] = [0, 0]
        sites[key][0] += trace.size
        sites[key][1] += 1
    return sites


def largest_sites(sites, limit=12):
    return [
        {"location": f"{filename}:{line}", "bytes": size, "count": count}
        for (filename, line), (size, count) in sorted(
            sites.items(), key=lambda item: (item[1][0], item[1][1], item[0]), reverse=True,
        )[:limit]
    ]


def changed_sites(before, after, limit=12):
    changes = []
    for filename, line in before.keys() | after.keys():
        key = filename, line
        previous, current = before.get(key, (0, 0)), after.get(key, (0, 0))
        changes.append({"location": f"{filename}:{line}",
                        "bytes_diff": current[0] - previous[0],
                        "count_diff": current[1] - previous[1]})
    return sorted(changes, key=lambda item: (
        abs(item["bytes_diff"]), abs(item["count_diff"]), item["location"],
    ), reverse=True)[:limit]


def pymalloc_counters():
    """Read numeric arena counters only before/after asyncio.run, no live threads.

    CPython's diagnostic writes to the C stderr descriptor. Redirect only while
    this fresh benchmark process is single-threaded, restore it before parsing,
    and never export the raw diagnostic or unrelated stderr content.
    """
    if threading.active_count() != 1 or not hasattr(sys, "_debugmallocstats"):
        return {"status": "blocked", "reason": "single_threaded_cpython_probe_required"}
    with tempfile.TemporaryFile() as stream:
        saved = os.dup(2)
        try:
            os.dup2(stream.fileno(), 2)
            sys._debugmallocstats()  # type: ignore[attr-defined]  # CPython diagnostic only
        finally:
            os.dup2(saved, 2)
            os.close(saved)
        stream.seek(0)
        raw = stream.read(32769)
    if len(raw) > 32768:
        return {"status": "blocked", "reason": "pymalloc_counter_output_limit"}
    text = raw.decode("ascii", errors="replace")
    fields = {
        "arenas_current": r"# arenas allocated current\s*=\s*([\d,]+)",
        "arenas_reclaimed": r"# arenas reclaimed\s*=\s*([\d,]+)",
        "arenas_highwater": r"# arenas highwater mark\s*=\s*([\d,]+)",
        "arena_size_bytes": r"arenas \* ([\d,]+) bytes/arena",
        "allocated_block_bytes": r"# bytes in allocated blocks\s*=\s*([\d,]+)",
        "available_block_bytes": r"# bytes in available blocks\s*=\s*([\d,]+)",
        "unused_pool_bytes": r"unused pools \* \d+ bytes\s*=\s*([\d,]+)",
    }
    result = {}
    for name, pattern in fields.items():
        match = re.search(pattern, text)
        if match is None:
            return {"status": "blocked", "reason": "pymalloc_counter_format_unavailable"}
        result[name] = int(match[1].replace(",", ""))
    return {
        "status": "observed", **result,
        "interpretation": "arena reservations and live/free blocks are not resident-page counts",
    }
