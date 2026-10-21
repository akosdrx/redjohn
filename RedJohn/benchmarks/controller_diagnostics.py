"""Opt-in controller-only counters for controlled memory attribution.

No object values, frames, process arguments, environment or mapped file paths
are exported. The probes allocate memory themselves; their figures are separate
observations, never additive accounting of RSS or an admission mechanism.
"""

# ruff: noqa: INP001 - standalone benchmark helper

from __future__ import annotations

import ctypes
import gc
import linecache
import re
import sys
import tracemalloc
from collections import Counter
from pathlib import Path

from allocation_profile import allocation_sites


MALLINFO_FIELDS = (
    "arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks", "fsmblks",
    "uordblks", "fordblks", "keepcost",
)
COUNTERS = {"Size", "Rss", "Pss", "Private_Clean", "Private_Dirty"}


class Mallinfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_size_t) for name in MALLINFO_FIELDS]


def mapping_counters(path=Path("/proc/self/smaps")):  # noqa: PLR0912 - fixed mapping categories
    """Aggregate numeric Linux mapping counters without publishing addresses."""
    groups = {}
    group = None
    count = 0
    try:
        with path.open() as handle:
            for line in handle:
                if re.match(r"^[0-9a-f]+-[0-9a-f]+ ", line):
                    count += 1
                    if count > 32768:
                        return {"status": "blocked", "reason": "mapping_count_limit"}
                    name = line.split(maxsplit=5)[-1].strip() if len(line.split()) >= 6 else ""
                    if name == "[heap]":
                        group = "brk_heap"
                    elif name.startswith("[stack"):
                        group = "stack"
                    elif not name or name.startswith("[anon"):
                        group = "anonymous"
                    elif name.startswith("["):
                        group = "kernel_special"
                    elif "/cryptography/" in name:
                        group = "cryptography_file_backed"
                    elif any(part in name for part in ("/libssl.", "/libcrypto.")):
                        group = "openssl_file_backed"
                    else:
                        group = "file_backed"
                    groups.setdefault(group, Counter())["mappings"] += 1
                elif group is not None:
                    fields = line.split()
                    key = fields[0].rstrip(":") if fields else ""
                    if key in COUNTERS:
                        if len(fields) != 3 or fields[2] != "kB":
                            return {"status": "blocked", "reason": "unexpected_smaps_unit"}
                        groups[group][key + "_bytes"] += int(fields[1]) * 1024
        if not groups or any(
            not {key + "_bytes" for key in COUNTERS} <= counters.keys()
            for counters in groups.values()
        ):
            return {"status": "blocked", "reason": "incomplete_mapping_counters"}
        return {"status": "observed", "mapping_count": count, "groups": dict(groups)}
    except (OSError, ValueError, IndexError):
        return {"status": "blocked", "reason": "linux_smaps_unavailable"}


class ControllerDiagnostics:
    """Fixed checkpoint summaries; never retain a heap/object snapshot."""

    def __init__(self, *, compact_summaries=True):
        self.initial_modules = frozenset(sys.modules)
        self.mallinfo = None
        self.compact_summaries = compact_summaries
        if sys.platform == "linux":
            try:
                library = ctypes.CDLL(None)
                function = library.mallinfo2
                function.argtypes, function.restype = [], Mallinfo
                self.mallinfo = function
            except (OSError, AttributeError):
                pass

    def capture(self):
        # Counter construction is intentionally last: avoid retaining the
        # gc.get_objects() list while reading mapping/allocator counters.
        modules = sorted(
            name for name in set(sys.modules) - self.initial_modules
            if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.]*", name)
        )
        cache = list(linecache.cache.values())
        value = {
            "measurement": "controller_checkpoint_not_additive_rss_accounting",
            "python_allocated_blocks": sys.getallocatedblocks(),
            "module_count": len(sys.modules),
            "new_modules": modules[:2048],
            "new_modules_truncated": len(modules) > 2048,
            "linecache_files": len(cache),
            "linecache_source_bytes": sum(
                sum(sys.getsizeof(line) for line in entry[2])
                for entry in cache if len(entry) == 4
            ),
            "mappings": mapping_counters(),
        }
        if self.mallinfo is None:
            value["glibc_allocator"] = {"status": "blocked", "reason": "mallinfo2_unavailable"}
        else:
            measured = self.mallinfo()
            value["glibc_allocator"] = {
                "status": "observed", **{name: getattr(measured, name) for name in MALLINFO_FIELDS}
            }
        if tracemalloc.is_tracing():
            groups = Counter()
            if self.compact_summaries:
                sites = allocation_sites()
                rows = ((name, size) for (name, _line), (size, _count) in sites.items())
            else:
                snapshot = tracemalloc.take_snapshot()
                rows = ((item.traceback[0].filename, item.size)
                        for item in snapshot.statistics("filename"))
            for name, size in rows:
                category = (
                    "playwright" if "/playwright/" in name else
                    "redjohn_runtime" if "/redjohn/" in name.lower() else
                    "benchmark" if "/benchmarks/" in name else
                    "imports" if name.startswith("<frozen importlib") else
                    "source_cache" if name.endswith("/linecache.py") else
                    "other_python"
                )
                groups[category] += size
            value["traced_allocation_groups_bytes"] = dict(groups)
        objects = gc.get_objects()
        selected = Counter()
        for item in objects:
            module = type(item).__module__
            if isinstance(module, str) and module.startswith(
                ("playwright.", "redjohn.assessment.")
            ):
                selected[module + "." + type(item).__name__] += 1
        value["gc_tracked_objects"] = len(objects)
        del objects
        value["live_component_types"] = dict(sorted(selected.items())[:512])
        return value
