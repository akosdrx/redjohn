#!/usr/bin/env python3
"""Fixed, fresh-process attribution controls; no arbitrary target or command.

Imports the same benchmark before the cold baseline. Import-only and synthetic
controls are explicitly not scanner/integration proof. Actual mixed E2E uses
mixed_soak.py and its scheduler/positive/fixed oracles separately.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import mixed_soak
from controller_diagnostics import ControllerDiagnostics
from memory_profile import allocator_trim_diagnostic, process_memory_sample


async def probe(case, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    details = ControllerDiagnostics()
    # Prepare the measuring machinery before the control's baseline.
    details.capture()
    observations = []

    def capture():
        return {"memory": process_memory_sample(), "details": details.capture()}

    def checkpoint(name):
        observations.append({"checkpoint": name, **capture()})

    started = time.monotonic()
    checkpoint("before")
    if case == "playwright_import":
        import playwright.async_api  # noqa: PLC0415, F401
    elif case == "tls_fixture":
        with mixed_soak.TLSFixtureServer():
            checkpoint("active")
    elif case == "synthetic_pressure":
        await mixed_soak.log_pressure(output)
        await mixed_soak.body_pressure()
    elif case != "idle":
        raise ValueError("unsupported_fixed_control")
    checkpoint("after")
    collected = gc.collect()
    checkpoint("after_gc")
    trim = allocator_trim_diagnostic(capture)
    checkpoint("after_trim")
    document = {
        "product": "RedJohn", "commit_sha": os.environ.get("GITHUB_SHA"),
        "measurement": "controlled_controller_attribution_not_scanner_evidence",
        "case": case, "python": sys.version, "observations": observations,
        "elapsed_seconds": time.monotonic() - started,
        "gc_collected": collected, "allocator_trim": trim,
        "benchmark_source_hashes": mixed_soak.benchmark_sources(),
        "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "ok": all(item["memory"]["status"] == "complete" for item in observations),
    }
    path = output / "controller-probe.json"
    path.write_text(json.dumps(document, indent=2) + "\n")
    path.chmod(0o600)
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=(
        "idle", "playwright_import", "tls_fixture", "synthetic_pressure",
    ), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = asyncio.run(probe(args.case, args.output))
    print(json.dumps({"case": args.case, "ok": result["ok"]}))  # noqa: T201
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
