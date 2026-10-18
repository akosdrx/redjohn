"""Actual engines, HTTPS server and four separate RedJohn CLI processes."""

from __future__ import annotations

import json
import os
from pathlib import Path

from redjohn.assessment.https_verification import https_demo
from tests.test_nuclei_live import DEFAULT_LOCK, existing_live_lock


async def test_actual_https_browser_inventory_nuclei_durable_process_restart(tmp_path: Path):
    existing_live_lock()  # Explicit skipped capability when dependency is absent.
    measurements = await https_demo(
        tmp_path, Path(os.environ.get("REDJOHN_NUCLEI_LOCK", str(DEFAULT_LOCK)))
    )
    assert len({row["pid"] for row in measurements["processes"]}) == 4
    assert all(row["exit_code"] == 0 for row in measurements["processes"])
    assert measurements["initial_candidates"] == 1
    assert measurements["fixed_control_new_findings"] == 0
    assert measurements["restart_duplicate_requests"] == 0
    assert measurements["http_requests"] == measurements["persisted_requests_used"]
    assert measurements["inventory_source"] == "observed"
    assert measurements["model_calls"] == 0
    if output := os.environ.get("REDJOHN_HTTPS_E2E_MEASUREMENTS"):
        Path(output).write_text(json.dumps(measurements, indent=2) + "\n")
