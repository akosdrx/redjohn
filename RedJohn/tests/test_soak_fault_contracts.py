"""Fault-injection contracts for the benchmark receipt, not live scanner E2E."""

from __future__ import annotations

import importlib
import json
import os
import tracemalloc
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "cycles,warmup,interval,minimum",
    [
        (1, 0, 10, 0),
        (2, 2, 10, 0),
        (2, -1, 10, 0),
        (2, 0, float("nan"), 0),
        (2, 0, 10, float("inf")),
        (1000, 0, 10, 0),
        (2, 0, -1, 0),
    ],
)
def test_invalid_soak_limits_rejected_before_mutation(
    monkeypatch, cycles, warmup, interval, minimum
):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "benchmarks"))
    soak = importlib.import_module("mixed_soak")
    before = os.environ.get("REDJOHN_RESOURCE_POOL_PATH")
    with pytest.raises(ValueError):
        soak.validate(cycles, warmup, interval, minimum)
    assert os.environ.get("REDJOHN_RESOURCE_POOL_PATH") == before


async def test_failed_later_cycle_preserves_partial_receipt_and_original_error(
    tmp_path, monkeypatch
):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "benchmarks"))
    soak = importlib.import_module("mixed_soak")
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", "/original/owned/pool")
    finished = False

    async def synthetic_pressure(*_args):
        return {"ok": True, "evidence_kind": "test_double"}

    async def broken_workload(*_args, progress, **_kwargs):
        nonlocal finished
        progress["cycles"] = [{"cycle": 0, "evidence_kind": "test_double"}]
        finished = True
        raise RuntimeError("later_cycle_failed")

    def sample():
        if finished:
            raise OSError("final_observation_unavailable")
        return {"process_count": 1, "file_descriptors": 7, "tcp_listeners": 0}

    monkeypatch.setattr(soak, "sample", sample)
    monkeypatch.setattr(soak, "log_pressure", synthetic_pressure)
    monkeypatch.setattr(soak, "body_pressure", synthetic_pressure)
    monkeypatch.setattr(soak, "workload", broken_workload)
    with pytest.raises(RuntimeError, match="later_cycle_failed"):
        await soak.run(tmp_path / "evidence", {}, {}, cycles=2, warmup=1, minimum=0)
    receipt = json.loads((tmp_path / "evidence/mixed-soak.json").read_text())
    assert not receipt["ok"]
    assert receipt["workload"]["cycles"][0]["cycle"] == 0
    assert receipt["error"]["message"] == "later_cycle_failed"
    assert receipt["final_observation_error"]["message"] == "final_observation_unavailable"
    assert os.environ["REDJOHN_RESOURCE_POOL_PATH"] == "/original/owned/pool"
    assert not tracemalloc.is_tracing()
