"""Real synthetic pressure of production limits; no scanner/provider doubles.

These are process/socket/SQLite/cache integration checks, not a long soak or
vulnerability detection claim. The separate benchmark runs the actual engines.
"""

from __future__ import annotations

import importlib
from pathlib import Path

from redjohn.assessment.cache import SmartCache
from redjohn.assessment.models import Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.store import AssessmentStore


def helpers(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "benchmarks"))
    return importlib.import_module("limit_pressure"), importlib.import_module("mixed_soak")


async def test_actual_supervisor_caps_each_stream_and_removes_owned_markers(tmp_path, monkeypatch):
    pressure, _ = helpers(monkeypatch)
    result = await pressure.log_pressure(tmp_path)
    assert result["ok"], result
    assert {r["channel"] for r in result["channels"]} == {"stdout", "stderr"}
    assert all(r["retained_bytes"] == 512 * 1024 for r in result["channels"])


async def test_actual_proxy_accepts_maximum_wire_and_blocks_one_byte_over(monkeypatch):
    pressure, _ = helpers(monkeypatch)
    result = await pressure.body_pressure()
    assert result["ok"], result
    assert result["trials"][0]["upstream_wire_bytes"] == 8 * 1024**2
    assert result["trials"][1]["complete_observations"] == 0


def test_actual_queue_full_dedup_cancel_and_second_sqlite_reader(tmp_path, monkeypatch):
    _, soak = helpers(monkeypatch)
    store = AssessmentStore(tmp_path / "agents.db")
    try:
        policy = store.register(
            EngagementPolicy(
                "pressure",
                "operator",
                ("https://127.0.0.1:34567",),
                profile="isolated-lab",
                egress_mode="local-fixture",
            )
        )
        sid = store.upsert_surface(
            policy.engagement_id,
            Surface("https://127.0.0.1:34567/", source="imported", workflow_state="approved_seed"),
        )
        result = soak.queue_pressure(store, policy, sid)
        assert result["ok"], result
        assert result["persisted_pending"] == result["cancelled_before_execution"] == 128
        assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 0
    finally:
        store.close()


def test_actual_serialized_cache_pressure_preserves_quota_and_retest_bypass(monkeypatch):
    _, soak = helpers(monkeypatch)
    cache = SmartCache(8 * 1024**2)
    try:
        result = soak.cache_pressure(cache, 1)
        assert result["ok"], result
        assert result["metrics"]["eviction"] >= 3
        assert cache.stats()["oversized"] == cache.stats()["bypass"] == 1
    finally:
        cache.close()
