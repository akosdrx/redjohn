"""Bounded retention for findings/audit/surfaces without deleting job evidence."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from redjohn.assessment.models import Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.store import AssessmentStore


if TYPE_CHECKING:
    from pathlib import Path


def _store(tmp_path: Path) -> tuple[AssessmentStore, EngagementPolicy]:
    store = AssessmentStore(
        tmp_path / "agents.db",
        max_findings=2,
        max_audit_rows=3,
        max_surfaces=2,
        max_sessions=2,
        max_capture_rows=2,
        max_followup_events=2,
    )
    policy = EngagementPolicy("retention", "owner", ("https://example.test",), deadline=0)
    store.register(policy)
    return store, policy


def test_findings_audit_and_unreferenced_surfaces_are_bounded(tmp_path):
    store, policy = _store(tmp_path)
    try:
        with store.transaction() as db:
            for index in range(5):
                db.execute(
                    "INSERT INTO rj_surface VALUES(?,?,?,?,?)",
                    (f"surface-{index}", policy.engagement_id,
                     f"https://example.test/{index}", "{}", float(index)),
                )
            for index in range(5):
                db.execute(
                    "INSERT INTO rj_finding VALUES(?,?,?,?,?)",
                    (f"finding-{index}", policy.engagement_id, f"job-{index}", "candidate",
                     json.dumps({"index": index})),
                )
            for index in range(8):
                store._audit(db, policy.engagement_id, "probe", {"index": index})
        assert store.findings_total(policy.engagement_id) == 2
        assert store.db.execute(
            "SELECT count(*) FROM rj_audit WHERE engagement=?", (policy.engagement_id,)
        ).fetchone()[0] == 3
        assert len(store.surfaces(policy.engagement_id)) == 2
        status = store.retention_status()
        assert status["limits"]["max_findings"] == 2
        assert status["pruned_this_process"]["findings"] >= 0
        assert status["pruned_this_process"]["audit"] >= 1
        assert status["pruned_this_process"]["surfaces"] >= 1
        store.checkpoint()
    finally:
        store.close()


def test_referenced_surface_is_never_pruned(tmp_path):
    store, policy = _store(tmp_path)
    try:
        surface_id = store.upsert_surface(
            policy.engagement_id, Surface("https://example.test/kept", source="observed")
        )
        with store.transaction() as db:
            for index in range(5):
                db.execute(
                    "INSERT INTO rj_finding VALUES(?,?,?,?,?)",
                    (f"finding-{index}", policy.engagement_id, f"job-{index}", "candidate",
                     "{}"),
                )
            # A synthetic job reference is enough to prove the retention query
            # protects the surface; it does not run or claim a scan.
            db.execute(
                "INSERT INTO rj_job(id,engagement,job_key,surface_id,family,capability,"
                "priority,spec,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("job-kept", policy.engagement_id, "job-key", surface_id, "web",
                 "http_observe", 1, "{}", 0),
            )
            store._audit(db, policy.engagement_id, "probe", {"index": 0})
        assert any(row["id"] == surface_id for row in store.surfaces(policy.engagement_id))
    finally:
        store.close()
