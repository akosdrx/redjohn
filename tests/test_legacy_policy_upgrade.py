"""Actual legacy SQLite documents remain resumable after additive replay fields."""

import json
from contextlib import closing
from dataclasses import replace

import pytest

from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.store import AssessmentStore


def test_legacy_policy_and_surface_keep_revision_and_job_identity(tmp_path):
    database = tmp_path / "agents.db"
    original = EngagementPolicy(
        "legacy",
        "owner",
        ("https://127.0.0.1:8443",),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )
    with closing(AssessmentStore(database)) as store:
        policy = store.register(original)
        surface_id = store.upsert_surface(
            policy.engagement_id, Surface(policy.allowed_origins[0] + "/")
        )
        spec = JobSpec(surface_id, "configuration", "headers_audit")
        job_id = store.submit(policy, [spec])[0]
        legacy = policy.to_dict()
        del legacy["allowed_replay_urls"], legacy["allowed_refresh_urls"]
        old_surface = json.loads(
            store.db.execute("SELECT payload FROM rj_surface WHERE id=?", (surface_id,)).fetchone()[
                0
            ]
        )
        del old_surface["body_sha256"]
        store.db.execute("UPDATE rj_engagement SET policy=?", (json.dumps(legacy),))
        store.db.execute(
            "UPDATE rj_surface SET payload=? WHERE id=?", (json.dumps(old_surface), surface_id)
        )
    with closing(AssessmentStore(database)) as reopened:
        current = reopened.register(original)
        assert current.revision == policy.revision and current.deadline == policy.deadline
        assert (
            reopened.upsert_surface(
                current.engagement_id, Surface(current.allowed_origins[0] + "/")
            )
            == surface_id
        )
        assert reopened.submit(current, [spec]) == [job_id]
        assert reopened.surface(current.engagement_id, surface_id).body_sha256 == ""
        assert len(reopened.jobs(current.engagement_id)) == 1
        with pytest.raises(PolicyDenied, match="policy_change_requires_new_revision"):
            reopened.register(
                replace(current, allowed_replay_urls=(current.allowed_origins[0] + "/post",))
            )
