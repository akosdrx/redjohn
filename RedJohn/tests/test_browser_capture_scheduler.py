"""Durable admission controls for browser jobs that may send approved POSTs."""

import pytest

from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore


async def test_missing_browser_capture_configuration_is_blocked_without_io(tmp_path):
    policy = EngagementPolicy(
        "capture-configuration",
        "operator",
        ("https://127.0.0.1:8443",),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("alice",),
        allowed_replay_urls=("https://127.0.0.1:8443/submit",),
    )
    store = AssessmentStore(tmp_path / "agents.db")
    try:
        async with AssessmentRuntime(store, policy, caller="operator") as runtime:
            surface_id = store.upsert_surface(
                policy.engagement_id,
                Surface(
                    policy.allowed_origins[0] + "/app",
                    actor_id="alice",
                    source="imported",
                    workflow_state="approved_seed",
                ),
            )
            with pytest.raises(PolicyDenied, match="requires_nonidempotent_job"):
                store.submit(
                    runtime.policy,
                    [JobSpec(surface_id, "discovery", "browser_post_capture", idempotent=True)],
                )
            assert not store.jobs(policy.engagement_id)
            job_id = store.submit(
                runtime.policy,
                [JobSpec(surface_id, "discovery", "browser_post_capture", idempotent=False)],
            )[0]
            assert await runtime.scheduler.run_batch(max_jobs=1) == [job_id]
            row = store.jobs(policy.engagement_id)[0]
            assert (row["execution_status"], row["coverage_status"]) == ("failed", "blocked")
            assert row["result"]["error"]["code"] == "browser_post_capture_configuration_missing"
            health = next(x for x in runtime.registry.health() if x["id"] == "browser_post_capture")
            assert health["status"] == "blocked_configuration"
            assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 0
    finally:
        store.close()
