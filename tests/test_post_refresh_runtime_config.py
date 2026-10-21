"""Missing refresh configuration is blocked capability, not a negative test."""

from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore


async def test_unconfigured_refresh_job_has_precise_blocked_result(tmp_path):
    policy = EngagementPolicy(
        "missing-refresh",
        "operator",
        ("https://127.0.0.1:8443",),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("alice",),
        allowed_refresh_urls=("https://127.0.0.1:8443/refresh",),
    )
    store = AssessmentStore(tmp_path / "agents.db")
    try:
        async with AssessmentRuntime(store, policy, caller="operator") as runtime:
            surface_id = store.upsert_surface(
                policy.engagement_id,
                Surface(
                    policy.allowed_origins[0] + "/private",
                    actor_id="alice",
                    source="imported",
                    workflow_state="approved_seed",
                ),
            )
            spec = JobSpec(surface_id, "authentication", "session_refresh", idempotent=False)
            job_id = store.submit(runtime.policy, [spec])[0]
            assert await runtime.scheduler.run_batch(max_jobs=1) == [job_id]
            row = store.jobs(policy.engagement_id)[0]
            assert (row["execution_status"], row["coverage_status"]) == ("failed", "blocked")
            assert row["result"]["error"]["code"] == "session_refresh_configuration_missing"
            health = next(x for x in runtime.registry.health() if x["id"] == "session_refresh")
            assert health["status"] == "blocked_configuration"
            assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 0
    finally:
        store.close()
