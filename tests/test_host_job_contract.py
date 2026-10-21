"""Real SQLite/control admission contracts, without executing a worker."""

import pytest

from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.models import Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.store import AssessmentStore


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "host.sqlite3"))
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(
        EngagementPolicy(
            "job-admission",
            "operator",
            ("https://127.0.0.1:8443",),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice"),
        )
    )
    api = AssessmentControl(store, policy, caller="operator")
    try:
        yield api
    finally:
        api.close()
        api.governor.close()
        store.close()


@pytest.mark.parametrize(
    "capability,method",
    [
        ("session_refresh", "GET"),
        ("browser_post_capture", "GET"),
        ("nuclei_scan", "POST"),
    ],
)
@pytest.mark.parametrize("unsafe_retry_flag", [False, True])
async def test_mutating_job_flags_are_derived_or_rejected_before_any_worker(
    service, capability, method, unsafe_retry_flag
):
    policy = service.policy
    sid = service.store.upsert_surface(
        policy.engagement_id,
        Surface(policy.allowed_origins[0] + "/private", method=method, actor_id="alice"),
    )
    value = {"surface_id": sid, "family": "authentication", "capability": capability}
    if unsafe_retry_flag:
        value["idempotent"] = True
    result = await service.call(
        "jobs_submit_batch", {"policy_revision": policy.revision, "jobs": [value]}
    )
    jobs = service.store.jobs(policy.engagement_id)
    if unsafe_retry_flag:
        assert result["error"]["code"] == "policy_denied"
        assert jobs == []
    else:
        assert result["ok"] is True, result
        assert len(jobs) == 1
        assert jobs[0]["spec"]["idempotent"] is False
        assert jobs[0]["execution_status"] == "queued"
    assert service.store.request_usage(policy) == 0
