"""Actual persistent preparation scheduler; no engine or cloud/cluster audit."""

from __future__ import annotations

import hashlib
import json

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment, enqueue_configured_jobs
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.preparation_tools import (
    PreparationAdapter,
    PreparationConfig,
    preparation_job,
)
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.scheduler import Scheduler
from redjohn.assessment.store import AssessmentStore
from tests.test_preparation_tools_contract import manifest


@pytest.mark.parametrize("tool", ["prowler", "kube-bench"])
async def test_real_scheduler_input_manifest_restart_is_not_a_live_audit(tmp_path, tool):
    path = tmp_path / "manifest.json"
    raw = json.dumps(manifest(tool)).encode()
    path.write_bytes(raw)
    document = {"manifest_file": str(path), "manifest_sha256": hashlib.sha256(raw).hexdigest()}
    config = PreparationConfig.from_mapping(tool, document)
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(
        EngagementPolicy(
            "preparation",
            "owner",
            (),
            target_domains=("source",),
            allowed_source_artifacts=(config.artifact_sha256,),
        )
    )
    registry = CapabilityRegistry(
        **{"prowler_config" if tool == "prowler" else "kube_bench_config": document}
    )
    governor = ResourceGovernor()
    adapter = PreparationAdapter(config, policy, store)
    scheduler = Scheduler(store, policy, governor, registry, {config.capability: adapter})
    spec = preparation_job(config, policy, store)
    job = store.submit(policy, [spec])[0]
    assert adapter.runner is None
    assert await scheduler.run_until_idle(max_jobs=1) == [job]
    row = store.jobs(policy.engagement_id)[0]
    assert row["execution_status"] == "succeeded", row
    assert row["result"]["summary"]["audit_executed"] is False
    assert row["result"]["summary"]["audit_coverage_status"] == "blocked"
    assert not row["result"]["findings"]
    assert governor.snapshot()["active"] == {} and adapter.runner is None
    assert store.request_usage(policy) == 0
    store.close()
    store = AssessmentStore(tmp_path / "state.db")
    resumed = Scheduler(
        store,
        policy,
        governor,
        registry,
        {config.capability: PreparationAdapter(config, policy, store)},
    )
    assert store.submit(policy, [preparation_job(config, policy, store)]) == [job]
    assert await resumed.run_until_idle(max_jobs=1) == []
    assert (
        store.db.execute(
            "SELECT count(*) FROM rj_evidence WHERE kind='approved_preparation_input'"
        ).fetchone()[0]
        == 1
    )
    store.close()


@pytest.mark.parametrize("tool", ["prowler", "kube-bench"])
async def test_configured_preparation_composition_is_lazy_and_persists_without_audit(
    tmp_path, monkeypatch, tool
):
    monkeypatch.setenv("REDJOHN_HOST_RESOURCE_DB", str(tmp_path / "host-pool.db"))
    path = tmp_path / "manifest.json"
    raw = json.dumps(manifest(tool)).encode()
    path.write_bytes(raw)
    document = {"manifest_file": str(path), "manifest_sha256": hashlib.sha256(raw).hexdigest()}
    selected = PreparationConfig.from_mapping(tool, document)
    config = {
        "policy": {
            "engagement_id": "configured-preparation",
            "owner_id": "operator",
            "allowed_origins": [],
            "target_domains": ["source"],
            "allowed_source_artifacts": [selected.artifact_sha256],
        },
        "prowler" if tool == "prowler" else "kube_bench": document,
        "preparation_jobs": [{"capability": selected.capability, "timeout_seconds": 20}],
    }
    output = tmp_path / "assessment"
    async with ConfiguredAssessment(config, output, caller="operator") as assessment:
        adapter = assessment.runtime.scheduler.adapters[selected.capability]
        assert adapter.runner is None
        queued = assessment.store.jobs(assessment.policy.engagement_id)
        assert len(queued) == 1 and queued[0]["execution_status"] == "queued"
        enqueue_configured_jobs(assessment.runtime, assessment.store, assessment.policy, config)
        job = assessment.store.jobs(assessment.policy.engagement_id)[0]
        assert adapter.runner is None
        assert await assessment.runtime.scheduler.run_until_idle(max_jobs=1) == [job["id"]]
        done = assessment.store.jobs(assessment.policy.engagement_id)[0]
        assert done["execution_status"] == "succeeded", done
        assert done["result"]["summary"]["audit_executed"] is False
        assert not done["result"]["findings"]
        assert assessment.runtime.governor.snapshot()["active"] == {}
    async with ConfiguredAssessment(config, output, caller="operator") as assessment:
        enqueue_configured_jobs(assessment.runtime, assessment.store, assessment.policy, config)
        assert await assessment.runtime.scheduler.run_until_idle(max_jobs=1) == []
        assert len(assessment.store.jobs(assessment.policy.engagement_id)) == 1
