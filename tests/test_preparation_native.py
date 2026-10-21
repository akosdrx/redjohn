"""Real native version-only preparation in the copied deny-all Linux namespace.

This is not a Kubernetes benchmark/audit, and accesses no cluster/node context.
Missing native installation or kernel capability is blocked, never a pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
from pathlib import Path

import pytest

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


async def test_actual_kube_bench_version_only_inside_deny_all_source_namespace(
    tmp_path, record_testsuite_property
):
    root = Path(__file__).resolve().parents[1] / ".tools/kube-bench/0.16.0"
    if platform.system() != "Linux" or not (root / "provenance.json").is_file():
        reason = (
            "blocked: reviewed Linux native kube-bench version preparation "
            "requires installation/kernel isolation"
        )
        if os.environ.get("REDJOHN_REQUIRE_PREPARATION_E2E") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    receipt = json.loads((root / "provenance.json").read_text())
    binary = receipt["binary"]
    assert binary["path"] == str(root / "kube-bench")
    assert binary["sha256"] == hashlib.sha256((root / "kube-bench").read_bytes()).hexdigest()
    assert receipt["audit_executed"] is False and receipt["version"] == "0.16.0"
    raw = json.dumps(manifest("kube-bench", "version_only")).encode()
    path = tmp_path / "manifest.json"
    path.write_bytes(raw)
    document = {
        "manifest_file": str(path),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "binary": binary,
    }
    config = PreparationConfig.from_mapping("kube-bench", document)
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(
        EngagementPolicy(
            "native-preparation",
            "owner",
            (),
            target_domains=("source",),
            allowed_source_artifacts=(config.artifact_sha256,),
            profile="isolated-lab",
        )
    )
    governor = ResourceGovernor()
    adapter = PreparationAdapter(config, policy, store)
    registry = CapabilityRegistry(kube_bench_config=document)
    scheduler = Scheduler(store, policy, governor, registry, {config.capability: adapter})
    job = store.submit(policy, [preparation_job(config, policy, store)])[0]
    try:
        assert await scheduler.run_until_idle(max_jobs=1) == [job]
        result = store.jobs(policy.engagement_id)[0]
        assert result["execution_status"] == "succeeded", result
        summary = result["result"]["summary"]
        assert summary["audit_executed"] is False and summary["audit_coverage_status"] == "blocked"
        assert summary["engine"]["tool_version"] == "0.16.0"
        assert summary["engine"]["deny_all_namespace_attested"] is True
        assert summary["engine"]["snapshot_readonly_attested"] is True
        assert summary["engine"]["denied_connections"] == 0
        assert not result["result"]["findings"]
        assert store.request_usage(policy) == 0 and governor.snapshot()["active"] == {}
        assert adapter.runner is None
        assert not list((tmp_path / "kube-bench-preparation").glob("job-*"))
        assert not list((tmp_path / "kube-bench-preparation").glob("snapshot-*"))
        record_testsuite_property("kube_bench_preparation_real_version", "0.16.0")
        record_testsuite_property("kube_bench_preparation_binary_sha256", binary["sha256"])
        record_testsuite_property("kube_bench_preparation_audit_executed", "false")
    finally:
        await adapter.cleanup()
        store.close()
