"""Preparation/file/SQLite contracts and MOCK imported provider report data.

No AWS account, kubeconfig, node or real provider/cluster audit is accessed.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.preparation_reports import summarize_kube_bench, summarize_prowler_ocsf
from redjohn.assessment.preparation_tools import (
    PreparationAdapter,
    PreparationConfig,
    preparation_job,
)
from redjohn.assessment.store import AssessmentStore


def manifest(tool, operation="manifest_validate"):
    common = {"version": 1, "tool": tool, "operation": operation, "live_authorization": "deferred"}
    return (
        {
            **common,
            "provider": "aws",
            "account_id": "000000000000",
            "profile": "owned-fixture",
            "regions": ["us-east-1"],
            "checks": ["s3_bucket_public_access"],
        }
        if tool == "prowler"
        else {
            **common,
            "cluster_id": "owned-fixture",
            "node_id": "fixture-node",
            "benchmark": "1.12",
            "checks": ["1.1.1"],
        }
    )


def configured(tmp_path, tool, value=None):
    value = manifest(tool) if value is None else value
    path = tmp_path / "preparation.json"
    raw = json.dumps(value, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return PreparationConfig.from_mapping(
        tool, {"manifest_file": str(path), "manifest_sha256": hashlib.sha256(raw).hexdigest()}
    )


@pytest.mark.parametrize("tool", ["prowler", "kube-bench"])
async def test_reviewed_input_preparation_never_claims_a_cloud_or_node_audit(tmp_path, tool):
    """Actual files/SQLite plus direct fenced adapter claim; no engine double."""
    config = configured(tmp_path, tool)
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
    spec = preparation_job(config, policy, store)
    surface = store.surface(policy.engagement_id, spec.surface_id)
    assert surface.url == "" and surface.resource_kind == "source_artifact"
    store.submit(policy, [spec])
    job = store.claim(policy, "preparation-worker")
    adapter = PreparationAdapter(config, policy, store)
    result = await adapter.run(job, surface, spec)
    assert result.execution_status == "succeeded" and result.coverage_status == "completed"
    assert result.summary["audit_executed"] is False
    assert result.summary["audit_coverage_status"] == "blocked"
    assert not result.findings and "no_finding_observed" not in result.summary
    assert adapter.runner is None and store.request_usage(policy) == 0
    assert store.finish(job, result)
    store.close()
    reopened = AssessmentStore(tmp_path / "state.db")
    assert reopened.jobs(policy.engagement_id)[0]["result"]["summary"]["audit_executed"] is False
    assert reopened.claim(policy, "new-worker") is None
    reopened.close()


@pytest.mark.parametrize("tool", ["prowler", "kube-bench"])
async def test_version_preparation_missing_complete_engine_is_explicitly_blocked(tmp_path, tool):
    config = configured(tmp_path, tool, manifest(tool, "version_only"))
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
    spec = preparation_job(config, policy, store)
    store.submit(policy, [spec])
    job = store.claim(policy, "preparation-worker")
    result = await PreparationAdapter(config, policy, store).run(
        job, store.surface(policy.engagement_id, spec.surface_id), spec
    )
    assert result.coverage_status == "blocked" and result.summary["audit_executed"] is False
    assert (
        "snapshot_unavailable" in result.error["code"]
        if tool == "prowler"
        else result.error["code"] == "preparation_pinned_engine_missing"
    )
    store.close()


@pytest.mark.parametrize("change", ["credentials", "live", "operation", "provider", "checks"])
def test_manifest_cannot_smuggle_live_credentials_commands_or_provider_expansion(tmp_path, change):
    value = manifest("prowler")
    if change == "credentials":
        value["credentials_file"] = "/must-not-read"
    elif change == "live":
        value["live_authorization"] = "approved"
    elif change == "operation":
        value["operation"] = "fixer"
    elif change == "provider":
        value["provider"] = "azure"
    else:
        value["checks"] = ["--fixer"]
    with pytest.raises(ValueError):
        configured(tmp_path, "prowler", value)


def test_preparation_artifact_grant_does_not_come_from_inventory_discovery(tmp_path):
    config = configured(tmp_path, "prowler")
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(
        EngagementPolicy(
            "preparation", "owner", ("https://approved.example",), target_domains=("source", "web")
        )
    )
    store.inventory.record_asset(
        policy, kind="source_artifact", locator=config.artifact_sha256, source="inferred"
    )
    with pytest.raises(PolicyDenied, match="not_approved"):
        preparation_job(config, policy, store)
    assert not store.jobs(policy.engagement_id)
    store.close()


def test_preparation_manifest_is_revalidated_after_configuration(tmp_path):
    config = configured(tmp_path, "prowler")
    config.manifest_file.write_text("{}")
    with pytest.raises(ValueError, match="digest"):
        config.manifest()


@pytest.mark.parametrize("wrong", [False, True])
def test_mock_prowler_report_is_summarized_without_resource_or_secret_data(wrong):
    value = manifest("prowler")
    record = {
        "metadata": {
            "event_code": value["checks"][0],
            "product": {"uid": "prowler", "version": "5.45.0"},
        },
        "cloud": {
            "provider": "aws",
            "account": {"uid": "111111111111" if wrong else value["account_id"]},
        },
        "status_code": "FAIL",
        "status_detail": "must-not-export-secret",
        "resources": [{"data": "must-not-export-secret"}],
    }
    if wrong:
        with pytest.raises(ValueError, match="identity"):
            summarize_prowler_ocsf(json.dumps([record]).encode(), value)
    else:
        result = summarize_prowler_ocsf(json.dumps([record]).encode(), value)
        assert result["status_counts"]["FAIL"] == 1 and result["live_audit_verified"] is False
        assert result["audit_coverage_status"] == "blocked" and "secret" not in json.dumps(result)


@pytest.mark.parametrize("bad_totals", [False, True])
def test_mock_kube_report_warn_is_manual_and_node_identity_is_unverified(bad_totals):
    value = manifest("kube-bench")
    record = {
        "version": "1.12",
        "total_pass": 1 if bad_totals else 0,
        "total_fail": 0,
        "total_warn": 1,
        "total_info": 0,
        "tests": [
            {
                "results": [
                    {
                        "test_number": "1.1.1",
                        "status": "WARN",
                        "audit": "must-not-run-shell",
                        "actual_value": "must-not-export-secret",
                    }
                ]
            }
        ],
    }
    if bad_totals:
        with pytest.raises(ValueError, match="totals"):
            summarize_kube_bench(json.dumps([record]).encode(), value)
    else:
        result = summarize_kube_bench(json.dumps([record]).encode(), value)
        assert result["status_counts"]["MANUAL"] == 1
        assert result["target_identity_attested"] is False
        assert "shell" not in json.dumps(result) and "secret" not in json.dumps(result)
