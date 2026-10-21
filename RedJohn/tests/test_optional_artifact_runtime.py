"""Public configuration/composition contracts; synthetic metadata, no native engines."""

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment, validate_configuration
from redjohn.assessment.registry import CapabilityRegistry
from tests.test_trivy_sbom_contract import configured as sbom_config
from tests.test_wpscan_observe_contract import configured as wordpress_config


@pytest.mark.parametrize("capability", ["trivy_sbom", "wordpress_observe"])
async def test_public_artifact_configuration_is_lazy_durable_and_version_bound(
    tmp_path, capability
):
    selected = sbom_config(tmp_path) if capability == "trivy_sbom" else wordpress_config(tmp_path)
    mapping = selected.to_dict() if capability == "trivy_sbom" else selected.to_mapping()
    config = validate_configuration(
        {
            "policy": {
                "engagement_id": "public-" + capability,
                "owner_id": "operator",
                "allowed_origins": [],
                "target_domains": ["source"],
                "allowed_source_artifacts": [selected.artifact_sha256],
                "profile": "isolated-lab",
                "egress_mode": "unavailable",
            },
            "resources": {"total_memory_budget": 2 * 1024**3, "max_workers": 1},
            capability: mapping,
            "source_jobs": [{"capability": capability}],
        }
    )
    output = tmp_path / "run"
    async with ConfiguredAssessment(config, output, caller="operator") as assessment:
        registry = assessment.runtime.registry
        assert registry.get(capability).resource_class == "scanner"
        adapter = assessment.runtime.scheduler.adapters[capability]
        assert adapter.resource_class == "scanner" and adapter.resource_cleanup_verified()
        rows = assessment.store.jobs(assessment.policy.engagement_id)
        assert len(rows) == 1 and rows[0]["execution_status"] == "queued"
        assert registry.execution_versions(capability) == {
            "tool_version": selected.version,
            "template_version": selected.revision,
        }
        job_id = rows[0]["id"]
        assert assessment.runtime.governor.snapshot()["active"] == {}
        assert assessment.store.request_usage(assessment.policy) == 0
    async with ConfiguredAssessment(config, output, caller="operator") as restarted:
        assert [row["id"] for row in restarted.store.jobs(restarted.policy.engagement_id)] == [
            job_id
        ]
        assert restarted.runtime.governor.snapshot()["active"] == {}


@pytest.mark.parametrize("capability", ["trivy_sbom", "wordpress_observe"])
def test_unconfigured_artifact_capability_is_blocked_and_never_live_verified(capability):
    registry = CapabilityRegistry()
    row = next(row for row in registry.health() if row["id"] == capability)
    assert row["status"] == "blocked_configuration"
    assert row["live_verified"] is False
    assert registry.get("wordpress_assess").adapter_implemented is False


@pytest.mark.parametrize("capability", ["trivy_sbom", "wordpress_observe"])
async def test_public_artifact_job_requires_explicit_grant(tmp_path, capability):
    from redjohn.assessment.policy import PolicyDenied

    selected = sbom_config(tmp_path) if capability == "trivy_sbom" else wordpress_config(tmp_path)
    config = {
        "policy": {
            "engagement_id": "unapproved",
            "owner_id": "operator",
            "allowed_origins": [],
            "target_domains": ["source"],
            "profile": "isolated-lab",
        },
        capability: selected.to_dict() if capability == "trivy_sbom" else selected.to_mapping(),
        "source_jobs": [{"capability": capability}],
    }
    with pytest.raises(PolicyDenied):
        async with ConfiguredAssessment(config, tmp_path / "run", caller="operator"):
            raise AssertionError("unapproved artifact admitted")


def test_controlled_database_is_lab_only_and_cannot_impersonate_official_publisher(tmp_path):
    from dataclasses import replace
    from redjohn.assessment.policy import EngagementPolicy, PolicyDenied

    selected = sbom_config(tmp_path)
    selected = replace(
        selected, database=replace(selected.database, origin="controlled_ghsa_fixture")
    )
    policy = EngagementPolicy(
        "scope",
        "owner",
        (),
        target_domains=("source",),
        allowed_source_artifacts=(selected.artifact_sha256,),
    )
    with pytest.raises(PolicyDenied, match="isolated_lab"):
        selected.validate(policy)
    with pytest.raises(ValueError, match="provenance_binding"):
        selected.database.read_metadata()
