"""Real Trivy 0.76.0, pinned GHSA fixture DB, public runtime and durable restart.

This is genuine native advisory matching against two licensed upstream records.
The controlled DB is neither the official aggregate nor current feed coverage.
"""

import hashlib
import json
from pathlib import Path

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment
from redjohn.assessment.trivy_sbom import TrivySBOMConfig
from tests.owned_artifact_execution import supervise_owned_test
from tests.test_source_tools_live import installed_pin


@pytest.mark.parametrize(
    "ecosystem,name,version,rule",
    [
        ("pypi", "requests", "2.20.0", "CVE-2023-32681"),
        ("pypi", "requests", "2.31.0", ""),
        ("npm", "semver", "7.5.1", "CVE-2022-25883"),
        ("npm", "semver", "7.5.2", ""),
    ],
    ids=["pypi-positive", "pypi-fixed", "npm-positive", "npm-fixed"],
)
async def test_real_sbom_public_scheduler_matching_and_restart(
    tmp_path, request, ecosystem, name, version, rule
):
    if await supervise_owned_test(request, tmp_path):
        return
    pin = installed_pin("trivy")
    root = Path(__file__).resolve().parents[1] / ".tools/trivy-sbom-fixture"
    assert (root / "configuration.json").is_file(), (
        "blocked_missing_dependency: pinned GHSA fixture database"
    )
    database = json.loads((root / "configuration.json").read_text())
    component = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem}/{name}@{version}",
        "bom-ref": name + "-" + version,
    }
    raw = json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": [component]}
    ).encode()
    source = tmp_path / "source"
    source.mkdir()
    (source / "bom.cdx.json").write_bytes(raw)
    document = {
        "binary": pin,
        "source_root": str(source),
        "files": [{"path": "bom.cdx.json", "sha256": hashlib.sha256(raw).hexdigest()}],
        "database": database,
    }
    selected = TrivySBOMConfig.from_mapping(document)
    config = {
        "policy": {
            "engagement_id": "owned-sbom-" + ecosystem + version,
            "owner_id": "operator",
            "allowed_origins": [],
            "target_domains": ["source"],
            "profile": "isolated-lab",
            "allowed_source_artifacts": [selected.artifact_sha256],
            "egress_mode": "unavailable",
        },
        "resources": {"total_memory_budget": 2 * 1024**3, "max_workers": 1},
        "trivy_sbom": document,
        "source_jobs": [{"capability": "trivy_sbom", "timeout_seconds": 90}],
    }
    output = tmp_path / "run"
    async with ConfiguredAssessment(config, output, caller="operator") as assessment:
        queued = assessment.store.jobs(assessment.policy.engagement_id)
        assert len(queued) == 1
        job_id = queued[0]["id"]
        assert await assessment.runtime.scheduler.run_batch(max_jobs=1) == [job_id]
        row = assessment.store.jobs(assessment.policy.engagement_id)[0]
        assert row["execution_status"] == "succeeded", json.dumps(row)
        assert row["coverage_status"] == "partial"
        result = row["result"]
        summary = result["summary"]
        assert summary["sbom_scan_completed"] and summary["snapshot_readonly_attested"]
        assert summary["packages"] == 1 and summary["requests"] == 0
        assert summary["database_origin"] == "controlled_ghsa_fixture"
        assert summary["official_aggregate_database"] is False
        assert summary["publisher_provenance_verified"] is False
        assert summary["package_installation_verified"] is False
        assert {item["template_id"] for item in result["findings"]} == ({rule} if rule else set())
        assert all(
            item["data_source_id"] == "ghsa" and item["finding_status"] == "candidate"
            for item in result["findings"]
        )
        assert assessment.store.request_usage(assessment.policy) == 0
        adapter = assessment.runtime.scheduler.adapters["trivy_sbom"]
        assert adapter.resource_cleanup_verified()
        assert assessment.runtime.governor.snapshot()["active"] == {}
        assert not list((output / ".state/trivy-sbom-workers").glob("owned-*"))
    async with ConfiguredAssessment(config, output, caller="operator") as restarted:
        assert await restarted.runtime.scheduler.run_batch(max_jobs=1) == []
        rows = restarted.store.jobs(restarted.policy.engagement_id)
        assert len(rows) == 1 and rows[0]["id"] == job_id and rows[0]["attempt"] == 1
        assert restarted.runtime.governor.snapshot()["active"] == {}
