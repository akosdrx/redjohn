"""Actual pinned Semgrep/Trivy -> offline namespace -> durable scheduler evidence.

Owned vulnerable and fixed source files are never executed. These tests do not
claim a public service, image/SBOM/database scan or cloud credential integration.
Missing engines/isolation are capability blocks, never successful negatives.
"""

import hashlib
import json
import os
import platform
from pathlib import Path

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment, enqueue_configured_jobs
from redjohn.assessment.source_tools import CAPABILITIES, VERSIONS, SourceToolConfig
from tests.test_source_tools_contract import config_document


def installed_pin(tool):
    root = Path(__file__).resolve().parents[1] / ".tools" / tool / VERSIONS[tool]
    executable = root / ("osemgrep" if tool == "semgrep" else "trivy")
    if (
        platform.system() != "Linux"
        or not executable.is_file()
        or not (root / "receipt.json").is_file()
    ):
        message = "blocked_missing_dependency: reviewed Linux source scanner installation required"
        if os.environ.get("REDJOHN_REQUIRE_SOURCE_SCANNER_E2E") == "1":
            pytest.fail(message)
        pytest.skip(message)
    receipt = json.loads((root / "receipt.json").read_text())
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert receipt["version"] == VERSIONS[tool]
    assert receipt["binary_sha256"] == digest
    return {"path": str(executable), "sha256": digest, "version": VERSIONS[tool]}


@pytest.mark.parametrize("tool", ["semgrep", "trivy"])
@pytest.mark.parametrize("fixed", [False, True], ids=["positive", "fixed"])
async def test_real_pinned_source_scanner_scheduler_positive_fixed_and_restart(  # noqa: PLR0915 - sequential real E2E lifecycle
    tmp_path, tool, fixed
):
    binary = installed_pin(tool)
    document = config_document(tmp_path, tool)
    document["binary"] = binary
    if tool == "semgrep":
        receipt = json.loads(Path(binary["path"]).with_name("receipt.json").read_text())
        document["native_libraries"] = [
            {"name": item["name"], "sha256": item["sha256"]} for item in receipt["native_libraries"]
        ]
    source = Path(document["source_root"])
    name = document["files"][0]["path"]
    if tool == "semgrep":
        content = "import ast\ndef chosen(value):\n    return " + (
            "ast.literal_eval(value)\n" if fixed else "eval(value)\n"
        )
    else:
        content = 'FROM scratch\nHEALTHCHECK CMD ["true"]\nUSER ' + (
            "65532\n" if fixed else "root\n"
        )
    (source / name).write_text(content)
    document["files"][0]["sha256"] = hashlib.sha256(content.encode()).hexdigest()
    source_config = SourceToolConfig.from_mapping(tool, document)
    config = {
        "policy": {
            "engagement_id": f"owned-{tool}-{'fixed' if fixed else 'positive'}",
            "owner_id": "operator",
            "allowed_origins": [],
            "target_domains": ["source"],
            "allowed_source_artifacts": [source_config.artifact_sha256],
            "profile": "isolated-lab",
            "egress_mode": "unavailable",
        },
        "resources": {"total_memory_budget": 2 * 1024**3, "max_workers": 1},
        tool: document,
        "source_jobs": [{"capability": CAPABILITIES[tool], "timeout_seconds": 60}],
    }
    output = tmp_path / "run"
    async with ConfiguredAssessment(config, output, caller="operator") as assessment:
        enqueue_configured_jobs(assessment.runtime, assessment.store, assessment.policy, config)
        queued = assessment.store.jobs(assessment.policy.engagement_id)
        assert len(queued) == 1
        job_id = queued[0]["id"]
        surface = assessment.store.surface(assessment.policy.engagement_id, queued[0]["surface_id"])
        assert surface.url == ""
        assert surface.resource_kind == "source_artifact"
        assert surface.artifact_sha256 == source_config.artifact_sha256
        assert await assessment.runtime.scheduler.run_batch(max_jobs=1) == [job_id]
        row = assessment.store.jobs(assessment.policy.engagement_id)[0]
        assert row["execution_status"] == "succeeded", row
        assert row["coverage_status"] == "completed", row
        result = row["result"] if isinstance(row["result"], dict) else json.loads(row["result"])
        candidates = result["findings"]
        target_rules = {"redjohn.owned-eval"} if tool == "semgrep" else {"DS-0002", "AVD-DS-0002"}
        matching = [finding for finding in candidates if finding["template_id"] in target_rules]
        assert len(matching) == (0 if fixed else 1), result
        assert all(finding["finding_status"] == "candidate" for finding in candidates)
        assert result["summary"]["requests"] == 0
        assert result["summary"]["snapshot_readonly_attested"] is True
        assert assessment.runtime.governor.snapshot()["active"] == {}
        assert assessment.store.request_usage(assessment.policy) == 0
        evidence = assessment.store.evidence_get(
            assessment.policy.engagement_id, result["summary"]["evidence_refs"][0]
        )
        assert "eval(value)" not in json.dumps(evidence)
        assert not list((output / ".state" / (tool + "-source-workers")).glob("job-*"))
        assert not list((output / ".state" / (tool + "-source-workers")).glob("snapshot-*"))
    # Reopen actual SQLite state: a duplicate configured source task must not
    # execute the scanner again, and the immutable result/evidence remain.
    async with ConfiguredAssessment(config, output, caller="operator") as restarted:
        enqueue_configured_jobs(restarted.runtime, restarted.store, restarted.policy, config)
        assert await restarted.runtime.scheduler.run_batch(max_jobs=1) == []
        rows = restarted.store.jobs(restarted.policy.engagement_id)
        assert len(rows) == 1
        assert rows[0]["id"] == job_id
        assert rows[0]["attempt"] == 1
        count = restarted.store.db.execute(
            "SELECT count(*) FROM rj_evidence WHERE engagement=? AND kind=?",
            (restarted.policy.engagement_id, "approved_source_manifest"),
        ).fetchone()[0]
        assert count == 1
