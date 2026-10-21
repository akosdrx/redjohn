"""SBOM parser/job contracts with synthetic engine replies and synthetic DB bytes.

No native scanner or official DB is executed; SQLite/file IO are real locally.
"""

from __future__ import annotations

import copy
import json
import time

import pytest

from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.trivy_sbom import (
    CAPABILITY,
    TrivySBOMAdapter,
    TrivySBOMConfig,
    TrivySBOMRunner,
    parse_cyclonedx,
    trivy_sbom_job,
)
from tests.test_trivy_database_contract import digest, synthetic_database


def sbom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.20.0",
                "purl": "pkg:pypi/requests@2.20.0",
                "bom-ref": "requests-2.20.0",
            }
        ],
    }


def configured(tmp_path):
    database, _ = synthetic_database(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    raw = json.dumps(sbom()).encode()
    (source / "bom.cdx.json").write_bytes(raw)
    engine = tmp_path / "synthetic-engine-never-executed"
    engine.write_bytes(b"SYNTHETIC_NOT_AN_EXECUTABLE")
    return TrivySBOMConfig.from_mapping(
        {
            "binary": {
                "path": str(engine),
                "sha256": digest(engine.read_bytes()),
                "version": "0.76.0",
            },
            "source_root": str(source),
            "files": [{"path": "bom.cdx.json", "sha256": digest(raw)}],
            "database": database,
        }
    )


def owned_store(tmp_path, config):
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(
        EngagementPolicy(
            "synthetic-sbom-contract",
            "owner",
            (),
            target_domains=("source",),
            allowed_source_artifacts=(config.artifact_sha256,),
        )
    )
    return store, policy


@pytest.mark.parametrize(
    "defect",
    [
        "xml",
        "external",
        "duplicate",
        "ambiguous_purl",
        "java",
        "nested",
        "unknown_dependency",
        "batch",
        "alias",
        "nonfinite",
    ],
)
def test_safe_sbom_subset_rejects_unsupported_inputs_explicitly(defect):
    value = sbom()
    if defect == "xml":
        raw = b'<bom xmlns="http://cyclonedx.org/schema/bom/1.5"></bom>'
    else:
        if defect == "external":
            value["externalReferences"] = [
                {"type": "vex", "url": "https://example.invalid/private"}
            ]
        elif defect == "duplicate":
            value["components"] *= 2
        elif defect == "ambiguous_purl":
            value["components"][0]["purl"] = (
                "pkg:pypi/requests@2.20.0?repository_url=https://example.invalid"
            )
        elif defect == "java":
            value["components"][0]["purl"] = "pkg:maven/requests@2.20.0"
        elif defect == "nested":
            value["components"][0]["components"] = []
        elif defect == "unknown_dependency":
            value["dependencies"] = [{"ref": "requests-2.20.0", "dependsOn": ["outside"]}]
        elif defect == "alias":
            value["components"][0]["name"] = "Requests"
        elif defect == "nonfinite":
            value["version"] = float("nan")
        raw = json.dumps([value] if defect == "batch" else value).encode()
    with pytest.raises(ValueError):
        parse_cyclonedx(raw)


def test_supported_declarations_and_fixed_argv_do_not_enable_other_scanners(tmp_path):
    config = configured(tmp_path)
    assert config.read_packages()[0].purl == "pkg:pypi/requests@2.20.0"
    runner = TrivySBOMRunner(config, tmp_path / "workers")
    runner.snapshot = tmp_path / "snapshot"
    argv = runner.argv()
    assert argv[1] == "sbom" and argv[argv.index("--scanners") + 1] == "vuln"
    assert argv[argv.index("--config") + 1] == ""
    assert "--list-all-pkgs" in argv and "--skip-db-update" in argv
    assert "--skip-java-db-update" in argv and "--skip-vex-repo-update" in argv
    assert "--offline-scan" in argv and "--disable-telemetry" in argv
    assert "--parallel" not in argv and "--skip-check-update" not in argv
    assert not any(
        word in argv for word in ("image", "repository", "--server", "--insecure", "--template")
    )


def test_actual_sqlite_job_is_explicit_and_restart_deduplicates_without_execution(tmp_path):
    config = configured(tmp_path)
    store, policy = owned_store(tmp_path, config)
    try:
        spec = trivy_sbom_job(config, policy, store)
        job = store.submit(policy, [spec])[0]
        assert spec.capability == CAPABILITY and spec.options == {}
        assert store.request_usage(policy) == 0
        assert store.jobs(policy.engagement_id)[0]["execution_status"] == "queued"
    finally:
        store.close()
    store = AssessmentStore(tmp_path / "state.db")
    try:
        assert store.submit(policy, [trivy_sbom_job(config, policy, store)]) == [job]
        assert len(store.jobs(policy.engagement_id)) == 1
        assert (
            store.db.execute(
                "SELECT count(*) FROM rj_evidence WHERE kind='approved_source_manifest'"
            ).fetchone()[0]
            == 1
        )
    finally:
        store.close()


def test_discovery_without_explicit_artifact_grant_cannot_create_job(tmp_path):
    config = configured(tmp_path)
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(EngagementPolicy("no-grant", "owner", ("https://example.invalid",)))
    try:
        with pytest.raises(PolicyDenied):
            trivy_sbom_job(config, policy, store)
        assert store.jobs(policy.engagement_id) == []
    finally:
        store.close()


def report():
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Packages": [{"Name": "requests", "Version": "2.20.0"}],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "SYNTHETIC-ADVISORY-1",
                        "PkgName": "requests",
                        "InstalledVersion": "2.20.0",
                        "Severity": "HIGH",
                        "DataSource": {"ID": "synthetic-advisory"},
                    }
                ],
            }
        ],
    }


@pytest.mark.parametrize("fixed", [False, True])
def test_synthetic_engine_positive_fixed_never_claims_official_feed_or_installation(
    tmp_path, fixed
):
    config = configured(tmp_path)
    store, policy = owned_store(tmp_path, config)
    try:
        adapter = TrivySBOMAdapter(config, policy, store)
        adapter.runner.snapshot_readonly_attested = True  # Synthetic attestation, not kernel proof.
        adapter.runner.data_sources = ("synthetic-advisory",)
        adapter.runner.declared_packages = parse_cyclonedx(json.dumps(sbom()).encode())
        adapter.runner.valid_until = time.time() + 60
        value = report()
        if fixed:
            value["Results"][0]["Vulnerabilities"] = []
        result = adapter.normalize(
            {"id": "synthetic-job"}, {"exit_code": 0, "stdout": json.dumps(value)}, {}, 0.1
        )
        assert result.coverage_status == "partial"
        assert len(result.findings) == (0 if fixed else 1)
        assert result.summary["publisher_provenance_verified"] is False
        assert result.summary["package_installation_verified"] is False
        assert result.summary["image_or_source_tree_scan"] is False
        assert all(row["finding_status"] == "candidate" for row in result.findings)
    finally:
        store.close()


@pytest.mark.parametrize(
    "defect",
    [
        "missing_inventory",
        "unlisted_package",
        "unreviewed_data_source",
        "partial_inventory",
        "duplicate_advisory",
        "wrong_schema",
    ],
)
def test_synthetic_partial_or_unbound_engine_output_cannot_be_success(tmp_path, defect):
    config = configured(tmp_path)
    store, policy = owned_store(tmp_path, config)
    try:
        adapter = TrivySBOMAdapter(config, policy, store)
        adapter.runner.snapshot_readonly_attested = True
        adapter.runner.data_sources = ("synthetic-advisory",)
        adapter.runner.declared_packages = parse_cyclonedx(json.dumps(sbom()).encode())
        adapter.runner.valid_until = time.time() + 60
        value = report()
        row = value["Results"][0]
        if defect == "missing_inventory":
            del row["Packages"]
        elif defect == "unlisted_package":
            row["Packages"][0]["Name"] = "private-outside-sbom"
        elif defect == "unreviewed_data_source":
            row["Vulnerabilities"][0]["DataSource"]["ID"] = "unreviewed-feed"
        elif defect == "partial_inventory":
            row["Packages"] = []
        elif defect == "duplicate_advisory":
            row["Vulnerabilities"].append(copy.deepcopy(row["Vulnerabilities"][0]))
        else:
            value["SchemaVersion"] = 3
        with pytest.raises(ValueError):
            adapter.normalize(
                {"id": "synthetic-job"}, {"exit_code": 0, "stdout": json.dumps(value)}, {}, 0.1
            )
    finally:
        store.close()


@pytest.mark.parametrize("lockfile_type", ["pip", "npm"])
def test_synthetic_lockfile_types_cannot_substitute_for_pinned_sbom_result_types(
    tmp_path, lockfile_type
):
    config = configured(tmp_path)
    store, policy = owned_store(tmp_path, config)
    try:
        adapter = TrivySBOMAdapter(config, policy, store)
        adapter.runner.snapshot_readonly_attested = True  # Explicit attestation double.
        adapter.runner.data_sources = ("synthetic-advisory",)
        adapter.runner.declared_packages = parse_cyclonedx(json.dumps(sbom()).encode())
        adapter.runner.valid_until = time.time() + 60
        value = report()
        value["Results"][0]["Type"] = lockfile_type
        with pytest.raises(ValueError, match="complete_package_inventory"):
            adapter.normalize(
                {"id": "synthetic-job"}, {"exit_code": 0, "stdout": json.dumps(value)}, {}, 0.1
            )
    finally:
        store.close()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ({"timed_out": True}, "inconclusive"),
        ({"truncated": True, "exit_code": 0}, "inconclusive"),
        ({"exit_code": 1}, "inconclusive"),
    ],
)
def test_timeout_and_output_failure_are_not_negative_advisory_results(tmp_path, raw, expected):
    config = configured(tmp_path)
    store, policy = owned_store(tmp_path, config)
    try:
        result = TrivySBOMAdapter(config, policy, store).normalize(
            {"id": "synthetic-job"}, raw, {}, 0.1
        )
        assert result.coverage_status == expected and not result.findings
    finally:
        store.close()


async def test_removed_job_lease_blocks_before_any_native_preparation(tmp_path):
    config = configured(tmp_path)
    store, policy = owned_store(tmp_path, config)
    try:
        spec = trivy_sbom_job(config, policy, store)
        job_id = store.submit(policy, [spec])[0]
        row = store.jobs(policy.engagement_id)[0]
        surface = store.surface(policy.engagement_id, spec.surface_id)
        with pytest.raises(PolicyDenied, match="current_job_lease"):
            await TrivySBOMAdapter(config, policy, store).run(
                {**row, "id": job_id, "owner": "unleased"}, surface, spec
            )
        assert not (tmp_path / "trivy-sbom-workers").exists()
    finally:
        store.close()


async def test_actual_claimed_job_without_kernel_owner_is_blocked_before_engine_start(
    tmp_path, monkeypatch
):
    from redjohn.assessment import trivy_copy  # noqa: PLC0415 - explicit admission fault

    config = configured(tmp_path)
    store, policy = owned_store(tmp_path, config)
    try:
        adapter = TrivySBOMAdapter(config, policy, store)
        spec = trivy_sbom_job(config, policy, store)
        store.submit(policy, [spec])
        row = store.claim(policy, "owned-contract-controller")
        assert row is not None
        surface = store.surface(policy.engagement_id, spec.surface_id)
        monkeypatch.setattr(trivy_copy, "current_memory_fence", lambda: None)
        result = await adapter.run(row, surface, spec)
        assert result.execution_status == "failed" and result.coverage_status == "blocked"
        assert not result.findings and not (tmp_path / "trivy-sbom-workers").exists()
        assert store.request_usage(policy) == 0
    finally:
        store.close()


def test_synthetic_normalization_never_reopens_original_operator_files(tmp_path, monkeypatch):
    from redjohn.assessment import trivy_sbom  # noqa: PLC0415 - no-IO fence

    config = configured(tmp_path)
    store, policy = owned_store(tmp_path, config)
    try:
        adapter = TrivySBOMAdapter(config, policy, store)
        adapter.runner.snapshot_readonly_attested = True  # Explicit attestation double.
        adapter.runner.data_sources = ("synthetic-advisory",)
        adapter.runner.declared_packages = parse_cyclonedx(json.dumps(sbom()).encode())
        adapter.runner.valid_until = time.time() + 60

        def forbidden_original_read(*_args, **_kwargs):
            raise AssertionError("normalization must consume owned prepared identity")

        monkeypatch.setattr(trivy_sbom, "read_source_file", forbidden_original_read)
        result = adapter.normalize(
            {"id": "synthetic-job"}, {"exit_code": 0, "stdout": json.dumps(report())}, {}, 0.1
        )
        assert result.execution_status == "succeeded" and result.coverage_status == "partial"
        adapter.runner.valid_until = time.time() - 1
        with pytest.raises(ValueError, match="prepared_database_expired"):
            adapter.normalize(
                {"id": "synthetic-job"}, {"exit_code": 0, "stdout": json.dumps(report())}, {}, 0.1
            )
    finally:
        store.close()
