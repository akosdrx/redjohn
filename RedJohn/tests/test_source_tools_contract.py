"""Source manifest/argument/parser contracts; scanner processes are not mocked as live."""

import hashlib
import json
import os

import pytest

from redjohn.assessment.models import AdapterResult, JobSpec, Surface, stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.source_tools import (
    VERSIONS,
    OfflineSourceRunner,
    SourceToolAdapter,
    SourceToolConfig,
    read_source_file,
    relative_source_path,
)
from redjohn.assessment.store import AssessmentStore


def config_document(tmp_path, tool="trivy"):
    source = tmp_path / "approved-source"
    source.mkdir(exist_ok=True)
    name = "example.py" if tool == "semgrep" else "Dockerfile"
    data = (
        b"def chosen(value):\n    return eval(value)\n"
        if tool == "semgrep"
        else b"FROM scratch\nUSER root\n"
    )
    (source / name).write_bytes(data)
    binary = tmp_path / ("osemgrep" if tool == "semgrep" else "trivy")
    binary.write_bytes(b"not-an-executed-contract-binary")
    value = {
        "binary": {
            "path": str(binary),
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "version": VERSIONS[tool],
        },
        "source_root": str(source),
        "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest()}],
    }
    if tool == "semgrep":
        libs = tmp_path / "libs"
        libs.mkdir(exist_ok=True)
        (libs / "libowned.so.1").write_bytes(b"synthetic-not-executed-library")
        value["native_libraries"] = [
            {
                "name": "libowned.so.1",
                "sha256": hashlib.sha256((libs / "libowned.so.1").read_bytes()).hexdigest(),
            }
        ]
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "redjohn.owned-eval",
                            "languages": ["python"],
                            "pattern": "eval($X)",
                            "message": "Owned static fixture",
                            "severity": "ERROR",
                        }
                    ]
                }
            )
        )
        value.update(
            rules_file=str(rules), rules_sha256=hashlib.sha256(rules.read_bytes()).hexdigest()
        )
    return value


def source_policy(artifact_sha256="a" * 64):
    return EngagementPolicy(
        "source-contract",
        "operator",
        (),
        profile="isolated-lab",
        target_domains=("source",),
        allowed_source_artifacts=(artifact_sha256,),
    )


@pytest.mark.parametrize(
    "path",
    [
        "../outside",
        "/absolute",
        "a/../../b",
        "a//b",
        "a/./b",
        "a\\b",
        ".git/config",
        ".semgrepignore",
        "trivy.yaml",
        "a\nsecret",
    ],
)
def test_source_manifest_rejects_escaping_or_implicit_tool_configuration(path):
    with pytest.raises(ValueError):
        relative_source_path(path)


@pytest.mark.parametrize("tool", ["semgrep", "trivy"])
def test_source_configuration_fixed_versions_and_revision_cover_every_file(tmp_path, tool):
    document = config_document(tmp_path, tool)
    config = SourceToolConfig.from_mapping(tool, document)
    assert config.version == VERSIONS[tool]
    revised = {**document, "files": [{**document["files"][0], "sha256": "a" * 64}]}
    assert SourceToolConfig.from_mapping(tool, revised).revision != config.revision
    with pytest.raises(ValueError):
        SourceToolConfig.from_mapping(tool, {**document, "command": "must-not-run"})
    with pytest.raises(ValueError):
        SourceToolConfig.from_mapping(
            tool, {**document, "binary": {**document["binary"], "version": "latest"}}
        )


def test_source_reader_rejects_leaf_and_directory_symlinks_and_changed_content(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"owned-fixture")
    digest = hashlib.sha256(b"owned-fixture").hexdigest()
    (source / "leaf").symlink_to(outside / "secret")
    (source / "directory").symlink_to(outside, target_is_directory=True)
    for relative in ("leaf", "directory/secret"):
        with pytest.raises(OSError):
            read_source_file(source, relative, digest, 100)
    (source / "regular").write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest"):
        read_source_file(source, "regular", digest, 100)
    with pytest.raises(ValueError, match="size"):
        read_source_file(source, "regular", hashlib.sha256(b"changed").hexdigest(), 2)


def test_source_reader_rejects_special_files_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(ValueError, match="type"):
        read_source_file(tmp_path, "fifo", "a" * 64, 100)


@pytest.mark.parametrize("tool", ["semgrep", "trivy"])
def test_source_argv_offline_single_worker_no_upload_build_or_remote_rules(tmp_path, tool):
    config = SourceToolConfig.from_mapping(tool, config_document(tmp_path, tool))
    runner = OfflineSourceRunner(config, tmp_path / "workers")
    runner.workspace, runner.snapshot = tmp_path / "workspace", tmp_path / "snapshot"
    argv = runner.argv()
    assert argv[0] == str(config.binary.path)
    assert not any(item.startswith(("http://", "https://", "p/")) for item in argv)
    if tool == "semgrep":
        assert argv[argv.index("--metrics") + 1] == "off"
        assert "--disable-version-check" in argv
        assert "--no-secrets-validation" in argv
        assert "--oss-only" in argv
        assert argv[argv.index("--jobs") + 1] == "1"
        assert "--allow-local-builds" not in argv
        assert "--autofix" not in argv
    else:
        assert "--offline-scan" in argv
        assert "--disable-telemetry" in argv
        assert "--skip-db-update" in argv
        assert "--skip-check-update" in argv
        assert argv[argv.index("--parallel") + 1] == "1"
        assert argv[argv.index("--scanners") + 1] == "misconfig"


def test_source_job_requires_explicit_domain_and_exact_artifact_revision(tmp_path):
    config = SourceToolConfig.from_mapping("trivy", config_document(tmp_path))
    surface = Surface(
        "",
        resource_kind="source_artifact",
        asset_ref="b" * 64,
        artifact_sha256=config.artifact_sha256,
        input_location="source_artifact",
        input_name=config.revision,
    )
    spec = JobSpec(
        "source-id",
        "source_configuration",
        "trivy_source",
        tool_version=config.version,
        template_version=config.revision,
    )
    config.validate_input(source_policy(config.artifact_sha256), surface, spec)
    with pytest.raises(ValueError):
        config.validate_input(
            source_policy(config.artifact_sha256), Surface("https://example.invalid"), spec
        )
    web = EngagementPolicy(
        "web",
        "operator",
        ("http://127.0.0.1:1",),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )
    with pytest.raises(PolicyDenied):
        config.validate_input(web, surface, spec)


@pytest.mark.parametrize("tool", ["semgrep", "trivy"])
def test_source_parser_keeps_candidates_sanitized_and_error_distinct(tmp_path, tool):
    config = SourceToolConfig.from_mapping(tool, config_document(tmp_path, tool))
    policy = source_policy()
    store = AssessmentStore(tmp_path / "evidence.sqlite3")
    store.register(policy)
    adapter = SourceToolAdapter(config, policy, store)
    adapter.runner.snapshot = tmp_path / "snapshot"
    name = config.files[0][0]
    if tool == "semgrep":
        document = {
            "results": [
                {
                    "check_id": "redjohn.owned-eval",
                    "path": str(adapter.runner.snapshot / "source" / name),
                    "start": {"line": 2},
                    "extra": {"severity": "ERROR", "lines": "must-not-be-evidence"},
                }
            ],
            "errors": [],
            "paths": {"scanned": [name]},
        }
    else:
        document = {
            "Results": [
                {
                    "Target": name,
                    "Misconfigurations": [
                        {
                            "ID": "DS-0002",
                            "Status": "FAIL",
                            "Severity": "HIGH",
                            "CauseMetadata": {
                                "StartLine": 2,
                                "Code": {"Lines": "must-not-be-evidence"},
                            },
                        }
                    ],
                }
            ]
        }
    raw = {"stdout": json.dumps(document), "exit_code": 0}
    result = adapter.normalize({"id": "owned-job"}, raw, {"tool_version": config.version}, 0.1)
    assert result.execution_status == "succeeded"
    assert result.findings[0]["finding_status"] == "candidate"
    assert "must-not-be-evidence" not in json.dumps(result.findings)
    assert result.summary["requests"] == 0
    limited = adapter.normalize({"id": "owned-job"}, {**raw, "truncated": True}, {}, 0.1)
    assert limited.execution_status == "failed"
    assert limited.coverage_status == "inconclusive"
    assert not limited.findings
    timed_out = adapter.normalize({"id": "owned-job"}, {"timed_out": True}, {}, 0.1)
    assert timed_out.execution_status == "timed_out"
    store.close()


def test_source_empty_or_partial_scan_cannot_pass_as_a_clean_scan(tmp_path):
    config = SourceToolConfig.from_mapping("semgrep", config_document(tmp_path, "semgrep"))
    store = AssessmentStore(tmp_path / "evidence.sqlite3")
    adapter = SourceToolAdapter(config, source_policy(), store)
    raw = {
        "stdout": json.dumps({"results": [], "errors": [], "paths": {"scanned": []}}),
        "exit_code": 0,
    }
    with pytest.raises(ValueError, match="empty"):
        adapter.normalize({"id": "owned-job"}, raw, {}, 0.1)
    raw["stdout"] = json.dumps(
        {
            "results": [],
            "errors": [{"message": "parse-error"}],
            "paths": {"scanned": ["example.py"]},
        }
    )
    with pytest.raises(ValueError, match="partial"):
        adapter.normalize({"id": "owned-job"}, raw, {}, 0.1)
    store.close()


def test_old_persisted_http_policy_surface_and_job_identity_survive_source_upgrade(tmp_path):
    """An old-schema payload is written without any newly added source fields."""
    old_policy = {
        "engagement_id": "legacy-persisted",
        "owner_id": "operator",
        "allowed_origins": ["http://127.0.0.1:1"],
        "revision": "legacy-7",
        "allowed_ips": [],
        "profile": "isolated-lab",
        "target_domains": ["web"],
        "egress_mode": "local-fixture",
        "actor_ids": ["anonymous"],
        "deadline": 4102444800.0,
        "max_attempts": 2,
        "retry_budget": 4,
        "request_budget": 128,
        "allowed_replay_urls": [],
        "allowed_refresh_urls": [],
    }
    old_surface = {
        "url": "http://127.0.0.1:1/legacy",
        "method": "GET",
        "content_type": "",
        "input_location": "",
        "input_name": "",
        "actor_id": "anonymous",
        "tenant_id": "",
        "session_revision": "1",
        "workflow_state": "initial",
        "source": "observed",
        "request_ref": "",
        "body_sha256": "",
    }
    policy = EngagementPolicy.from_mapping(old_policy)
    assert json.loads(json.dumps(policy.to_dict())) == old_policy
    expected_surface_key = stable_key(
        {
            key: value
            for key, value in old_surface.items()
            if key not in {"source", "request_ref", "body_sha256"}
        }
    )
    assert Surface(**old_surface).key == expected_surface_key
    db_path = tmp_path / "pre-source-schema.sqlite3"
    store = AssessmentStore(db_path)
    policy = store.register(policy)
    surface_id = store.upsert_surface(policy.engagement_id, Surface(**old_surface))
    assert surface_id == stable_key([policy.engagement_id, expected_surface_key])
    spec = JobSpec(surface_id, "configuration", "headers_audit", policy_revision="legacy-7")
    job_id = store.submit(policy, [spec])[0]
    # Persist literal old payloads, then close/reopen to exercise additive
    # schema migration rather than relying only on constructors/defaults.
    with store.transaction() as conn:
        conn.execute(
            "UPDATE rj_surface SET payload=? WHERE id=?",
            (json.dumps(old_surface, sort_keys=True, separators=(",", ":")), surface_id),
        )
        conn.execute(
            "UPDATE rj_engagement SET policy=? WHERE id=?",
            (json.dumps(old_policy, sort_keys=True, separators=(",", ":")), policy.engagement_id),
        )
    before = store.jobs(policy.engagement_id)[0]
    store.close()
    reopened = AssessmentStore(db_path)
    current = reopened.register(EngagementPolicy.from_mapping(old_policy))
    assert current.revision == "legacy-7"
    assert reopened.surface(current.engagement_id, surface_id).key == expected_surface_key
    assert reopened.jobs(current.engagement_id)[0]["id"] == before["id"] == job_id
    assert reopened.submit(current, [spec]) == [job_id]
    claimed = reopened.claim(current, "owned-old-worker", lease_seconds=30)
    assert claimed["id"] == job_id
    reopened.finish(claimed, AdapterResult("succeeded", "completed"))
    assert reopened.jobs(current.engagement_id)[0]["execution_status"] == "succeeded"
    reopened.close()


def test_source_policy_discovery_does_not_implicitly_grant_execution(tmp_path):
    config = SourceToolConfig.from_mapping("trivy", config_document(tmp_path))
    policy = EngagementPolicy(
        "source-no-execution-grant",
        "operator",
        ("https://example.invalid",),
        target_domains=("source",),
    )
    store = AssessmentStore(tmp_path / "state.sqlite3")
    policy = store.register(policy)
    asset = store.inventory.record_asset(
        policy, kind="source_artifact", locator=config.artifact_sha256, source="imported"
    )
    surface = Surface(
        "",
        resource_kind="source_artifact",
        asset_ref=asset,
        artifact_sha256=config.artifact_sha256,
        input_location="source_artifact",
        input_name=config.revision,
        source="imported",
        workflow_state="approved_seed",
    )
    surface_id = store.upsert_surface(policy.engagement_id, surface)
    with pytest.raises(PolicyDenied, match="not_approved"):
        store.submit(policy, [JobSpec(surface_id, "source_configuration", "trivy_source")])
    store.close()


def test_source_reader_rejects_symlink_in_absolute_root_ancestry(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    (original / "file.py").write_bytes(b"owned")
    link = tmp_path / "linked-root"
    link.symlink_to(original, target_is_directory=True)
    with pytest.raises(OSError):
        read_source_file(link, "file.py", hashlib.sha256(b"owned").hexdigest(), 1024)


def test_source_engine_and_libraries_are_immutable_snapshot_inputs(tmp_path):
    document = config_document(tmp_path, "semgrep")
    config = SourceToolConfig.from_mapping("semgrep", document)
    runner = OfflineSourceRunner(config, tmp_path / "workers")
    snapshot = tmp_path / "private-snapshot"
    snapshot.mkdir()
    runner.snapshot = snapshot
    runner._snapshot_engine()
    assert runner.binary.path == snapshot / "engine/osemgrep"
    assert hashlib.sha256(runner.binary.path.read_bytes()).hexdigest() == config.binary.sha256
    config.binary.path.write_bytes(b"host-changed-after-copy")
    host_lib = config.binary.path.parent / "libs/libowned.so.1"
    host_lib.write_bytes(b"host-library-changed-after-copy")
    assert hashlib.sha256(runner.binary.path.read_bytes()).hexdigest() == config.binary.sha256
    assert (
        hashlib.sha256((snapshot / "engine/libs/libowned.so.1").read_bytes()).hexdigest()
        == (config.native_libraries[0][1])
    )
    replacement = tmp_path / "second-snapshot"
    replacement.mkdir()
    runner.snapshot = replacement
    with pytest.raises(ValueError, match="digest_or_size"):
        runner._snapshot_engine()


@pytest.mark.parametrize("libraries", [[], [{"name": "../outside.so.1", "sha256": "a" * 64}]])
def test_semgrep_requires_bounded_explicit_native_library_pins(tmp_path, libraries):
    document = config_document(tmp_path, "semgrep")
    document["native_libraries"] = libraries
    with pytest.raises(ValueError, match="library"):
        SourceToolConfig.from_mapping("semgrep", document)
