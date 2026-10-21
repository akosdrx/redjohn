"""ffuf input/health contracts. No scanner is installed or started here."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from redjohn.assessment.ffuf import FFUFConfig, ffuf_argv
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore


def config_document(binary=None, paths=None):
    return {
        "binary": {
            "path": str(binary or Path("/approved/ffuf")),
            "version": "2.1.0",
            "sha256": "a" * 64,
        },
        "paths": paths or ["health", "api/status"],
    }


def policy(origin="http://127.0.0.1:12345"):
    return EngagementPolicy(
        "ffuf-contract", "operator", (origin,), profile="isolated-lab", egress_mode="local-fixture"
    )


@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        "//elsewhere",
        "a/../b",
        "a?x=1",
        "x#frag",
        "x%2fy",
        "-config",
        "a\nb",
        "a\\b",
        "FUZZ",
        "a//b",
    ],
)
def test_rejects_unsafe_wordlist_before_any_process(path):
    with pytest.raises(ValueError, match="invalid_ffuf_configuration"):
        FFUFConfig.from_mapping(config_document(paths=[path]))


@pytest.mark.parametrize(
    "field,value",
    [
        ("additional_args", "-r"),
        ("config", "/secret"),
        ("rate_limit", 11),
        ("request_timeout", True),
    ],
)
def test_rejects_unreviewed_configuration_fields(field, value):
    document = config_document()
    document[field] = value
    with pytest.raises(ValueError, match="invalid_ffuf_configuration"):
        FFUFConfig.from_mapping(document)


@pytest.mark.parametrize(
    "surface",
    [
        Surface("http://127.0.0.1:12345/", method="POST"),
        Surface("http://127.0.0.1:12345/", actor_id="alice"),
        Surface("http://127.0.0.1:12345/no-slash"),
        Surface("http://127.0.0.1:12345/?q=1"),
    ],
)
def test_unsupported_request_shapes(surface):
    config = FFUFConfig.from_mapping(config_document())
    spec = JobSpec(
        "surface",
        "content_discovery",
        "ffuf_discover",
        tool_version=config.version,
        template_version=config.revision,
    )
    with pytest.raises(ValueError, match="ffuf_unsupported_input"):
        config.validate_input(policy(), surface, spec)


def test_approved_subset_revision_and_policy_enforced():
    config = FFUFConfig.from_mapping(config_document())
    surface = Surface("http://127.0.0.1:12345/")
    spec = JobSpec(
        "surface",
        "content_discovery",
        "ffuf_discover",
        tool_version=config.version,
        template_version=config.revision,
        options={"path_subset": ["health"]},
    )
    assert config.validate_input(policy(), surface, spec) == ("health",)
    with pytest.raises(ValueError, match="ffuf_unapproved_paths"):
        config.validate_input(policy(), surface, replace(spec, options={"path_subset": ["other"]}))
    with pytest.raises(ValueError, match="revision_mismatch"):
        config.validate_input(policy(), surface, replace(spec, template_version="old"))
    with pytest.raises(PolicyDenied, match="capability_profile_denied"):
        config.validate_input(replace(policy(), profile="safe-production"), surface, spec)
    unsafe = FFUFConfig.from_mapping(config_document(paths=["logout"]))
    with pytest.raises(PolicyDenied, match="state_changing_read_route_denied"):
        unsafe.validate_input(
            policy(), surface, replace(spec, template_version=unsafe.revision, options={})
        )


def test_health_presence_and_lazy_loading_do_not_execute(tmp_path, monkeypatch):
    binary = tmp_path / "ffuf"
    binary.write_bytes(b"presence fixture")
    binary.chmod(0o700)
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: None)
    registry = CapabilityRegistry(ffuf_config=config_document(binary))
    for _ in range(2):
        row = next(row for row in registry.health() if row["id"] == "ffuf_discover")
        assert row["adapter_implemented"] and row["binary_presence_only"]
        assert not row["live_verified"]
    binary.unlink()
    assert (
        next(row for row in registry.health() if row["id"] == "ffuf_discover")["status"]
        == "blocked_missing_dependency"
    )


def test_managed_ffuf_presence_still_requires_approved_configuration(tmp_path, monkeypatch):
    binary = tmp_path / ".tools/ffuf/2.1.0/ffuf"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"presence only; never executed by health")
    binary.chmod(0o700)
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: None)
    registry = CapabilityRegistry(repository_root=tmp_path)
    row = next(row for row in registry.health() if row["id"] == "ffuf_discover")
    assert row["binary_path_source"] == "repo_managed"
    assert row["binary_presence_only"] is True and row["live_verified"] is False
    assert row["status"] == "blocked_configuration"


async def test_missing_configuration_is_blocked_durable_not_negative(tmp_path):
    store = AssessmentStore(tmp_path / "agents.db")
    try:
        async with AssessmentRuntime(store, policy(), caller="operator") as runtime:
            sid = store.upsert_surface(
                policy().engagement_id, Surface(policy().allowed_origins[0] + "/")
            )
            job = store.submit(policy(), [JobSpec(sid, "content_discovery", "ffuf_discover")])[0]
            await runtime.scheduler.run_batch()
            row = store.jobs(policy().engagement_id)[0]
            assert row["id"] == job
            assert row["coverage_status"] == "blocked"
            assert "ffuf_discover_configuration_missing" in json.dumps(row)
            assert not store.findings(policy().engagement_id)
    finally:
        store.close()


def test_argv_cannot_enable_recursion_redirects_mutators_or_configs():
    config = FFUFConfig.from_mapping(config_document())
    argv = ffuf_argv(
        config, "https://example.invalid/", Path("/private/words"), "http://127.0.0.1:2345"
    )
    assert all(
        flag not in argv
        for flag in ["-r", "-recursion", "-ac", "-input-cmd", "-config", "-o", "-replay-proxy"]
    )
    assert argv[argv.index("-t") + 1] == "1"
