"""App-native skill loading/provenance and capability gating (no scanner execution)."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from redjohn import skills
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.skills.assessment_registry import AssessmentSkillRegistry


def test_manifest_contract_and_missing_adapters():
    registry = AssessmentSkillRegistry()
    definitions = registry.definitions()
    assert definitions
    assert len({row.id for row in definitions}) == len(definitions)
    for definition in definitions:
        path = registry.path.parent / definition.path
        assert path.is_file()
        assert definition.path == f"{definition.id}/SKILL.md"
        assert definition.control_test_refs
        assert definition.provenance["upstream_code_copied"] is False
        assert len(definition.provenance["source_sha256"]) == 64
        for capability in (*definition.capabilities, *definition.optional_capabilities):
            assert registry.capabilities.get(capability) is not None
        text = path.read_text()
        for required in (
            "## Purpose and activation",
            "## Prerequisites and context",
            "## Supported input and body formats",
            "## Canonical capability",
            "## Impact profile",
            "## Procedure and control measurements",
            "## Result criteria",
            "## Three separate status dimensions",
            "## Timeout, stop, cleanup and recovery",
            "## Version, provenance and test references",
        ):
            assert required in text, (definition.id, required)
        assert "execution_status" in text and "coverage_status" in text and "finding_status" in text
    sql = registry.eligibility(
        "sql-injection-validation",
        profile="active-staging",
        actor_ref="test-actor",
        has_fixture=True,
    )
    assert not sql.eligible
    assert sql.status in {"blocked_configuration", "blocked_missing_dependency"}
    assert "sqlmap_validate" in sql.missing_capabilities


def test_english_contracts_have_distinct_source_and_translated_content_provenance():
    registry = AssessmentSkillRegistry()
    manifest = json.loads(registry.path.read_text())
    assert manifest["content_language"] == "en"
    for definition in registry.definitions():
        path = registry.path.parent / definition.path
        content = path.read_bytes()
        text = content.decode("utf-8")
        provenance = definition.provenance
        assert provenance["content_language"] == "en"
        assert provenance["content_sha256"] == hashlib.sha256(content).hexdigest()
        assert provenance["source_sha256"] != provenance["content_sha256"]
        assert len(provenance["translation_input_sha256"]) == 64
        assert f'description: "{definition.description}"' in text
        assert not set("áéíóöőúüűÁÉÍÓÖŐÚÜŰ").intersection(text)


def test_new_domain_and_resource_contracts_registered_without_hardcoded_runtime_count():
    registry = AssessmentSkillRegistry()
    required = {
        "service-discovery",
        "dns-asset-discovery",
        "wordpress-assessment",
        "cloud-posture-assessment",
        "kubernetes-benchmark-assessment",
        "local-binary-triage",
        "resilience-recovery",
        "memory-context-budgeting",
        "cache-freshness-control",
        "correlation-hypothesis-review",
        "performance-regression",
        "safe-reproducer-validation",
    }
    assert required <= {row.id for row in registry.definitions()}
    for name in (
        "memory-context-budgeting",
        "cache-freshness-control",
        "correlation-hypothesis-review",
    ):
        assert registry.readiness(name).eligible
    assert registry.get("local-binary-triage").domains == ("binary-lab",)
    assert registry.readiness("local-binary-triage").status == "deferred_not_required"


def test_lazy_metadata_listing_never_reads_skill_bodies():
    skills._assessment_registry_for_file.cache_clear()
    original = Path.read_text

    def read(path, *args, **kwargs):
        assert path.name != "SKILL.md", (
            "listing must use the manifest instead of eager skill body reads"
        )
        return original(path, *args, **kwargs)

    with patch.object(Path, "read_text", read):
        available = skills.get_available_skills()
    assert available["assessment"]
    sql = next(
        item for item in available["assessment"] if item["name"] == "sql-injection-validation"
    )
    assert sql["status"] in {"blocked_configuration", "blocked_missing_dependency"}


def test_namespaced_bare_unique_and_legacy_domain_loading():
    assert skills.validate_requested_skills(["assessment/cache-freshness-control"]) is None
    assert skills.validate_requested_skills(["cache-freshness-control"]) is None
    namespaced = skills.load_skills(["assessment/cache-freshness-control"])
    bare = skills.load_skills(["cache-freshness-control"])
    assert namespaced == bare
    assert "RedJohn capability status" in bare["cache-freshness-control"]
    assert skills.load_skills(["domains/recon"])
    sql = skills.load_skills(["assessment/sql-injection-validation"])
    assert any(
        f"`{status}`" in sql["sql-injection-validation"]
        for status in ("blocked_configuration", "blocked_missing_dependency")
    )


def test_custom_nested_override_ambiguity_and_path_traversal_protection():
    original = list(skills._EXTRA_SKILL_DIRS)
    try:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            nested = path / "assessment" / "cache-freshness-control"
            nested.mkdir(parents=True)
            (nested / "SKILL.md").write_text(
                "---\ndescription: custom cache reference\n---\ncustom body"
            )
            other = path / "other"
            other.mkdir()
            (other / "cache-freshness-control.md").write_text("other body")
            skills.register_skill_dir(path)
            assert "Ambiguous" in skills.validate_requested_skills(["cache-freshness-control"])
            assert (
                skills.load_skills(["assessment/cache-freshness-control"])[
                    "cache-freshness-control"
                ]
                == "custom body"
            )
            assert skills.load_skills(["assessment/../../README"]) == {}
    finally:
        skills._EXTRA_SKILL_DIRS[:] = original


def test_activation_domain_profile_actor_fixture_and_format_are_separate():
    registry = AssessmentSkillRegistry()
    wrong_domain = registry.eligibility("cache-freshness-control", domain="cloud")
    assert wrong_domain.status == "blocked_by_policy" and not wrong_domain.eligible
    assert "target_domain_not_applicable" in wrong_domain.reasons
    sql = registry.eligibility("sql-injection-validation", content_type="application/json")
    assert "controlled_fixture_required" in sql.reasons
    assert "impact_profile_not_permitted" in sql.reasons
    assert "unsupported_body_format" in sql.reasons
    auth = registry.eligibility("authentication-session", profile="active-staging")
    assert "explicit_actor_required" in auth.reasons
    assert not registry.eligibility("does-not-exist").eligible


def test_unknown_capability_or_path_escape_manifest_is_rejected(tmp_path):
    registry = AssessmentSkillRegistry()
    original = json.loads(registry.path.read_text())
    original["skills"][0]["capabilities"] = ["run_any_command"]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(original))
    with pytest.raises(ValueError, match="unknown_assessment_skill_capability"):
        AssessmentSkillRegistry(path)
    original["skills"][0]["capabilities"] = []
    original["skills"][0]["path"] = "../../README.md"
    path.write_text(json.dumps(original))
    with pytest.raises(ValueError, match="invalid_assessment_skill_identity"):
        AssessmentSkillRegistry(path)


def test_dependency_status_and_unimplemented_mapping_are_not_live_proof():
    capabilities = CapabilityRegistry()
    original_health = capabilities.health

    def blocked_health():
        result = original_health()
        for entry in result:
            if entry["id"] == "browser_discover":
                entry["status"] = "blocked_missing_dependency"
        return result

    with patch.object(capabilities, "health", blocked_health):
        registry = AssessmentSkillRegistry(capability_registry=capabilities)
        assert (
            registry.readiness("headless-browser-discovery").status == "blocked_missing_dependency"
        )
    # A binary being found cannot invent reviewed execution configuration.
    with patch("redjohn.assessment.registry.shutil.which", return_value="/fixture/sqlmap"):
        assert (
            AssessmentSkillRegistry().readiness("sql-injection-validation").status
            == "blocked_configuration"
        )
