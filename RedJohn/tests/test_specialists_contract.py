"""Contract tests, distinct from the real CLI/Chromium/SQLite suite."""

import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.specialists import (
    CAPABILITIES,
    SpecialistAdapter,
    SpecialistConfig,
    query_mutation_allowed,
    replace_query_value,
)


def document(tool):
    result = {
        "binary": {
            "path": "/absent/" + tool,
            "sha256": "a" * 64,
            "version": {"arjun": "2.2.7", "sqlmap": "1.10.10", "dalfox": "3.2.4"}[tool],
        }
    }
    if tool == "arjun":
        result["parameters"] = ["hidden", "unused"]
    return result


@pytest.mark.parametrize("tool", list(CAPABILITIES))
@pytest.mark.parametrize(
    "field,value",
    [
        ("additional_args", ["--dump"]),
        ("output", "/unapproved/output"),
        ("max_requests", 129),
        ("rate_limit", True),
        ("request_timeout", 0),
    ],
)
def test_configuration_rejects_untyped_arguments_and_unbounded_limits(tool, field, value):
    value_doc = document(tool)
    value_doc[field] = value
    with pytest.raises(ValueError):
        SpecialistConfig.from_mapping(tool, value_doc)


@pytest.mark.parametrize("tool", list(CAPABILITIES))
def test_pins_are_exact_and_qos_does_not_authorize_duplicate_tests(tool):
    original = SpecialistConfig.from_mapping(tool, document(tool))
    assert original.revision == replace(original, rate_limit=1, request_timeout=10).revision
    assert original.revision != replace(original, max_requests=8).revision
    for field, value in (("version", "latest"), ("sha256", "wrong"), ("path", "relative")):
        data = document(tool)
        data["binary"][field] = value
        with pytest.raises(ValueError):
            SpecialistConfig.from_mapping(tool, data)


@pytest.mark.parametrize("tool", list(CAPABILITIES))
def test_registration_is_lazy_and_missing_config_is_blocked_not_negative(tool):
    with patch("asyncio.create_subprocess_exec", side_effect=AssertionError("eager launch")):
        registry = CapabilityRegistry(**{tool + "_config": document(tool)})
        row = next(r for r in registry.health() if r["id"] == CAPABILITIES[tool])
        assert row["adapter_implemented"] and row["status"] == "blocked_missing_dependency"
        assert row["live_verified"] is False
        assert (
            registry.execution_versions(CAPABILITIES[tool])["tool_version"]
            == document(tool)["binary"]["version"]
        )


@pytest.mark.parametrize(
    "original,mutated,allowed",
    [
        (
            "https://example.test/a%2Fb?id=1&x=%2F&x=2&blank=",
            "https://example.test/a%2Fb?id=1%20AND%201=1&x=%2F&x=2&blank=",
            True,
        ),
        ("https://example.test/a%2Fb?id=1", "https://example.test/a/b?id=2", False),
        ("https://example.test/?id=1&x=%2F", "https://example.test/?id=2&x=/", False),
        ("https://example.test/?id=1&x=2", "https://example.test/?x=2&id=3", False),
        ("https://example.test/?id=1", "https://other.test/?id=2", False),
        ("https://example.test/?id=1", "https://example.test/?id=2&id=3", False),
        ("https://example.test/?id=1", "https://example.test/?id=2&extra=3", False),
    ],
)
def test_mutation_preserves_every_unselected_encoded_pair_and_origin(original, mutated, allowed):
    assert query_mutation_allowed(original, mutated, "id") is allowed


def test_targeted_replacement_preserves_encoding_order_and_duplicate_other_params():
    url = "https://example.test/a%2Fb?x=1&id=benign&x=2&empty=&encoded=%2F"
    mutated = replace_query_value(url, "id", "<svg>")
    assert mutated == "https://example.test/a%2Fb?x=1&id=%3Csvg%3E&x=2&empty=&encoded=%2F"


@pytest.mark.parametrize("capability", ["sqlmap_validate", "dalfox_validate"])
def test_new_hint_reference_cannot_authorize_a_duplicate_probe(capability):
    original = JobSpec("surface", "validation", capability, options={"hint_ref": "a" * 32})
    replanned = replace(original, options={"hint_ref": "b" * 32})
    assert original.key == replanned.key
    assert original.options == {"hint_ref": "a" * 32}
    assert original.key != replace(replanned, retest_revision="explicit-retest").key
    assert original.key != replace(replanned, tool_version="different-version").key


@pytest.mark.parametrize("tool", list(CAPABILITIES))
def test_post_and_inferred_inputs_are_explicitly_unsupported(tool):
    config = SpecialistConfig.from_mapping(tool, document(tool))
    policy = EngagementPolicy(
        "e", "o", ("https://example.test",), profile="isolated-lab", egress_mode="enforced"
    )
    spec = JobSpec(
        "surface",
        "test",
        CAPABILITIES[tool],
        tool_version=config.version,
        template_version=config.revision,
    )
    for surface in (
        Surface("https://example.test/input", method="POST"),
        Surface("https://example.test/input", source="inferred"),
    ):
        with pytest.raises((ValueError, PolicyDenied)):
            config.validate_input(policy, surface, spec)


@pytest.mark.parametrize("names", [["x"], ["x", "x"], ["x", "--config"], ["x", "unsafe\nname"]])
def test_arjun_only_host_reviewed_bounded_parameter_names(names):
    data = document("arjun")
    data["parameters"] = names
    with pytest.raises(ValueError):
        SpecialistConfig.from_mapping("arjun", data)


@pytest.mark.parametrize(
    "change", ["incomplete", "wrong-version", "failed-request", "wrong-target", "malformed"]
)
def test_dalfox_schema_failures_are_not_empty_negative_results(tmp_path, change):
    config = SpecialistConfig.from_mapping("dalfox", document("dalfox"))
    alias = "http://127.0.0.1:1234/xss?q=benign"
    data = {
        "findings": [],
        "meta": {
            "dalfox_version": config.version,
            "incomplete": False,
            "failed_requests": 0,
            "targets": [alias],
            "findings_count": 0,
            "target_summary": [{"status": "clean"}],
        },
    }
    if change == "incomplete":
        data["meta"]["incomplete"] = True
    elif change == "wrong-version":
        data["meta"]["dalfox_version"] = "future"
    elif change == "failed-request":
        data["meta"]["failed_requests"] = 1
    elif change == "wrong-target":
        data["meta"]["targets"] = ["https://outside.invalid"]
    else:
        data["meta"]["target_summary"] = ["invalid"]
    assert (
        SpecialistAdapter.read_output(
            SimpleNamespace(config=config),
            {"stdout": json.dumps(data)},
            tmp_path,
            alias,
            "q",
            "payload",
        )
        is None
    )
