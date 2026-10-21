"""Native skill eligibility metadata, separate from actual engine/refresh proof."""

import pytest

from redjohn.skills.assessment_registry import AssessmentSkillRegistry


@pytest.mark.parametrize(
    "content_type",
    [
        "",
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=owned",
    ],
)
def test_nuclei_replay_skill_checks_declared_body_subset(content_type):
    registry = AssessmentSkillRegistry()
    result = registry.eligibility(
        "nuclei-cve-planning",
        profile="active-staging",
        content_type=content_type,
        actor_ref="alice",
    )
    assert "unsupported_body_format" not in result.reasons
    unsupported = registry.eligibility(
        "nuclei-cve-planning",
        profile="active-staging",
        content_type="application/xml",
        actor_ref="alice",
    )
    assert not unsupported.eligible
    assert "unsupported_body_format" in unsupported.reasons


def test_implemented_refresh_subset_does_not_claim_complete_authentication_workflow():
    registry = AssessmentSkillRegistry()
    definition = registry.get("authentication-session")
    assert definition.optional_capabilities == (
        "nuclei_scan",
        "session_refresh",
        "browser_post_capture",
    )
    result = registry.eligibility(
        "authentication-session",
        profile="active-staging",
        content_type="application/json",
        actor_ref="alice",
    )
    assert not result.eligible
    assert result.status == "adapter_not_implemented"
    assert "controlled_session_replay" in result.missing_capabilities
    assert "unsupported_body_format" not in result.reasons
