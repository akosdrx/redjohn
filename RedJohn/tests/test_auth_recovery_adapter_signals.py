"""Fake browser result contracts; real HTTPS/Chromium cases live in separate E2E."""

from types import SimpleNamespace

import pytest

from redjohn.assessment.adapters import BrowserInventoryAdapter
from redjohn.assessment.browser import (
    BrowserDiscoveryResult,
    BrowserDiscoveryService,
    BrowserFailure,
    BrowserObservation,
)
from redjohn.assessment.browser_capture import BrowserCaptureDenied
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.store import AssessmentStore


@pytest.mark.parametrize(
    ("enabled", "code", "expected_signal"),
    [
        (True, "browser_capture_credentials_expired", "credential_expired"),
        (False, "browser_capture_credentials_expired", None),
        (True, "browser_capture_credentials_expired_or_superseded", None),
        (True, "browser_capture_private_vault_unavailable", None),
        (True, "browser_capture_revision_or_rule_expired", None),
    ],
)
async def test_mock_browser_preflight_only_proven_credential_expiry_requests_recovery(
    tmp_path, enabled, code, expected_signal
):
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(
        EngagementPolicy(
            "adapter-expiry", "operator", ("https://127.0.0.1:8443",), actor_ids=("alice",)
        )
    )

    def metadata(*_args, **_kwargs):
        raise BrowserCaptureDenied(code)

    service = SimpleNamespace(post_capture=SimpleNamespace(context_metadata=metadata))
    adapter = BrowserInventoryAdapter(
        service, policy, store, capture_post=True, session_recovery_enabled=enabled
    )
    surface = Surface(policy.allowed_origins[0] + "/start", actor_id="alice", session_revision="7")
    try:
        result = await adapter.run(
            {"id": "mock-browser-job"},
            surface,
            JobSpec("surface", "discovery", "browser_post_capture", idempotent=False),
        )
        assert result.execution_status == "failed" and result.coverage_status == "blocked"
        if expected_signal is None:
            assert "auth_recovery" not in result.summary
            assert result.error["code"] == "browser_capture_context_unavailable"
        else:
            assert result.summary["auth_recovery"] == {
                "admitted": True,
                "signal": expected_signal,
                "actor_id": "alice",
                "tenant_id": "",
                "session_revision": "7",
            }
            assert result.error["code"] == code
    finally:
        store.close()


@pytest.mark.parametrize(
    ("method", "path", "status", "expected"),
    [
        ("GET", "/start", 401, 1),
        ("POST", "/submit", 401, 1),
        ("GET", "/submit", 401, 0),
        ("HEAD", "/start", 401, 0),
        ("POST", "/start", 401, 0),
        ("GET", "/start", 403, 0),
    ],
)
def test_mock_complete_response_requires_the_exact_reviewed_http_method(
    method, path, status, expected
):
    origin = "https://127.0.0.1:8443"
    service = BrowserDiscoveryService(
        EngagementPolicy("method-proof", "operator", (origin,)), ResourceGovernor()
    )
    service._active_recovery_requests = frozenset(
        {("GET", origin + "/start"), ("POST", origin + "/submit")}
    )
    service._completed_recovery_response(origin + path, method, status, {})
    assert service._complete_http_401_responses == expected


@pytest.mark.parametrize(
    ("enabled", "complete", "uncertain", "expected"),
    [
        (True, True, False, True),
        (False, True, False, False),
        (True, False, False, False),
        (True, True, True, False),
    ],
)
async def test_mock_browser_metadata_or_unknown_post_cannot_supply_complete_401_proof(
    tmp_path, enabled, complete, uncertain, expected
):
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(
        EngagementPolicy(
            "adapter-401", "operator", ("https://127.0.0.1:8443",), actor_ids=("alice",)
        )
    )
    surface = Surface(policy.allowed_origins[0] + "/start", actor_id="alice", session_revision="7")
    result = BrowserDiscoveryResult(
        observations=[
            BrowserObservation(
                url=surface.url,
                method="GET",
                resource_type="document",
                content_type="text/html",
                actor_id="alice",
                tenant_id="",
                session_revision="7",
                policy_revision=policy.revision,
                engagement_id=policy.engagement_id,
                status=401,
            )
        ],
        metrics={"complete_http_401_responses": int(complete)},
        failures=[BrowserFailure("browser_capture_request_inconclusive")] if uncertain else [],
    )

    async def discover(*_args, **_kwargs):
        return result

    service = SimpleNamespace(
        post_capture=SimpleNamespace(
            context_metadata=lambda *_args, **_kwargs: {"session_revision": "7"}
        ),
        discover=discover,
        healthcheck=dict,
    )
    adapter = BrowserInventoryAdapter(
        service, policy, store, capture_post=True, session_recovery_enabled=enabled
    )
    try:
        observed = await adapter.run(
            {"id": "mock-browser-job"},
            surface,
            JobSpec("surface", "discovery", "browser_post_capture", idempotent=False),
        )
        assert observed.execution_status == "failed" and observed.coverage_status == "blocked"
        assert ("auth_recovery" in observed.summary) is expected
        if expected:
            assert observed.summary["auth_recovery"]["status"] == 401
            assert observed.summary["auth_recovery"]["response_complete"] is True
    finally:
        store.close()
