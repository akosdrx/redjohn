"""Synthetic auth-signal contract tests, separate from real remote recovery E2E.

SQLite admission, budgets and private-file validation are real. Authentication
responses and session transitions in this file are explicit test doubles.
"""

from __future__ import annotations

import copy
import time

import pytest

from redjohn.assessment.browser_workflow import ContinuousBrowserWorkflow
from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.session_recovery import SessionRecoveryOptions, validate_recovery_event
from tests.test_continuous_browser_workflow import (
    _private_json,
    _synthetic_session_state,
)
from tests.test_continuous_browser_workflow import (
    setup_workflow as setup_workflow,  # noqa: PLC0414 - explicitly expose the pytest fixture
)


def _workflow(setup, *, max_refreshes=1, cooldown_seconds=0):
    configuration = copy.deepcopy(setup["configuration"])
    configuration["session_recovery"] = {
        "max_refreshes": max_refreshes,
        "cooldown_seconds": cooldown_seconds,
    }
    provider_file = setup["vault_path"].with_name("provider.json")
    _private_json(provider_file, {"version": 1, "providers": []})
    return ContinuousBrowserWorkflow(
        setup["service"],
        setup["store"],
        setup["policy"],
        configuration,
        setup["lock"],
        setup["vault_path"],
        refresh_provider_file=provider_file,
    )


def _failure(setup, *, revision="7", label="", expired=False, url=None):
    store, policy = setup["store"], setup["policy"]
    parent = Surface(
        url or setup["origin"] + "/start",
        actor_id="alice",
        tenant_id="tenant-a",
        session_revision=revision,
        source="imported",
        workflow_state="approved_seed",
    )
    surface_id = store.upsert_surface(policy.engagement_id, parent)
    job_id = store.submit(
        policy,
        [
            JobSpec(
                surface_id,
                "discovery",
                "browser_post_capture",
                idempotent=False,
                retest_revision=label,
                policy_revision=policy.revision,
            )
        ],
    )[0]
    job = store.claim(policy, "synthetic-auth-worker")
    assert job["id"] == job_id
    marker = {
        "admitted": True,
        "signal": "credential_expired" if expired else "http_401",
        "actor_id": parent.actor_id,
        "tenant_id": parent.tenant_id,
        "session_revision": parent.session_revision,
        **({} if expired else {"response_complete": True, "status": 401}),
    }
    assert store.finish(
        job,
        AdapterResult(
            "failed",
            "blocked",
            {"auth_recovery": marker},
            error=error_record(
                "browser_capture_credentials_expired" if expired else "authentication_expired",
                category="auth",
                coverage_effect="blocked",
            ),
        ),
    )
    return job_id


def _rotate_synthetic_private_identity(setup, revision):
    setup["vault"]["entries"][0]["session_revision"] = revision
    _private_json(setup["vault_path"], setup["vault"])
    _synthetic_session_state(setup, revision)


@pytest.mark.parametrize("expired", [False, True])
def test_trusted_auth_failure_queues_separate_exact_get_refresh_and_preserves_parent(
    setup_workflow, expired
):
    setup = setup_workflow
    if expired:
        setup["vault"]["entries"][0]["expires_at"] = time.time() - 1
        _private_json(setup["vault_path"], setup["vault"])
    parent_id = _failure(setup, expired=expired)
    workflow = _workflow(setup)
    workflow.reconcile()
    status = workflow.status()
    assert len(status["refresh_job_ids"]) == 1
    assert status["pending_events"] == 0
    assert status["session_recovery"]["refreshes_used"] == 1
    jobs = {row["id"]: row for row in setup["store"].jobs(setup["policy"].engagement_id)}
    assert jobs[parent_id]["execution_status"] == "failed"
    assert jobs[parent_id]["coverage_status"] == "blocked"
    child = jobs[status["refresh_job_ids"][0]]
    assert child["capability"] == "session_refresh"
    assert child["spec"]["idempotent"] is False
    assert not child["spec"]["options"]
    assert child["spec"]["tool_version"] == "1"
    seed = setup["store"].surface(setup["policy"].engagement_id, child["surface_id"])
    assert (seed.method, seed.url, seed.session_revision) == (
        "GET",
        setup["origin"] + "/start",
        "7",
    )
    assert (seed.actor_id, seed.tenant_id) == ("alice", "tenant-a")
    workflow.reconcile()
    assert workflow.status()["session_recovery"]["refreshes_used"] == 1
    assert len(setup["store"].jobs(setup["policy"].engagement_id)) == 2


def test_two_auth_failures_coalesce_to_one_canonical_refresh(setup_workflow):
    setup = setup_workflow
    _failure(setup, label="one")
    _failure(setup, label="two")
    workflow = _workflow(setup)
    workflow.reconcile()
    status = workflow.status()
    assert status["pending_events"] == 0
    assert len(status["refresh_job_ids"]) == 1
    assert status["session_recovery"]["refreshes_used"] == 1
    assert len(setup["store"].jobs(setup["policy"].engagement_id)) == 3


@pytest.mark.parametrize(
    ("max_refreshes", "cooldown_seconds", "expected"),
    [(1, 0, "auth_recovery_budget_exhausted"), (3, 3600, "auth_recovery_cooldown_active")],
)
def test_budget_and_cooldown_survive_new_reconciler_and_session_revision(
    setup_workflow, max_refreshes, cooldown_seconds, expected
):
    setup = setup_workflow
    _failure(setup)
    workflow = _workflow(setup, max_refreshes=max_refreshes, cooldown_seconds=cooldown_seconds)
    workflow.reconcile()
    refresh_id = workflow.status()["refresh_job_ids"][0]
    setup["store"].cancel(setup["policy"].engagement_id, refresh_id)
    _rotate_synthetic_private_identity(setup, "8")
    _failure(setup, revision="8")
    recovered = _workflow(setup, max_refreshes=max_refreshes, cooldown_seconds=cooldown_seconds)
    recovered.reconcile()
    status = recovered.status()
    assert status["pending_events"] == 1
    assert status["errors"][0]["code"] == expected
    assert status["session_recovery"]["refreshes_used"] == 1
    assert not status["refresh_job_ids"]


def test_superseded_auth_failure_acknowledges_without_old_vault_or_refresh(setup_workflow):
    setup = setup_workflow
    _failure(setup)
    _rotate_synthetic_private_identity(setup, "8")
    workflow = _workflow(setup)
    workflow.reconcile()
    status = workflow.status()
    assert status["pending_events"] == 0
    assert status["session_recovery"]["refreshes_used"] == 0
    assert not status["refresh_job_ids"]


@pytest.mark.parametrize("problem", ["uncertain", "missing_anchor", "private_permissions"])
def test_unknown_session_or_unreviewed_private_anchor_never_refreshes(setup_workflow, problem):
    setup = setup_workflow
    _failure(setup)
    if problem == "uncertain":
        _synthetic_session_state(setup, "7", "uncertain")
        expected = "session_refresh_uncertain"
    elif problem == "missing_anchor":
        setup["vault"]["entries"][0]["allowed_requests"][0]["url"] = (
            setup["origin"] + "/different-private-anchor"
        )
        _private_json(setup["vault_path"], setup["vault"])
        expected = "session_recovery_private_get_anchor_missing"
    else:
        setup["vault_path"].chmod(0o644)
        expected = "auth_replay_secret_file_not_private"
    workflow = _workflow(setup)
    workflow.reconcile()
    status = workflow.status()
    assert status["pending_events"] == 1
    assert status["errors"][0]["code"] == expected
    assert status["session_recovery"]["refreshes_used"] == 0
    assert not status["refresh_job_ids"]


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"max_refreshes": 1},
        {"max_refreshes": True, "cooldown_seconds": 0},
        {"max_refreshes": 0, "cooldown_seconds": 0},
        {"max_refreshes": 4, "cooldown_seconds": 0},
        {"max_refreshes": 1, "cooldown_seconds": -1},
        {"max_refreshes": 1, "cooldown_seconds": 3601},
        {"max_refreshes": 1, "cooldown_seconds": True},
        {"max_refreshes": 1, "cooldown_seconds": 0.5},
        {"max_refreshes": 1, "cooldown_seconds": 0, "extra": 1},
    ],
)
def test_recovery_configuration_is_strict_and_bounded(value):
    with pytest.raises(ValueError, match="session_recovery_invalid_configuration"):
        SessionRecoveryOptions.from_mapping(value)


@pytest.mark.parametrize(
    "marker_change",
    [
        {"admitted": False},
        {"actor_id": "bob"},
        {"tenant_id": "other"},
        {"session_revision": "8"},
        {"status": 403},
        {"response_complete": False},
        {"signal": "browser_text_says_logged_out"},
    ],
)
def test_missing_or_wrong_host_authentication_signal_is_not_recovery_proof(marker_change):
    parent = Surface("https://127.0.0.1:8443/start", actor_id="alice", tenant_id="tenant-a")
    event = {
        "capability": "browser_post_capture",
        "result": {
            "execution_status": "failed",
            "coverage_status": "blocked",
            "error": {"code": "authentication_expired"},
            "summary": {
                "auth_recovery": {
                    "admitted": True,
                    "signal": "http_401",
                    "actor_id": "alice",
                    "tenant_id": "tenant-a",
                    "session_revision": "1",
                    "response_complete": True,
                    "status": 401,
                    **marker_change,
                }
            },
        },
    }
    with pytest.raises(ValueError, match="session_recovery_untrusted_failure"):
        validate_recovery_event(event, parent)


async def test_recovery_optin_requires_provider_and_enables_only_selected_adapters(setup_workflow):
    setup = setup_workflow
    configuration = copy.deepcopy(setup["configuration"])
    configuration["session_recovery"] = {"max_refreshes": 1, "cooldown_seconds": 0}
    with pytest.raises(ValueError, match="session_recovery_provider_configuration_missing"):
        AssessmentRuntime(
            setup["store"],
            setup["policy"],
            caller="owner",
            nuclei_lock=setup["lock"],
            auth_vault_file=setup["vault_path"],
            browser_capture_file=setup["rules_path"],
            continuous_replay=configuration,
        )
    provider = setup["vault_path"].with_name("provider.json")
    _private_json(provider, {"version": 1, "providers": []})
    async with AssessmentRuntime(
        setup["store"],
        setup["policy"],
        caller="owner",
        nuclei_lock=setup["lock"],
        auth_vault_file=setup["vault_path"],
        browser_capture_file=setup["rules_path"],
        continuous_replay=configuration,
        refresh_provider_file=provider,
    ) as runtime:
        assert runtime.workflow_status()["session_recovery"]["enabled"]
        assert runtime.scheduler.adapters["nuclei_scan"].session_recovery_enabled
        assert runtime.scheduler.adapters["browser_post_capture"].session_recovery_enabled
        assert not runtime.scheduler.adapters["browser_discover"].session_recovery_enabled
        assert (
            setup["store"].db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 0
        )
