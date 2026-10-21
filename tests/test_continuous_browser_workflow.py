"""Workflow contract tests with synthetic completion events, without network I/O.

These tests exercise real SQLite admission/acknowledgement and private-vault
validation. The capture metadata and refresh state are deliberate test doubles;
the independent remote E2E test supplies real Chromium/Nuclei proof.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from base64 import b64encode

import pytest

from redjohn.assessment.browser_capture import BrowserPostCaptureService
from redjohn.assessment.browser_workflow import ContinuousBrowserWorkflow
from redjohn.assessment.models import AdapterResult, JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from redjohn.tools.hunt.nuclei import bundle_digest


def _private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


@pytest.fixture
def setup_workflow(tmp_path):
    origin = "https://127.0.0.1:8443"
    policy = EngagementPolicy(
        "continuous-contract",
        "owner",
        (origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("anonymous", "alice", "bob"),
        allowed_replay_urls=(origin + "/json", origin + "/other"),
        allowed_refresh_urls=(origin + "/refresh",),
    )
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(policy)
    identity = {
        "engagement_id": policy.engagement_id,
        "owner_id": policy.owner_id,
        "actor_id": "alice",
        "tenant_id": "tenant-a",
        "policy_revision": policy.revision,
    }
    vault_path, rules_path = tmp_path / "vault.json", tmp_path / "rules.json"
    vault = {
        "version": 2,
        "entries": [
            {
                **identity,
                "session_revision": "7",
                "origin": origin,
                "expires_at": time.time() + 300,
                "headers": {"Authorization": "Bearer harmless-unit-credential"},
                "cookies": [],
                "allowed_requests": [
                    {"url": origin + "/start", "method": "GET", "request_ref": "unit-anchor"}
                ],
            }
        ],
    }
    capture_rules = {
        "version": 1,
        "rules": [
            {
                **identity,
                "session_revision": "current",
                "url": origin + "/json",
                "content_type": "application/json",
                "expires_at": time.time() + 300,
                "automatic_approval": True,
                "start_url": origin + "/start",
            }
        ],
    }
    _private_json(vault_path, vault)
    _private_json(rules_path, capture_rules)
    service = BrowserPostCaptureService(policy, store, vault_path, rules_path)
    files = {"unit.yaml": "a" * 64}
    lock = {
        "binary": {
            "path": "/unit/no-process-started/nuclei",
            "version": "3.11.1",
            "sha256": "b" * 64,
            "source": "Synthetic workflow contract binary metadata",
            "license": "MIT",
        },
        "bundle": {
            "root": "/unit/no-template-read",
            "version": "unit-contract-v1",
            "sha256": bundle_digest(files),
            "source": "Synthetic workflow contract template metadata",
            "license": "Apache-2.0",
            "files": files,
            "templates": [
                {
                    "path": "unit.yaml",
                    "id": "unit-authenticated-post",
                    "profiles": ["isolated-lab"],
                    "effect": "authenticated-replay",
                    "protocol": "http",
                }
            ],
        },
    }
    configuration = {
        "version": 1,
        "rules": [
            {
                "actor_id": "alice",
                "tenant_id": "tenant-a",
                "url": origin + "/json",
                "content_type": "application/json",
                "template_id": "unit-authenticated-post",
            }
        ],
    }
    value = {
        "policy": policy,
        "store": store,
        "service": service,
        "vault_path": vault_path,
        "rules_path": rules_path,
        "vault": vault,
        "capture_rules": capture_rules,
        "configuration": configuration,
        "lock": lock,
        "origin": origin,
    }
    try:
        yield value
    finally:
        store.close()


def _workflow(setup):
    return ContinuousBrowserWorkflow(
        setup["service"],
        setup["store"],
        setup["policy"],
        setup["configuration"],
        setup["lock"],
        setup["vault_path"],
    )


def _finish(setup, capability, parent, surface_ids, *, coverage="completed"):
    store, policy = setup["store"], setup["policy"]
    parent_id = store.upsert_surface(policy.engagement_id, parent)
    job_id = store.submit(
        policy,
        [JobSpec(parent_id, "unit", capability, policy_revision=policy.revision, idempotent=False)],
    )[0]
    job = store.claim(policy, "synthetic-worker")
    assert job["id"] == job_id
    assert store.finish(job, AdapterResult("succeeded", coverage, {"surface_ids": surface_ids}))
    return job_id


def _observed_capture(
    setup, *, revision="7", evidence_changes=None, actor="alice", coverage="completed"
):
    store, policy = setup["store"], setup["policy"]
    body = b'{"value":"harmless-unit-body"}'
    body_sha = hashlib.sha256(body).hexdigest()
    metadata = {
        "engagement_id": policy.engagement_id,
        "policy_revision": policy.revision,
        "actor_id": actor,
        "tenant_id": "tenant-a",
        "session_revision": revision,
        "url": setup["origin"] + "/json",
        "method": "POST",
        "body_sha256": body_sha,
        "request_content_type": "application/json",
        "sent": True,
        "response_complete": True,
        "status": 200,
        **(evidence_changes or {}),
    }
    reference = store.evidence_put(policy.engagement_id, metadata)
    surface = Surface(
        setup["origin"] + "/json",
        "POST",
        "application/json",
        actor_id=actor,
        tenant_id="tenant-a",
        session_revision=revision,
        request_ref=reference,
        body_sha256=body_sha,
    )
    entry = setup["vault"]["entries"][0]
    entry["session_revision"] = revision
    entry["allowed_requests"].append(
        {
            "url": surface.url,
            "method": "POST",
            "request_ref": reference,
            "content_type": surface.content_type,
            "body_base64": b64encode(body).decode(),
            "body_sha256": body_sha,
            "replay_safety": "operator-approved",
        }
    )
    _private_json(setup["vault_path"], setup["vault"])
    surface_id = store.upsert_surface(policy.engagement_id, surface)
    parent = Surface(
        setup["origin"] + "/start",
        actor_id="alice",
        tenant_id="tenant-a",
        session_revision=revision,
        source="imported",
        workflow_state="approved_seed",
    )
    _finish(setup, "browser_post_capture", parent, [surface_id], coverage=coverage)
    return surface


def _synthetic_session_state(setup, revision, status="ready"):
    policy = setup["policy"]
    with setup["store"].transaction() as database:
        database.execute(
            "INSERT OR REPLACE INTO rj_session_state VALUES(?,?,?,?,?,?,NULL,?)",
            (
                policy.engagement_id,
                "alice",
                "tenant-a",
                policy.revision,
                revision,
                status,
                time.time(),
            ),
        )


@pytest.mark.parametrize("coverage", ["completed", "partial"])
def test_capture_success_queues_exact_pinned_template_once_and_recovers_ack(
    setup_workflow, coverage
):
    setup = setup_workflow
    surface = _observed_capture(setup, coverage=coverage)
    workflow = _workflow(setup)
    workflow.reconcile()
    rows = [
        row
        for row in setup["store"].jobs(setup["policy"].engagement_id)
        if row["capability"] == "nuclei_scan"
    ]
    assert len(rows) == 1
    spec = JobSpec(**rows[0]["spec"])
    assert spec.options == {"cve_id": "unit-authenticated-post"}
    assert spec.tool_version == "3.11.1"
    assert spec.template_version == setup["lock"]["bundle"]["sha256"]
    assert not spec.idempotent
    assert setup["store"].surface(setup["policy"].engagement_id, spec.surface_id) == surface
    assert workflow.status()["pending_events"] == 0
    # A new reconciler represents a coordinator recovering after enqueue/ack.
    recovered = _workflow(setup)
    recovered.reconcile()
    assert len(setup["store"].jobs(setup["policy"].engagement_id)) == 2
    assert not recovered.status()["errors"]


@pytest.mark.parametrize("coverage", ["completed", "partial"])
@pytest.mark.parametrize(
    "change",
    [
        {"sent": False},
        {"response_complete": False},
        {"status": 302},
        {"status": 401},
        {"status": True},
        {"session_revision": "6"},
        {"body_sha256": "a" * 64},
        {"policy_revision": "old-policy"},
        {"request_content_type": "application/x-www-form-urlencoded"},
    ],
)
def test_unverified_capture_stays_pending_without_replay(setup_workflow, change, coverage):
    setup = setup_workflow
    _observed_capture(setup, evidence_changes=change, coverage=coverage)
    workflow = _workflow(setup)
    workflow.reconcile()
    assert len(setup["store"].jobs(setup["policy"].engagement_id)) == 1
    assert workflow.status()["pending_events"] == 1
    assert workflow.status()["errors"][0]["code"] == "continuous_replay_capture_unverified"


@pytest.mark.parametrize("status", ["refreshing", "uncertain"])
def test_unready_session_never_replays(setup_workflow, status):
    setup = setup_workflow
    _observed_capture(setup)
    _synthetic_session_state(setup, "7", status)
    workflow = _workflow(setup)
    workflow.reconcile()
    assert not workflow.status()["replay_job_ids"]
    assert workflow.status()["errors"][0]["code"] == "session_refresh_" + status


def test_superseded_capture_is_not_relabelled_as_refreshed(setup_workflow):
    setup = setup_workflow
    _observed_capture(setup)
    _synthetic_session_state(setup, "8")
    workflow = _workflow(setup)
    workflow.reconcile()
    assert workflow.status()["errors"][0]["code"] == "session_revision_superseded"
    assert not workflow.status()["replay_job_ids"]


def test_expired_approval_or_removed_private_binding_blocks_followup(setup_workflow):
    setup = setup_workflow
    _observed_capture(setup)
    setup["vault"]["entries"][0]["allowed_requests"].pop()
    _private_json(setup["vault_path"], setup["vault"])
    workflow = _workflow(setup)
    workflow.reconcile()
    assert workflow.status()["errors"][0]["code"] == "auth_replay_identity_or_request_mismatch"
    assert not workflow.status()["replay_job_ids"]


def test_private_capture_rule_expiry_blocks_new_child(setup_workflow):
    setup = setup_workflow
    _observed_capture(setup)
    workflow = _workflow(setup)
    setup["capture_rules"]["rules"][0]["expires_at"] = time.time() - 1
    _private_json(setup["rules_path"], setup["capture_rules"])
    workflow.reconcile()
    assert (
        workflow.status()["errors"][0]["code"]
        == "continuous_replay_capture_rule_expired_or_changed"
    )
    assert not workflow.status()["replay_job_ids"]


@pytest.mark.parametrize("get_only", [False, True])
@pytest.mark.parametrize("start", ["/start", "/unrelated-start"])
def test_missing_expected_post_is_blocked_and_unrelated_starts_ack_empty(
    setup_workflow, get_only, start
):
    setup = setup_workflow
    policy, store = setup["policy"], setup["store"]
    parent = Surface(
        setup["origin"] + start,
        actor_id="alice",
        tenant_id="tenant-a",
        session_revision="7",
        source="imported",
        workflow_state="approved_seed",
    )
    parent_id = store.upsert_surface(policy.engagement_id, parent)
    _finish(setup, "browser_post_capture", parent, [parent_id] if get_only else [])
    workflow = _workflow(setup)
    workflow.reconcile()
    status = workflow.status()
    assert not status["replay_job_ids"]
    assert len(store.jobs(policy.engagement_id)) == 1
    if start == "/start":
        assert status["pending_events"] == 1
        assert status["errors"][0]["code"] == "continuous_replay_capture_missing"
        assert status["errors"][0]["coverage_status"] == "blocked"
    else:
        assert status["pending_events"] == 0
        assert not status["errors"]


def test_refresh_event_queues_current_capture_without_scanning_pending_body(setup_workflow):
    setup = setup_workflow
    policy, store = setup["policy"], setup["store"]
    old = Surface(
        setup["origin"] + "/json",
        actor_id="alice",
        tenant_id="tenant-a",
        session_revision="7",
    )
    _finish(setup, "session_refresh", old, [])
    _synthetic_session_state(setup, "8")
    setup["vault"]["entries"][0]["session_revision"] = "8"
    _private_json(setup["vault_path"], setup["vault"])
    workflow = _workflow(setup)
    workflow.reconcile()
    assert workflow.status()["pending_events"] == 0
    assert len(workflow.status()["capture_job_ids"]) == 1
    assert not workflow.status()["replay_job_ids"]
    queued = next(
        row
        for row in store.jobs(policy.engagement_id)
        if row["capability"] == "browser_post_capture"
    )
    assert store.surface(policy.engagement_id, queued["surface_id"]).session_revision == "8"
    assert not queued["spec"]["idempotent"]
    workflow.reconcile()
    assert len(store.jobs(policy.engagement_id)) == 2


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("template_id", "unreviewed", "template_not_reviewed"),
        ("url", "https://127.0.0.1:8443/other", "capture_rule_missing"),
        ("content_type", "application/x-www-form-urlencoded", "capture_rule_missing"),
        ("actor_id", "anonymous", "named_actor_and_post_required"),
        ("tenant_id", "different-tenant", "capture_rule_missing"),
    ],
)
def test_replay_configuration_cannot_expand_private_approval(setup_workflow, field, value, error):
    setup = setup_workflow
    setup["configuration"]["rules"][0][field] = value
    with pytest.raises(ValueError, match="continuous_replay_" + error):
        _workflow(setup)


def test_duplicate_and_ambiguous_casefold_selection_are_rejected(setup_workflow):
    setup = setup_workflow
    rule = copy.deepcopy(setup["configuration"]["rules"][0])
    setup["configuration"]["rules"].append(rule)
    with pytest.raises(ValueError, match="duplicate_rule"):
        _workflow(setup)
    setup["configuration"]["rules"].pop()
    alias = copy.deepcopy(setup["lock"]["bundle"]["templates"][0])
    alias["id"] = alias["id"].upper()
    setup["lock"]["bundle"]["templates"].append(alias)
    with pytest.raises(ValueError, match="template_not_reviewed"):
        _workflow(setup)


def test_metadata_accessor_omits_body_token_bindings_and_credentials(setup_workflow):
    setup = setup_workflow
    setup["capture_rules"]["rules"][0]["body_tokens"] = [{"private": "not-public"}]
    _private_json(setup["rules_path"], setup["capture_rules"])
    metadata = setup["service"].reviewed_rule_metadata()
    assert metadata[0]["url"].endswith("/json")
    assert not {"headers", "cookies", "body_tokens", "body_base64"}.intersection(metadata[0])


async def test_runtime_optin_and_prerequisites_preserve_original_startup_mode(setup_workflow):
    setup = setup_workflow
    with pytest.raises(ValueError, match="continuous_replay_configuration_missing"):
        AssessmentRuntime(
            setup["store"],
            setup["policy"],
            caller="owner",
            continuous_replay=setup["configuration"],
        )
    async with AssessmentRuntime(
        setup["store"],
        setup["policy"],
        caller="owner",
        auth_vault_file=setup["vault_path"],
        browser_capture_file=setup["rules_path"],
    ) as runtime:
        assert runtime.scheduler.reconcile is None
        assert not runtime.workflow_status()["enabled"]
        assert len(runtime.capture_job_ids) == 1
    async with AssessmentRuntime(
        setup["store"],
        setup["policy"],
        caller="owner",
        auth_vault_file=setup["vault_path"],
        browser_capture_file=setup["rules_path"],
        continuous_replay=setup["configuration"],
        nuclei_lock=setup["lock"],
    ) as runtime:
        assert runtime.scheduler.reconcile is not None
        assert runtime.workflow_status()["enabled"]
        assert len(runtime.capture_job_ids) == 1
        assert (
            setup["store"].db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 0
        )
