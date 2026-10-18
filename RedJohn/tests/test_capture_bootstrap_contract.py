"""Synthetic auth proof preconditions test the host bridge, not real login/E2E."""

import base64
import copy
import hashlib
import json
import time

import pytest

from redjohn.assessment.auth_flow_state import AuthFlowRepository
from redjohn.assessment.browser_capture import BrowserCaptureDenied
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import PolicyDenied
from tests.test_browser_post_capture import configured_capture


@pytest.fixture
def bootstrap_case(tmp_path):
    origin = "https://127.0.0.1:44443"
    policy, store, service, vault_file, rules_file = configured_capture(tmp_path, origin)
    AuthFlowRepository(store)
    vault_file.write_text(json.dumps({"version": 2, "entries": []}))
    surface_id = store.upsert_surface(
        policy.engagement_id,
        Surface(origin + "/whoami", actor_id="alice", tenant_id="tenant-a", session_revision="6"),
    )
    job_id = store.submit(
        policy,
        [
            JobSpec(
                surface_id,
                "auth",
                "browser_auth_flow",
                idempotent=False,
                options={"flow_id": "owned-flow", "expected_revision": 1},
            )
        ],
    )[0]
    expiry = time.time() + 200
    data = {
        "engagement_id": policy.engagement_id,
        "owner_id": policy.owner_id,
        "policy_revision": policy.revision,
        "flow_id": "owned-flow",
        "actor_id": "alice",
        "tenant_id": "tenant-a",
        "session_revision": "7",
        "outcome": "authenticated",
        "identity_verified": True,
        "identity_url": origin + "/whoami",
        "identity_status": 200,
        "origin": origin,
        "expires_at": expiry,
        "requests": 3,
    }
    ref = store.evidence_put(policy.engagement_id, data, job_id=job_id, kind="auth_flow_outcome")
    storage = {
        "cookies": [
            {
                "name": "session",
                "value": "private-fixture-cookie",
                "domain": "127.0.0.1",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "sameSite": "Strict",
                "expires": -1,
            }
        ],
        "origins": [],
    }
    state_file = tmp_path / "auth-state.json"
    checkpoint = {
        "actor_id": "alice",
        "tenant_id": "tenant-a",
        "session_revision": "7",
        "outcome": "authenticated",
        "auth_evidence_ref": ref,
        "storage_state": storage,
    }
    state = {
        "version": 1,
        "engagement_id": policy.engagement_id,
        "owner_id": policy.owner_id,
        "policy_revision": policy.revision,
        "flows": {"owned-flow": checkpoint},
    }
    state_file.write_text(json.dumps(state))
    state_file.chmod(0o600)
    with store.transaction() as db:
        db.execute(
            "UPDATE rj_job SET execution_status='running',lease_until=? WHERE id=?",
            (time.time() + 200, job_id),
        )
        db.execute(
            "INSERT INTO rj_auth_plan VALUES(?,?,?,?)",
            (
                "owned-plan",
                policy.engagement_id,
                policy.revision,
                json.dumps(
                    {
                        "identity_url": origin + "/whoami",
                        "actor_id": "alice",
                        "tenant_id": "tenant-a",
                        "outcome": "authenticated",
                    }
                ),
            ),
        )
        db.execute(
            "INSERT INTO rj_auth_flow(id,engagement,policy_revision,plan_id,run_key,"
            "actor,tenant,from_revision,revision,status,next_action,owner,attempt,"
            "admitted,updated_at,job_id) VALUES(?,?,?,?,?,?,?,?,1,'ready',0,NULL,NULL,0,?,?)",
            (
                "owned-flow",
                policy.engagement_id,
                policy.revision,
                "owned-plan",
                "owned-run",
                "alice",
                "tenant-a",
                "6",
                time.time(),
                job_id,
            ),
        )
        db.execute(
            "INSERT INTO rj_session_state VALUES(?,?,?,?,?,'ready',NULL,?)",
            (policy.engagement_id, "alice", "tenant-a", policy.revision, "7", time.time()),
        )
    case = dict(locals())
    try:
        yield case
    finally:
        store.close()


def invoke(case):
    case["service"].bootstrap_authenticated_context(
        "alice",
        "tenant-a",
        "7",
        case["storage"],
        case["ref"],
        private_state_file=case["state_file"],
    )


def test_verified_private_bridge_only_adds_reviewed_get_anchors_and_is_idempotent(bootstrap_case):
    c = bootstrap_case
    invoke(c)
    vault = json.loads(c["vault_file"].read_text())
    assert len(vault["entries"]) == 1
    entry = vault["entries"][0]
    assert entry["session_revision"] == "7" and entry["headers"] == {}
    assert entry["cookies"] == [{"name": "session", "value": "private-fixture-cookie"}]
    assert entry["allowed_requests"] == [
        {
            "url": c["origin"] + "/start",
            "method": "GET",
            "request_ref": "auth-bootstrap:" + c["ref"],
        }
    ]
    assert entry["expires_at"] <= c["data"]["expires_at"]
    before = c["vault_file"].read_bytes()
    invoke(c)
    assert c["vault_file"].read_bytes() == before
    assert c["store"].network_request_usage(c["policy"]) == 0


@pytest.mark.parametrize("producer_job", [None, "unrelated-producer"])
def test_bootstrap_requires_the_ready_flows_exact_outcome_producer(bootstrap_case, producer_job):
    c = bootstrap_case
    c["store"].db.execute(
        "UPDATE rj_auth_flow SET job_id=? WHERE id='owned-flow'", (producer_job,)
    )
    before = c["vault_file"].read_bytes()
    with pytest.raises(BrowserCaptureDenied, match="outcome_producer_mismatch"):
        invoke(c)
    assert c["vault_file"].read_bytes() == before
    assert c["store"].network_request_usage(c["policy"]) == 0


@pytest.mark.parametrize(
    "fault",
    [
        "actor",
        "tenant",
        "policy",
        "expired",
        "not_verified",
        "status",
        "producer_capability",
        "producer_cancelled",
        "producer_expired_lease",
        "producer_failed",
        "wrong_job_flow",
        "flow_not_ready",
        "session_stale",
        "checkpoint",
        "checkpoint_permissions",
        "cookie_domain",
        "cookie_path",
        "cookie_duplicate",
        "cookie_expired",
        "rule_expired",
    ],
)
def test_bootstrap_denies_unverified_stale_cross_identity_and_cookie_scope_without_vault_write(
    bootstrap_case, fault
):
    c = bootstrap_case
    data = copy.deepcopy(c["data"])
    if fault in {"actor", "tenant", "policy", "expired", "not_verified", "status"}:
        key, value = {
            "actor": ("actor_id", "bob"),
            "tenant": ("tenant_id", "other"),
            "policy": ("policy_revision", "stale"),
            "expired": ("expires_at", time.time() - 1),
            "not_verified": ("identity_verified", False),
            "status": ("identity_status", 401),
        }[fault]
        data[key] = value
        with c["store"].transaction() as db:
            db.execute(
                "UPDATE rj_evidence SET payload=? WHERE id=?", (json.dumps(data).encode(), c["ref"])
            )
    elif fault.startswith("producer_"):
        query, value = {
            "producer_capability": (
                "UPDATE rj_job SET capability=? WHERE id=?",
                "browser_discover",
            ),
            "producer_cancelled": ("UPDATE rj_job SET cancel_requested=? WHERE id=?", 1),
            "producer_expired_lease": ("UPDATE rj_job SET lease_until=? WHERE id=?", 1),
            "producer_failed": ("UPDATE rj_job SET execution_status=? WHERE id=?", "failed"),
        }[fault]
        with c["store"].transaction() as db:
            db.execute(query, (value, c["job_id"]))
    elif fault == "wrong_job_flow":
        with c["store"].transaction() as db:
            spec = json.loads(
                db.execute("SELECT spec FROM rj_job WHERE id=?", (c["job_id"],)).fetchone()[0]
            )
            spec["options"]["flow_id"] = "other"
            db.execute("UPDATE rj_job SET spec=? WHERE id=?", (json.dumps(spec), c["job_id"]))
    elif fault == "flow_not_ready":
        c["store"].db.execute("UPDATE rj_auth_flow SET status='uncertain'")
    elif fault == "session_stale":
        c["store"].db.execute("UPDATE rj_session_state SET revision='8'")
    elif fault == "checkpoint":
        c["state"]["flows"]["owned-flow"]["auth_evidence_ref"] = "other"
        c["state_file"].write_text(json.dumps(c["state"]))
    elif fault == "checkpoint_permissions":
        c["state_file"].chmod(0o644)
    elif fault.startswith("cookie_"):
        cookie = c["storage"]["cookies"][0]
        if fault == "cookie_duplicate":
            c["storage"]["cookies"].append(dict(cookie))
        else:
            key, value = {
                "cookie_domain": ("domain", "elsewhere.test"),
                "cookie_path": ("path", "/login"),
                "cookie_expired": ("expires", time.time() - 1),
            }[fault]
            cookie[key] = value
        c["state_file"].write_text(json.dumps(c["state"]))
    elif fault == "rule_expired":
        rules = json.loads(c["rules_file"].read_text())
        for rule in rules["rules"]:
            rule["expires_at"] = time.time() - 1
        c["rules_file"].write_text(json.dumps(rules))
    before = c["vault_file"].read_bytes()
    with pytest.raises((BrowserCaptureDenied, PolicyDenied, ValueError)):
        invoke(c)
    assert c["vault_file"].read_bytes() == before


def test_current_conflicting_credentials_are_not_overwritten(bootstrap_case):
    c = bootstrap_case
    invoke(c)
    vault = json.loads(c["vault_file"].read_text())
    vault["entries"][0]["cookies"][0]["value"] = "other-private-cookie"
    c["vault_file"].write_text(json.dumps(vault))
    before = c["vault_file"].read_bytes()
    with pytest.raises(BrowserCaptureDenied, match="current_credentials_conflict"):
        invoke(c)
    assert c["vault_file"].read_bytes() == before


def test_idempotent_restore_preserves_fresh_captured_post_and_other_identities(bootstrap_case):
    c = bootstrap_case
    invoke(c)
    vault = json.loads(c["vault_file"].read_text())
    captured = copy.deepcopy(vault["entries"][0])
    body = b'{"value":"reviewed-fixture"}'
    captured["allowed_requests"] = [
        {
            "url": c["origin"] + "/json",
            "method": "POST",
            "request_ref": "fresh-private-capture",
            "content_type": "application/json",
            "body_base64": base64.b64encode(body).decode(),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "replay_safety": "operator-approved",
        }
    ]
    other = copy.deepcopy(vault["entries"][0])
    other["actor_id"] = "bob"
    other["cookies"][0]["value"] = "bob-private-cookie"
    vault["entries"].extend([captured, other])
    c["vault_file"].write_text(json.dumps(vault))
    before = c["vault_file"].read_bytes()
    invoke(c)
    assert c["vault_file"].read_bytes() == before
