"""Private-file/SQLite contracts; fabricated checkpoints are not browser evidence."""

from __future__ import annotations

import base64
import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from redjohn.assessment.browser_action_models import BrowserAuthPlan, ReviewedBrowserAction
from redjohn.assessment.browser_auth_flow import BrowserAuthFlowAdapter, BrowserAuthFlowConfig
from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.inventory import InventoryConflictError
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.workflow_inputs import PrivateWorkflowState, WorkflowInputVault


ORIGIN = "https://127.0.0.1:41011"


def private_file(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def prepared(tmp_path, *, budget=0):
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(
        EngagementPolicy(
            "auth",
            "operator",
            (ORIGIN,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice"),
            allowed_replay_urls=(ORIGIN + "/login",),
            network_request_budget=budget,
        )
    )
    plan = BrowserAuthPlan(
        "login",
        "1",
        "alice",
        "a",
        (
            ReviewedBrowserAction("navigate", url=ORIGIN + "/login"),
            ReviewedBrowserAction(
                "submit",
                selector="#form",
                url=ORIGIN + "/login",
                nonce_selector="#csrf",
                nonce_field="csrf",
                fields=("csrf",),
            ),
        ),
        (ORIGIN + "/login", ORIGIN + "/whoami"),
        ORIGIN + "/whoami",
    )
    pid = store.auth_flows.register(policy, plan)
    flow = store.auth_flows.start(policy, pid, "first")
    sid = store.upsert_surface(
        policy.engagement_id,
        Surface(
            ORIGIN + "/login",
            actor_id="alice",
            tenant_id="a",
            source="imported",
            workflow_state="approved_seed",
        ),
    )
    store.submit(
        policy,
        [
            JobSpec(
                sid,
                "auth",
                "browser_auth_flow",
                policy_revision=policy.revision,
                idempotent=False,
                options={"flow_id": flow, "expected_revision": 1},
            )
        ],
    )
    job = store.claim(policy, "owned-worker")
    store.auth_flows.claim(policy, job, flow)
    return store, policy, flow, job


def test_one_use_input_stays_consumed_across_checkpoint_and_restart(tmp_path):
    store, policy, flow, job = prepared(tmp_path)
    store.auth_flows.admit(policy, job, flow, ("opaque-one-use-reference",))
    assert store.request_usage(policy) == 1
    store.auth_flows.checkpoint(policy, job, flow, 1)
    with pytest.raises(PolicyDenied, match="already_consumed"):
        store.auth_flows.admit(policy, job, flow, ("opaque-one-use-reference",))
    assert store.request_usage(policy) == 1
    store.close()
    reopened = AssessmentStore(tmp_path / "state.db")
    with pytest.raises(PolicyDenied, match="already_consumed"):
        reopened.auth_flows.admit(policy, job, flow, ("opaque-one-use-reference",))
    assert reopened.db.execute("SELECT state FROM rj_auth_input_use").fetchone()[0] == "settled"
    reopened.close()


@pytest.mark.parametrize("admitted", [False, True])
def test_cancellation_or_lost_lease_does_not_reuse_admitted_inputs(tmp_path, admitted):
    store, policy, flow, job = prepared(tmp_path)
    if admitted:
        store.auth_flows.admit(policy, job, flow, ("opaque-nonce",))
    store.db.execute("UPDATE rj_job SET cancel_requested=1,lease_until=0")
    store.auth_flows.uncertain(policy, job, flow)
    state = store.auth_flows.get(policy, flow)
    assert state["status"] == ("uncertain" if admitted else "awaiting_input")
    assert store.db.execute("SELECT count(*) FROM rj_auth_input_use").fetchone()[0] == int(admitted)
    with pytest.raises(PolicyDenied, match="scheduler_lease"):
        store.auth_flows.admit(policy, job, flow, ("never-sent",))
    store.close()


def test_failure_after_ready_commit_downgrades_current_identity(tmp_path):
    store, policy, flow, job = prepared(tmp_path)
    assert store.auth_flows.finish(policy, job, flow, "authenticated") == "2"
    store.auth_flows.uncertain(policy, job, flow)
    assert store.auth_flows.get(policy, flow)["status"] == "uncertain"
    state = store.session_state(policy, Surface(ORIGIN, actor_id="alice", tenant_id="a"))
    assert state["revision"] == "2" and state["status"] == "uncertain"
    store.close()


def test_auth_session_commit_requires_exact_row_cas(tmp_path):
    store, policy, flow, job = prepared(tmp_path)
    store.db.execute("UPDATE rj_session_state SET revision='99'")
    with pytest.raises(InventoryConflictError, match="commit_not_current"):
        store.auth_flows.finish(policy, job, flow, "authenticated")
    assert store.auth_flows.get(policy, flow)["status"] == "running"
    store.close()


def test_private_checkpoint_cas_prevents_cross_actor_lost_update(tmp_path):
    store, policy, _flow, _job = prepared(tmp_path)
    identity = {
        "version": 1,
        "engagement_id": policy.engagement_id,
        "owner_id": policy.owner_id,
        "policy_revision": policy.revision,
    }
    path = private_file(tmp_path / "private-state.json", {**identity, "flows": {}})
    one, two = PrivateWorkflowState(path, policy), PrivateWorkflowState(path, policy)
    one.put("first", {"private": "first-private-cookie"})
    with pytest.raises(ValueError):
        two.put("second", {"private": "must-not-overwrite-first"})
    assert json.loads(path.read_text())["flows"] == {"first": {"private": "first-private-cookie"}}
    assert "first-private-cookie" not in "\n".join(store.db.iterdump())
    store.close()


def test_private_inputs_bound_to_actor_tenant_and_keyed_nonce_identity(tmp_path):
    store, policy, _flow, _job = prepared(tmp_path)
    value = {
        "version": 1,
        "engagement_id": policy.engagement_id,
        "owner_id": policy.owner_id,
        "policy_revision": policy.revision,
        "state_key_base64": base64.b64encode(secrets.token_bytes(32)).decode(),
        "inputs": [
            {
                "reference": "otp",
                "actor_id": "alice",
                "tenant_id": "a",
                "purpose": "mfa_code",
                "value": "123456",
                "single_use": True,
                "expires_at": time.time() + 60,
            }
        ],
    }
    path = private_file(tmp_path / "inputs.json", value)
    vault = WorkflowInputVault(path, policy)
    assert vault.get("otp", "alice", "a").value == "123456"
    assert "123456" not in repr(vault.get("otp", "alice", "a"))
    with pytest.raises(PolicyDenied):
        vault.get("otp", "alice", "foreign-tenant")
    nonce = vault.nonce_reference("alice", "a", ORIGIN, "123456")
    assert len(nonce) == 64 and nonce != vault.nonce_reference("alice", "a", ORIGIN, "123457")
    assert nonce != vault.nonce_reference("alice", "b", ORIGIN, "123456")
    value["inputs"][0]["single_use"] = False
    private_file(path, value)
    with pytest.raises(ValueError):
        WorkflowInputVault(path, policy)
    store.close()


def test_independent_network_budget_exact_limit_and_restart(tmp_path):
    store, policy, _flow, _job = prepared(tmp_path)
    with pytest.raises(PolicyDenied, match="network_request_budget"):
        store.consume_network_requests(policy)
    bounded = store.register(replace(policy, revision="2", network_request_budget=2))
    store.consume_network_requests(bounded, 2)
    assert store.network_request_usage(bounded) == 2
    with pytest.raises(PolicyDenied):
        store.consume_network_requests(bounded)
    assert store.request_usage(bounded) == 0
    store.close()
    reopened = AssessmentStore(tmp_path / "state.db")
    assert reopened.network_request_usage(bounded) == 2
    with pytest.raises(PolicyDenied):
        reopened.consume_network_requests(policy)
    reopened.cancel(bounded.engagement_id)
    with pytest.raises(PolicyDenied):
        reopened.consume_network_requests(bounded)
    reopened.close()


def test_concurrent_network_budget_cannot_overspend(tmp_path):
    store, policy, _flow, _job = prepared(tmp_path, budget=1)
    second = AssessmentStore(tmp_path / "state.db")
    barrier = Barrier(2)

    def charge(connection):
        barrier.wait()
        try:
            connection.consume_network_requests(policy)
        except PolicyDenied:
            return "denied"
        else:
            return "charged"

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(charge, (store, second)))
    assert sorted(results) == ["charged", "denied"]
    assert store.network_request_usage(policy) == 1
    store.close()
    second.close()


async def test_removed_auth_plan_never_executes_or_reappears_as_current_config(tmp_path):
    """No-browser contract double proves a removed plan cannot reach Chromium."""
    store, policy, flow, job = prepared(tmp_path)
    old = store.auth_flows.get(policy, flow)
    configured = replace(store.auth_flows.plan(policy, old["plan_id"]), name="currently-selected")
    identity = {
        "version": 1,
        "engagement_id": policy.engagement_id,
        "owner_id": policy.owner_id,
        "policy_revision": policy.revision,
    }
    inputs = private_file(
        tmp_path / "inputs.json",
        {
            **identity,
            "state_key_base64": base64.b64encode(secrets.token_bytes(32)).decode(),
            "inputs": [],
        },
    )
    state = private_file(tmp_path / "private-state.json", {**identity, "flows": {}})
    adapter = BrowserAuthFlowAdapter(
        BrowserAuthFlowConfig(inputs, state, (configured,)), policy, store, object()
    )
    spec = JobSpec(**json.loads(job["spec"]))
    result = await adapter.run(job, store.surface(policy.engagement_id, spec.surface_id), spec)
    assert (
        result.coverage_status == "blocked"
        and result.error["code"] == "auth_plan_not_currently_configured"
    )
    assert store.request_usage(policy) == 0
    control = AssessmentControl(store, policy, caller=policy.owner_id)
    control.auth_plan_ids = adapter.plan_ids
    try:
        visible = await control.call("auth_plan_search", {"policy_revision": policy.revision})
        assert [item["plan_id"] for item in visible["result"]["items"]] == list(adapter.plan_ids)
        denied = await control.call(
            "auth_flow_start",
            {"policy_revision": policy.revision, "plan_id": old["plan_id"], "run_key": "removed"},
        )
        assert not denied["ok"]
    finally:
        control.close()
        store.close()
