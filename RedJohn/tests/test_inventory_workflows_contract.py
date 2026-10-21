"""SQLite metadata/state contracts; synthetic outcomes are not network E2E."""

from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from threading import Barrier

import pytest

from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.inventory import InventoryConflictError, InventoryRepository
from redjohn.assessment.models import JobSpec, Surface, stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.scheduler import Scheduler
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.workflow_execution import WorkflowExecutionConfig
from redjohn.assessment.workflow_models import InventoryLimits, WorkflowDefinition, WorkflowStep


ORIGIN = "https://127.0.0.1:38841"


def policy(store, engagement="inventory", **changes):
    return store.register(
        EngagementPolicy(
            engagement,
            "operator",
            (ORIGIN,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice", "bob"),
            allowed_replay_urls=(ORIGIN + "/create", ORIGIN + "/cleanup"),
            **changes,
        )
    )


def definition():
    return WorkflowDefinition(
        "owned-object",
        "1",
        "empty",
        ("cleaned",),
        (
            WorkflowStep(
                "create", "empty", "created", "POST", ORIGIN + "/create", "mutation", (201,)
            ),
            WorkflowStep(
                "cleanup", "created", "cleaned", "POST", ORIGIN + "/cleanup", "cleanup", (204,)
            ),
        ),
    )


def started(store, p, *, actor="alice", tenant="a", revision="1"):
    workflow = store.inventory.register_workflow(p, definition())
    instance = store.inventory.start_workflow(
        p,
        workflow,
        instance_key="object",
        actor_id=actor,
        tenant_id=tenant,
        session_revision=revision,
    )
    surface = Surface(
        ORIGIN + "/create",
        method="POST",
        actor_id=actor,
        tenant_id=tenant,
        session_revision=revision,
        source="imported",
        workflow_state="approved_seed",
    )
    sid = store.upsert_surface(p.engagement_id, surface)
    return instance, sid


def test_additive_inventory_preserves_legacy_payload_and_surface_job_identity(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    surface = Surface(
        ORIGIN + "/items?x=1&x=2&encoded=%2f", source="imported", workflow_state="approved_seed"
    )
    payload = {
        k: v
        for k, v in asdict(surface).items()
        if k not in {"resource_kind", "asset_ref", "artifact_sha256"}
    }
    encoded = json.dumps(payload, indent=3)
    sid = stable_key([p.engagement_id, surface.key])
    store.db.execute(
        "INSERT INTO rj_surface VALUES(?,?,?,?,?)",
        (sid, p.engagement_id, surface.key, encoded, time.time()),
    )
    before = store.db.execute("SELECT payload FROM rj_surface WHERE id=?", (sid,)).fetchone()[0]
    assert store.inventory.backfill_surfaces(p, limit=1)["migrated"] == 1
    assert store.surface(p.engagement_id, sid).key == surface.key
    assert (
        store.db.execute("SELECT payload FROM rj_surface WHERE id=?", (sid,)).fetchone()[0]
        == before
    )
    spec = JobSpec(sid, "headers", "headers_audit", policy_revision=p.revision)
    assert store.submit(p, [spec]) == [stable_key([p.engagement_id, spec.key])]
    asset = store.inventory.assets(p)[0]
    assert asset["source"] == "imported"
    store.close()
    reopened = AssessmentStore(tmp_path / "state.db")
    assert reopened.inventory.assets(p)[0]["id"] == asset["id"]
    assert (
        reopened.db.execute("SELECT payload FROM rj_surface WHERE id=?", (sid,)).fetchone()[0]
        == before
    )
    reopened.close()


def test_observation_provenance_scope_retirement_and_quotas(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p, foreign = policy(store), policy(store, "foreign")
    proof = store.evidence_put(p.engagement_id, {"observed": True})
    asset = store.inventory.record_asset(
        p, kind="ip_address", locator="127.0.0.1", source="observed", evidence_refs=(proof,)
    )
    assert store.inventory.observations(p, asset)[0]["evidence_ref"] == proof
    with pytest.raises(PolicyDenied):
        store.inventory.record_asset(
            foreign,
            kind="ip_address",
            locator="127.0.0.1",
            source="observed",
            evidence_refs=(proof,),
        )
    with pytest.raises(PolicyDenied):
        store.inventory.asset(foreign, asset)
    sid = store.upsert_surface(p.engagement_id, Surface(ORIGIN + "/", request_ref=proof))
    web = next(row for row in store.inventory.assets(p) if row["kind"] == "http_origin")
    assert web["source"] == "observed"
    store.inventory.set_asset_state(p, web["id"], "retired", 1)
    with pytest.raises(PolicyDenied, match="retired_inventory"):
        store.submit(p, [JobSpec(sid, "headers", "headers_audit")])
    with pytest.raises(InventoryConflictError):
        store.inventory.set_asset_state(p, web["id"], "active", 1)
    store.inventory.set_asset_state(p, web["id"], "active", 2)
    limited = InventoryRepository(store, InventoryLimits(assets=2))
    with pytest.raises(ValueError, match="quota"):
        limited.record_asset(p, kind="dns_name", locator="new.example.test", source="inferred")
    assert len(store.inventory.assets(p)) == 2
    store.close()


def test_imported_and_inferred_discovery_never_grants_new_origin_permission(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    store.inventory.record_asset(
        p, kind="http_origin", locator="https://unapproved.example.test", source="imported"
    )
    sid = store.upsert_surface(
        p.engagement_id,
        Surface(
            "https://unapproved.example.test/", source="imported", workflow_state="approved_seed"
        ),
    )
    with pytest.raises(PolicyDenied, match="origin_denied"):
        store.submit(p, [JobSpec(sid, "headers", "headers_audit")])
    store.close()


def test_workflow_definition_requires_current_policy_and_versioned_cleanup(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    identity = store.inventory.register_workflow(p, definition())
    assert identity == store.inventory.register_workflow(p, definition())
    with pytest.raises(InventoryConflictError):
        store.inventory.register_workflow(
            p,
            replace(
                definition(),
                steps=(replace(definition().steps[0], name="create-v2"), definition().steps[1]),
            ),
        )
    with pytest.raises(ValueError, match="cleanup"):
        WorkflowDefinition("unsafe", "1", "empty", ("created",), (definition().steps[0],))
    with pytest.raises(PolicyDenied):
        store.inventory.register_workflow(
            p,
            replace(
                definition(),
                steps=(
                    replace(definition().steps[0], url="https://elsewhere.example/create"),
                    definition().steps[1],
                ),
            ),
        )
    store.close()


def test_two_actual_sqlite_connections_compete_for_one_workflow_lease(tmp_path):
    path = tmp_path / "state.db"
    first, second = AssessmentStore(path), AssessmentStore(path)
    p = policy(first)
    instance, sid = started(first, p)
    barrier = Barrier(2)

    def claim(store, owner):
        barrier.wait(timeout=2)
        try:
            return store.inventory.claim_step(
                p, instance, "create", sid, expected_revision=1, owner=owner
            )
        except InventoryConflictError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        a, b = executor.submit(claim, first, "first"), executor.submit(claim, second, "second")
        outcomes = [a.result(), b.result()]
    assert sum(row is not None for row in outcomes) == 1
    assert first.db.execute("SELECT count(*) FROM rj_workflow_lease").fetchone()[0] == 1
    first.close()
    second.close()


def test_expired_inflight_is_never_replayed_and_explicit_evidence_reconciles(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    instance, sid = started(store, p)
    lease = store.inventory.claim_step(
        p, instance, "create", sid, expected_revision=1, owner="owned", seconds=1
    )
    store.inventory.mark_sent(p, instance, lease["lease_ref"], owner="owned")
    time.sleep(1.02)  # Real lease expiry, no mocked clock.
    with pytest.raises(InventoryConflictError, match="reconciliation"):
        store.inventory.claim_step(p, instance, "create", sid, expected_revision=1, owner="restart")
    with pytest.raises(InventoryConflictError, match="reconciliation"):
        store.inventory.release_prepared_step(p, instance, lease["lease_ref"], owner="owned")
    proof = store.inventory.record_http_outcome(
        p,
        instance,
        lease["lease_ref"],
        owner="owned",
        status=201,
        response_sha256=hashlib.sha256(b"synthetic-contract-response").hexdigest(),
        assertion_passed=True,
        reconciliation=True,
    )
    with pytest.raises(InventoryConflictError, match="stale_workflow_lease"):
        store.inventory.complete_step(p, instance, lease["lease_ref"], proof, owner="owned")
    state = store.inventory.complete_step(
        p, instance, lease["lease_ref"], proof, owner="owned", reconciliation=True
    )
    assert state["state"] == "created" and state["revision"] == 2
    with pytest.raises(InventoryConflictError):
        store.inventory.complete_step(
            p, instance, lease["lease_ref"], proof, owner="owned", reconciliation=True
        )
    store.close()


@pytest.mark.parametrize("change", ["actor", "tenant", "session", "inferred"])
def test_workflow_claim_rejects_wrong_request_context(tmp_path, change):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    instance, sid = started(store, p)
    surface = store.surface(p.engagement_id, sid)
    replacements = {
        "actor": {"actor_id": "bob"},
        "tenant": {"tenant_id": "b"},
        "session": {"session_revision": "2"},
        "inferred": {"source": "inferred"},
    }
    # A fresh non-approved workflow state prevents a higher-ranked existing
    # imported record from masking this independent inferred candidate.
    if change == "inferred":
        replacements[change]["workflow_state"] = "inferred_only"
    wrong = store.upsert_surface(p.engagement_id, replace(surface, **replacements[change]))
    with pytest.raises(PolicyDenied, match="context_mismatch"):
        store.inventory.claim_step(
            p, instance, "create", wrong, expected_revision=1, owner="worker"
        )
    assert store.db.execute("SELECT count(*) FROM rj_workflow_lease").fetchone()[0] == 0
    store.close()


async def test_control_api_is_bounded_owner_bound_and_cannot_forge_outcomes(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    instance, sid = started(store, p)
    control = AssessmentControl(store, p, caller=p.owner_id)
    values = {
        "policy_revision": p.revision,
        "instance_id": instance,
        "step_name": "create",
        "surface_id": sid,
        "expected_revision": 1,
    }
    lease = await control.call("workflow_claim_step", values)
    assert lease["ok"]
    denied = await control.call("workflow_claim_step", {**values, "owner": "forged"})
    assert not denied["ok"]
    assert not (await control.call("record_http_outcome", {"policy_revision": p.revision}))["ok"]
    assert not (await control.call("asset_search", {"policy_revision": p.revision, "limit": 101}))[
        "ok"
    ]
    other = AssessmentControl(store, p, caller="another-owner")
    assert not (
        await other.call("workflow_get", {"policy_revision": p.revision, "instance_id": instance})
    )["ok"]
    control.close()
    other.close()
    store.close()


def test_service_retirement_filters_and_immutable_manifest_reuse(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    proof = store.evidence_put(
        p.engagement_id, {"manifest_sha256": "a" * 64}, kind="source_manifest", deduplicate=True
    )
    assert (
        store.evidence_put(
            p.engagement_id, {"manifest_sha256": "a" * 64}, kind="source_manifest", deduplicate=True
        )
        == proof
    )
    assert (
        store.evidence_put(p.engagement_id, {"manifest_sha256": "a" * 64}, kind="measurement")
        != proof
    )
    sid = store.upsert_surface(
        p.engagement_id, Surface(ORIGIN + "/", actor_id="alice", tenant_id="a", request_ref=proof)
    )
    service = store.inventory.services(p)[0]
    store.inventory.set_service_state(p, service["id"], "retired", 1)
    with pytest.raises(PolicyDenied, match="retired_inventory"):
        store.submit(p, [JobSpec(sid, "configuration", "headers_audit")])
    with pytest.raises(InventoryConflictError, match="stale_inventory"):
        store.inventory.set_service_state(p, service["id"], "active", 1)
    store.inventory.set_service_state(p, service["id"], "active", 2)
    asset = store.inventory.assets(p)[0]
    assert [
        row["id"]
        for row in store.surfaces(
            p.engagement_id, actor_id="alice", tenant_id="a", asset_id=asset["id"]
        )
    ] == [sid]
    assert store.surfaces(p.engagement_id, actor_id="bob") == []
    store.close()
    reopened = AssessmentStore(tmp_path / "state.db")
    assert (
        reopened.evidence_put(
            p.engagement_id, {"manifest_sha256": "a" * 64}, kind="source_manifest", deduplicate=True
        )
        == proof
    )
    reopened.close()


def test_unready_session_cannot_start_and_unrelated_evidence_cannot_refresh_workflow(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    instance, _sid = started(store, p)
    store.db.execute(
        "INSERT INTO rj_session_state VALUES(?,?,?,?,?,'refreshing',NULL,?)",
        (p.engagement_id, "alice", "a", p.revision, "1", time.time()),
    )
    definition_id = store.inventory.register_workflow(p, definition())
    with pytest.raises(InventoryConflictError, match="session_not_current"):
        store.inventory.start_workflow(
            p, definition_id, instance_key="second", actor_id="alice", tenant_id="a"
        )
    store.db.execute("UPDATE rj_session_state SET status='ready',revision='2'")
    unrelated = store.evidence_put(p.engagement_id, {"fake": True})
    with pytest.raises(PolicyDenied, match="committed_refresh_evidence"):
        store.inventory.refresh_workflow_session(
            p, instance, expected_revision=1, session_revision="2", evidence_ref=unrelated
        )
    assert store.inventory.workflow(p, instance)["session_revision"] == "1"
    store.close()


@pytest.mark.parametrize("change", ["extra_option", "wrong_revision", "wrong_capture"])
async def test_workflow_submission_rejects_unreviewed_or_stale_inputs(tmp_path, change):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    instance, sid = started(store, p)
    proof = store.evidence_put(p.engagement_id, {"contract_capture": True})
    base = store.surface(p.engagement_id, sid)
    sid = store.upsert_surface(p.engagement_id, replace(base, source="observed", request_ref=proof))
    args = {
        "policy_revision": p.revision,
        "instance_id": instance,
        "step_name": "create",
        "surface_id": sid,
        "expected_revision": 1,
    }
    if change == "extra_option":
        args["body"] = "arbitrary unreviewed bytes"
    elif change == "wrong_revision":
        args["expected_revision"] = 99
    else:
        args["surface_id"] = store.upsert_surface(
            p.engagement_id, replace(base, actor_id="bob", source="observed", request_ref=proof)
        )
    control = AssessmentControl(store, p, caller=p.owner_id)
    try:
        result = await control.call("workflow_submit_step", args)
        assert not result["ok"]
        assert store.jobs(p.engagement_id) == []
        assert not store.db.execute("SELECT 1 FROM rj_workflow_lease").fetchone()
    finally:
        control.close()
        store.close()


def test_reviewed_workflow_config_and_each_mutation_cleanup_path():
    value = {"enabled": True, "definitions": [asdict(definition())]}
    value["definitions"][0]["terminal_states"] = list(value["definitions"][0]["terminal_states"])
    value["definitions"][0]["steps"] = list(value["definitions"][0]["steps"])
    parsed = WorkflowExecutionConfig.from_mapping(value)
    assert parsed.definitions == (definition(),)
    with pytest.raises(ValueError, match="config_fields"):
        WorkflowExecutionConfig.from_mapping({"enabled": True, "command": "arbitrary"})
    with pytest.raises(ValueError, match="config"):
        WorkflowExecutionConfig.from_mapping({"enabled": False})
    with pytest.raises(ValueError, match="no_cleanup_path"):
        WorkflowDefinition(
            "bad-branch",
            "1",
            "empty",
            ("cleaned", "stranded"),
            (
                WorkflowStep("create", "empty", "stranded", "POST", ORIGIN + "/create", "mutation"),
                WorkflowStep("cleanup", "empty", "cleaned", "POST", ORIGIN + "/cleanup", "cleanup"),
            ),
        )


def test_refresh_and_workflow_request_reservations_mutually_exclude(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    instance, sid = started(store, p)
    surface = store.surface(p.engagement_id, sid)
    store.submit(
        p,
        [JobSpec(sid, "session", "session_refresh", policy_revision=p.revision, idempotent=False)],
    )
    job = store.claim(p, "refresh-worker")
    lease = store.inventory.claim_step(
        p, instance, "create", sid, expected_revision=1, owner="workflow-worker"
    )
    with pytest.raises(PolicyDenied, match="workflow_reconciliation_required"):
        store.begin_session_refresh(p, job, surface)
    assert store.session_state(p, surface) is None
    store.inventory.release_prepared_step(p, instance, lease["lease_ref"], owner="workflow-worker")
    store.begin_session_refresh(p, job, surface)
    with pytest.raises(InventoryConflictError, match="session_not_current"):
        store.inventory.claim_step(
            p, instance, "create", sid, expected_revision=1, owner="workflow-worker"
        )
    store.close()


@pytest.mark.parametrize("kind", ["asset", "service"])
async def test_retirement_after_queue_prevents_worker_admission(tmp_path, kind):
    """The trap worker is a contract double, not real scanner evidence."""
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    sid = store.upsert_surface(p.engagement_id, Surface(ORIGIN + "/"))
    store.submit(p, [JobSpec(sid, "observation", "http_observe", policy_revision=p.revision)])
    if kind == "asset":
        entity = store.inventory.assets(p)[0]
        store.inventory.set_asset_state(p, entity["id"], "retired", entity["revision"])
    else:
        entity = store.inventory.services(p)[0]
        store.inventory.set_service_state(p, entity["id"], "retired", entity["revision"])

    class TrapWorker:
        called = False

        async def run(self, *_args):
            self.called = True
            raise AssertionError("retired worker must not start")

        async def cancel(self):
            pass

        async def cleanup(self):
            pass

    worker = TrapWorker()
    scheduler = Scheduler(
        store, p, ResourceGovernor(), CapabilityRegistry(), {"http_observe": worker}
    )
    await scheduler.run_until_idle(max_jobs=1)
    assert not worker.called
    assert store.jobs(p.engagement_id)[0]["coverage_status"] == "blocked"
    store.close()


async def test_runtime_optin_registers_reviewed_definitions_without_starting_workers(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    p = policy(store)
    proof = store.evidence_put(p.engagement_id, {"metadata_contract": True})
    vault = tmp_path / "private.json"
    vault.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "engagement_id": p.engagement_id,
                        "owner_id": p.owner_id,
                        "actor_id": "alice",
                        "tenant_id": "",
                        "session_revision": "1",
                        "policy_revision": p.revision,
                        "expires_at": time.time() + 300,
                        "origin": ORIGIN,
                        "allowed_requests": [
                            {"url": ORIGIN + "/read", "method": "GET", "request_ref": proof}
                        ],
                        "headers": {"Authorization": "Bearer contract-only-secret"},
                        "cookies": [],
                    }
                ],
            }
        )
    )
    vault.chmod(0o600)
    runtime = AssessmentRuntime(
        store,
        p,
        caller=p.owner_id,
        host_pool_path=tmp_path / "pool.db",
        auth_vault_file=vault,
        workflow_execution_config={
            "enabled": True,
            "definitions": json.loads(json.dumps([asdict(definition())])),
        },
    )
    try:
        response = await runtime.control.call(
            "workflow_definition_search", {"policy_revision": p.revision, "limit": 1}
        )
        assert response["ok"] and response["result"]["items"][0]["name"] == "owned-object"
        assert store.jobs(p.engagement_id) == []
        assert runtime.governor.snapshot()["active"] == {}
    finally:
        await runtime.close()
        store.close()
