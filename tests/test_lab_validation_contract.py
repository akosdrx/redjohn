"""Synthetic fixture/process contracts; no native execution is claimed."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from redjohn.assessment import lab_contract, lab_worker
from redjohn.assessment.egress import EgressUnavailable
from redjohn.assessment.intelligence import CorrelationEdge
from redjohn.assessment.lab_contract import (
    CAPABILITY,
    FixtureProof,
    LabDenied,
    OwnedFixtureBinding,
    local_url,
)
from redjohn.assessment.lab_validation import LabValidation
from redjohn.assessment.lab_worker import (
    TEMPLATE_SHA256,
    LabWorker,
    regression_source,
    validate_source,
)
from redjohn.assessment.models import AdapterResult, JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.proof_bound_correlation import ProofBoundCorrelation
from redjohn.assessment.store import AssessmentStore


@pytest.fixture
def unit(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_contract, "_owned_process", lambda _process: True)
    monkeypatch.setattr(lab_contract, "process_identity", lambda _pid: "unit-kernel-identity")
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(
        EngagementPolicy(
            "owned-lab",
            "owner",
            ("http://127.0.0.1:18080",),
            profile="isolated-lab",
            egress_mode="local-fixture",
            request_budget=20,
        )
    )
    binding = OwnedFixtureBinding(
        SimpleNamespace(pid=os.getpid(), returncode=None),
        fixture_ref="fixture",
        asset_ref="asset",
        url="http://127.0.0.1:18080/regression",
        phase="candidate",
        source=b"unit-before",
        deployment_ref="before",
    )
    surface = Surface(binding.proof.url, session_revision="7", workflow_state="lab-ready")
    surface_id = store.upsert_surface(policy.engagement_id, surface)
    asset = store.db.execute(
        "SELECT asset_id FROM rj_inventory_surface WHERE surface_id=?", (surface_id,)
    ).fetchone()[0]
    binding.proof = replace(binding.proof, asset_ref=asset)
    job_id = store.submit(policy, [JobSpec(surface_id, "headers", "headers_audit")])[0]
    job = store.claim(policy, "unit-owner")
    assert job["id"] == job_id
    capture = store.evidence_put(
        policy.engagement_id,
        {
            "url": surface.url,
            "actor_id": "anonymous",
            "status": 200,
            "headers": {},
            "session_revision": "7",
        },
        job_id=job_id,
    )
    store.finish(
        job,
        AdapterResult(
            "succeeded",
            "completed",
            findings=(
                {
                    "title": "Missing x-content-type-options",
                    "observed": "header_absent",
                    "actor_id": "anonymous",
                    "session_revision": "7",
                    "evidence_refs": [capture],
                },
            ),
        ),
    )
    component = LabValidation(store, policy, caller="owner")
    key = component.bind_fixture(binding)
    plan = component.create(store.findings(policy.engagement_id)[0]["id"], surface_id, key)
    try:
        yield SimpleNamespace(
            store=store,
            policy=policy,
            component=component,
            plan=plan,
            binding=binding,
            key=key,
            surface=surface,
            root=tmp_path,
        )
    finally:
        store.close()


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:18080/regression",
        "http://192.0.2.1:18080/regression",
        "http://127.0.0.1:18080/other",
        "http://127.0.0.1:18080/regression?x=1",
        "http://alice@127.0.0.1:18080/regression",
        "https://127.0.0.1:18080/regression",
        "http://127.0.0.1:0/regression",
    ],
)
def test_fixture_contract_rejects_dns_external_and_unreviewed_requests(url):
    with pytest.raises(LabDenied):
        local_url(url)


def test_template_never_accepts_arbitrary_code_or_carrier():
    carrier = "/rj-lab/" + "a" * 64
    source = regression_source(12345, carrier)
    assert len(validate_source(source, 12345, carrier)) == 64
    with pytest.raises(LabDenied, match="template_mismatch"):
        validate_source(source + "\nimport os\nos.system('false')", 12345, carrier)
    with pytest.raises(LabDenied, match="carrier"):
        regression_source(12345, "/outside")


def test_host_binding_cannot_be_replaced_by_dict_or_dead_process(unit):
    with pytest.raises(LabDenied, match="typed_host"):
        unit.component.bind_fixture(asdict(unit.binding.proof))
    unit.binding.process.returncode = 0
    with pytest.raises(LabDenied, match="not_live"):
        unit.component.submit(unit.plan.key, "candidate", unit.key)


def test_candidate_requires_completed_finding_row(unit):
    with pytest.raises(LabDenied, match="header_candidate"):
        unit.component.create("invented", unit.plan.surface_id, unit.key)
    unit.store.db.execute("UPDATE rj_finding SET status='fixed'")
    with pytest.raises(LabDenied, match="header_candidate"):
        unit.component.create(unit.plan.candidate_ref, unit.plan.surface_id, unit.key)


def test_plan_and_queued_job_survive_reopen_without_duplicate_dispatch(unit):
    first = unit.component.submit(unit.plan.key, "candidate", unit.key)
    reopened = LabValidation(unit.store, unit.policy, caller="owner")
    assert reopened.plan(unit.plan.key) == unit.plan
    with pytest.raises(LabDenied, match="live_host_binding"):
        reopened.submit(unit.plan.key, "candidate", unit.key)
    reopened.bind_fixture(unit.binding)
    assert reopened.submit(unit.plan.key, "candidate", unit.key) == first
    assert (
        sum(row["capability"] == CAPABILITY for row in unit.store.jobs(unit.policy.engagement_id))
        == 1
    )


def test_admitted_unknown_attempt_is_never_replayed_after_restart(unit):
    job_id = unit.component.submit(unit.plan.key, "candidate", unit.key)
    job = unit.store.claim(unit.policy, "controller-before")
    spec = JobSpec(**json.loads(job["spec"]))
    unit.component.reserve(job, unit.plan, spec)
    unit.component.admit(job)
    restored = LabValidation(unit.store, unit.policy, caller="owner")
    restored.bind_fixture(unit.binding)
    with pytest.raises(LabDenied, match="unknown_no_replay"):
        restored.reserve(job, unit.plan, spec)
    with pytest.raises(LabDenied, match="no_replay"):
        restored.admit(job)
    assert restored.submit(unit.plan.key, "candidate", unit.key) == job_id
    assert (
        restored.submit(unit.plan.key, "candidate", unit.key, retest_revision="explicit") != job_id
    )
    assert unit.store.request_usage(unit.policy) == 1


@pytest.mark.parametrize("change", ["owner", "attempt", "cancel", "policy"])
def test_stale_or_cancelled_dispatch_cannot_admit_request(unit, change):
    unit.component.submit(unit.plan.key, "candidate", unit.key)
    job = unit.store.claim(unit.policy, "controller")
    spec = JobSpec(**json.loads(job["spec"]))
    unit.component.reserve(job, unit.plan, spec)
    if change in {"owner", "attempt"}:
        job[change] = "forged" if change == "owner" else job["attempt"] + 1
    elif change == "cancel":
        unit.store.cancel(unit.policy.engagement_id, job["id"])
    else:
        unit.store.register(replace(unit.policy, revision="2"))
    with pytest.raises(PolicyDenied):
        unit.component.admit(job)
    assert unit.store.request_usage(unit.policy) == 0


def test_storage_failure_leaves_phase_unknown(unit, monkeypatch):
    unit.component.submit(unit.plan.key, "candidate", unit.key)
    job = unit.store.claim(unit.policy, "controller")
    spec = JobSpec(**json.loads(job["spec"]))
    unit.component.reserve(job, unit.plan, spec)
    unit.component.admit(job)

    def unavailable(*_args, **_kw):
        raise OSError("unit storage failure")

    monkeypatch.setattr(unit.store, "evidence_put", unavailable)
    with pytest.raises(OSError):
        unit.component.finish(job, unit.plan, spec, {})
    assert unit.store.db.execute("SELECT stage FROM rj_lab_phase").fetchone()[0] == "admitted"
    with pytest.raises(LabDenied):
        ProofBoundCorrelation(unit.component).validate(unit.plan.key, job["id"], job["id"])


def test_scanner_evidence_is_not_lab_assertion_authority(unit):
    proof = ProofBoundCorrelation(unit.component)
    edge = CorrelationEdge(
        "asset",
        unit.plan.candidate_ref,
        "reachability",
        ("invented",),
        (unit.plan.capture_ref,),
        "validated_in_lab",
        "invented-fixture",
        unit.plan.capture_ref,
    )
    with pytest.raises(LabDenied, match="exact_owned_assertion"):
        proof.authorize_edge(edge)
    proof.authorize_edge(replace(edge, status="hypothesized"))


async def test_missing_kernel_boundary_blocks_before_workspace_or_network(unit, monkeypatch):
    worker = LabWorker(
        unit.root / "not-created",
        memory_config={"delegated_root": "/missing"},
        owner_budget=1024**3,
    )
    monkeypatch.setattr(lab_worker.LinuxMemoryBoundary, "current", lambda *_args: None)
    with pytest.raises(EgressUnavailable, match="precontained"):
        await worker.execute(
            unit.policy,
            unit.plan,
            unit.binding,
            admit=lambda: pytest.fail("network admitted"),
            timeout=2,
        )
    assert not worker.root.exists()


def test_fixture_versions_are_typed_and_bounded():
    with pytest.raises(LabDenied):
        FixtureProof(
            "f", "a", "http://127.0.0.1:1/regression", "candidate", "bad", "before", 1, "fake"
        )
    assert len(TEMPLATE_SHA256) == 64


def test_fixed_control_requires_distinct_process_source_and_completed_positive(unit):
    process = SimpleNamespace(pid=os.getpid() + 100, returncode=None)
    fixed = OwnedFixtureBinding(
        process,
        fixture_ref=unit.plan.fixture_ref,
        asset_ref=unit.plan.asset_ref,
        url=unit.plan.url,
        phase="fixed_control",
        source=b"unit-fixed",
        deployment_ref="fixed",
    )
    key = unit.component.bind_fixture(fixed)
    with pytest.raises(LabDenied, match="completed_positive"):
        unit.component.submit(unit.plan.key, "fixed_control", key)
    same = OwnedFixtureBinding(
        process,
        fixture_ref=unit.plan.fixture_ref,
        asset_ref=unit.plan.asset_ref,
        url=unit.plan.url,
        phase="fixed_control",
        source=b"unit-before",
        deployment_ref="fixed",
    )
    with pytest.raises(LabDenied, match="distinct_fixed_source"):
        unit.component.submit(unit.plan.key, "fixed_control", unit.component.bind_fixture(same))
    assert unit.store.request_usage(unit.policy) == 0


def test_fixture_asset_must_be_the_actual_inventory_link(unit):
    unit.binding.proof = replace(unit.binding.proof, asset_ref="invented-asset")
    key = unit.component.bind_fixture(unit.binding)
    with pytest.raises(LabDenied, match="inventory_asset_mismatch"):
        unit.component.create(unit.plan.candidate_ref, unit.plan.surface_id, key)


def test_reserved_phase_rejects_a_spec_different_from_durable_job(unit):
    unit.component.submit(unit.plan.key, "candidate", unit.key)
    job = unit.store.claim(unit.policy, "controller")
    spec = JobSpec(**json.loads(job["spec"]))
    with pytest.raises(LabDenied, match="exact_durable_job"):
        unit.component.reserve(job, unit.plan, replace(spec, timeout_seconds=2))
    assert not unit.store.db.execute("SELECT 1 FROM rj_lab_phase").fetchone()


def test_kill_switch_blocks_reopened_component_before_dispatch(unit):
    unit.store.cancel(unit.policy.engagement_id)
    restored = LabValidation(unit.store, unit.policy, caller="owner")
    with pytest.raises(PolicyDenied, match="current_policy"):
        restored.bind_fixture(unit.binding)
    assert unit.store.request_usage(unit.policy) == 0
