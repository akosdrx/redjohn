"""Synthetic paired-proof/public composition contracts; no kernel proof."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment, validate_configuration
from redjohn.assessment.intelligence import CorrelationEdge, VulnerabilityCorrelator
from redjohn.assessment.lab_contract import CAPABILITY, VERSION, LabDenied, OwnedFixtureBinding
from redjohn.assessment.lab_worker import TEMPLATE_SHA256, LabWorker, regression_source
from redjohn.assessment.models import AdapterResult, JobSpec
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.proof_bound_correlation import ProofBoundCorrelation
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.report import build_report
from redjohn.assessment.reproducer import SafeReproducerGenerator
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.runtime import AssessmentRuntime
from tests.test_lab_validation_contract import unit  # noqa: F401 - explicit synthetic fixture


def paired(unit):  # noqa: F811 - synthetic fixture helper argument
    """Inject typed proof records only in this synthetic test group."""
    component, store, plan = unit.component, unit.store, unit.plan
    jobs = []
    for phase in ("candidate", "fixed_control"):
        key = unit.key
        if phase == "fixed_control":
            binding = OwnedFixtureBinding(
                SimpleNamespace(pid=os.getpid() + 100, returncode=None),
                fixture_ref=plan.fixture_ref,
                asset_ref=plan.asset_ref,
                url=plan.url,
                phase=phase,
                source=b"independent-fixed-source",
                deployment_ref="distinct-fixed-deployment",
            )
            key = component.bind_fixture(binding)
        job_id = component.submit(plan.key, phase, key)
        job = store.claim(unit.policy, "synthetic-controller")
        assert job["id"] == job_id
        spec = JobSpec(**json.loads(job["spec"]))
        component.reserve(job, plan, spec)
        component.admit(job)
        observed = "nosniff" if phase == "fixed_control" else None
        result = {
            "assertion": {
                "status": 200,
                "observed": observed,
                "payload_readonly": True,
                "cpu_limit_seconds": 2,
                "address_space_limit_bytes": 134217728,
            },
            "transport": {
                "status": 200,
                "observed": observed,
                "response_complete": True,
                "method": "GET",
                "url": plan.url,
                "fixture_key": key,
            },
            "template_sha256": TEMPLATE_SHA256,
            "artifact_sha256": hashlib.sha256(
                regression_source(12345, "/rj-lab/" + plan.key).encode()
            ).hexdigest(),
            "owner_memory": {"enforced": True, "owner_namespace": {"verified": True}},
            "namespace": [
                {
                    "interfaces": ["lo"],
                    "effective_capabilities": "0",
                    "no_new_privileges": True,
                    "proxy_url": "http://127.0.0.1:12345",
                }
            ],
            "negative_controls": {
                "direct_blocked": True,
                "offscope_status": 403,
                "payload_readonly": True,
            },
            "request_sent": True,
        }
        component.finish(job, plan, spec, result)
        store.finish(job, AdapterResult("succeeded", "completed", {"assertion_matched": True}))
        jobs.append(job_id)
    return jobs


def test_generic_correlator_cannot_add_or_read_old_labelled_validation(unit):  # noqa: F811
    edge = CorrelationEdge(
        unit.plan.asset_ref,
        unit.plan.candidate_ref,
        "reachability",
        ("caller-string",),
        (unit.plan.capture_ref,),
        "validated_in_lab",
        "caller-fixture",
        unit.plan.capture_ref,
    )
    graph = VulnerabilityCorrelator(unit.store.path)
    try:
        with pytest.raises(ValueError, match="persisted_paired"):
            graph.add(unit.policy.engagement_id, edge)
        graph.db.execute(
            "INSERT INTO rj_correlation VALUES(?,?,?,?,?)",
            (
                unit.policy.engagement_id,
                edge.source_ref,
                edge.target_ref,
                edge.relation,
                json.dumps(asdict(edge)),
            ),
        )
        graph.db.commit()
        with pytest.raises(ValueError, match="persisted_paired"):
            graph.query(unit.policy.engagement_id, edge.source_ref)
    finally:
        graph.close()


@pytest.mark.parametrize(
    "change",
    ["policy", "surface", "phase", "memory", "assertion", "capture", "asset_link", "session"],
)
def test_bound_graph_and_report_revalidate_durable_proof(unit, change):  # noqa: F811
    before, fixed = paired(unit)
    proof = ProofBoundCorrelation(unit.component)
    assertion = proof.validate(unit.plan.key, before, fixed)
    graph = VulnerabilityCorrelator(unit.store.path, lab_validation=unit.component)
    try:
        edge = proof.edge(assertion["assertion_ref"])
        graph.add(unit.policy.engagement_id, edge)
        assert (
            graph.query(unit.policy.engagement_id, unit.plan.asset_ref).chain_status
            == "validated_in_lab"
        )
        report = build_report(unit.store, unit.policy.engagement_id, lab_validation=unit.component)
        assert report["owned_lab"]["assertions"][0]["assertion_ref"] == assertion["assertion_ref"]
        assert report["findings_page"][0]["status"] == "candidate"
        if change == "policy":
            unit.store.register(replace(unit.policy, revision="next"))
        elif change == "surface":
            unit.store.db.execute("UPDATE rj_asset SET state='deleted'")
        elif change == "phase":
            unit.store.db.execute(
                "UPDATE rj_job SET coverage_status='inconclusive' WHERE id=?", (fixed,)
            )
        elif change == "capture":
            unit.store.db.execute(
                "UPDATE rj_evidence SET payload='{}' WHERE id=?", (unit.plan.capture_ref,)
            )
        elif change == "asset_link":
            unit.store.db.execute(
                "DELETE FROM rj_inventory_surface WHERE surface_id=?", (unit.plan.surface_id,)
            )
        elif change == "session":
            row = unit.store.db.execute(
                "SELECT payload FROM rj_surface WHERE id=?", (unit.plan.surface_id,)
            ).fetchone()
            surface = json.loads(row[0])
            surface["session_revision"] = "stale"
            unit.store.db.execute(
                "UPDATE rj_surface SET payload=? WHERE id=?",
                (json.dumps(surface), unit.plan.surface_id),
            )
        elif change == "memory":
            row = unit.store.db.execute(
                "SELECT evidence_ref FROM rj_lab_phase WHERE job_id=?", (fixed,)
            ).fetchone()
            payload = json.loads(
                unit.store.db.execute(
                    "SELECT payload FROM rj_evidence WHERE id=?", (row[0],)
                ).fetchone()[0]
            )
            payload["result"]["owner_memory"]["enforced"] = False
            unit.store.db.execute(
                "UPDATE rj_evidence SET payload=? WHERE id=?", (json.dumps(payload), row[0])
            )
        else:
            unit.store.db.execute("UPDATE rj_lab_assertion SET payload='{}'")
        with pytest.raises((LabDenied, PolicyDenied)):
            graph.query(unit.policy.engagement_id, unit.plan.asset_ref)
        rejected = build_report(
            unit.store, unit.policy.engagement_id, lab_validation=unit.component
        )
        assert rejected["owned_lab"]["assertions"] == []
        assert rejected["owned_lab"]["coverage_status"] in {"blocked", "inconclusive"}
    finally:
        graph.close()


async def test_public_config_is_inert_and_typed_binding_not_json_authority(unit, monkeypatch):  # noqa: F811
    def forbidden(*_args, **_kwargs):
        pytest.fail("composition started an optional worker")

    monkeypatch.setattr(LabWorker, "execute", forbidden)
    config = validate_configuration(
        {
            "policy": asdict(unit.policy),
            "lab_validation": {"version": VERSION},
            "os_memory": {"delegated_root": str(unit.root / "not-created")},
        }
    )
    async with ConfiguredAssessment(config, unit.root / "configured", caller="owner") as selected:
        runtime = selected.runtime
        assert runtime.lab_validation is not None
        assert CAPABILITY in runtime.scheduler.adapters
        assert not (selected.store.path.parent / "owned-lab-workers").exists()
        with pytest.raises(LabDenied, match="typed_host"):
            runtime.bind_owned_lab_fixture(asdict(unit.binding.proof))
        assert selected.metrics()["owned_lab"]["assertions"] == []
        assert runtime.registry.execution_versions(CAPABILITY) == {
            "tool_version": VERSION,
            "template_version": TEMPLATE_SHA256,
        }
    assert not (unit.root / "not-created").exists()


async def test_public_runtime_submits_only_existing_queue_and_requires_host_rebind(unit):  # noqa: F811
    kwargs = {
        "caller": "owner",
        "host_pool_path": unit.root / "host.sqlite3",
        "lab_validation_config": {"version": VERSION},
        "os_memory_config": {"delegated_root": str(unit.root / "not-created")},
    }
    runtime = AssessmentRuntime(unit.store, unit.policy, **kwargs)
    try:
        key = runtime.bind_owned_lab_fixture(unit.binding)
        plan = runtime.create_owned_lab_plan(unit.plan.candidate_ref, unit.plan.surface_id, key)
        job = runtime.submit_owned_lab(plan.key, "candidate", key)
        assert runtime.submit_owned_lab(plan.key, "candidate", key) == job
    finally:
        await runtime.close()
    runtime = AssessmentRuntime(unit.store, unit.policy, **kwargs)
    try:
        with pytest.raises(LabDenied, match="live_host_binding"):
            runtime.submit_owned_lab(plan.key, "candidate", key)
        runtime.bind_owned_lab_fixture(unit.binding)
        assert runtime.submit_owned_lab(plan.key, "candidate", key) == job
        before, fixed = paired(unit)
        assertion = runtime.validate_owned_lab(plan.key, before, fixed)
        assert runtime.owned_lab_status()["assertions"] == [assertion]
    finally:
        await runtime.close()


def test_default_registry_blocks_lab_and_raw_process_metadata_is_not_owned():
    row = next(row for row in CapabilityRegistry().health() if row["id"] == CAPABILITY)
    assert row["status"] == "blocked_configuration" and row["live_verified"] is False
    with pytest.raises(LabDenied, match="child_process_object"):
        OwnedFixtureBinding(
            SimpleNamespace(pid=os.getpid(), returncode=None),
            fixture_ref="f",
            asset_ref="a",
            url="http://127.0.0.1:1/regression",
            phase="candidate",
            source=b"x",
            deployment_ref="d",
        )


def test_legacy_facade_and_mixed_chain_share_the_persisted_verifier(unit):  # noqa: F811
    before, fixed = paired(unit)
    governor = ResourceGovernor()
    kwargs = {
        "caller": "owner",
        "governor": governor,
        "evidence_reader": lambda ref: unit.store.evidence_get(unit.policy.engagement_id, ref),
        "evidence_sink": lambda value: unit.store.evidence_put(unit.policy.engagement_id, value),
        "request_admission": lambda _count: None,
    }
    unbound = SafeReproducerGenerator(unit.policy, **kwargs)
    with pytest.raises(PolicyDenied, match="persisted_paired"):
        unbound.validate_owned_pair(unit.plan.key, before, fixed)
    bound = SafeReproducerGenerator(unit.policy, **kwargs, lab_validation=unit.component)
    value = bound.validate_owned_pair(unit.plan.key, before, fixed)
    proof = ProofBoundCorrelation(unit.component)
    graph = VulnerabilityCorrelator(unit.store.path, lab_validation=unit.component)
    try:
        graph.add(unit.policy.engagement_id, proof.edge(value["assertion_ref"]))
        graph.add(
            unit.policy.engagement_id,
            CorrelationEdge(
                unit.plan.candidate_ref,
                "unproved-next",
                "prerequisite",
                ("unknown",),
                (unit.plan.capture_ref,),
            ),
        )
        assert (
            graph.query(unit.policy.engagement_id, unit.plan.asset_ref).chain_status
            == "partially_supported"
        )
    finally:
        graph.close()
        governor.close()


@pytest.mark.parametrize("invalid", ["version", "raw_fixture", "memory", "profile"])
def test_public_lab_preflight_blocks_before_any_pool_or_worker(unit, invalid):  # noqa: F811
    policy = unit.policy
    selected = {"version": VERSION}
    memory = {"delegated_root": str(unit.root / "not-created")}
    if invalid == "version":
        selected["version"] = "unreviewed"
    elif invalid == "raw_fixture":
        selected["pid"] = os.getpid()
    elif invalid == "memory":
        memory = None
    else:
        policy = replace(policy, profile="safe-production")
    pool = unit.root / "unopened" / "host.sqlite3"
    with pytest.raises((ValueError, TypeError, PolicyDenied)):
        AssessmentRuntime(
            unit.store,
            policy,
            caller="owner",
            host_pool_path=pool,
            lab_validation_config=selected,
            os_memory_config=memory,
        )
    assert not pool.exists()
