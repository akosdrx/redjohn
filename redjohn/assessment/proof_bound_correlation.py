"""Restricted header-lab correlation from durable paired job proof only.

The public runtime, generic correlator and reports share this verifier. No
caller-provided scanner evidence or fixture labels grant promotion authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from redjohn.assessment.intelligence import CorrelationEdge
from redjohn.assessment.lab_contract import (
    CAPABILITY,
    EXPECTED,
    ORIGINAL_RCE,
    VERSION,
    FixtureProof,
    LabDenied,
    LabPlan,
)
from redjohn.assessment.lab_worker import TEMPLATE_SHA256, regression_source
from redjohn.assessment.models import stable_key


if TYPE_CHECKING:
    from redjohn.assessment.lab_validation import LabValidation


class ProofBoundCorrelation:
    def __init__(self, validation: LabValidation) -> None:
        self.validation = validation
        with validation.store._lock:
            validation.store.db.executescript("""
            CREATE TABLE IF NOT EXISTS rj_lab_assertion(
              engagement TEXT NOT NULL, assertion_ref TEXT NOT NULL, plan_ref TEXT NOT NULL,
              before_job TEXT NOT NULL, fixed_job TEXT NOT NULL, evidence_ref TEXT NOT NULL,
              payload TEXT NOT NULL, PRIMARY KEY(engagement,assertion_ref));
            """)

    def _phase(
        self, plan: LabPlan, job_id: str, phase: str
    ) -> tuple[dict[str, Any], FixtureProof, str]:
        c = self.validation
        with c.store._lock:
            row = c.store.db.execute(
                "SELECT p.*,j.execution_status,j.coverage_status,j.spec,j.surface_id,"
                "j.capability,j.result,"
                "j.attempt AS current_attempt FROM rj_lab_phase p JOIN rj_job j ON p.job_id=j.id "
                "WHERE p.engagement=? AND p.job_id=? AND j.engagement=p.engagement",
                (c.policy.engagement_id, job_id),
            ).fetchone()
        if row is None:
            raise LabDenied("lab_owned_phase_proof_required")
        spec = json.loads(row["spec"])
        if (
            row["stage"] != "proved"
            or row["phase"] != phase
            or row["plan_ref"] != plan.key
            or row["execution_status"] != "succeeded"
            or row["coverage_status"] != "completed"
            or row["capability"] != CAPABILITY
            or row["surface_id"] != plan.surface_id
            or row["attempt"] != row["current_attempt"]
            or spec.get("idempotent") is not False
            or spec.get("policy_revision") != plan.policy_revision
            or spec.get("tool_version") != VERSION
            or spec.get("template_version") != TEMPLATE_SHA256
            or spec.get("options")
            != {"plan_ref": plan.key, "phase": phase, "fixture_key": row["fixture_key"]}
            or json.loads(row["result"])["summary"].get("assertion_matched") is not True
        ):
            raise LabDenied("lab_completed_exact_phase_required")
        with c.store._lock:
            evidence = c.store.db.execute(
                "SELECT payload FROM rj_evidence WHERE id=? AND engagement=? AND job_id=? "
                "AND kind='owned_lab_phase_proof' AND bytes<=16384",
                (row["evidence_ref"], c.policy.engagement_id, job_id),
            ).fetchone()
            fixture = c.store.db.execute(
                "SELECT payload FROM rj_lab_fixture WHERE engagement=? AND fixture_key=?",
                (c.policy.engagement_id, row["fixture_key"]),
            ).fetchone()
        if evidence is None or fixture is None:
            raise LabDenied("lab_typed_phase_evidence_required")
        proof = json.loads(evidence[0])
        deployment = FixtureProof(**json.loads(fixture[0]))
        result = proof.get("result", {})
        observation, transport = result.get("assertion", {}), result.get("transport", {})
        if (
            any(proof.get(k) != v for k, v in plan.context().items())
            or proof.get("schema") != 1
            or proof.get("phase") != phase
            or proof.get("job_id") != job_id
            or proof.get("attempt") != row["attempt"]
            or proof.get("fixture_key") != deployment.key
            or deployment.phase != phase
            or any(
                getattr(deployment, k) != getattr(plan, k)
                for k in ("fixture_ref", "asset_ref", "url")
            )
            or result.get("template_sha256") != TEMPLATE_SHA256
            or result.get("request_sent") is not True
            or observation.get("status") != 200
            or transport.get("status") != 200
            or observation.get("observed") != transport.get("observed")
            or (
                observation.get("observed") != EXPECTED
                if phase == "fixed_control"
                else observation.get("observed") is not None
            )
            or transport.get("response_complete") is not True
            or transport.get("method") != "GET"
            or transport.get("url") != plan.url
            or transport.get("fixture_key") != deployment.key
            or observation.get("payload_readonly") is not True
            or observation.get("cpu_limit_seconds") != 2
            or observation.get("address_space_limit_bytes") != 134217728
            or result.get("owner_memory", {}).get("enforced") is not True
            or result.get("owner_memory", {}).get("owner_namespace", {}).get("verified") is not True
            or not result.get("namespace")
            or result.get("negative_controls")
            != {
                "direct_blocked": True,
                "offscope_status": 403,
                "payload_readonly": True,
            }
        ):
            raise LabDenied("lab_phase_context_or_assertion_mismatch")
        proxies: set[str] = set()
        for attestation in result["namespace"]:
            if (
                attestation.get("interfaces") != ["lo"]
                or attestation.get("effective_capabilities") != "0"
                or attestation.get("no_new_privileges") is not True
            ):
                raise LabDenied("lab_namespace_proof_required")
            proxy = attestation.get("proxy_url")
            if not isinstance(proxy, str):
                raise LabDenied("lab_namespace_proxy_required")
            proxies.add(proxy)
        if len(proxies) != 1:
            raise LabDenied("lab_single_controller_proxy_required")
        proxy_url = urlsplit(proxies.pop())
        if (
            proxy_url.scheme != "http"
            or proxy_url.hostname != "127.0.0.1"
            or proxy_url.port is None
        ):
            raise LabDenied("lab_controller_proxy_required")
        expected_source = regression_source(proxy_url.port, "/rj-lab/" + plan.key)
        if result.get("artifact_sha256") != hashlib.sha256(expected_source.encode()).hexdigest():
            raise LabDenied("lab_exact_executed_template_required")
        return spec, deployment, row["evidence_ref"]

    def validate(self, plan_ref: str, before_job: str, fixed_job: str) -> dict[str, Any]:
        c = self.validation
        plan = c.plan(plan_ref)
        before_spec, before, before_ref = self._phase(plan, before_job, "candidate")
        fixed_spec, fixed, fixed_ref = self._phase(plan, fixed_job, "fixed_control")
        with c.store._lock:
            order = c.store.db.execute(
                "SELECT b.ended_at,f.started_at FROM rj_job b JOIN rj_job f "
                "WHERE b.id=? AND f.id=? AND b.engagement=? AND f.engagement=b.engagement",
                (before_job, fixed_job, c.policy.engagement_id),
            ).fetchone()
        if (
            before_job == fixed_job
            or before.key != plan.candidate_deployment
            or before.source_sha256 == fixed.source_sha256
            or before.deployment_ref == fixed.deployment_ref
            or before_ref == fixed_ref
            or before_spec.get("retest_revision") != fixed_spec.get("retest_revision")
            or (before.pid, before.process_start) == (fixed.pid, fixed.process_start)
            or order is None
            or order[0] is None
            or order[1] is None
            or order[0] > order[1]
        ):
            raise LabDenied("lab_independent_positive_fixed_proof_required")
        assertion = stable_key([plan.key, before_job, fixed_job, before_ref, fixed_ref, VERSION])
        value = {
            **plan.context(),
            "assertion_ref": assertion,
            "before_job": before_job,
            "fixed_job": fixed_job,
            "evidence_refs": [plan.capture_ref, before_ref, fixed_ref],
            "finding_status": "confirmed_weakness",
            "proof_level": "owned_local_header_positive_and_fixed_regression",
            "cwe": "CWE-693",
            "cwe_basis": "owned_fixture_missing_response_protection_header",
            "technical_severity": "low",
            "business_risk": "not_assessed",
            "tool_version": VERSION,
            "template_version": TEMPLATE_SHA256,
            "expected": EXPECTED,
            "observed": "header_absent",
            "control_observed": EXPECTED,
            "chain_status": "validated_in_lab",
            "execution_path": "durable_owned_lab_scheduler",
            "original_rce_status": ORIGINAL_RCE,
            "limitation": (
                "Exact owned header fixture only; no RCE, CVE impact or general exploit-chain proof"
            ),
        }
        # Repeated validation reuses the existing proof, not duplicate network or evidence.
        with c.store._lock:
            existing = c.store.db.execute(
                "SELECT payload FROM rj_lab_assertion WHERE engagement=? AND assertion_ref=?",
                (c.policy.engagement_id, assertion),
            ).fetchone()
        if existing is not None:
            previous = json.loads(existing[0])
            if not isinstance(previous, dict) or previous != value:
                raise LabDenied("lab_assertion_integrity_mismatch")
            return previous
        with c.store._lock:
            count = c.store.db.execute(
                "SELECT count(*) FROM rj_lab_assertion WHERE engagement=?",
                (c.policy.engagement_id,),
            ).fetchone()[0]
        if count >= 32:
            raise LabDenied("lab_assertion_quota")
        ref = c.store.evidence_put(
            c.policy.engagement_id, value, kind="owned_lab_validation_assertion", deduplicate=True
        )
        with c.store.transaction() as db:
            c._policy()
            count = db.execute(
                "SELECT count(*) FROM rj_lab_assertion WHERE engagement=?",
                (c.policy.engagement_id,),
            ).fetchone()[0]
            if count >= 32:
                raise LabDenied("lab_assertion_quota")
            db.execute(
                "INSERT OR IGNORE INTO rj_lab_assertion VALUES(?,?,?,?,?,?,?)",
                (
                    c.policy.engagement_id,
                    assertion,
                    plan.key,
                    before_job,
                    fixed_job,
                    ref,
                    json.dumps(value),
                ),
            )
        return value

    def edge(self, assertion_ref: str) -> CorrelationEdge:
        c = self.validation
        with c.store._lock:
            row = c.store.db.execute(
                "SELECT * FROM rj_lab_assertion WHERE engagement=? AND assertion_ref=?",
                (c.policy.engagement_id, assertion_ref),
            ).fetchone()
        if row is None:
            raise LabDenied("lab_owned_assertion_required")
        value = self.validate(row["plan_ref"], row["before_job"], row["fixed_job"])
        with c.store._lock:
            evidence = c.store.db.execute(
                "SELECT payload FROM rj_evidence WHERE engagement=? AND id=? "
                "AND kind='owned_lab_validation_assertion' AND bytes<=16384",
                (c.policy.engagement_id, row["evidence_ref"]),
            ).fetchone()
        if evidence is None or json.loads(evidence[0]) != value:
            raise LabDenied("lab_assertion_evidence_integrity_mismatch")
        plan = c.plan(row["plan_ref"])
        return CorrelationEdge(
            plan.asset_ref,
            plan.candidate_ref,
            "reachability",
            (
                "owned_fixture",
                "exact_anonymous_session_workflow",
                "positive_and_distinct_fixed_source",
            ),
            tuple(value["evidence_refs"]),
            status="validated_in_lab",
            lab_fixture_ref=plan.fixture_ref,
            validation_assertion_ref=row["evidence_ref"],
        )

    def authorize_edge(self, edge: CorrelationEdge) -> None:
        """Mandatory persistent binding; scanner evidence cannot stand in."""
        if edge.status != "validated_in_lab":
            return
        c = self.validation
        with c.store._lock:
            row = c.store.db.execute(
                "SELECT assertion_ref FROM rj_lab_assertion WHERE engagement=? AND evidence_ref=?",
                (c.policy.engagement_id, edge.validation_assertion_ref),
            ).fetchone()
        if row is None or asdict(self.edge(row[0])) != asdict(edge):
            raise LabDenied("lab_edge_requires_exact_owned_assertion")
