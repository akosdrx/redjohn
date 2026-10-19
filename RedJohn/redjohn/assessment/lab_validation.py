"""Explicit owned-lab capability on the existing durable rj_job scheduler.

Phase rows are transmission/proof records, never another dispatch mechanism.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import EgressUnavailable
from redjohn.assessment.lab_contract import (
    CAPABILITY,
    EXPECTED,
    HEADER,
    VERSION,
    FixtureProof,
    LabDenied,
    LabPlan,
    OwnedFixtureBinding,
    Phase,
)
from redjohn.assessment.lab_worker import TEMPLATE_SHA256, LabWorker
from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record
from redjohn.assessment.persistent_rate_limit import PersistentRateLimitDetector
from redjohn.assessment.policy import PolicyDenied, origin_for
from redjohn.assessment.resources import ResourceAdmissionError
from redjohn.assessment.store import CapacityExceeded


if TYPE_CHECKING:
    import sqlite3

    from redjohn.assessment.models import CoverageStatus
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


class LabValidation:
    def __init__(self, store: AssessmentStore, policy: EngagementPolicy, *, caller: str) -> None:
        policy.authorize(caller)
        policy.check_capability(domains=("web",), profiles=("isolated-lab",))
        self.store, self.policy = store, policy
        self.rate_limits = PersistentRateLimitDetector(
            store, policy.engagement_id, requests_per_window=min(60, policy.request_budget)
        )
        self._bindings: dict[str, OwnedFixtureBinding] = {}
        with store._lock:
            store.db.executescript("""
            CREATE TABLE IF NOT EXISTS rj_lab_fixture(
              engagement TEXT NOT NULL, fixture_key TEXT NOT NULL, payload TEXT NOT NULL,
              PRIMARY KEY(engagement,fixture_key));
            CREATE TABLE IF NOT EXISTS rj_lab_plan(
              engagement TEXT NOT NULL, plan_ref TEXT NOT NULL, payload TEXT NOT NULL,
              PRIMARY KEY(engagement,plan_ref));
            CREATE TABLE IF NOT EXISTS rj_lab_phase(
              engagement TEXT NOT NULL, job_id TEXT NOT NULL, plan_ref TEXT NOT NULL,
              phase TEXT NOT NULL, fixture_key TEXT NOT NULL, stage TEXT NOT NULL,
              attempt INTEGER NOT NULL, owner TEXT NOT NULL, evidence_ref TEXT,
              updated_at REAL NOT NULL, PRIMARY KEY(engagement,job_id));
            CREATE INDEX IF NOT EXISTS rj_lab_phase_plan ON rj_lab_phase(engagement,plan_ref);
            """)

    def _policy(self) -> None:
        current = self.store.policy(self.policy.engagement_id, self.policy.owner_id)
        if current != self.policy or self.store.is_stopped(self.policy):
            raise PolicyDenied("lab_current_policy_required")

    def bind_fixture(self, binding: OwnedFixtureBinding) -> str:
        self._policy()
        if type(binding) is not OwnedFixtureBinding:
            raise LabDenied("lab_typed_host_fixture_required")
        proof = binding.require_live()
        self.policy.check_readonly_request(proof.url, "GET")
        with self.store.transaction() as db:
            count = db.execute(
                "SELECT count(*) FROM rj_lab_fixture WHERE engagement=?",
                (self.policy.engagement_id,),
            ).fetchone()[0]
            existing = db.execute(
                "SELECT payload FROM rj_lab_fixture WHERE engagement=? AND fixture_key=?",
                (self.policy.engagement_id, proof.key),
            ).fetchone()
            if existing is None and count >= 64:
                raise CapacityExceeded("lab_fixture_quota")
            db.execute(
                "INSERT OR IGNORE INTO rj_lab_fixture VALUES(?,?,?)",
                (self.policy.engagement_id, proof.key, json.dumps(asdict(proof))),
            )
        self._bindings[proof.key] = binding
        return proof.key

    def fixture(self, key: str) -> OwnedFixtureBinding:
        binding = self._bindings.get(key)
        if binding is None:
            raise LabDenied("lab_live_host_binding_required")
        binding.require_live()
        return binding

    def create(self, candidate_ref: str, surface_id: str, fixture_key: str) -> LabPlan:
        self._policy()
        proof = self.fixture(fixture_key).proof
        surface = self.store.surface(self.policy.engagement_id, surface_id)
        with self.store._lock:
            self.store.inventory.require_surface_active(self.store.db, self.policy, surface_id)
            link = self.store.db.execute(
                "SELECT asset_id FROM rj_inventory_surface WHERE engagement=? AND surface_id=?",
                (self.policy.engagement_id, surface_id),
            ).fetchone()
        if link is None or link[0] != proof.asset_ref:
            raise LabDenied("lab_fixture_inventory_asset_mismatch")
        with self.store._lock:
            row = self.store.db.execute(
                "SELECT f.payload,f.job_id,j.execution_status,j.coverage_status,"
                "j.capability,j.spec,j.result "
                "FROM rj_finding f JOIN rj_job j ON j.id=f.job_id "
                "WHERE f.id=? AND f.engagement=? AND f.status='candidate' AND j.surface_id=?",
                (candidate_ref, self.policy.engagement_id, surface_id),
            ).fetchone()
        if (
            row is None
            or row["execution_status"] != "succeeded"
            or row["coverage_status"] != "completed"
            or row["capability"] != "headers_audit"
            or json.loads(row["result"]).get("error") is not None
            or json.loads(row["spec"])["policy_revision"] != self.policy.revision
            or surface.method != "GET"
            or surface.source != "observed"
            or surface.actor_id != "anonymous"
            or surface.url != proof.url
            or proof.phase != "candidate"
        ):
            raise LabDenied("lab_completed_current_header_candidate_required")
        finding = json.loads(row["payload"])
        refs = finding.get("evidence_refs")
        if (
            finding.get("title") != "Missing " + HEADER
            or finding.get("observed") != "header_absent"
            or finding.get("actor_id") != surface.actor_id
            or finding.get("session_revision") != surface.session_revision
            or not isinstance(refs, list)
            or len(refs) != 1
            or not isinstance(refs[0], str)
        ):
            raise LabDenied("lab_exact_header_candidate_required")
        capture = self.store.evidence_get(self.policy.engagement_id, refs[0], max_bytes=65536)
        data = json.loads(capture["excerpt"])
        if (
            capture["truncated"]
            or data.get("url") != surface.url
            or data.get("status") != 200
            or data.get("actor_id") != surface.actor_id
            or data.get("session_revision") != surface.session_revision
            or not isinstance(data.get("headers"), dict)
            or HEADER in {str(k).lower() for k in data["headers"]}
        ):
            raise LabDenied("lab_capture_context_mismatch")
        with self.store._lock:
            owned = self.store.db.execute(
                "SELECT 1 FROM rj_evidence WHERE engagement=? AND id=? AND job_id=?",
                (self.policy.engagement_id, refs[0], row["job_id"]),
            ).fetchone()
        if owned is None:
            raise LabDenied("lab_candidate_capture_job_mismatch")
        plan = LabPlan(
            self.policy.engagement_id,
            self.policy.revision,
            candidate_ref,
            row["job_id"],
            surface_id,
            refs[0],
            proof.fixture_ref,
            proof.asset_ref,
            surface.url,
            surface.actor_id,
            surface.session_revision,
            surface.workflow_state,
            proof.key,
            TEMPLATE_SHA256,
        )
        plan.authorize(self.policy)
        with self.store.transaction() as db:
            count = db.execute(
                "SELECT count(*) FROM rj_lab_plan WHERE engagement=?", (self.policy.engagement_id,)
            ).fetchone()[0]
            present = db.execute(
                "SELECT 1 FROM rj_lab_plan WHERE engagement=? AND plan_ref=?",
                (self.policy.engagement_id, plan.key),
            ).fetchone()
            if present is None and count >= 32:
                raise CapacityExceeded("lab_plan_quota")
            db.execute(
                "INSERT OR IGNORE INTO rj_lab_plan VALUES(?,?,?)",
                (self.policy.engagement_id, plan.key, json.dumps(asdict(plan))),
            )
        return plan

    def plan(self, ref: str) -> LabPlan:
        self._policy()
        with self.store._lock:
            row = self.store.db.execute(
                "SELECT payload FROM rj_lab_plan WHERE engagement=? AND plan_ref=?",
                (self.policy.engagement_id, ref),
            ).fetchone()
        if row is None:
            raise LabDenied("lab_unknown_plan")
        plan = LabPlan(**json.loads(row[0]))
        if plan.key != ref:
            raise LabDenied("lab_plan_integrity_mismatch")
        plan.authorize(self.policy)
        surface = self.store.surface(self.policy.engagement_id, plan.surface_id)
        if (
            surface.method != "GET"
            or surface.source != "observed"
            or any(
                getattr(surface, key) != getattr(plan, key)
                for key in ("url", "actor_id", "session_revision", "workflow_state")
            )
        ):
            raise LabDenied("lab_current_surface_context_required")
        with self.store._lock:
            self.store.inventory.require_surface_active(self.store.db, self.policy, plan.surface_id)
            link = self.store.db.execute(
                "SELECT asset_id FROM rj_inventory_surface WHERE engagement=? AND surface_id=?",
                (self.policy.engagement_id, plan.surface_id),
            ).fetchone()
            candidate = self.store.db.execute(
                "SELECT f.payload,j.spec FROM rj_finding f JOIN rj_job j ON f.job_id=j.id "
                "WHERE f.engagement=? AND f.id=? AND f.job_id=? AND f.status='candidate' "
                "AND j.engagement=f.engagement AND j.surface_id=? AND j.capability='headers_audit' "
                "AND j.execution_status='succeeded' AND j.coverage_status='completed'",
                (
                    self.policy.engagement_id,
                    plan.candidate_ref,
                    plan.candidate_job,
                    plan.surface_id,
                ),
            ).fetchone()
            capture = self.store.db.execute(
                "SELECT payload FROM rj_evidence WHERE engagement=? AND id=? AND job_id=? "
                "AND bytes<=65536",
                (self.policy.engagement_id, plan.capture_ref, plan.candidate_job),
            ).fetchone()
        if link is None or link[0] != plan.asset_ref or candidate is None or capture is None:
            raise LabDenied("lab_current_candidate_context_required")
        finding, spec, observed = (
            json.loads(candidate[0]),
            json.loads(candidate[1]),
            json.loads(capture[0]),
        )
        if (
            spec.get("policy_revision") != plan.policy_revision
            or finding.get("title") != "Missing " + HEADER
            or finding.get("observed") != "header_absent"
            or finding.get("evidence_refs") != [plan.capture_ref]
            or any(
                finding.get(key) != getattr(plan, key) for key in ("actor_id", "session_revision")
            )
            or observed.get("status") != 200
            or any(
                observed.get(key) != getattr(plan, key)
                for key in ("url", "actor_id", "session_revision")
            )
            or not isinstance(observed.get("headers"), dict)
            or HEADER in {str(key).lower() for key in observed["headers"]}
        ):
            raise LabDenied("lab_current_candidate_context_required")
        return plan

    def require_phase(
        self, plan: LabPlan, phase: Phase, fixture_key: str, *, retest_revision: str = ""
    ) -> FixtureProof:
        proof = self.fixture(fixture_key).proof
        if (
            not isinstance(phase, str)
            or phase not in {"candidate", "fixed_control"}
            or proof.phase != phase
            or any(
                getattr(proof, k) != getattr(plan, k) for k in ("fixture_ref", "asset_ref", "url")
            )
            or (phase == "candidate" and fixture_key != plan.candidate_deployment)
        ):
            raise LabDenied("lab_phase_fixture_mismatch")
        if phase == "fixed_control":
            with self.store._lock:
                initial = self.store.db.execute(
                    "SELECT payload FROM rj_lab_fixture WHERE engagement=? AND fixture_key=?",
                    (self.policy.engagement_id, plan.candidate_deployment),
                ).fetchone()
            before = FixtureProof(**json.loads(initial[0])) if initial else None
            if (
                before is None
                or before.source_sha256 == proof.source_sha256
                or before.deployment_ref == proof.deployment_ref
                or (before.pid, before.process_start) == (proof.pid, proof.process_start)
            ):
                raise LabDenied("lab_distinct_fixed_source_required")
            with self.store._lock:
                positives = self.store.db.execute(
                    "SELECT j.spec FROM rj_lab_phase p JOIN rj_job j ON j.id=p.job_id "
                    "WHERE p.engagement=? AND p.plan_ref=? AND p.phase='candidate' "
                    "AND p.stage='proved' AND j.execution_status='succeeded' "
                    "AND j.coverage_status='completed' LIMIT 64",
                    (self.policy.engagement_id, plan.key),
                ).fetchall()
            if not any(
                json.loads(row[0]).get("retest_revision") == retest_revision for row in positives
            ):
                raise LabDenied("lab_completed_positive_phase_required")
        return proof

    def submit(
        self, plan_ref: str, phase: Phase, fixture_key: str, *, retest_revision: str = ""
    ) -> str:
        plan = self.plan(plan_ref)
        self.require_phase(plan, phase, fixture_key, retest_revision=retest_revision)
        spec = JobSpec(
            plan.surface_id,
            "validation",
            CAPABILITY,
            tool_version=VERSION,
            template_version=TEMPLATE_SHA256,
            policy_revision=self.policy.revision,
            retest_revision=retest_revision,
            idempotent=False,
            timeout_seconds=10,
            options={"plan_ref": plan_ref, "phase": phase, "fixture_key": fixture_key},
        )
        return self.store.submit(self.policy, [spec])[0]

    def _fence(self, db: sqlite3.Connection, job: dict[str, Any]) -> None:
        row = db.execute(
            "SELECT spec,capability FROM rj_job WHERE id=? AND engagement=? "
            "AND owner=? AND attempt=? "
            "AND execution_status='running' AND cancel_requested=0",
            (job["id"], self.policy.engagement_id, job["owner"], job["attempt"]),
        ).fetchone()
        current = db.execute(
            "SELECT revision,stopped FROM rj_engagement WHERE id=?", (self.policy.engagement_id,)
        ).fetchone()
        if (
            row is None
            or row["capability"] != CAPABILITY
            or current is None
            or current["revision"] != self.policy.revision
            or current["stopped"]
        ):
            raise PolicyDenied("lab_stale_job_or_policy")

    def reserve(self, job: dict[str, Any], plan: LabPlan, spec: JobSpec) -> None:
        with self.store.transaction() as db:
            self._fence(db, job)
            stored = db.execute("SELECT spec FROM rj_job WHERE id=?", (job["id"],)).fetchone()
            if stored is None or json.loads(stored[0]) != asdict(spec):
                raise LabDenied("lab_exact_durable_job_required")
            prior = db.execute(
                "SELECT stage FROM rj_lab_phase WHERE engagement=? AND job_id=?",
                (self.policy.engagement_id, job["id"]),
            ).fetchone()
            if prior is not None:
                raise LabDenied("lab_previous_attempt_unknown_no_replay")
            count = db.execute(
                "SELECT count(*) FROM rj_lab_phase WHERE engagement=?", (self.policy.engagement_id,)
            ).fetchone()[0]
            if count >= 64:
                raise CapacityExceeded("lab_phase_quota")
            db.execute(
                "INSERT INTO rj_lab_phase VALUES(?,?,?,?,?,?,?,?,NULL,?)",
                (
                    self.policy.engagement_id,
                    job["id"],
                    plan.key,
                    spec.options["phase"],
                    spec.options["fixture_key"],
                    "reserved",
                    job["attempt"],
                    job["owner"],
                    time.time(),
                ),
            )

    def admit(self, job: dict[str, Any]) -> None:
        with self.store._lock:
            state = self.store.db.execute(
                "SELECT plan_ref FROM rj_lab_phase WHERE engagement=? AND job_id=?",
                (self.policy.engagement_id, job["id"]),
            ).fetchone()
        if state is None or not self.rate_limits.admit(origin_for(self.plan(state[0]).url)):
            raise CapacityExceeded("lab_shared_origin_cooldown")
        with self.store.transaction() as db:
            self._fence(db, job)
            phase = db.execute(
                "SELECT stage FROM rj_lab_phase WHERE engagement=? AND job_id=?",
                (self.policy.engagement_id, job["id"]),
            ).fetchone()
            if phase is None or phase[0] != "reserved":
                raise LabDenied("lab_request_already_reserved_no_replay")
            changed = db.execute(
                "UPDATE rj_engagement SET requests_used=requests_used+1 "
                "WHERE id=? AND requests_used<?",
                (self.policy.engagement_id, self.policy.request_budget),
            ).rowcount
            if not changed:
                raise CapacityExceeded("request_budget_exhausted")
            db.execute(
                "UPDATE rj_lab_phase SET stage='admitted',updated_at=? "
                "WHERE engagement=? AND job_id=?",
                (time.time(), self.policy.engagement_id, job["id"]),
            )

    def finish(
        self, job: dict[str, Any], plan: LabPlan, spec: JobSpec, result: dict[str, Any]
    ) -> str:
        value = {
            **plan.context(),
            "phase": spec.options["phase"],
            "job_id": job["id"],
            "attempt": job["attempt"],
            "fixture_key": spec.options["fixture_key"],
            "result": result,
            "schema": 1,
        }
        # Evidence is written before the phase becomes validatable. An evidence
        # failure leaves an admitted/unknown reservation, never a forged proof.
        ref = self.store.evidence_put(
            self.policy.engagement_id, value, job_id=job["id"], kind="owned_lab_phase_proof"
        )
        with self.store.transaction() as db:
            self._fence(db, job)
            changed = db.execute(
                "UPDATE rj_lab_phase SET stage='proved',evidence_ref=?,updated_at=? "
                "WHERE engagement=? AND job_id=? AND stage='admitted' AND attempt=? AND owner=?",
                (
                    ref,
                    time.time(),
                    self.policy.engagement_id,
                    job["id"],
                    job["attempt"],
                    job["owner"],
                ),
            ).rowcount
            if changed != 1:
                raise LabDenied("lab_phase_completion_not_owned")
        return ref

    def unknown(self, job: dict[str, Any], code: str) -> str:
        # This is diagnostic evidence, never assertion authority.
        with self.store._lock:
            row = self.store.db.execute(
                "SELECT stage FROM rj_lab_phase WHERE engagement=? AND job_id=?",
                (self.policy.engagement_id, job["id"]),
            ).fetchone()
        return self.store.evidence_put(
            self.policy.engagement_id,
            {
                "code": code,
                "job_id": job["id"],
                "stage": row[0] if row else "not_reserved",
                "outcome": "unknown_no_automatic_replay",
            },
            job_id=job["id"],
            kind="owned_lab_incomplete",
        )


class LabValidationAdapter:
    resource_class = "worker"

    def __init__(self, component: LabValidation, worker: LabWorker) -> None:
        self.component, self.worker = component, worker

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:
        c = self.component
        reserved = False
        try:
            if (
                spec.capability != CAPABILITY
                or spec.idempotent
                or spec.tool_version != VERSION
                or spec.template_version != TEMPLATE_SHA256
                or set(spec.options) != {"plan_ref", "phase", "fixture_key"}
                or any(not isinstance(v, str) for v in spec.options.values())
            ):
                raise LabDenied("lab_exact_nonidempotent_profile_required")  # noqa: TRY301
            plan = c.plan(spec.options["plan_ref"])
            current = c.store.surface(c.policy.engagement_id, plan.surface_id)
            if (
                current != surface
                or surface.url != plan.url
                or any(
                    getattr(surface, k) != getattr(plan, k)
                    for k in ("actor_id", "session_revision", "workflow_state")
                )
            ):
                raise LabDenied("lab_surface_context_changed")  # noqa: TRY301
            proof = c.require_phase(
                plan,
                spec.options["phase"],
                spec.options["fixture_key"],
                retest_revision=spec.retest_revision,
            )
            c.reserve(job, plan, spec)
            reserved = True
            result = await self.worker.execute(
                c.policy,
                plan,
                c.fixture(proof.key),
                admit=lambda: c.admit(job),
                timeout=spec.timeout_seconds,
            )
            status = result["assertion"]["status"]
            c.rate_limits.observe(origin_for(plan.url), status, {})
            if status != 200:
                raise LabDenied("lab_response_blocked_or_inconclusive")  # noqa: TRY301
            ref = c.finish(job, plan, spec, result)
            observed = result["assertion"]["observed"]
            matched = (
                observed == EXPECTED
                if spec.options["phase"] == "fixed_control"
                else observed is None
            )
            return AdapterResult(
                "succeeded",
                "completed" if matched else "inconclusive",
                {
                    **plan.context(),
                    "phase": spec.options["phase"],
                    "evidence_refs": [ref],
                    "assertion_matched": matched,
                    "execution_path": "durable_owned_lab_scheduler",
                },
            )
        except asyncio.CancelledError:
            if reserved:
                c.unknown(job, "cancelled")
            raise
        except TimeoutError:
            refs = [c.unknown(job, "timed_out")] if reserved else []
            return AdapterResult(
                "timed_out",
                "inconclusive",
                {"evidence_refs": refs},
                error=error_record("lab_worker_timeout"),
            )
        except (LabDenied, PolicyDenied, EgressUnavailable, CapacityExceeded) as exc:
            refs = [c.unknown(job, type(exc).__name__)] if reserved else []
            code = (
                str(exc)
                if isinstance(exc, (LabDenied, PolicyDenied, EgressUnavailable))
                else "lab_budget_exhausted"
            )
            coverage: CoverageStatus = (
                "inconclusive"
                if code
                in {
                    "lab_previous_attempt_unknown_no_replay",
                    "lab_worker_failed",
                    "lab_worker_transport_assertion_mismatch",
                    "lab_worker_output_budget",
                    "lab_worker_output_schema",
                }
                else "blocked"
            )
            return AdapterResult(
                "failed",
                coverage,
                {"evidence_refs": refs},
                error=error_record(code, coverage_effect=coverage),
            )
        except ResourceAdmissionError:
            refs = [c.unknown(job, "kernel_memory_unavailable")] if reserved else []
            return AdapterResult(
                "failed",
                "blocked",
                {"evidence_refs": refs},
                error=error_record("lab_kernel_memory_unavailable", coverage_effect="blocked"),
            )
        except (OSError, ValueError):
            refs = [c.unknown(job, "worker_io_or_output_invalid")] if reserved else []
            return AdapterResult(
                "failed",
                "inconclusive",
                {"evidence_refs": refs},
                error=error_record("lab_worker_io_or_output_invalid"),
            )
        finally:
            await asyncio.shield(self.worker.cleanup())

    async def cancel(self) -> None:
        await self.worker.cancel()

    async def cleanup(self) -> None:
        await self.worker.cleanup()

    def resource_cleanup_verified(self) -> bool:
        return self.worker.resource_cleanup_verified()
