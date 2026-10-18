"""Durable auth challenges and one-use admission; no secrets in SQLite."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, cast

from redjohn.assessment.browser_action_models import BrowserAuthPlan
from redjohn.assessment.inventory import InventoryConflictError
from redjohn.assessment.models import JobSpec, stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.workflow_models import bounded_name


if TYPE_CHECKING:
    import sqlite3

    from redjohn.assessment.store import AssessmentStore


class AuthFlowRepository:
    def __init__(self, store: AssessmentStore) -> None:
        self.store = store
        with store.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS rj_auth_plan(id TEXT PRIMARY "
                "KEY,engagement TEXT NOT NULL,policy_revision TEXT NOT NULL,payload "
                "TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS rj_auth_flow(id TEXT PRIMARY "
                "KEY,engagement TEXT NOT NULL,policy_revision TEXT NOT NULL,plan_id "
                "TEXT NOT NULL,run_key TEXT NOT NULL,actor TEXT NOT NULL,tenant TEXT "
                "NOT NULL,from_revision TEXT NOT NULL,revision INTEGER NOT "
                "NULL,status TEXT NOT NULL,next_action INTEGER NOT NULL,owner "
                "TEXT,attempt INTEGER,admitted INTEGER NOT NULL,updated_at REAL NOT "
                "NULL)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS rj_auth_flow_identity ON "
                "rj_auth_flow(engagement,actor,tenant,policy_revision,status)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS rj_auth_input_use(engagement TEXT NOT "
                "NULL,actor TEXT NOT NULL,tenant TEXT NOT NULL,policy_revision TEXT "
                "NOT NULL,input_ref TEXT NOT NULL,flow_id TEXT NOT NULL,job_id TEXT "
                "NOT NULL,state TEXT NOT NULL,at REAL NOT NULL,PRIMARY "
                "KEY(engagement,actor,tenant,policy_revision,input_ref))"
            )

    def register(self, policy: EngagementPolicy, plan: BrowserAuthPlan) -> str:
        plan.authorize(policy)
        identity = stable_key([policy.engagement_id, policy.revision, plan.key])
        with self.store.transaction() as db:
            self.store.inventory._fence(db, policy)
            if (
                db.execute(
                    "SELECT count(*) FROM rj_auth_plan WHERE engagement=?", (policy.engagement_id,)
                ).fetchone()[0]
                >= 64
                and not db.execute("SELECT 1 FROM rj_auth_plan WHERE id=?", (identity,)).fetchone()
            ):
                raise ValueError("auth_plan_capacity_exhausted")
            db.execute(
                "INSERT OR IGNORE INTO rj_auth_plan VALUES(?,?,?,?)",
                (identity, policy.engagement_id, policy.revision, json.dumps(asdict(plan))),
            )
        return identity

    def plan(self, policy: EngagementPolicy, plan_id: str) -> BrowserAuthPlan:
        with self.store._lock:
            self.store.inventory._fence(self.store.db, policy)
            row = self.store.db.execute(
                "SELECT payload FROM rj_auth_plan WHERE id=? AND engagement=? AND "
                "policy_revision=?",
                (plan_id, policy.engagement_id, policy.revision),
            ).fetchone()
        if row is None:
            raise PolicyDenied("auth_plan_access_denied")
        return BrowserAuthPlan.from_mapping(json.loads(row[0]))

    def start(self, policy: EngagementPolicy, plan_id: str, run_key: str) -> str:
        bounded_name(run_key)
        plan = self.plan(policy, plan_id)
        identity = stable_key([policy.engagement_id, plan_id, run_key])
        with self.store.transaction() as db:
            self.store.inventory._fence(db, policy)
            if db.execute("SELECT 1 FROM rj_auth_flow WHERE id=?", (identity,)).fetchone():
                return identity
            if (
                db.execute(
                    "SELECT count(*) FROM rj_auth_flow WHERE engagement=?", (policy.engagement_id,)
                ).fetchone()[0]
                >= 128
            ):
                raise ValueError("auth_flow_capacity_exhausted")
            state = db.execute(
                "SELECT revision,status FROM rj_session_state WHERE engagement=? AND "
                "actor=? AND tenant=? AND policy_revision=?",
                (policy.engagement_id, plan.actor_id, plan.tenant_id, policy.revision),
            ).fetchone()
            if state and state["status"] not in {"ready", "revoked"}:
                raise InventoryConflictError("auth_identity_busy_or_uncertain")
            if plan.outcome == "logged_out" and (not state or state["status"] != "ready"):
                raise InventoryConflictError("logout_requires_ready_session")
            revision = state["revision"] if state else "1"
            if not revision.isascii() or not revision.isdigit() or not 1 <= int(revision) < 10**18:
                raise ValueError("auth_flow_numeric_session_revision_required")
            db.execute(
                "INSERT INTO rj_auth_flow VALUES(?,?,?,?,?,?,?,?,1,'prepared',0,NULL,NULL,0,?)",
                (
                    identity,
                    policy.engagement_id,
                    policy.revision,
                    plan_id,
                    run_key,
                    plan.actor_id,
                    plan.tenant_id,
                    revision,
                    time.time(),
                ),
            )
        return identity

    def get(self, policy: EngagementPolicy, flow_id: str) -> dict[str, Any]:
        with self.store._lock:
            self.store.inventory._fence(self.store.db, policy)
            row = self.store.db.execute(
                "SELECT * FROM rj_auth_flow WHERE id=? AND engagement=? AND policy_revision=?",
                (flow_id, policy.engagement_id, policy.revision),
            ).fetchone()
        if row is None:
            raise PolicyDenied("auth_flow_access_denied")
        result = dict(row)
        result.pop("owner", None)
        result.pop("attempt", None)
        return result

    def _fence(
        self, db: sqlite3.Connection, policy: EngagementPolicy, job: dict[str, Any], flow_id: str
    ) -> sqlite3.Row:
        self.store.inventory._fence(db, policy)
        job_row = db.execute(
            "SELECT spec FROM rj_job WHERE id=? AND engagement=? AND owner=? AND "
            "attempt=? AND execution_status='running' AND cancel_requested=0 AND "
            "lease_until>? AND capability='browser_auth_flow'",
            (job["id"], policy.engagement_id, job["owner"], job["attempt"], time.time()),
        ).fetchone()
        if job_row is None:
            raise PolicyDenied("auth_flow_scheduler_lease_denied")
        spec = JobSpec(**json.loads(job_row[0]))
        row = db.execute(
            "SELECT * FROM rj_auth_flow WHERE id=? AND engagement=? AND policy_revision=?",
            (flow_id, policy.engagement_id, policy.revision),
        ).fetchone()
        if (
            row is None
            or spec.idempotent
            or spec.options != {"flow_id": flow_id, "expected_revision": row["revision"]}
        ):
            raise InventoryConflictError("auth_flow_stale_revision")
        return cast("sqlite3.Row", row)

    def claim(self, policy: EngagementPolicy, job: dict[str, Any], flow_id: str) -> dict[str, Any]:
        with self.store.transaction() as db:
            row = self._fence(db, policy, job, flow_id)
            if row["status"] not in {"prepared", "awaiting_input"}:
                raise InventoryConflictError("auth_flow_requires_reconciliation")
            identity = (policy.engagement_id, row["actor"], row["tenant"], policy.revision)
            if (
                db.execute(
                    "SELECT 1 FROM rj_auth_flow WHERE engagement=? AND actor=? AND "
                    "tenant=? AND policy_revision=? AND id<>? AND status IN "
                    "('running','awaiting_input','uncertain')",
                    (*identity, flow_id),
                ).fetchone()
                or db.execute(
                    "SELECT 1 FROM rj_workflow_lease l JOIN rj_workflow_instance w ON "
                    "w.id=l.instance_id WHERE w.engagement=? AND w.actor=? AND "
                    "w.tenant=? AND w.policy_revision=? AND (l.phase='inflight' OR "
                    "l.expires_at>?)",
                    (*identity, time.time()),
                ).fetchone()
            ):
                raise InventoryConflictError("auth_identity_busy_or_uncertain")
            current = db.execute(
                "SELECT revision,status FROM rj_session_state WHERE engagement=? AND "
                "actor=? AND tenant=? AND policy_revision=?",
                identity,
            ).fetchone()
            if current and (
                current["revision"] != row["from_revision"]
                or current["status"] not in {"ready", "revoked", "authenticating"}
            ):
                raise InventoryConflictError("auth_session_changed")
            db.execute(
                "INSERT INTO rj_session_state "
                "VALUES(?,?,?,?,?,'authenticating',NULL,?) ON "
                "CONFLICT(engagement,actor,tenant,policy_revision) DO UPDATE SET "
                "status='authenticating',updated_at=excluded.updated_at",
                (*identity, row["from_revision"], time.time()),
            )
            db.execute(
                "UPDATE rj_auth_flow SET "
                "status='running',owner=?,attempt=?,updated_at=? WHERE id=?",
                (job["owner"], job["attempt"], time.time(), flow_id),
            )
        return self.get(policy, flow_id)

    def admit(
        self,
        policy: EngagementPolicy,
        job: dict[str, Any],
        flow_id: str,
        references: tuple[str, ...],
    ) -> None:
        if not references or len(references) > 17 or len(set(references)) != len(references):
            raise ValueError("invalid_auth_input_admission")
        with self.store.transaction() as db:
            row = self._fence(db, policy, job, flow_id)
            if row["status"] != "running" or row["admitted"]:
                raise InventoryConflictError("auth_request_already_admitted")
            for reference in references:
                bounded_name(reference)
                if db.execute(
                    "SELECT 1 FROM rj_auth_input_use WHERE engagement=? AND actor=? AND "
                    "tenant=? AND policy_revision=? AND input_ref=?",
                    (policy.engagement_id, row["actor"], row["tenant"], policy.revision, reference),
                ).fetchone():
                    raise PolicyDenied("auth_one_use_input_already_consumed")
            if not db.execute(
                "UPDATE rj_engagement SET requests_used=requests_used+1 WHERE id=? "
                "AND requests_used<? AND stopped=0",
                (policy.engagement_id, policy.request_budget),
            ).rowcount:
                raise PolicyDenied("auth_request_budget_exhausted")
            for reference in references:
                db.execute(
                    "INSERT INTO rj_auth_input_use VALUES(?,?,?,?,?,?,?,'admitted',?)",
                    (
                        policy.engagement_id,
                        row["actor"],
                        row["tenant"],
                        policy.revision,
                        reference,
                        flow_id,
                        job["id"],
                        time.time(),
                    ),
                )
            db.execute(
                "UPDATE rj_auth_flow SET admitted=1,updated_at=? WHERE id=?", (time.time(), flow_id)
            )

    def checkpoint(
        self,
        policy: EngagementPolicy,
        job: dict[str, Any],
        flow_id: str,
        next_action: int,
        *,
        awaiting: bool = False,
    ) -> None:
        with self.store.transaction() as db:
            row = self._fence(db, policy, job, flow_id)
            if row["status"] != "running":
                raise InventoryConflictError("auth_flow_not_running")
            db.execute(
                "UPDATE rj_auth_input_use SET state='settled' WHERE flow_id=? AND state='admitted'",
                (flow_id,),
            )
            db.execute(
                "UPDATE rj_auth_flow SET "
                "next_action=?,admitted=0,status=?,revision=revision+?,updated_at=? "
                "WHERE id=?",
                (
                    next_action,
                    "awaiting_input" if awaiting else "running",
                    int(awaiting),
                    time.time(),
                    flow_id,
                ),
            )

    def finish(
        self, policy: EngagementPolicy, job: dict[str, Any], flow_id: str, outcome: str
    ) -> str:
        if outcome not in {"authenticated", "logged_out"}:
            raise ValueError("invalid_auth_flow_outcome")
        with self.store.transaction() as db:
            row = self._fence(db, policy, job, flow_id)
            if row["status"] != "running" or row["admitted"]:
                raise InventoryConflictError("auth_outcome_unsettled")
            revision = str(int(row["from_revision"]) + 1)
            changed = db.execute(
                "UPDATE rj_session_state SET revision=?,status=?,updated_at=? WHERE "
                "engagement=? AND actor=? AND tenant=? AND policy_revision=? AND "
                "revision=? AND status='authenticating'",
                (
                    revision,
                    "ready" if outcome == "authenticated" else "revoked",
                    time.time(),
                    policy.engagement_id,
                    row["actor"],
                    row["tenant"],
                    policy.revision,
                    row["from_revision"],
                ),
            ).rowcount
            if changed != 1:
                raise InventoryConflictError("auth_session_commit_not_current")
            db.execute(
                "UPDATE rj_auth_flow SET "
                "status=?,revision=revision+1,owner=NULL,attempt=NULL,updated_at=? "
                "WHERE id=?",
                ("ready" if outcome == "authenticated" else "revoked", time.time(), flow_id),
            )
        return revision

    def uncertain(self, policy: EngagementPolicy, job: dict[str, Any], flow_id: str) -> None:
        """Downgrade only this attempt, including failure after the ready CAS."""
        with self.store.transaction() as db:
            row = db.execute(
                "SELECT * FROM rj_auth_flow WHERE id=? AND engagement=? AND "
                "status IN ('running','ready','revoked')",
                (flow_id, policy.engagement_id),
            ).fetchone()
            actual = db.execute(
                "SELECT spec FROM rj_job WHERE id=? AND engagement=? AND owner=? "
                "AND attempt=? AND execution_status='running' AND capability='browser_auth_flow'",
                (job["id"], policy.engagement_id, job["owner"], job["attempt"]),
            ).fetchone()
            if row is None or actual is None:
                return
            spec = json.loads(actual[0])
            expected_revision = spec.get("options", {}).get("expected_revision")
            if (
                spec.get("options", {}).get("flow_id") != flow_id
                or (
                    row["status"] == "running"
                    and (row["owner"], row["attempt"]) != (job["owner"], job["attempt"])
                )
                or row["revision"] != expected_revision + int(row["status"] != "running")
            ):
                return
            if row["status"] == "running" and not row["admitted"]:
                db.execute(
                    "UPDATE rj_auth_flow SET status='awaiting_input',revision=revision+1,"
                    "owner=NULL,attempt=NULL,updated_at=? WHERE id=?",
                    (time.time(), flow_id),
                )
                return
            session_revision = str(int(row["from_revision"]) + int(row["status"] != "running"))
            db.execute(
                "UPDATE rj_auth_flow SET status='uncertain',updated_at=? WHERE id=?",
                (time.time(), flow_id),
            )
            db.execute(
                "UPDATE rj_session_state SET status='uncertain',updated_at=? WHERE "
                "engagement=? AND actor=? AND tenant=? AND policy_revision=? AND "
                "revision=? AND status IN ('authenticating','ready','revoked')",
                (
                    time.time(),
                    policy.engagement_id,
                    row["actor"],
                    row["tenant"],
                    policy.revision,
                    session_revision,
                ),
            )
