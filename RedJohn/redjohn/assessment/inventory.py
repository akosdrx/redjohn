"""Durable bounded asset/service/workflow state in the assessment SQLite store.

Observation is separate from authorization. Workflow leases serialize declared
steps, but never send requests, select credentials or execute an action.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from redjohn.assessment.models import stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied, origin_for
from redjohn.assessment.workflow_models import (
    SOURCES,
    InventoryLimits,
    WorkflowDefinition,
    asset_identity,
    bounded_name,
    canonical_asset_locator,
    evidence_references,
    lease_seconds,
)


if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Callable

    from redjohn.assessment.models import Surface
    from redjohn.assessment.store import AssessmentStore


_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS rj_inventory_schema(version INTEGER PRIMARY KEY)",
    "INSERT OR IGNORE INTO rj_inventory_schema VALUES(1)",
    (
        "CREATE TABLE IF NOT EXISTS rj_asset("
        "id TEXT PRIMARY KEY,engagement TEXT NOT NULL REFERENCES rj_engagement(id),"
        "kind TEXT NOT NULL,locator TEXT NOT NULL,source TEXT NOT NULL,state TEXT NOT NULL,"
        "revision INTEGER NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL,"
        "UNIQUE(engagement,kind,locator))"
    ),
    "CREATE INDEX IF NOT EXISTS rj_asset_page ON rj_asset(engagement,kind,id)",
    (
        "CREATE TABLE IF NOT EXISTS rj_service("
        "id TEXT PRIMARY KEY,engagement TEXT NOT NULL REFERENCES rj_engagement(id),"
        "asset_id TEXT NOT NULL REFERENCES rj_asset(id),protocol TEXT"
        " NOT NULL,port INTEGER NOT NULL,"
        "source TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,"
        "created_at REAL NOT NULL,updated_at REAL NOT "
        "NULL,UNIQUE(engagement,asset_id,protocol,port))"
    ),
    "CREATE INDEX IF NOT EXISTS rj_service_page ON rj_service(engagement,asset_id,id)",
    (
        "CREATE TABLE IF NOT EXISTS rj_inventory_surface("
        "engagement TEXT NOT NULL,surface_id TEXT NOT NULL REFERENCES rj_surface(id),"
        "asset_id TEXT NOT NULL REFERENCES rj_asset(id),service_id TEXT REFERENCES rj_service(id),"
        "PRIMARY KEY(engagement,surface_id))"
    ),
    (
        "CREATE INDEX IF NOT EXISTS rj_inventory_surface_asset ON "
        "rj_inventory_surface(engagement,asset_id,surface_id)"
    ),
    (
        "CREATE TABLE IF NOT EXISTS rj_inventory_observation("
        "id TEXT PRIMARY KEY,engagement TEXT NOT NULL,entity_id TEXT NOT NULL,"
        "source TEXT NOT NULL,evidence_ref TEXT NOT NULL REFERENCES "
        "rj_evidence(id),at REAL NOT NULL)"
    ),
    (
        "CREATE INDEX IF NOT EXISTS rj_inventory_observation_page ON "
        "rj_inventory_observation(engagement,entity_id,id)"
    ),
    (
        "CREATE TABLE IF NOT EXISTS rj_workflow_definition("
        "id TEXT PRIMARY KEY,engagement TEXT NOT NULL,policy_revision"
        " TEXT NOT NULL,name TEXT NOT NULL,"
        "revision TEXT NOT NULL,payload TEXT NOT NULL,UNIQUE(engagement,name,revision))"
    ),
    (
        "CREATE TABLE IF NOT EXISTS rj_workflow_instance("
        "id TEXT PRIMARY KEY,engagement TEXT NOT NULL,definition_id "
        "TEXT NOT NULL REFERENCES rj_workflow_definition(id),"
        "instance_key TEXT NOT NULL,actor TEXT NOT NULL,tenant TEXT "
        "NOT NULL,session_revision TEXT NOT NULL,"
        "policy_revision TEXT NOT NULL,state TEXT NOT NULL,status "
        "TEXT NOT NULL,revision INTEGER NOT NULL,"
        "created_at REAL NOT NULL,updated_at REAL NOT "
        "NULL,UNIQUE(engagement,definition_id,instance_key,actor,tenant))"
    ),
    (
        "CREATE INDEX IF NOT EXISTS rj_workflow_instance_page ON "
        "rj_workflow_instance(engagement,actor,tenant,id)"
    ),
    (
        "CREATE TABLE IF NOT EXISTS rj_workflow_lease("
        "instance_id TEXT PRIMARY KEY REFERENCES rj_workflow_instance(id),lease_ref TEXT NOT NULL,"
        "owner TEXT NOT NULL,step TEXT NOT NULL,surface_id TEXT NOT NULL REFERENCES rj_surface(id),"
        "instance_revision INTEGER NOT NULL,phase TEXT NOT NULL,expires_at REAL NOT NULL)"
    ),
    (
        "CREATE TABLE IF NOT EXISTS rj_workflow_history("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,engagement TEXT NOT NULL,instance_id TEXT NOT NULL,"
        "action TEXT NOT NULL,at REAL NOT NULL,payload TEXT NOT NULL)"
    ),
    (
        "CREATE INDEX IF NOT EXISTS rj_workflow_history_page ON "
        "rj_workflow_history(engagement,instance_id,id)"
    ),
)


_QUOTA_QUERIES = {
    "rj_asset": "SELECT count(*) FROM rj_asset WHERE engagement=?",
    "rj_service": "SELECT count(*) FROM rj_service WHERE engagement=?",
    "rj_inventory_surface": "SELECT count(*) FROM rj_inventory_surface WHERE engagement=?",
    "rj_inventory_observation": "SELECT count(*) FROM rj_inventory_observation WHERE engagement=?",
    "rj_workflow_definition": "SELECT count(*) FROM rj_workflow_definition WHERE engagement=?",
    "rj_workflow_instance": "SELECT count(*) FROM rj_workflow_instance WHERE engagement=?",
    "rj_workflow_history": "SELECT count(*) FROM rj_workflow_history WHERE engagement=?",
}

INVENTORY_OPERATIONS = frozenset(
    {
        "asset_search",
        "asset_get",
        "asset_set_state",
        "service_search",
        "service_set_state",
        "inventory_observations",
        "inventory_backfill",
        "workflow_definition_search",
        "workflow_search",
        "workflow_get",
        "workflow_history",
        "workflow_start",
        "workflow_claim_step",
        "workflow_mark_sent",
        "workflow_complete_step",
        "workflow_reconcile_step",
        "workflow_release_prepared",
        "workflow_refresh_session",
    }
)


class InventoryConflictError(RuntimeError):
    """A state/lease changed or requires explicit reconciliation."""


class InventoryRepository:
    def __init__(self, store: AssessmentStore, limits: InventoryLimits | None = None) -> None:
        self.store = store
        self.limits = limits or InventoryLimits()
        with store.transaction() as db:
            for statement in _SCHEMA:
                db.execute(statement)
            if [row[0] for row in db.execute("SELECT version FROM rj_inventory_schema")] != [1]:
                raise ValueError("unsupported_inventory_schema")

    def _fence(self, db: sqlite3.Connection, policy: EngagementPolicy) -> None:
        if not self.store._capture_policy_fenced(db, policy):
            raise PolicyDenied("inventory_policy_fence_failed")

    @staticmethod
    def _page(limit: int, after: str | int = "") -> None:
        if type(limit) is not int or not 1 <= limit <= 100 or len(str(after)) > 128:
            raise ValueError("invalid_inventory_page")

    def _quota(self, db: sqlite3.Connection, table: str, engagement: str, maximum: int) -> None:
        # Table names are internal constants, never API input.
        if db.execute(_QUOTA_QUERIES[table], (engagement,)).fetchone()[0] >= maximum:
            raise ValueError("inventory_quota_exhausted:" + table)

    @staticmethod
    def _evidence(db: sqlite3.Connection, engagement: str, references: tuple[str, ...]) -> None:
        evidence_references(references)
        if any(
            not db.execute(
                "SELECT 1 FROM rj_evidence WHERE engagement=? AND id=?", (engagement, ref)
            ).fetchone()
            for ref in references
        ):
            raise PolicyDenied("inventory_evidence_missing_or_wrong_engagement")

    def _observe(
        self,
        db: sqlite3.Connection,
        engagement: str,
        entity: str,
        source: str,
        references: tuple[str, ...],
    ) -> None:
        self._evidence(db, engagement, references)
        for reference in references:
            identity = stable_key([engagement, entity, source, reference])
            if not db.execute(
                "SELECT 1 FROM rj_inventory_observation WHERE id=?", (identity,)
            ).fetchone():
                self._quota(db, "rj_inventory_observation", engagement, self.limits.observations)
                db.execute(
                    "INSERT INTO rj_inventory_observation VALUES(?,?,?,?,?,?)",
                    (identity, engagement, entity, source, reference, time.time()),
                )

    def _asset(
        self,
        db: sqlite3.Connection,
        policy: EngagementPolicy,
        *,
        kind: str,
        locator: str,
        source: str,
        evidence_refs: tuple[str, ...],
    ) -> str:
        if source not in SOURCES:
            raise ValueError("invalid_inventory_source")
        evidence_references(evidence_refs, required=source == "observed")
        self._evidence(db, policy.engagement_id, evidence_refs)
        locator = canonical_asset_locator(kind, locator)
        identity = asset_identity(policy.engagement_id, kind, locator)
        old = db.execute("SELECT source FROM rj_asset WHERE id=?", (identity,)).fetchone()
        if old is None:
            self._quota(db, "rj_asset", policy.engagement_id, self.limits.assets)
            now = time.time()
            db.execute(
                "INSERT INTO rj_asset VALUES(?,?,?,?,?,'active',1,?,?)",
                (identity, policy.engagement_id, kind, locator, source, now, now),
            )
        elif {"inferred": 0, "imported": 1, "observed": 2}[source] > {
            "inferred": 0,
            "imported": 1,
            "observed": 2,
        }[old[0]]:
            db.execute(
                "UPDATE rj_asset SET source=?,updated_at=? WHERE id=?",
                (source, time.time(), identity),
            )
        self._observe(db, policy.engagement_id, identity, source, evidence_refs)
        return identity

    def record_asset(
        self,
        policy: EngagementPolicy,
        *,
        kind: str,
        locator: str,
        source: str,
        evidence_refs: tuple[str, ...] = (),
    ) -> str:
        """Record metadata only. Policy grants remain independent and mandatory."""
        with self.store.transaction() as db:
            self._fence(db, policy)
            return self._asset(
                db, policy, kind=kind, locator=locator, source=source, evidence_refs=evidence_refs
            )

    def _get_asset(
        self, db: sqlite3.Connection, policy: EngagementPolicy, asset_id: str
    ) -> sqlite3.Row:
        row = db.execute(
            "SELECT * FROM rj_asset WHERE engagement=? AND id=?", (policy.engagement_id, asset_id)
        ).fetchone()
        if row is None:
            raise PolicyDenied("inventory_asset_access_denied")
        return cast("sqlite3.Row", row)

    def asset(self, policy: EngagementPolicy, asset_id: str) -> dict[str, Any]:
        with self.store._lock:
            self._fence(self.store.db, policy)
            return {
                **dict(self._get_asset(self.store.db, policy, asset_id)),
                "execution_authority": "explicit_current_policy_required",
            }

    def assets(
        self,
        policy: EngagementPolicy,
        *,
        limit: int = 50,
        after: str = "",
        kind: str = "",
        source: str = "",
    ) -> list[dict[str, Any]]:
        self._page(limit, after)
        if (
            kind
            and kind
            not in {
                "http_origin",
                "dns_name",
                "ip_address",
                "ip_network",
                "source_artifact",
                "cloud_account",
                "kubernetes_cluster",
            }
        ) or (source and source not in SOURCES):
            raise ValueError("invalid_inventory_filter")
        with self.store._lock:
            self._fence(self.store.db, policy)
            rows = self.store.db.execute(
                "SELECT * FROM rj_asset WHERE engagement=? AND id>? AND (?='' OR "
                "kind=?) AND (?='' OR source=?) ORDER BY id LIMIT ?",
                (policy.engagement_id, after, kind, kind, source, source, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def require_source_asset(self, policy: EngagementPolicy, asset_id: str, digest: str) -> None:
        with self.store._lock:
            self._fence(self.store.db, policy)
            row = self._get_asset(self.store.db, policy, asset_id)
            if (
                row["kind"] != "source_artifact"
                or row["locator"] != canonical_asset_locator("source_artifact", digest)
                or row["state"] != "active"
            ):
                raise PolicyDenied("source_artifact_inventory_binding_denied")

    def set_asset_state(
        self, policy: EngagementPolicy, asset_id: str, state: str, expected_revision: int
    ) -> dict[str, Any]:
        if state not in {"active", "retired"} or type(expected_revision) is not int:
            raise ValueError("invalid_inventory_state")
        with self.store.transaction() as db:
            self._fence(db, policy)
            row = self._get_asset(db, policy, asset_id)
            if row["revision"] != expected_revision:
                raise InventoryConflictError("stale_inventory_revision")
            db.execute(
                "UPDATE rj_asset SET state=?,revision=revision+1,updated_at=? WHERE id=?",
                (state, time.time(), asset_id),
            )
        return self.asset(policy, asset_id)

    def _service(
        self,
        db: sqlite3.Connection,
        policy: EngagementPolicy,
        asset_id: str,
        protocol: str,
        port: int,
        source: str,
        references: tuple[str, ...],
    ) -> str:
        self._get_asset(db, policy, asset_id)
        if (
            protocol not in {"http", "https", "tcp", "udp", "dns", "file"}
            or type(port) is not int
            or not (port == 0 if protocol == "file" else 1 <= port <= 65535)
            or source not in SOURCES
        ):
            raise ValueError("invalid_inventory_service")
        evidence_references(references, required=source == "observed")
        identity = stable_key([policy.engagement_id, asset_id, protocol, port])
        if not db.execute("SELECT 1 FROM rj_service WHERE id=?", (identity,)).fetchone():
            self._quota(db, "rj_service", policy.engagement_id, self.limits.services)
            now = time.time()
            db.execute(
                "INSERT INTO rj_service VALUES(?,?,?,?,?,?,'active',1,?,?)",
                (identity, policy.engagement_id, asset_id, protocol, port, source, now, now),
            )
        else:
            previous = db.execute(
                "SELECT source FROM rj_service WHERE id=?", (identity,)
            ).fetchone()[0]
            ranks = {"inferred": 0, "imported": 1, "observed": 2}
            if ranks[source] > ranks[previous]:
                db.execute(
                    "UPDATE rj_service SET source=?,updated_at=? WHERE id=?",
                    (source, time.time(), identity),
                )
        self._observe(db, policy.engagement_id, identity, source, references)
        return identity

    def record_service(
        self,
        policy: EngagementPolicy,
        asset_id: str,
        *,
        protocol: str,
        port: int,
        source: str,
        evidence_refs: tuple[str, ...] = (),
    ) -> str:
        with self.store.transaction() as db:
            self._fence(db, policy)
            return self._service(db, policy, asset_id, protocol, port, source, evidence_refs)

    def services(
        self, policy: EngagementPolicy, *, asset_id: str = "", limit: int = 50, after: str = ""
    ) -> list[dict[str, Any]]:
        self._page(limit, after)
        with self.store._lock:
            self._fence(self.store.db, policy)
            return [
                dict(row)
                for row in self.store.db.execute(
                    "SELECT * FROM rj_service WHERE engagement=? AND id>? AND (?='' OR "
                    "asset_id=?) ORDER BY id LIMIT ?",
                    (policy.engagement_id, after, asset_id, asset_id, limit),
                ).fetchall()
            ]

    def set_service_state(
        self, policy: EngagementPolicy, service_id: str, state: str, expected_revision: int
    ) -> dict[str, Any]:
        if state not in {"active", "retired"} or type(expected_revision) is not int:
            raise ValueError("invalid_inventory_state")
        with self.store.transaction() as db:
            self._fence(db, policy)
            row = db.execute(
                "SELECT * FROM rj_service WHERE engagement=? AND id=?",
                (policy.engagement_id, service_id),
            ).fetchone()
            if row is None:
                raise PolicyDenied("inventory_service_access_denied")
            if row["revision"] != expected_revision:
                raise InventoryConflictError("stale_inventory_revision")
            db.execute(
                "UPDATE rj_service SET state=?,revision=revision+1,updated_at=? WHERE id=?",
                (state, time.time(), service_id),
            )
            return dict(db.execute("SELECT * FROM rj_service WHERE id=?", (service_id,)).fetchone())

    def backfill_surfaces(
        self, policy: EngagementPolicy, *, limit: int = 64, after: str = ""
    ) -> dict[str, Any]:
        """Explicit bounded legacy migration; existing payloads and IDs stay intact."""
        self._page(limit, after)
        with self.store.transaction() as db:
            self._fence(db, policy)
            rows = db.execute(
                "SELECT id,payload FROM rj_surface WHERE engagement=? AND id>? ORDER BY id LIMIT ?",
                (policy.engagement_id, after, limit),
            ).fetchall()
            from redjohn.assessment.models import Surface  # noqa: PLC0415 - runtime migration model

            for row in rows:
                self.attach_surface(
                    db, policy.engagement_id, row["id"], Surface(**json.loads(row["payload"]))
                )
        return {
            "migrated": len(rows),
            "after": rows[-1]["id"] if rows else after,
            "page_full": len(rows) == limit,
        }

    def observations(
        self, policy: EngagementPolicy, entity_id: str, *, limit: int = 50, after: str = ""
    ) -> list[dict[str, Any]]:
        self._page(limit, after)
        with self.store._lock:
            db = self.store.db
            self._fence(db, policy)
            if not db.execute(
                "SELECT 1 FROM rj_asset WHERE engagement=? AND id=? UNION ALL "
                "SELECT 1 FROM rj_service WHERE engagement=? AND id=?",
                (policy.engagement_id, entity_id, policy.engagement_id, entity_id),
            ).fetchone():
                raise PolicyDenied("inventory_entity_access_denied")
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM rj_inventory_observation WHERE engagement=? AND "
                    "entity_id=? AND id>? ORDER BY id LIMIT ?",
                    (policy.engagement_id, entity_id, after, limit),
                ).fetchall()
            ]

    def attach_surface(
        self, db: sqlite3.Connection, engagement: str, surface_id: str, surface: Surface
    ) -> None:
        """Atomic additive metadata hook; never changes Surface.key or job IDs."""
        row = db.execute("SELECT policy FROM rj_engagement WHERE id=?", (engagement,)).fetchone()
        if row is None:
            raise PolicyDenied("inventory_engagement_missing")

        policy = EngagementPolicy.from_mapping(json.loads(row[0]))
        if getattr(surface, "resource_kind", "") == "source_artifact":
            self.require_source_asset(policy, surface.asset_ref, surface.artifact_sha256)
            asset_id, service_id = surface.asset_ref, None
        else:
            references = (surface.request_ref,) if surface.request_ref else ()
            valid = all(
                db.execute(
                    "SELECT 1 FROM rj_evidence WHERE engagement=? AND id=?", (engagement, ref)
                ).fetchone()
                for ref in references
            )
            # Historical observed surfaces without provenance remain readable;
            # do not turn their old label into a new observed asset assertion.
            source = (
                surface.source
                if valid and (references or surface.source != "observed")
                else "inferred"
            )
            references = references if valid else ()
            asset_id = self._asset(
                db,
                policy,
                kind="http_origin",
                locator=origin_for(surface.url),
                source=source,
                evidence_refs=references,
            )
            parsed = urlsplit(surface.url)
            service_id = self._service(
                db,
                policy,
                asset_id,
                parsed.scheme,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                source,
                references,
            )
        if not db.execute(
            "SELECT 1 FROM rj_inventory_surface WHERE engagement=? AND surface_id=?",
            (engagement, surface_id),
        ).fetchone():
            self._quota(db, "rj_inventory_surface", engagement, self.limits.surface_links)
            db.execute(
                "INSERT INTO rj_inventory_surface VALUES(?,?,?,?)",
                (engagement, surface_id, asset_id, service_id),
            )

    def require_surface_active(
        self, db: sqlite3.Connection, policy: EngagementPolicy, surface_id: str
    ) -> None:
        row = db.execute(
            "SELECT a.state asset_state,s.state service_state FROM "
            "rj_inventory_surface l JOIN rj_asset a ON a.id=l.asset_id LEFT JOIN "
            "rj_service s ON s.id=l.service_id WHERE l.engagement=? AND "
            "l.surface_id=?",
            (policy.engagement_id, surface_id),
        ).fetchone()
        if row and (row["asset_state"] != "active" or row["service_state"] not in {None, "active"}):
            raise PolicyDenied("retired_inventory_resource")

    def register_workflow(self, policy: EngagementPolicy, definition: WorkflowDefinition) -> str:
        for step in definition.steps:
            step.authorize(policy)
        identity = stable_key([policy.engagement_id, definition.name, definition.revision])
        encoded = json.dumps(asdict(definition), sort_keys=True, separators=(",", ":"))
        with self.store.transaction() as db:
            self._fence(db, policy)
            old = db.execute(
                "SELECT payload,policy_revision FROM rj_workflow_definition WHERE id=?", (identity,)
            ).fetchone()
            if old and (old[0] != encoded or old[1] != policy.revision):
                raise InventoryConflictError("workflow_definition_revision_reuse_denied")
            if old is None:
                self._quota(
                    db,
                    "rj_workflow_definition",
                    policy.engagement_id,
                    self.limits.workflow_definitions,
                )
                db.execute(
                    "INSERT INTO rj_workflow_definition VALUES(?,?,?,?,?,?)",
                    (
                        identity,
                        policy.engagement_id,
                        policy.revision,
                        definition.name,
                        definition.revision,
                        encoded,
                    ),
                )
        return identity

    def _definition(
        self, db: sqlite3.Connection, policy: EngagementPolicy, identity: str
    ) -> WorkflowDefinition:
        row = db.execute(
            "SELECT payload FROM rj_workflow_definition WHERE engagement=? AND "
            "policy_revision=? AND id=?",
            (policy.engagement_id, policy.revision, identity),
        ).fetchone()
        if row is None:
            raise PolicyDenied("workflow_definition_access_denied")
        return WorkflowDefinition.from_mapping(json.loads(row[0]))

    def _history(
        self,
        db: sqlite3.Connection,
        policy: EngagementPolicy,
        identity: str,
        action: str,
        payload: dict[str, Any],
    ) -> None:
        encoded = json.dumps(payload, separators=(",", ":"))
        if len(encoded.encode()) > 8192:
            raise ValueError("workflow_history_payload_limit")
        self._quota(db, "rj_workflow_history", policy.engagement_id, self.limits.workflow_history)
        db.execute(
            "INSERT INTO "
            "rj_workflow_history(engagement,instance_id,action,at,payload) "
            "VALUES(?,?,?,?,?)",
            (policy.engagement_id, identity, action, time.time(), encoded),
        )

    def definitions(
        self, policy: EngagementPolicy, *, limit: int = 50, after: str = ""
    ) -> list[dict[str, Any]]:
        self._page(limit, after)
        with self.store._lock:
            self._fence(self.store.db, policy)
            rows = self.store.db.execute(
                "SELECT id,payload FROM rj_workflow_definition WHERE engagement=? "
                "AND policy_revision=? AND id>? ORDER BY id LIMIT ?",
                (policy.engagement_id, policy.revision, after, limit),
            ).fetchall()
        return [{"id": row["id"], **json.loads(row["payload"])} for row in rows]

    def start_workflow(
        self,
        policy: EngagementPolicy,
        definition_id: str,
        *,
        instance_key: str,
        actor_id: str,
        tenant_id: str = "",
        session_revision: str = "1",
    ) -> str:
        for value in (instance_key, actor_id, session_revision):
            bounded_name(value)
        bounded_name(tenant_id, empty=True)
        policy.check_actor(actor_id)
        identity = stable_key(
            [policy.engagement_id, definition_id, instance_key, actor_id, tenant_id]
        )
        with self.store.transaction() as db:
            self._fence(db, policy)
            state = db.execute(
                "SELECT revision,status FROM rj_session_state WHERE engagement=? AND "
                "actor=? AND tenant=? AND policy_revision=?",
                (policy.engagement_id, actor_id, tenant_id, policy.revision),
            ).fetchone()
            if state and (state["status"] != "ready" or state["revision"] != session_revision):
                raise InventoryConflictError("workflow_session_not_current_and_ready")
            definition = self._definition(db, policy, definition_id)
            if not db.execute(
                "SELECT 1 FROM rj_workflow_instance WHERE id=?", (identity,)
            ).fetchone():
                self._quota(
                    db, "rj_workflow_instance", policy.engagement_id, self.limits.workflow_instances
                )
                now = time.time()
                db.execute(
                    "INSERT INTO rj_workflow_instance VALUES(?,?,?,?,?,?,?,?,?,'active',1,?,?)",
                    (
                        identity,
                        policy.engagement_id,
                        definition_id,
                        instance_key,
                        actor_id,
                        tenant_id,
                        session_revision,
                        policy.revision,
                        definition.initial_state,
                        now,
                        now,
                    ),
                )
                self._history(
                    db,
                    policy,
                    identity,
                    "started",
                    {
                        "definition_id": definition_id,
                        "actor_id": actor_id,
                        "tenant_id": tenant_id,
                        "session_revision": session_revision,
                    },
                )
            else:
                existing = self._instance(db, policy, identity)
                if existing["session_revision"] != session_revision:
                    raise InventoryConflictError("workflow_session_revision_changed")
        return identity

    def _instance(
        self, db: sqlite3.Connection, policy: EngagementPolicy, identity: str
    ) -> sqlite3.Row:
        row = db.execute(
            "SELECT * FROM rj_workflow_instance WHERE engagement=? AND policy_revision=? AND id=?",
            (policy.engagement_id, policy.revision, identity),
        ).fetchone()
        if row is None:
            raise PolicyDenied("workflow_instance_access_denied")
        policy.check_actor(row["actor"])
        return cast("sqlite3.Row", row)

    def workflow(self, policy: EngagementPolicy, instance_id: str) -> dict[str, Any]:
        with self.store._lock:
            self._fence(self.store.db, policy)
            result = dict(self._instance(self.store.db, policy, instance_id))
            lease = self.store.db.execute(
                "SELECT lease_ref,step,surface_id,instance_revision,phase,expires_at "
                "FROM rj_workflow_lease WHERE instance_id=?",
                (instance_id,),
            ).fetchone()
            result["active_lease"] = dict(lease) if lease else None
            return result

    def workflows(
        self,
        policy: EngagementPolicy,
        *,
        actor_id: str = "",
        tenant_id: str = "",
        limit: int = 50,
        after: str = "",
    ) -> list[dict[str, Any]]:
        self._page(limit, after)
        if actor_id:
            policy.check_actor(actor_id)
        bounded_name(tenant_id, empty=True)
        with self.store._lock:
            self._fence(self.store.db, policy)
            return [
                dict(row)
                for row in self.store.db.execute(
                    "SELECT * FROM rj_workflow_instance WHERE engagement=? AND "
                    "policy_revision=? AND id>? AND (?='' OR actor=?) AND (?='' OR "
                    "tenant=?) ORDER BY id LIMIT ?",
                    (
                        policy.engagement_id,
                        policy.revision,
                        after,
                        actor_id,
                        actor_id,
                        tenant_id,
                        tenant_id,
                        limit,
                    ),
                ).fetchall()
            ]

    @staticmethod
    def _session(
        db: sqlite3.Connection,
        policy: EngagementPolicy,
        instance: sqlite3.Row,
        revision: str | None = None,
    ) -> None:
        state = db.execute(
            "SELECT revision,status FROM rj_session_state WHERE engagement=? AND "
            "actor=? AND tenant=? AND policy_revision=?",
            (policy.engagement_id, instance["actor"], instance["tenant"], policy.revision),
        ).fetchone()
        if state and (
            state["status"] != "ready"
            or state["revision"] != (revision or instance["session_revision"])
        ):
            raise InventoryConflictError("workflow_session_not_current_and_ready")

    def claim_step(
        self,
        policy: EngagementPolicy,
        instance_id: str,
        step_name: str,
        surface_id: str,
        *,
        expected_revision: int,
        owner: str,
        seconds: float = 30,
    ) -> dict[str, Any]:
        bounded_name(owner)
        lease_seconds(seconds)
        if type(expected_revision) is not int:
            raise ValueError("invalid_workflow_revision")
        with self.store.transaction() as db:
            self._fence(db, policy)
            instance = self._instance(db, policy, instance_id)
            if instance["revision"] != expected_revision or instance["status"] != "active":
                raise InventoryConflictError("stale_or_terminal_workflow")
            self._session(db, policy, instance)
            step = self._definition(db, policy, instance["definition_id"]).step(step_name)
            step.authorize(policy)
            surface = self.store.surface(policy.engagement_id, surface_id)
            self.require_surface_active(db, policy, surface_id)
            if (
                step.from_state != instance["state"]
                or (
                    surface.url,
                    surface.method,
                    surface.actor_id,
                    surface.tenant_id,
                    surface.session_revision,
                )
                != (
                    step.url,
                    step.method,
                    instance["actor"],
                    instance["tenant"],
                    instance["session_revision"],
                )
                or surface.source == "inferred"
                or (surface.source == "imported" and surface.workflow_state != "approved_seed")
            ):
                raise PolicyDenied("workflow_surface_or_context_mismatch")
            old = db.execute(
                "SELECT * FROM rj_workflow_lease WHERE instance_id=?", (instance_id,)
            ).fetchone()
            if old and (old["phase"] != "prepared" or old["expires_at"] > time.time()):
                raise InventoryConflictError("workflow_busy_or_reconciliation_required")
            lease = {
                "instance_id": instance_id,
                "lease_ref": uuid.uuid4().hex,
                "owner": owner,
                "step": step_name,
                "surface_id": surface_id,
                "instance_revision": expected_revision,
                "phase": "prepared",
                "expires_at": time.time() + seconds,
            }
            db.execute(
                "INSERT OR REPLACE INTO rj_workflow_lease VALUES(?,?,?,?,?,?,?,?)",
                tuple(lease.values()),
            )
            self._history(
                db,
                policy,
                instance_id,
                "step_claimed",
                {
                    "step": step_name,
                    "surface_id": surface_id,
                    "instance_revision": expected_revision,
                },
            )
            return lease

    def _lease(
        self,
        db: sqlite3.Connection,
        policy: EngagementPolicy,
        instance_id: str,
        lease_ref: str,
        owner: str,
        *,
        unexpired: bool = True,
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        self._fence(db, policy)
        instance = self._instance(db, policy, instance_id)
        lease = db.execute(
            "SELECT * FROM rj_workflow_lease WHERE instance_id=? AND lease_ref=? AND owner=?",
            (instance_id, lease_ref, owner),
        ).fetchone()
        if (
            lease is None
            or lease["instance_revision"] != instance["revision"]
            or (unexpired and lease["expires_at"] <= time.time())
        ):
            raise InventoryConflictError("stale_workflow_lease")
        self._session(db, policy, instance)
        return instance, lease

    def mark_sent(
        self, policy: EngagementPolicy, instance_id: str, lease_ref: str, *, owner: str
    ) -> None:
        with self.store.transaction() as db:
            _instance, lease = self._lease(db, policy, instance_id, lease_ref, owner)
            if lease["phase"] != "prepared":
                raise InventoryConflictError("workflow_request_already_admitted")
            db.execute(
                "UPDATE rj_workflow_lease SET phase='inflight' WHERE instance_id=?", (instance_id,)
            )
            self._history(
                db,
                policy,
                instance_id,
                "request_admitted",
                {"step": lease["step"], "surface_id": lease["surface_id"]},
            )

    def record_http_outcome(
        self,
        policy: EngagementPolicy,
        instance_id: str,
        lease_ref: str,
        *,
        owner: str,
        status: int,
        response_sha256: str,
        assertion_passed: bool,
        reconciliation: bool = False,
    ) -> str:
        """Trusted response-producer seam; not exposed as a public control op."""
        if (
            type(status) is not int
            or not 100 <= status <= 599
            or type(assertion_passed) is not bool
            or canonical_asset_locator("source_artifact", response_sha256)
            != "sha256:" + response_sha256
        ):
            raise ValueError("invalid_workflow_http_outcome")
        with self.store._lock:
            instance, lease = self._lease(
                self.store.db, policy, instance_id, lease_ref, owner, unexpired=not reconciliation
            )
            if lease["phase"] != "inflight":
                raise InventoryConflictError("workflow_request_not_admitted")
            payload = {
                "instance_id": instance_id,
                "instance_revision": instance["revision"],
                "step": lease["step"],
                "surface_id": lease["surface_id"],
                "actor_id": instance["actor"],
                "tenant_id": instance["tenant"],
                "session_revision": instance["session_revision"],
                "policy_revision": policy.revision,
                "lease_ref": lease_ref,
                "response_complete": True,
                "status": status,
                "response_sha256": response_sha256,
                "assertion_passed": assertion_passed,
            }
        return self.store.evidence_put(policy.engagement_id, payload, kind="workflow_http_outcome")

    def complete_step(
        self,
        policy: EngagementPolicy,
        instance_id: str,
        lease_ref: str,
        evidence_ref: str,
        *,
        owner: str,
        reconciliation: bool = False,
    ) -> dict[str, Any]:
        with self.store.transaction() as db:
            instance, lease = self._lease(
                db, policy, instance_id, lease_ref, owner, unexpired=not reconciliation
            )
            if lease["phase"] != "inflight":
                raise InventoryConflictError("workflow_request_not_admitted")
            row = db.execute(
                "SELECT payload FROM rj_evidence WHERE engagement=? AND id=? AND "
                "kind='workflow_http_outcome'",
                (policy.engagement_id, evidence_ref),
            ).fetchone()
            if row is None:
                raise PolicyDenied("workflow_outcome_evidence_required")
            outcome = json.loads(row[0])
            expected = {
                "instance_id": instance_id,
                "instance_revision": instance["revision"],
                "step": lease["step"],
                "surface_id": lease["surface_id"],
                "actor_id": instance["actor"],
                "tenant_id": instance["tenant"],
                "session_revision": instance["session_revision"],
                "policy_revision": policy.revision,
                "lease_ref": lease_ref,
                "response_complete": True,
                "assertion_passed": True,
            }
            definition = self._definition(db, policy, instance["definition_id"])
            step = definition.step(lease["step"])
            if (
                not isinstance(outcome, dict)
                or any(outcome.get(key) != value for key, value in expected.items())
                or outcome.get("status") not in step.expected_statuses
            ):
                raise InventoryConflictError("workflow_outcome_did_not_validate")
            status = "completed" if step.to_state in definition.terminal_states else "active"
            db.execute(
                "UPDATE rj_workflow_instance SET "
                "state=?,status=?,revision=revision+1,updated_at=? WHERE id=?",
                (step.to_state, status, time.time(), instance_id),
            )
            db.execute("DELETE FROM rj_workflow_lease WHERE instance_id=?", (instance_id,))
            self._history(
                db,
                policy,
                instance_id,
                "step_completed",
                {
                    "step": step.name,
                    "from_state": step.from_state,
                    "to_state": step.to_state,
                    "evidence_ref": evidence_ref,
                },
            )
        return self.workflow(policy, instance_id)

    def release_prepared_step(
        self, policy: EngagementPolicy, instance_id: str, lease_ref: str, *, owner: str
    ) -> dict[str, Any]:
        """Release only an unadmitted step. Inflight expiry never authorizes replay."""
        with self.store.transaction() as db:
            _instance, lease = self._lease(
                db, policy, instance_id, lease_ref, owner, unexpired=False
            )
            if lease["phase"] != "prepared":
                raise InventoryConflictError("inflight_workflow_requires_reconciliation")
            db.execute("DELETE FROM rj_workflow_lease WHERE instance_id=?", (instance_id,))
            self._history(
                db, policy, instance_id, "prepared_step_released", {"step": lease["step"]}
            )
        return self.workflow(policy, instance_id)

    def record_session_refresh_outcome(
        self, policy: EngagementPolicy, instance_id: str, refresh_key: str
    ) -> str:
        """Host-owned proof derived from a committed, fenced refresh transaction."""
        with self.store._lock:
            db = self.store.db
            self._fence(db, policy)
            instance = self._instance(db, policy, instance_id)
            refresh = db.execute(
                "SELECT to_revision,job_id FROM rj_session_refresh WHERE refresh_key=? "
                "AND engagement=? AND actor=? AND tenant=? AND policy_revision=? "
                "AND from_revision=? AND state='succeeded'",
                (
                    refresh_key,
                    policy.engagement_id,
                    instance["actor"],
                    instance["tenant"],
                    policy.revision,
                    instance["session_revision"],
                ),
            ).fetchone()
            if refresh is None:
                raise PolicyDenied("workflow_committed_refresh_required")
            self._session(db, policy, instance, refresh["to_revision"])
            payload = {
                "instance_id": instance_id,
                "refresh_key": refresh_key,
                "actor_id": instance["actor"],
                "tenant_id": instance["tenant"],
                "from_revision": instance["session_revision"],
                "session_revision": refresh["to_revision"],
                "policy_revision": policy.revision,
                "job_id": refresh["job_id"],
            }
        return self.store.evidence_put(
            policy.engagement_id, payload, kind="workflow_session_refresh"
        )

    def refresh_workflow_session(
        self,
        policy: EngagementPolicy,
        instance_id: str,
        *,
        expected_revision: int,
        session_revision: str,
        evidence_ref: str,
    ) -> dict[str, Any]:
        bounded_name(session_revision)
        with self.store.transaction() as db:
            self._fence(db, policy)
            instance = self._instance(db, policy, instance_id)
            if instance["revision"] != expected_revision or instance["status"] != "active":
                raise InventoryConflictError("stale_or_terminal_workflow")
            if db.execute(
                "SELECT 1 FROM rj_workflow_lease WHERE instance_id=?", (instance_id,)
            ).fetchone():
                raise InventoryConflictError("workflow_busy_or_reconciliation_required")
            state = db.execute(
                "SELECT revision,status FROM rj_session_state WHERE engagement=? AND "
                "actor=? AND tenant=? AND policy_revision=?",
                (policy.engagement_id, instance["actor"], instance["tenant"], policy.revision),
            ).fetchone()
            if (
                not state
                or state["revision"] != session_revision
                or state["status"] != "ready"
                or session_revision == instance["session_revision"]
            ):
                raise InventoryConflictError("workflow_refresh_not_ready")
            evidence = db.execute(
                "SELECT payload FROM rj_evidence WHERE engagement=? AND id=? "
                "AND kind='workflow_session_refresh'",
                (policy.engagement_id, evidence_ref),
            ).fetchone()
            proof = json.loads(evidence[0]) if evidence else {}
            expected = {
                "instance_id": instance_id,
                "actor_id": instance["actor"],
                "tenant_id": instance["tenant"],
                "policy_revision": policy.revision,
                "from_revision": instance["session_revision"],
                "session_revision": session_revision,
            }
            if (
                not isinstance(proof, dict)
                or any(proof.get(key) != value for key, value in expected.items())
                or not db.execute(
                    "SELECT 1 FROM rj_session_refresh WHERE refresh_key=? AND engagement=? "
                    "AND actor=? AND tenant=? AND policy_revision=? AND from_revision=? "
                    "AND to_revision=? AND state='succeeded'",
                    (
                        proof.get("refresh_key"),
                        policy.engagement_id,
                        instance["actor"],
                        instance["tenant"],
                        policy.revision,
                        instance["session_revision"],
                        session_revision,
                    ),
                ).fetchone()
            ):
                raise PolicyDenied("workflow_committed_refresh_evidence_required")
            db.execute(
                "UPDATE rj_workflow_instance SET "
                "session_revision=?,revision=revision+1,updated_at=? WHERE id=?",
                (session_revision, time.time(), instance_id),
            )
            self._history(
                db,
                policy,
                instance_id,
                "session_refreshed",
                {
                    "old_revision": instance["session_revision"],
                    "session_revision": session_revision,
                    "evidence_ref": evidence_ref,
                },
            )
        return self.workflow(policy, instance_id)

    def history(
        self, policy: EngagementPolicy, instance_id: str, *, limit: int = 50, after: int = 0
    ) -> list[dict[str, Any]]:
        self._page(limit, after)
        if type(after) is not int or after < 0:
            raise ValueError("invalid_workflow_history_cursor")
        with self.store._lock:
            self._fence(self.store.db, policy)
            self._instance(self.store.db, policy, instance_id)
            rows = self.store.db.execute(
                "SELECT * FROM rj_workflow_history WHERE engagement=? AND "
                "instance_id=? AND id>? ORDER BY id LIMIT ?",
                (policy.engagement_id, instance_id, after, limit),
            ).fetchall()
        return [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]

    def control_call(  # noqa: PLR0912 - fixed typed operation boundary
        self, policy: EngagementPolicy, operation: str, arguments: dict[str, Any], *, owner: str
    ) -> dict[str, Any]:
        """Small owner-bound API. Definitions and response evidence stay host-owned."""
        handlers: dict[str, tuple[Callable[..., Any], set[str], set[str]]] = {
            "asset_search": (self.assets, set(), {"limit", "after", "kind", "source"}),
            "asset_get": (self.asset, {"asset_id"}, {"asset_id"}),
            "asset_set_state": (
                self.set_asset_state,
                {"asset_id", "state", "expected_revision"},
                {"asset_id", "state", "expected_revision"},
            ),
            "service_search": (self.services, set(), {"asset_id", "limit", "after"}),
            "service_set_state": (
                self.set_service_state,
                {"service_id", "state", "expected_revision"},
                {"service_id", "state", "expected_revision"},
            ),
            "inventory_observations": (
                self.observations,
                {"entity_id"},
                {"entity_id", "limit", "after"},
            ),
            "inventory_backfill": (self.backfill_surfaces, set(), {"limit", "after"}),
            "workflow_definition_search": (self.definitions, set(), {"limit", "after"}),
            "workflow_search": (self.workflows, set(), {"actor_id", "tenant_id", "limit", "after"}),
            "workflow_get": (self.workflow, {"instance_id"}, {"instance_id"}),
            "workflow_history": (self.history, {"instance_id"}, {"instance_id", "limit", "after"}),
            "workflow_start": (
                self.start_workflow,
                {"definition_id", "instance_key", "actor_id"},
                {"definition_id", "instance_key", "actor_id", "tenant_id", "session_revision"},
            ),
            "workflow_claim_step": (
                self.claim_step,
                {"instance_id", "step_name", "surface_id", "expected_revision"},
                {"instance_id", "step_name", "surface_id", "expected_revision", "seconds"},
            ),
            "workflow_mark_sent": (
                self.mark_sent,
                {"instance_id", "lease_ref"},
                {"instance_id", "lease_ref"},
            ),
            "workflow_complete_step": (
                self.complete_step,
                {"instance_id", "lease_ref", "evidence_ref"},
                {"instance_id", "lease_ref", "evidence_ref"},
            ),
            "workflow_reconcile_step": (
                self.complete_step,
                {"instance_id", "lease_ref", "evidence_ref"},
                {"instance_id", "lease_ref", "evidence_ref"},
            ),
            "workflow_release_prepared": (
                self.release_prepared_step,
                {"instance_id", "lease_ref"},
                {"instance_id", "lease_ref"},
            ),
            "workflow_refresh_session": (
                self.refresh_workflow_session,
                {"instance_id", "expected_revision", "session_revision", "evidence_ref"},
                {"instance_id", "expected_revision", "session_revision", "evidence_ref"},
            ),
        }
        if operation not in handlers:
            raise ValueError("unsupported_inventory_operation")
        handler, required, allowed = handlers[operation]
        if not required <= set(arguments) or set(arguments) - allowed:
            raise ValueError("invalid_inventory_api_fields")
        values = dict(arguments)
        for key, value in values.items():
            if key == "after" and operation == "workflow_history":
                if type(value) is not int or value < 0:
                    raise ValueError("invalid_workflow_history_cursor")
            elif key in {"limit", "expected_revision"}:
                if type(value) is not int or value < 1:
                    raise ValueError("invalid_inventory_api_integer")
            elif key == "seconds":
                if type(value) not in {int, float}:
                    raise ValueError("invalid_workflow_lease_duration")
            elif not isinstance(value, str) or len(value) > 128:
                raise ValueError("invalid_inventory_api_string")
        if operation in {
            "workflow_claim_step",
            "workflow_mark_sent",
            "workflow_complete_step",
            "workflow_reconcile_step",
            "workflow_release_prepared",
        }:
            values["owner"] = owner
        if operation == "workflow_reconcile_step":
            values["reconciliation"] = True
        response = handler(policy, **values)
        if isinstance(response, dict):
            return response
        if isinstance(response, list):
            return {"items": response}
        if isinstance(response, str):
            return {"instance_id": response}
        return {"recorded": True}
