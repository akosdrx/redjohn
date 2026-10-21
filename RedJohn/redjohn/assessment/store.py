"""Additive rj_* SQLite tables in the existing .state/agents.db database.

The SDK's session tables and existing JSON reports are left intact. All reads are
indexed and paged; evidence never enters the cache and cannot be evicted by LRU.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager, suppress
from dataclasses import asdict, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from redjohn.assessment.inventory import InventoryRepository
from redjohn.assessment.models import (
    AdapterResult,
    JobSpec,
    Surface,
    error_record,
    stable_key,
)
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied


if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping


_SECRET = re.compile(
    r"^(?:authorization|proxy-authorization|set-cookie|cookie|token|password|passwd|secret|"
    r"(?:access|refresh|id|session|auth)[_-]?token|api[_-]?key|client[_-]?secret|"
    r"sid|session|sessionid|credential|bearer)$",
    re.I,
)
_URL = re.compile(r"https?://[^\s\"'<>]+")
_HEADER_SECRET = re.compile(
    r"(?im)(^|\n)(authorization|proxy-authorization|cookie|set-cookie):[^\r\n]*"
)


def _redact_url(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        parsed = urlsplit(value)
        query = "&".join(
            item.partition("=")[0] + "=%5Bredacted%5D"
            if _SECRET.search(unquote_plus(item.partition("=")[0]))
            else item
            for item in parsed.query.split("&")
        )
        netloc = parsed.netloc.split("@")[-1] if "@" in parsed.netloc else parsed.netloc
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))
    except ValueError:
        return "[redacted-invalid-url]"


def redact(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(k): "[redacted]" if _SECRET.search(str(k)) else redact(v) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _HEADER_SECRET.sub(r"\1\2: [redacted]", _URL.sub(_redact_url, value))
    return value


def json_text(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


class CapacityExceeded(RuntimeError):  # noqa: N818 - public compatibility name
    code = "queue_capacity_exhausted"


class EvidenceWriteError(RuntimeError):
    code = "evidence_write_failed"


class AssessmentStore:
    def __init__(
        self,
        path: Path,
        *,
        queue_max_items: int = 128,
        artifact_max_bytes: int = 4 * 1024 * 1024,
        evidence_quota_bytes: int = 128 * 1024 * 1024,
        max_findings: int = 10000,
        max_audit_rows: int = 10000,
        max_sessions: int = 256,
        max_capture_rows: int = 2048,
        max_followup_events: int = 4096,
        max_surfaces: int = 10000,
    ) -> None:
        if min(
            queue_max_items,
            artifact_max_bytes,
            evidence_quota_bytes,
            max_findings,
            max_audit_rows,
            max_sessions,
            max_capture_rows,
            max_followup_events,
            max_surfaces,
        ) <= 0:
            raise ValueError("invalid_store_limits")
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = path
        self.queue_max_items, self.artifact_max_bytes = queue_max_items, artifact_max_bytes
        self.evidence_quota_bytes = evidence_quota_bytes
        self.max_findings = max_findings
        self.max_audit_rows = max_audit_rows
        self.max_sessions = max_sessions
        self.max_capture_rows = max_capture_rows
        self.max_followup_events = max_followup_events
        self.max_surfaces = max_surfaces
        self._retention_pruned = {
            "findings": 0,
            "audit": 0,
            "sessions": 0,
            "captures": 0,
            "followups": 0,
            "surfaces": 0,
        }
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=10000")
        path.chmod(0o600)
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS rj_schema(version INTEGER PRIMARY KEY);
        INSERT OR IGNORE INTO rj_schema VALUES(1);
        CREATE TABLE IF NOT EXISTS rj_engagement(
          id TEXT PRIMARY KEY, owner TEXT NOT NULL, revision TEXT NOT NULL,
          policy TEXT NOT NULL, retries_used INTEGER NOT NULL DEFAULT 0,
          requests_used INTEGER NOT NULL DEFAULT 0, stopped INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS rj_policy_history(
          engagement TEXT NOT NULL, revision TEXT NOT NULL, policy TEXT NOT NULL,
          PRIMARY KEY(engagement,revision));
        CREATE TABLE IF NOT EXISTS rj_surface(
          id TEXT PRIMARY KEY, engagement TEXT NOT NULL REFERENCES rj_engagement(id),
          surface_key TEXT NOT NULL, payload TEXT NOT NULL, observed_at REAL NOT NULL,
          UNIQUE(engagement,surface_key));
        CREATE INDEX IF NOT EXISTS rj_surface_engagement ON rj_surface(engagement,id);
        CREATE TABLE IF NOT EXISTS rj_job(
          id TEXT PRIMARY KEY, engagement TEXT NOT NULL REFERENCES rj_engagement(id),
          job_key TEXT NOT NULL, surface_id TEXT NOT NULL REFERENCES rj_surface(id),
          family TEXT NOT NULL, capability TEXT NOT NULL, priority REAL NOT NULL,
          spec TEXT NOT NULL, execution_status TEXT NOT NULL DEFAULT 'queued',
          coverage_status TEXT NOT NULL DEFAULT 'not_tested',
          attempt INTEGER NOT NULL DEFAULT 0, owner TEXT, lease_until REAL,
          ready_at REAL NOT NULL DEFAULT 0, created_at REAL NOT NULL,
          started_at REAL, ended_at REAL, result TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0,
          UNIQUE(engagement,job_key));
        CREATE INDEX IF NOT EXISTS rj_job_queue
          ON rj_job(engagement,execution_status,ready_at,family);
        CREATE INDEX IF NOT EXISTS rj_job_capability
          ON rj_job(engagement,capability,created_at,id);
        CREATE TABLE IF NOT EXISTS rj_attempt(
          job_id TEXT NOT NULL REFERENCES rj_job(id), number INTEGER NOT NULL,
          owner TEXT NOT NULL, started_at REAL NOT NULL, ended_at REAL,
          execution_status TEXT NOT NULL, error TEXT, PRIMARY KEY(job_id,number));
        CREATE TABLE IF NOT EXISTS rj_fairness(
          engagement TEXT NOT NULL, family TEXT NOT NULL, served INTEGER NOT NULL,
          PRIMARY KEY(engagement,family));
        CREATE TABLE IF NOT EXISTS rj_planner_state(
          engagement TEXT PRIMARY KEY, surface_cursor TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS rj_evidence(
          id TEXT PRIMARY KEY, engagement TEXT NOT NULL REFERENCES rj_engagement(id),
          job_id TEXT, digest TEXT NOT NULL, bytes INTEGER NOT NULL, payload BLOB NOT NULL,
          created_at REAL NOT NULL, kind TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS rj_evidence_engagement ON rj_evidence(engagement,id);
        CREATE TABLE IF NOT EXISTS rj_finding(
          id TEXT PRIMARY KEY, engagement TEXT NOT NULL, job_id TEXT NOT NULL,
          status TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(job_id,id));
        CREATE INDEX IF NOT EXISTS rj_finding_engagement ON rj_finding(engagement,id);
        CREATE INDEX IF NOT EXISTS rj_evidence_identity ON rj_evidence(engagement,kind,digest);
        CREATE TABLE IF NOT EXISTS rj_audit(
          sequence INTEGER PRIMARY KEY AUTOINCREMENT, engagement TEXT NOT NULL,
          event_key TEXT UNIQUE, action TEXT NOT NULL, at REAL NOT NULL, payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS rj_audit_engagement ON rj_audit(engagement,sequence);
        CREATE TABLE IF NOT EXISTS rj_network_usage(
          engagement TEXT PRIMARY KEY REFERENCES rj_engagement(id),used INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS rj_session_state(
          engagement TEXT NOT NULL REFERENCES rj_engagement(id), actor TEXT NOT NULL,
          tenant TEXT NOT NULL, policy_revision TEXT NOT NULL, revision TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'ready', refresh_key TEXT, updated_at REAL NOT NULL,
          PRIMARY KEY(engagement,actor,tenant,policy_revision));
        CREATE TABLE IF NOT EXISTS rj_session_refresh(
          refresh_key TEXT PRIMARY KEY, engagement TEXT NOT NULL REFERENCES rj_engagement(id),
          actor TEXT NOT NULL, tenant TEXT NOT NULL, policy_revision TEXT NOT NULL,
          from_revision TEXT NOT NULL, to_revision TEXT NOT NULL, job_id TEXT NOT NULL,
          owner TEXT NOT NULL, attempt INTEGER NOT NULL, state TEXT NOT NULL,
          error_code TEXT, created_at REAL NOT NULL, ended_at REAL);
        CREATE INDEX IF NOT EXISTS rj_session_refresh_job ON rj_session_refresh(job_id,state);
        CREATE TABLE IF NOT EXISTS rj_request_capture(
          capture_key TEXT PRIMARY KEY, engagement TEXT NOT NULL REFERENCES rj_engagement(id),
          policy_revision TEXT NOT NULL, surface_key TEXT NOT NULL, actor TEXT NOT NULL,
          tenant TEXT NOT NULL, session_revision TEXT NOT NULL, owner TEXT NOT NULL,
          lease_until REAL NOT NULL, state TEXT NOT NULL, admitted INTEGER NOT NULL DEFAULT 0,
          completed_surface_id TEXT, created_at REAL NOT NULL, ended_at REAL, error_code TEXT);
        CREATE INDEX IF NOT EXISTS rj_request_capture_active
          ON rj_request_capture(engagement,state,lease_until);
        CREATE TABLE IF NOT EXISTS rj_followup_event(
          id TEXT PRIMARY KEY, engagement TEXT NOT NULL REFERENCES rj_engagement(id),
          policy_revision TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE REFERENCES rj_job(id),
          capability TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
          created_at REAL NOT NULL, completed_at REAL, error_code TEXT,
          child_ids TEXT NOT NULL DEFAULT '[]',kind TEXT NOT NULL DEFAULT 'completion');
        CREATE INDEX IF NOT EXISTS rj_followup_pending
          ON rj_followup_event(engagement,policy_revision,state,id);
        CREATE TABLE IF NOT EXISTS rj_auth_recovery_budget(
          engagement TEXT NOT NULL REFERENCES rj_engagement(id), actor TEXT NOT NULL,
          tenant TEXT NOT NULL, policy_revision TEXT NOT NULL,
          refreshes_used INTEGER NOT NULL DEFAULT 0,last_queued_at REAL NOT NULL,
          PRIMARY KEY(engagement,actor,tenant,policy_revision));
        CREATE INDEX IF NOT EXISTS rj_auth_recovery_budget_policy
          ON rj_auth_recovery_budget(engagement,policy_revision,actor,tenant);
        CREATE TABLE IF NOT EXISTS rj_auth_recovery_job(
          engagement TEXT NOT NULL REFERENCES rj_engagement(id), actor TEXT NOT NULL,
          tenant TEXT NOT NULL, policy_revision TEXT NOT NULL,from_revision TEXT NOT NULL,
          job_id TEXT NOT NULL REFERENCES rj_job(id),created_at REAL NOT NULL,
          PRIMARY KEY(engagement,actor,tenant,policy_revision,from_revision));
        """)
        # Additive migration for existing completion-only outboxes. Keeping the
        # default preserves every previously committed continuation event.
        with self.transaction() as db:
            if "kind" not in {
                row["name"] for row in db.execute("PRAGMA table_info(rj_followup_event)")
            }:
                db.execute(
                    "ALTER TABLE rj_followup_event ADD COLUMN "
                    "kind TEXT NOT NULL DEFAULT 'completion'"
                )
        versions = [row[0] for row in self.db.execute("SELECT version FROM rj_schema")]
        if versions != [1]:
            raise ValueError("unsupported_assessment_schema")
        self.inventory = InventoryRepository(self)
        from redjohn.assessment.auth_flow_state import AuthFlowRepository  # noqa: PLC0415 - additive store extension

        self.auth_flows = AuthFlowRepository(self)

    def close(self) -> None:
        with self._lock:
            with suppress(sqlite3.Error):
                self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.close()

    @staticmethod
    def _capture_policy_fenced(db: sqlite3.Connection, policy: EngagementPolicy) -> bool:
        current = db.execute(
            "SELECT owner,revision,stopped,policy FROM rj_engagement WHERE id=?",
            (policy.engagement_id,),
        ).fetchone()
        return bool(
            current
            and current["owner"] == policy.owner_id
            and current["revision"] == policy.revision
            and not current["stopped"]
            and current["policy"] == json_text(policy.to_dict())
            and (not policy.deadline or time.time() < policy.deadline)
        )

    @staticmethod
    def _capture_session_ready(
        db: sqlite3.Connection, policy: EngagementPolicy, row: sqlite3.Row | Mapping[str, str]
    ) -> bool:
        current = db.execute(
            "SELECT revision,status FROM rj_session_state WHERE engagement=? AND actor=? "
            "AND tenant=? AND policy_revision=?",
            (policy.engagement_id, row["actor"], row["tenant"], policy.revision),
        ).fetchone()
        return not current or (
            current["status"] == "ready" and current["revision"] == row["session_revision"]
        )

    def reserve_capture(
        self, policy: EngagementPolicy, surface: Surface, *, timeout_seconds: float
    ) -> dict[str, Any]:
        """Reserve one mutating observation durably, without storing private bytes."""
        if (
            not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 15
            or surface.method != "POST"
            or surface.actor_id == "anonymous"
            or not surface.body_sha256
        ):
            raise PolicyDenied("capture_reservation_input_invalid")
        policy.check_actor(surface.actor_id)
        policy.check_replay_request(surface.url, surface.method)
        key = stable_key([policy.engagement_id, policy.revision, surface.key])
        owner, now = uuid.uuid4().hex, time.time()
        denied, completed = None, None
        with self.transaction() as db:
            if not self._capture_policy_fenced(db, policy):
                raise PolicyDenied("capture_policy_fence_denied")
            row = db.execute(
                "SELECT * FROM rj_request_capture WHERE capture_key=?", (key,)
            ).fetchone()
            if row:
                owner = row["owner"]
                if row["state"] == "succeeded":
                    completed = row["completed_surface_id"]
                elif row["state"] == "inflight" and row["lease_until"] <= now:
                    db.execute(
                        "UPDATE rj_request_capture SET state='uncertain',ended_at=?,"
                        "error_code='capture_unknown_execution_outcome' WHERE capture_key=?",
                        (now, key),
                    )
                    self._audit(
                        db,
                        policy.engagement_id,
                        "capture_outcome_uncertain",
                        {
                            "capture_key": key,
                            "admitted": bool(row["admitted"]),
                        },
                    )
                    denied = "capture_outcome_uncertain"
                else:
                    denied = (
                        "capture_in_progress"
                        if row["state"] == "inflight"
                        else ("capture_" + row["state"])
                    )
            else:
                session = {
                    "actor": surface.actor_id,
                    "tenant": surface.tenant_id,
                    "session_revision": surface.session_revision,
                }
                if not self._capture_session_ready(db, policy, session):
                    raise PolicyDenied("capture_session_not_ready")
                active = db.execute(
                    "SELECT count(*) FROM rj_request_capture WHERE engagement=? "
                    "AND state='inflight' AND lease_until>?",
                    (policy.engagement_id, now),
                ).fetchone()[0]
                if active >= self.queue_max_items:
                    raise CapacityExceeded("capture_capacity_exhausted")
                db.execute(
                    "INSERT INTO rj_request_capture "
                    "VALUES(?,?,?,?,?,?,?,?,?,'inflight',0,NULL,?,NULL,NULL)",
                    (
                        key,
                        policy.engagement_id,
                        policy.revision,
                        surface.key,
                        surface.actor_id,
                        surface.tenant_id,
                        surface.session_revision,
                        owner,
                        now + timeout_seconds + 5,
                        now,
                    ),
                )
                self._audit(db, policy.engagement_id, "capture_reserved", {"capture_key": key})
        if denied:
            raise PolicyDenied(denied)
        return {"key": key, "owner": owner, "completed_surface_id": completed}

    def mark_capture_admitted(self, policy: EngagementPolicy, key: str, owner: str) -> bool:
        """Fence and charge the engagement budget atomically immediately before send."""
        with self.transaction() as db:
            if not self._capture_policy_fenced(db, policy):
                return False
            row = db.execute(
                "SELECT * FROM rj_request_capture WHERE capture_key=? AND engagement=? "
                "AND policy_revision=? AND owner=? AND state='inflight' AND admitted=0 "
                "AND lease_until>?",
                (key, policy.engagement_id, policy.revision, owner, time.time()),
            ).fetchone()
            if not row or not self._capture_session_ready(db, policy, row):
                return False
            charged = db.execute(
                "UPDATE rj_engagement SET requests_used=requests_used+1 WHERE id=? "
                "AND stopped=0 AND requests_used<?",
                (policy.engagement_id, policy.request_budget),
            ).rowcount
            if not charged:
                raise CapacityExceeded("request_budget_exhausted")
            db.execute("UPDATE rj_request_capture SET admitted=1 WHERE capture_key=?", (key,))
            self._audit(db, policy.engagement_id, "capture_admitted", {"capture_key": key})
            return True

    def finish_capture(
        self, policy: EngagementPolicy, key: str, owner: str, observed_surface: Surface
    ) -> bool:
        """Commit verified sent-request metadata and inventory with the reservation."""
        with self.transaction() as db:
            if not self._capture_policy_fenced(db, policy):
                return False
            row = db.execute(
                "SELECT * FROM rj_request_capture WHERE capture_key=? AND engagement=? "
                "AND policy_revision=? AND owner=? AND state='inflight' AND admitted=1 "
                "AND lease_until>?",
                (key, policy.engagement_id, policy.revision, owner, time.time()),
            ).fetchone()
            if (
                not row
                or observed_surface.source != "observed"
                or row["surface_key"] != observed_surface.key
                or not self._capture_session_ready(db, policy, row)
            ):
                return False
            evidence = db.execute(
                "SELECT payload,bytes FROM rj_evidence WHERE id=? AND engagement=? "
                "AND kind='authenticated_request_metadata'",
                (observed_surface.request_ref, policy.engagement_id),
            ).fetchone()
            if not evidence or evidence["bytes"] > 16384:
                return False
            try:
                metadata = json.loads(evidence["payload"])
            except (ValueError, TypeError):
                return False
            expected = {
                "url": observed_surface.url,
                "method": "POST",
                "actor_id": observed_surface.actor_id,
                "tenant_id": observed_surface.tenant_id,
                "session_revision": observed_surface.session_revision,
                "policy_revision": policy.revision,
                "engagement_id": policy.engagement_id,
                "body_sha256": observed_surface.body_sha256,
                "sent": True,
                "response_complete": True,
            }
            if (
                not isinstance(metadata, dict)
                or any(metadata.get(field) != value for field, value in expected.items())
                or type(metadata.get("status")) is not int
                or not 200 <= metadata["status"] < 300
                or metadata.get("sent") is not True
                or metadata.get("response_complete") is not True
            ):
                return False
            surface_id = stable_key([policy.engagement_id, observed_surface.key])
            db.execute(
                "INSERT INTO rj_surface VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "payload=excluded.payload,observed_at=excluded.observed_at",
                (
                    surface_id,
                    policy.engagement_id,
                    observed_surface.key,
                    json_text(asdict(observed_surface)),
                    time.time(),
                ),
            )
            self.inventory.attach_surface(db, policy.engagement_id, surface_id, observed_surface)
            db.execute(
                "UPDATE rj_request_capture SET state='succeeded',completed_surface_id=?,ended_at=? "
                "WHERE capture_key=?",
                (surface_id, time.time(), key),
            )
            self._audit(
                db,
                policy.engagement_id,
                "capture_completed",
                {
                    "capture_key": key,
                    "surface_id": surface_id,
                },
            )
            return True

    def fail_capture(self, policy: EngagementPolicy, key: str, owner: str, code: str) -> None:
        if not re.fullmatch(r"[a-z_]{1,128}", code):
            raise ValueError("invalid_capture_failure_code")
        with self.transaction() as db:
            row = db.execute(
                "SELECT admitted FROM rj_request_capture WHERE capture_key=? AND engagement=? "
                "AND policy_revision=? AND owner=? AND state='inflight'",
                (key, policy.engagement_id, policy.revision, owner),
            ).fetchone()
            if not row:
                return
            state = "uncertain" if row["admitted"] else "blocked"
            db.execute(
                "UPDATE rj_request_capture SET state=?,error_code=?,ended_at=? WHERE capture_key=?",
                (state, code, time.time(), key),
            )
            self._audit(
                db,
                policy.engagement_id,
                "capture_failed",
                {
                    "capture_key": key,
                    "state": state,
                    "code": code,
                },
            )

    @staticmethod
    def _session_identity(policy: EngagementPolicy, surface: Surface) -> tuple[str, ...]:
        policy.check_actor(surface.actor_id)
        if surface.actor_id == "anonymous":
            raise PolicyDenied("session_refresh_named_actor_required")
        return policy.engagement_id, surface.actor_id, surface.tenant_id, policy.revision

    def assert_session_revision(self, policy: EngagementPolicy, surface: Surface) -> None:
        """Tracked sessions must be ready and exact; legacy untracked sessions pass."""
        identity = self._session_identity(policy, surface)
        with self.transaction() as db:
            row = db.execute(
                "SELECT revision,status FROM rj_session_state WHERE "
                "engagement=? AND actor=? AND tenant=? AND policy_revision=?",
                identity,
            ).fetchone()
            if row is None:
                return
            if row["revision"] != surface.session_revision:
                raise PolicyDenied("session_revision_superseded")
            if row["status"] != "ready":
                raise PolicyDenied("session_refresh_" + row["status"])

    def session_state(self, policy: EngagementPolicy, surface: Surface) -> dict[str, Any] | None:
        identity = self._session_identity(policy, surface)
        with self._lock:
            row = self.db.execute(
                "SELECT revision,status,refresh_key,updated_at FROM rj_session_state WHERE "
                "engagement=? AND actor=? AND tenant=? AND policy_revision=?",
                identity,
            ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _refresh_job_fenced(
        db: sqlite3.Connection, policy: EngagementPolicy, job: dict[str, Any]
    ) -> bool:
        current = db.execute(
            "SELECT owner,revision,stopped FROM rj_engagement WHERE id=?",
            (policy.engagement_id,),
        ).fetchone()
        return bool(
            current
            and current["owner"] == policy.owner_id
            and current["revision"] == policy.revision
            and not current["stopped"]
            and db.execute(
                "SELECT 1 FROM rj_job WHERE id=? AND engagement=? AND owner=? AND attempt=? "
                "AND execution_status='running' AND cancel_requested=0 AND lease_until>?",
                (job["id"], policy.engagement_id, job["owner"], job["attempt"], time.time()),
            ).fetchone()
        )

    def begin_session_refresh(
        self, policy: EngagementPolicy, job: dict[str, Any], surface: Surface
    ) -> dict[str, Any]:
        """One durable refresh reservation per identity and old numeric revision."""
        identity = self._session_identity(policy, surface)
        if not re.fullmatch(r"[1-9][0-9]{0,17}", surface.session_revision):
            raise PolicyDenied("session_refresh_numeric_revision_required")
        key = stable_key([*identity, surface.session_revision, "session_refresh_v1"])
        next_revision = str(int(surface.session_revision) + 1)
        with self.transaction() as db:
            if not self._refresh_job_fenced(db, policy, job):
                raise PolicyDenied("session_refresh_stale_lease")
            actual = db.execute(
                "SELECT j.spec,s.payload FROM rj_job j JOIN rj_surface s ON s.id=j.surface_id "
                "WHERE j.id=?",
                (job["id"],),
            ).fetchone()
            spec = json.loads(actual["spec"])
            if spec["capability"] != "session_refresh" or spec["idempotent"]:
                raise PolicyDenied("session_refresh_requires_nonidempotent_job")
            captured = Surface(**json.loads(actual["payload"]))
            if captured != surface:
                raise PolicyDenied("session_refresh_surface_mismatch")
            if db.execute(
                "SELECT 1 FROM rj_workflow_lease l JOIN rj_workflow_instance w "
                "ON w.id=l.instance_id WHERE w.engagement=? AND w.actor=? AND "
                "w.tenant=? AND w.policy_revision=? AND (l.phase='inflight' OR "
                "l.expires_at>?) LIMIT 1",
                (*identity, time.time()),
            ).fetchone():
                raise PolicyDenied("session_refresh_workflow_reconciliation_required")
            previous = db.execute(
                "SELECT state FROM rj_session_refresh WHERE refresh_key=?", (key,)
            ).fetchone()
            if previous:
                raise PolicyDenied("session_refresh_already_" + previous["state"])
            db.execute(
                "INSERT OR IGNORE INTO rj_session_state VALUES(?,?,?,?,?,'ready',NULL,?)",
                (*identity, surface.session_revision, time.time()),
            )
            changed = db.execute(
                "UPDATE rj_session_state SET status='refreshing',refresh_key=?,updated_at=? "
                "WHERE engagement=? AND actor=? AND tenant=? AND policy_revision=? "
                "AND revision=? AND status='ready'",
                (key, time.time(), *identity, surface.session_revision),
            ).rowcount
            if not changed:
                raise PolicyDenied("session_refresh_state_conflict")
            db.execute(
                "INSERT INTO rj_session_refresh VALUES(?,?,?,?,?,?,?,?,?,?,'inflight',NULL,?,NULL)",
                (
                    key,
                    *identity,
                    surface.session_revision,
                    next_revision,
                    job["id"],
                    job["owner"],
                    job["attempt"],
                    time.time(),
                ),
            )
            self._audit(
                db,
                policy.engagement_id,
                "session_refresh_started",
                {
                    "refresh_key": key,
                    "actor_id": surface.actor_id,
                    "tenant_id": surface.tenant_id,
                    "from_revision": surface.session_revision,
                    "to_revision": next_revision,
                    "job_id": job["id"],
                },
            )
        return {"refresh_key": key, "next_revision": next_revision}

    def finish_session_refresh(
        self, policy: EngagementPolicy, job: dict[str, Any], surface: Surface, refresh_key: str
    ) -> bool:
        identity = self._session_identity(policy, surface)
        with self.transaction() as db:
            if not self._refresh_job_fenced(db, policy, job):
                return False
            row = db.execute(
                "SELECT to_revision FROM rj_session_refresh WHERE refresh_key=? AND job_id=? "
                "AND owner=? AND attempt=? AND state='inflight'",
                (refresh_key, job["id"], job["owner"], job["attempt"]),
            ).fetchone()
            if not row:
                return False
            changed = db.execute(
                "UPDATE rj_session_state SET revision=?,status='ready',refresh_key=NULL,"
                "updated_at=? "
                "WHERE engagement=? AND actor=? AND tenant=? AND policy_revision=? "
                "AND revision=? AND refresh_key=? AND status='refreshing'",
                (row["to_revision"], time.time(), *identity, surface.session_revision, refresh_key),
            ).rowcount
            if not changed:
                return False
            db.execute(
                "UPDATE rj_session_refresh SET state='succeeded',ended_at=? WHERE refresh_key=?",
                (time.time(), refresh_key),
            )
            self._audit(
                db,
                policy.engagement_id,
                "session_refresh_completed",
                {
                    "refresh_key": refresh_key,
                    "to_revision": row["to_revision"],
                    "job_id": job["id"],
                },
            )
            return True

    def fail_session_refresh(
        self,
        policy: EngagementPolicy,
        job: dict[str, Any],
        surface: Surface,
        refresh_key: str,
        *,
        uncertain: bool,
        code: str,
    ) -> bool:
        identity = self._session_identity(policy, surface)
        # Codes are chosen by the host implementation, never by a remote response.
        if not re.fullmatch(r"[a-z_]{1,128}", code):
            raise ValueError("invalid_session_refresh_error_code")
        state = "uncertain" if uncertain else "blocked"
        with self.transaction() as db:
            changed = db.execute(
                "UPDATE rj_session_refresh SET state=?,error_code=?,ended_at=? WHERE refresh_key=? "
                "AND job_id=? AND owner=? AND attempt=? AND state='inflight'",
                (state, code, time.time(), refresh_key, job["id"], job["owner"], job["attempt"]),
            ).rowcount
            if changed:
                db.execute(
                    "UPDATE rj_session_state SET status=?,updated_at=? WHERE engagement=? "
                    "AND actor=? "
                    "AND tenant=? AND policy_revision=? AND refresh_key=? AND status='refreshing'",
                    (state, time.time(), *identity, refresh_key),
                )
                self._audit(
                    db,
                    policy.engagement_id,
                    "session_refresh_failed",
                    {
                        "refresh_key": refresh_key,
                        "state": state,
                        "code": code,
                        "job_id": job["id"],
                    },
                )
            return bool(changed)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def _prune_engagement(self, db: sqlite3.Connection, engagement: str) -> None:
        """Bounded retention outside the fenced job/evidence ledgers.

        Jobs, attempts and evidence are deliberately not deleted here: they are
        the durable proof of what ran. Findings and terminal control rows are
        capped by insertion order, while pending/in-flight rows are retained.
        """
        deleted = db.execute(
            "DELETE FROM rj_finding WHERE engagement=? AND rowid NOT IN "
            "(SELECT rowid FROM rj_finding WHERE engagement=? ORDER BY rowid DESC LIMIT ?)",
            (engagement, engagement, self.max_findings),
        ).rowcount
        self._retention_pruned["findings"] += max(0, deleted)
        deleted = db.execute(
            "DELETE FROM rj_audit WHERE engagement=? AND sequence NOT IN "
            "(SELECT sequence FROM rj_audit WHERE engagement=? ORDER BY sequence DESC LIMIT ?)",
            (engagement, engagement, self.max_audit_rows),
        ).rowcount
        self._retention_pruned["audit"] += max(0, deleted)
        deleted = db.execute(
            "DELETE FROM rj_session_refresh WHERE engagement=? AND state!='inflight' "
            "AND rowid NOT IN (SELECT rowid FROM rj_session_refresh WHERE engagement=? "
            "AND state!='inflight' ORDER BY created_at DESC, rowid DESC LIMIT ?)",
            (engagement, engagement, self.max_sessions),
        ).rowcount
        self._retention_pruned["sessions"] += max(0, deleted)
        deleted = db.execute(
            "DELETE FROM rj_request_capture WHERE engagement=? AND state!='inflight' "
            "AND rowid NOT IN (SELECT rowid FROM rj_request_capture WHERE engagement=? "
            "AND state!='inflight' ORDER BY created_at DESC, rowid DESC LIMIT ?)",
            (engagement, engagement, self.max_capture_rows),
        ).rowcount
        self._retention_pruned["captures"] += max(0, deleted)
        deleted = db.execute(
            "DELETE FROM rj_followup_event WHERE engagement=? AND state!='pending' "
            "AND rowid NOT IN (SELECT rowid FROM rj_followup_event WHERE engagement=? "
            "AND state!='pending' ORDER BY created_at DESC, rowid DESC LIMIT ?)",
            (engagement, engagement, self.max_followup_events),
        ).rowcount
        self._retention_pruned["followups"] += max(0, deleted)
        # A surface is only removable when no job, inventory link, capture or
        # follow-up still references it. Referenced inventory remains intact.
        deleted = db.execute(
            "DELETE FROM rj_surface WHERE engagement=? AND id NOT IN "
            "(SELECT surface_id FROM rj_job WHERE engagement=? "
            "UNION SELECT surface_id FROM rj_inventory_surface WHERE engagement=? "
            "UNION SELECT completed_surface_id FROM rj_request_capture "
            "WHERE engagement=? AND completed_surface_id IS NOT NULL) "
            "AND id NOT IN (SELECT id FROM rj_surface WHERE engagement=? "
            "ORDER BY observed_at DESC, id DESC LIMIT ?)",
            (engagement, engagement, engagement, engagement, engagement, self.max_surfaces),
        ).rowcount
        self._retention_pruned["surfaces"] += max(0, deleted)

    def retention_status(self) -> dict[str, Any]:
        return {
            "limits": {
                "max_findings": self.max_findings,
                "max_audit_rows": self.max_audit_rows,
                "max_sessions": self.max_sessions,
                "max_capture_rows": self.max_capture_rows,
                "max_followup_events": self.max_followup_events,
                "max_surfaces": self.max_surfaces,
            },
            "pruned_this_process": dict(self._retention_pruned),
            "protected": ["jobs", "attempts", "evidence", "pending_control_rows"],
        }

    def checkpoint(self) -> None:
        with self._lock:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def vacuum(self) -> None:
        with self._lock:
            self.db.execute("VACUUM")

    def _audit(
        self,
        db: sqlite3.Connection,
        engagement: str,
        action: str,
        payload: object,
        event_key: str | None = None,
    ) -> None:
        db.execute(
            (
                "INSERT OR IGNORE INTO rj_audit(engagement,event_key,action,at,payload) "
                "VALUES(?,?,?,?,?)"
            ),
            (engagement, event_key, action, time.time(), json_text(redact(payload))),
        )
        self._prune_engagement(db, engagement)

    def register(self, policy: EngagementPolicy) -> EngagementPolicy:
        with self.transaction() as db:
            old = db.execute(
                "SELECT owner,revision,policy FROM rj_engagement WHERE id=?",
                (policy.engagement_id,),
            ).fetchone()
            if not policy.deadline:
                # The initial default is persisted once; restart never extends it.
                previous = json.loads(old["policy"]).get("deadline", 0) if old else 0
                policy = replace(policy, deadline=previous or time.time() + 3600)
            encoded = json_text(policy.to_dict())
            if old and old["owner"] != policy.owner_id:
                raise PolicyDenied("engagement_access_denied")
            # Additive default fields do not change authorization. Normalize
            # legacy documents through the schema before comparing, while any
            # nonempty POST/refresh permission still requires a new revision.
            previous_encoded = (
                json_text(EngagementPolicy.from_mapping(json.loads(old["policy"])).to_dict())
                if old
                else None
            )
            if old and previous_encoded != encoded:
                if old["revision"] == policy.revision:
                    raise PolicyDenied("policy_change_requires_new_revision")
                previous_revision = db.execute(
                    "SELECT policy FROM rj_policy_history WHERE engagement=? AND revision=?",
                    (policy.engagement_id, policy.revision),
                ).fetchone()
                if previous_revision:
                    raise PolicyDenied("policy_revision_reuse_denied")
                db.execute(
                    "UPDATE rj_engagement SET revision=?,policy=? WHERE id=?",
                    (policy.revision, encoded, policy.engagement_id),
                )
                db.execute(
                    (
                        "UPDATE rj_job SET cancel_requested=1 WHERE engagement=? AND "
                        "execution_status='running'"
                    ),
                    (policy.engagement_id,),
                )
                db.execute(
                    (
                        "UPDATE rj_job SET "
                        "execution_status='failed',coverage_status='blocked',ended_at=? WHERE "
                        "engagement=? AND execution_status IN ('queued','retry_wait')"
                    ),
                    (time.time(), policy.engagement_id),
                )
            db.execute(
                "INSERT OR IGNORE INTO rj_engagement(id,owner,revision,policy) VALUES(?,?,?,?)",
                (policy.engagement_id, policy.owner_id, policy.revision, encoded),
            )
            db.execute(
                "INSERT OR IGNORE INTO rj_policy_history VALUES(?,?,?)",
                (policy.engagement_id, policy.revision, encoded),
            )
            self._audit(
                db,
                policy.engagement_id,
                "policy_registered",
                {"revision": policy.revision},
                f"{policy.engagement_id}:policy:{policy.revision}",
            )
        return policy

    def policy(self, engagement: str, caller: str) -> EngagementPolicy:
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM rj_engagement WHERE id=? AND owner=?", (engagement, caller)
            ).fetchone()
        if not row:
            raise PolicyDenied("engagement_access_denied")
        return EngagementPolicy.from_mapping(json.loads(row["policy"]))

    def upsert_surface(self, engagement: str, surface: Surface) -> str:
        surface_id = stable_key([engagement, surface.key])
        with self.transaction() as db:
            old = db.execute(
                "SELECT payload FROM rj_surface WHERE id=? AND engagement=?",
                (surface_id, engagement),
            ).fetchone()
            if old:
                previous = json.loads(old[0])
                ranks = {"inferred": 0, "imported": 1, "observed": 2}
                if ranks[surface.source] >= ranks[previous["source"]]:
                    payload = asdict(surface)
                    payload["request_ref"] = surface.request_ref or previous["request_ref"]
                    db.execute(
                        "UPDATE rj_surface SET payload=?,observed_at=? WHERE id=?",
                        (json_text(payload), time.time(), surface_id),
                    )
                self.inventory.attach_surface(db, engagement, surface_id, surface)
                return surface_id
            db.execute(
                "INSERT OR IGNORE INTO rj_surface VALUES(?,?,?,?,?)",
                (surface_id, engagement, surface.key, json_text(asdict(surface)), time.time()),
            )
            self.inventory.attach_surface(db, engagement, surface_id, surface)
        return surface_id

    def is_stopped(self, policy: EngagementPolicy) -> bool:
        """Read the durable stop flag without granting access to another owner."""
        with self._lock:
            row = self.db.execute(
                "SELECT stopped FROM rj_engagement WHERE id=? AND owner=?",
                (policy.engagement_id, policy.owner_id),
            ).fetchone()
        if row is None:
            raise PolicyDenied("engagement_access_denied")
        return bool(row[0])

    def surfaces(
        self,
        engagement: str,
        *,
        limit: int = 50,
        after: str = "",
        actor_id: str = "",
        tenant_id: str = "",
        session_revision: str = "",
        method: str = "",
        source: str = "",
        workflow_state: str = "",
        asset_id: str = "",
    ) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("page_limit_must_be_1_to_100")
        filters = {
            "actor_id": actor_id,
            "tenant_id": tenant_id,
            "session_revision": session_revision,
            "method": method,
            "source": source,
            "workflow_state": workflow_state,
        }
        if any(
            not isinstance(value, str) or len(value) > 128
            for value in (after, asset_id, *filters.values())
        ):
            raise ValueError("invalid_surface_filter")
        with self._lock:
            rows = self.db.execute(
                "SELECT s.id,s.payload FROM rj_surface s WHERE s.engagement=? AND s.id>? "
                "AND (?='' OR json_extract(s.payload,'$.actor_id')=?) "
                "AND (?='' OR json_extract(s.payload,'$.tenant_id')=?) "
                "AND (?='' OR json_extract(s.payload,'$.session_revision')=?) "
                "AND (?='' OR json_extract(s.payload,'$.method')=?) "
                "AND (?='' OR json_extract(s.payload,'$.source')=?) "
                "AND (?='' OR json_extract(s.payload,'$.workflow_state')=?) "
                "AND (?='' OR EXISTS(SELECT 1 FROM rj_inventory_surface i WHERE "
                "i.engagement=s.engagement AND i.surface_id=s.id AND i.asset_id=?)) "
                "ORDER BY s.id LIMIT ?",
                (
                    engagement,
                    after,
                    actor_id,
                    actor_id,
                    tenant_id,
                    tenant_id,
                    session_revision,
                    session_revision,
                    method,
                    method,
                    source,
                    source,
                    workflow_state,
                    workflow_state,
                    asset_id,
                    asset_id,
                    limit,
                ),
            ).fetchall()
        return [{"id": row["id"], **json.loads(row["payload"])} for row in rows]

    def surface(self, engagement: str, surface_id: str) -> Surface:
        with self._lock:
            row = self.db.execute(
                "SELECT payload FROM rj_surface WHERE engagement=? AND id=?",
                (engagement, surface_id),
            ).fetchone()
        if not row:
            raise PolicyDenied("surface_access_denied")
        return Surface(**json.loads(row[0]))

    def job_exists(self, engagement: str, job_key: str) -> bool:
        with self._lock:
            return bool(
                self.db.execute(
                    "SELECT 1 FROM rj_job WHERE engagement=? AND job_key=?", (engagement, job_key)
                ).fetchone()
            )

    def planner_cursor(self, engagement: str) -> str:
        with self._lock:
            row = self.db.execute(
                "SELECT surface_cursor FROM rj_planner_state WHERE engagement=?", (engagement,)
            ).fetchone()
            return row[0] if row else ""

    def set_planner_cursor(self, engagement: str, cursor: str) -> None:
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO rj_planner_state VALUES(?,?)", (engagement, cursor))

    def family_order(self, engagement: str) -> dict[str, int]:
        with self._lock:
            return dict(
                self.db.execute(
                    "SELECT family,served FROM rj_fairness WHERE engagement=?", (engagement,)
                )
            )

    def submit(self, policy: EngagementPolicy, specs: list[JobSpec]) -> list[str]:
        current = self.policy(policy.engagement_id, policy.owner_id)
        if current.revision != policy.revision:
            raise PolicyDenied("stale_policy_revision")
        policy = current
        with self.transaction() as db:
            return self._submit(db, policy, specs)

    def _submit(
        self, db: sqlite3.Connection, policy: EngagementPolicy, specs: list[JobSpec]
    ) -> list[str]:
        """Submit within the caller's transaction, including outbox acknowledgement."""
        if len(specs) > self.queue_max_items:
            raise CapacityExceeded("batch_capacity_exhausted")
        ids: list[str] = []
        state = db.execute(
            "SELECT stopped,owner,revision FROM rj_engagement WHERE id=?",
            (policy.engagement_id,),
        ).fetchone()
        if not state or state["stopped"]:
            raise PolicyDenied("engagement_stopped")
        if state["owner"] != policy.owner_id:
            raise PolicyDenied("engagement_access_denied")
        if state["revision"] != policy.revision:
            raise PolicyDenied("stale_policy_revision")
        for spec in specs:
            policy.authorize(policy.owner_id, spec.policy_revision)
            surface = self.surface(policy.engagement_id, spec.surface_id)
            if surface.method == "POST" and spec.idempotent:
                raise PolicyDenied("post_replay_requires_nonidempotent_job")
            if spec.capability == "browser_post_capture" and spec.idempotent:
                raise PolicyDenied("browser_post_capture_requires_nonidempotent_job")
            if surface.source == "inferred" or (
                surface.source == "imported" and surface.workflow_state != "approved_seed"
            ):
                raise PolicyDenied("observed_or_operator_approved_input_required")
            policy.check_actor(surface.actor_id)
            policy.check_surface(surface)
            if surface.resource_kind == "source_artifact":
                self.inventory.require_source_asset(
                    policy, surface.asset_ref, surface.artifact_sha256
                )
            self.inventory.attach_surface(db, policy.engagement_id, spec.surface_id, surface)
            self.inventory.require_surface_active(db, policy, spec.surface_id)
            job_id = stable_key([policy.engagement_id, spec.key])
            if not db.execute("SELECT 1 FROM rj_job WHERE id=?", (job_id,)).fetchone():
                count = db.execute(
                    (
                        "SELECT count(*) FROM rj_job WHERE engagement=? "
                        "AND execution_status IN "
                        "('queued','running','retry_wait')"
                    ),
                    (policy.engagement_id,),
                ).fetchone()[0]
                if count >= self.queue_max_items:
                    raise CapacityExceeded("queue_capacity_exhausted")
                db.execute(
                    """INSERT INTO rj_job(id,engagement,job_key,surface_id,family,capability,
                           priority,spec,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        job_id,
                        policy.engagement_id,
                        spec.key,
                        spec.surface_id,
                        spec.family,
                        spec.capability,
                        spec.priority,
                        json_text(asdict(spec)),
                        time.time(),
                    ),
                )
                self._audit(
                    db,
                    policy.engagement_id,
                    "job_submitted",
                    {"job_id": job_id},
                    f"submit:{job_id}",
                )
            ids.append(job_id)
        return ids

    @staticmethod
    def _followup_policy(db: sqlite3.Connection, policy: EngagementPolicy) -> EngagementPolicy:
        row = db.execute(
            "SELECT owner,revision,policy FROM rj_engagement WHERE id=?",
            (policy.engagement_id,),
        ).fetchone()
        if row is None or row["owner"] != policy.owner_id:
            raise PolicyDenied("engagement_access_denied")
        if row["revision"] != policy.revision:
            raise PolicyDenied("stale_policy_revision")
        return EngagementPolicy.from_mapping(json.loads(row["policy"]))

    def pending_followups(
        self, policy: EngagementPolicy, *, limit: int = 64, after: str = ""
    ) -> list[dict[str, Any]]:
        """Page committed successes without duplicating sensitive result data.

        The outbox only stores identifiers. The existing durable job supplies its
        result and spec; no browser bodies, cookies or credentials are copied.
        Old policy events cannot enter a new policy's continuation chain.
        """
        if not 1 <= limit <= 64:
            raise ValueError("invalid_followup_page_limit")
        with self._lock:
            self._followup_policy(self.db, policy)
            rows = self.db.execute(
                "SELECT e.id,e.job_id,e.capability,e.policy_revision,e.created_at,e.kind,"
                "e.error_code,j.surface_id,j.spec,j.result FROM rj_followup_event e "
                "JOIN rj_job j ON j.id=e.job_id AND j.engagement=e.engagement "
                "WHERE e.engagement=? AND e.policy_revision=? AND e.state='pending' "
                "AND e.id>? ORDER BY e.id LIMIT ?",
                (policy.engagement_id, policy.revision, after, limit),
            ).fetchall()
        return [
            {**dict(row), "spec": json.loads(row["spec"]), "result": json.loads(row["result"])}
            for row in rows
        ]

    def complete_followup(
        self, policy: EngagementPolicy, event_id: str, specs: list[JobSpec]
    ) -> list[str]:
        """Atomically publish children and acknowledge one committed success.

        Failed admission rolls back every child and leaves the parent event
        pending. A crash after commit can only retrieve the same child IDs.
        """
        with self.transaction() as db:
            current = self._followup_policy(db, policy)
            row = db.execute(
                "SELECT state,child_ids,kind FROM rj_followup_event WHERE id=? "
                "AND engagement=? AND policy_revision=?",
                (event_id, current.engagement_id, current.revision),
            ).fetchone()
            if row is None:
                raise PolicyDenied("followup_access_denied")
            if row["kind"] != "completion":
                raise PolicyDenied("auth_recovery_admission_required")
            if row["state"] == "completed":
                return list(json.loads(row["child_ids"]))
            if current.deadline and time.time() >= current.deadline:
                raise PolicyDenied("campaign_deadline_exceeded")
            ids = self._submit(db, current, specs)
            self._ack_followup(db, current, event_id, ids)
            return ids

    def _ack_followup(
        self, db: sqlite3.Connection, policy: EngagementPolicy, event_id: str, ids: list[str]
    ) -> None:
        db.execute(
            "UPDATE rj_followup_event SET state='completed',completed_at=?,"
            "error_code=NULL,child_ids=? WHERE id=? AND state='pending'",
            (time.time(), json_text(ids), event_id),
        )
        self._audit(
            db,
            policy.engagement_id,
            "followup_completed",
            {"event_id": event_id, "child_ids": ids},
            f"followup:complete:{event_id}",
        )

    @staticmethod
    def _admitted_auth_failure(
        db: sqlite3.Connection, row: sqlite3.Row, result: AdapterResult
    ) -> bool:
        if (
            result.execution_status != "failed"
            or result.coverage_status != "blocked"
            or row["capability"]
            not in {
                "browser_post_capture",
                "nuclei_scan",
                "tinja_validate",
                "schemathesis_validate",
                "oast_correlate",
            }
            or result.error is None
        ):
            return False
        marker = result.summary.get("auth_recovery")
        code = result.error.get("code")
        if (
            not isinstance(code, str)
            or not isinstance(marker, dict)
            or marker.get("admitted") is not True
        ):
            return False
        surface_row = db.execute(
            "SELECT payload FROM rj_surface WHERE id=? AND engagement=?",
            (row["surface_id"], row["engagement"]),
        ).fetchone()
        if surface_row is None:
            return False
        surface = Surface(**json.loads(surface_row["payload"]))
        if surface.actor_id == "anonymous" or any(
            marker.get(key) != getattr(surface, key)
            for key in ("actor_id", "tenant_id", "session_revision")
        ):
            return False
        if code == "authentication_expired":
            return (
                marker.get("signal") == "http_401"
                and marker.get("response_complete") is True
                and type(marker.get("status")) is int
                and marker["status"] == 401
            )
        return marker.get("signal") == "credential_expired" and (
            (
                code == "auth_replay_expired"
                and row["capability"]
                in {"nuclei_scan", "tinja_validate", "schemathesis_validate", "oast_correlate"}
            )
            or (
                code == "browser_capture_credentials_expired"
                and row["capability"] == "browser_post_capture"
            )
        )

    def complete_auth_recovery(  # noqa: PLR0912, PLR0915 - fenced atomic admission and coalescing
        self,
        policy: EngagementPolicy,
        event_id: str,
        spec: JobSpec,
        *,
        max_refreshes: int,
        cooldown_seconds: int,
    ) -> list[str]:
        """Coalesce one failed-session signal into a persistently bounded refresh.

        Admission consumes budget, never the failed browser/scanner request.
        Parent evidence remains failed and no non-idempotent parent is resent.
        """
        if type(max_refreshes) is not int or not 1 <= max_refreshes <= 3:
            raise ValueError("auth_recovery_invalid_budget")
        if type(cooldown_seconds) is not int or not 0 <= cooldown_seconds <= 3600:
            raise ValueError("auth_recovery_invalid_cooldown")
        with self.transaction() as db:
            current = self._followup_policy(db, policy)
            if not self._capture_policy_fenced(db, current):
                raise PolicyDenied("auth_recovery_policy_inactive")
            event = db.execute(
                "SELECT e.state,e.child_ids,e.kind,j.* FROM rj_followup_event e "
                "JOIN rj_job j ON j.id=e.job_id WHERE e.id=? AND e.engagement=? "
                "AND e.policy_revision=?",
                (event_id, current.engagement_id, current.revision),
            ).fetchone()
            if event is None or event["kind"] != "auth_failure":
                raise PolicyDenied("auth_recovery_event_access_denied")
            if event["state"] == "completed":
                return list(json.loads(event["child_ids"]))
            result = AdapterResult(**json.loads(event["result"]))
            if not self._admitted_auth_failure(db, event, result):
                raise PolicyDenied("auth_recovery_signal_unverified")
            parent = self.surface(current.engagement_id, event["surface_id"])
            identity = self._session_identity(current, parent)
            if not re.fullmatch(r"[1-9][0-9]{0,17}", parent.session_revision):
                raise PolicyDenied("session_refresh_numeric_revision_required")
            previous = db.execute(
                "SELECT j.id,j.execution_status,j.spec FROM rj_auth_recovery_job r "
                "JOIN rj_job j ON j.id=r.job_id WHERE r.engagement=? AND r.actor=? "
                "AND r.tenant=? AND r.policy_revision=? AND r.from_revision=?",
                (*identity, parent.session_revision),
            ).fetchone()
            state = db.execute(
                "SELECT revision,status FROM rj_session_state WHERE engagement=? AND actor=? "
                "AND tenant=? AND policy_revision=?",
                identity,
            ).fetchone()
            if state is not None:
                if (
                    state["status"] == "refreshing"
                    and state["revision"] == parent.session_revision
                    and previous is not None
                    and previous["execution_status"] == "running"
                ):
                    ids = [previous["id"]]
                    self._ack_followup(db, current, event_id, ids)
                    return ids
                if state["status"] != "ready":
                    raise PolicyDenied("auth_recovery_session_" + state["status"])
                if not re.fullmatch(r"[1-9][0-9]{0,17}", state["revision"]):
                    raise PolicyDenied("session_refresh_numeric_revision_required")
                if int(state["revision"]) > int(parent.session_revision):
                    # A late 401 for revision 7 cannot refresh the now-current 8.
                    self._ack_followup(db, current, event_id, [])
                    return []
                if state["revision"] != parent.session_revision:
                    raise PolicyDenied("auth_recovery_session_revision_mismatch")
            surface = self.surface(current.engagement_id, spec.surface_id)
            if (
                spec.capability != "session_refresh"
                or spec.idempotent
                or spec.policy_revision != current.revision
                or surface.method != "GET"
                or any(
                    getattr(surface, key) != getattr(parent, key)
                    for key in ("actor_id", "tenant_id", "session_revision")
                )
            ):
                raise PolicyDenied("auth_recovery_invalid_refresh_job")
            current.check_readonly_request(surface.url, "GET")
            if (
                spec.tool_version != "1"
                or spec.template_version
                or spec.profile_version != "1"
                or spec.retest_revision
                or spec.options
            ):
                raise PolicyDenied("auth_recovery_noncanonical_refresh_job")
            if previous:
                if previous["execution_status"] not in {"queued", "running", "retry_wait"}:
                    raise PolicyDenied("auth_recovery_prior_refresh_terminal")
                ids = [previous["id"]]
                self._ack_followup(db, current, event_id, ids)
                return ids
            # A manually admitted refresh for this identity/revision remains the
            # canonical job. Coalescing neither launches nor charges another one.
            existing = db.execute(
                "SELECT j.id,j.execution_status,j.spec FROM rj_job j "
                "JOIN rj_surface s ON s.id=j.surface_id "
                "WHERE j.engagement=? AND j.capability='session_refresh' "
                "AND json_extract(j.spec,'$.policy_revision')=? "
                "AND json_extract(s.payload,'$.actor_id')=? "
                "AND json_extract(s.payload,'$.tenant_id')=? "
                "AND json_extract(s.payload,'$.session_revision')=? "
                "ORDER BY j.created_at,j.id LIMIT 1",
                (
                    current.engagement_id,
                    current.revision,
                    parent.actor_id,
                    parent.tenant_id,
                    parent.session_revision,
                ),
            ).fetchone()
            if existing:
                if existing["execution_status"] not in {"queued", "running", "retry_wait"}:
                    raise PolicyDenied("auth_recovery_prior_refresh_terminal")
                if json.loads(existing["spec"])["idempotent"]:
                    raise PolicyDenied("auth_recovery_prior_refresh_invalid")
                db.execute(
                    "INSERT INTO rj_auth_recovery_job VALUES(?,?,?,?,?,?,?)",
                    (*identity, parent.session_revision, existing["id"], time.time()),
                )
                ids = [existing["id"]]
                self._ack_followup(db, current, event_id, ids)
                return ids
            budget = db.execute(
                "SELECT refreshes_used,last_queued_at FROM rj_auth_recovery_budget "
                "WHERE engagement=? AND actor=? AND tenant=? AND policy_revision=?",
                identity,
            ).fetchone()
            now = time.time()
            if budget is not None:
                if budget["refreshes_used"] >= max_refreshes:
                    raise PolicyDenied("auth_recovery_budget_exhausted")
                if now < budget["last_queued_at"] + cooldown_seconds:
                    raise PolicyDenied("auth_recovery_cooldown_active")
            ids = self._submit(db, current, [spec])
            db.execute(
                "INSERT INTO rj_auth_recovery_budget VALUES(?,?,?,?,1,?) "
                "ON CONFLICT(engagement,actor,tenant,policy_revision) DO UPDATE SET "
                "refreshes_used=refreshes_used+1,last_queued_at=excluded.last_queued_at",
                (*identity, now),
            )
            db.execute(
                "INSERT INTO rj_auth_recovery_job VALUES(?,?,?,?,?,?,?)",
                (*identity, parent.session_revision, ids[0], now),
            )
            db.execute(
                "INSERT OR IGNORE INTO rj_session_state VALUES(?,?,?,?,?,'ready',NULL,?)",
                (*identity, parent.session_revision, now),
            )
            self._ack_followup(db, current, event_id, ids)
            self._audit(
                db,
                current.engagement_id,
                "auth_recovery_admitted",
                {
                    "event_id": event_id,
                    "job_id": ids[0],
                    "actor_id": parent.actor_id,
                    "tenant_id": parent.tenant_id,
                    "from_revision": parent.session_revision,
                },
                stable_key(["auth_recovery", *identity, parent.session_revision]),
            )
            return ids

    def recovery_status(self, policy: EngagementPolicy) -> dict[str, Any]:
        """Expose counters, never session credentials or captured request bodies."""
        with self._lock:
            self._followup_policy(self.db, policy)
            count, used = self.db.execute(
                "SELECT count(*),coalesce(sum(refreshes_used),0) FROM rj_auth_recovery_budget "
                "WHERE engagement=? AND policy_revision=?",
                (policy.engagement_id, policy.revision),
            ).fetchone()
            rows = self.db.execute(
                "SELECT actor AS actor_id,tenant AS tenant_id,refreshes_used,last_queued_at "
                "FROM rj_auth_recovery_budget WHERE engagement=? AND policy_revision=? "
                "ORDER BY actor,tenant LIMIT 64",
                (policy.engagement_id, policy.revision),
            ).fetchall()
        return {
            "refreshes_used": used,
            "identities": [dict(row) for row in rows],
            "identities_truncated": count > 64,
        }

    def followup_status(self, policy: EngagementPolicy) -> dict[str, Any]:
        """Return exact pending counts and a bounded list of safe blockage codes."""
        with self._lock:
            self._followup_policy(self.db, policy)
            pending = self.db.execute(
                "SELECT count(*) FROM rj_followup_event WHERE engagement=? "
                "AND policy_revision=? AND state='pending'",
                (policy.engagement_id, policy.revision),
            ).fetchone()[0]
            errors = self.db.execute(
                "SELECT id AS event_id,error_code AS code FROM rj_followup_event "
                "WHERE engagement=? AND policy_revision=? AND state='pending' "
                "AND error_code IS NOT NULL ORDER BY id LIMIT 64",
                (policy.engagement_id, policy.revision),
            ).fetchall()
        return {
            "pending_events": pending,
            "errors": [{**dict(row), "coverage_status": "blocked"} for row in errors],
        }

    def record_followup_error(
        self, policy: EngagementPolicy, event_id: str | None, code: str
    ) -> None:
        """Keep a blocked continuation visible without retrying its parent."""
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
            raise ValueError("invalid_followup_error_code")
        with self.transaction() as db:
            self._followup_policy(db, policy)
            if event_id is not None:
                changed = db.execute(
                    "UPDATE rj_followup_event SET error_code=? WHERE id=? AND engagement=? "
                    "AND policy_revision=? AND state='pending'",
                    (code, event_id, policy.engagement_id, policy.revision),
                ).rowcount
                if not changed:
                    raise PolicyDenied("pending_followup_access_denied")
            self._audit(
                db,
                policy.engagement_id,
                "followup_blocked",
                {"event_id": event_id, "code": code},
                stable_key(
                    ["followup_error", policy.engagement_id, policy.revision, event_id, code]
                ),
            )

    def claim(
        self, policy: EngagementPolicy, owner: str, *, lease_seconds: float = 15
    ) -> dict[str, Any] | None:
        current = self.policy(policy.engagement_id, policy.owner_id)
        if current.revision != policy.revision:
            return None
        policy = current
        now = time.time()
        with self.transaction() as db:
            engagement = db.execute(
                "SELECT stopped FROM rj_engagement WHERE id=?", (policy.engagement_id,)
            ).fetchone()
            if policy.deadline and now >= policy.deadline:
                db.execute(
                    (
                        "UPDATE rj_job SET "
                        "execution_status='timed_out',coverage_status='blocked',ended_at=? WHERE "
                        "engagement=? AND execution_status IN ('queued','retry_wait')"
                    ),
                    (now, policy.engagement_id),
                )
                self._audit(
                    db,
                    policy.engagement_id,
                    "campaign_deadline",
                    {},
                    f"{policy.engagement_id}:deadline:{policy.revision}",
                )
                return None
            if not engagement or engagement[0]:
                return None
            row = db.execute(
                """SELECT j.* FROM rj_job j LEFT JOIN rj_fairness f
              ON f.engagement=j.engagement AND f.family=j.family
              WHERE j.engagement=? AND j.execution_status IN ('queued','retry_wait')
              AND j.ready_at<=? AND j.cancel_requested=0
              ORDER BY COALESCE(f.served,0),j.priority DESC,j.created_at,j.id LIMIT 1""",
                (policy.engagement_id, now),
            ).fetchone()
            if row is None:
                return None
            attempt = row["attempt"] + 1
            db.execute(
                (
                    "UPDATE rj_job SET "
                    "execution_status='running',owner=?,lease_until=?,attempt=?,started_at=? "
                    "WHERE id=?"
                ),
                (owner, now + lease_seconds, attempt, now, row["id"]),
            )
            db.execute(
                "INSERT INTO rj_attempt VALUES(?,?,?,?,NULL,'running',NULL)",
                (row["id"], attempt, owner, now),
            )
            tick = db.execute(
                "SELECT COALESCE(max(served),0)+1 FROM rj_fairness WHERE engagement=?",
                (policy.engagement_id,),
            ).fetchone()[0]
            db.execute(
                "INSERT OR REPLACE INTO rj_fairness VALUES(?,?,?)",
                (policy.engagement_id, row["family"], tick),
            )
            self._audit(
                db, policy.engagement_id, "job_started", {"job_id": row["id"], "attempt": attempt}
            )
            return {
                **dict(row),
                "attempt": attempt,
                "owner": owner,
                "started_at": now,
                "execution_status": "running",
            }

    def heartbeat(self, job_id: str, owner: str, attempt: int, lease_seconds: float = 15) -> bool:
        with self.transaction() as db:
            cursor = db.execute(
                (
                    "UPDATE rj_job SET lease_until=? WHERE id=? AND owner=? AND attempt=? AND "
                    "execution_status='running' AND cancel_requested=0"
                ),
                (time.time() + lease_seconds, job_id, owner, attempt),
            )
            return bool(cursor.rowcount)

    def recover_expired(self, policy: EngagementPolicy) -> int:
        now, count = time.time(), 0
        with self.transaction() as db:
            rows = db.execute(
                (
                    "SELECT * FROM rj_job WHERE engagement=? AND execution_status='running' AND "
                    "lease_until<? LIMIT ?"
                ),
                (policy.engagement_id, now, self.queue_max_items),
            ).fetchall()
            for row in rows:
                # A refresh may have reached its server before worker loss. Keep
                # that identity blocked until explicit operator reconciliation;
                # retrying a one-use refresh token could invalidate the session.
                refresh_rows = db.execute(
                    "SELECT refresh_key FROM rj_session_refresh WHERE job_id=? "
                    "AND state='inflight'",
                    (row["id"],),
                ).fetchall()
                for refresh in refresh_rows:
                    db.execute(
                        "UPDATE rj_session_refresh SET state='uncertain',"
                        "error_code='unknown_refresh_outcome',"
                        "ended_at=? WHERE refresh_key=? AND state='inflight'",
                        (now, refresh["refresh_key"]),
                    )
                    db.execute(
                        "UPDATE rj_session_state SET status='uncertain',updated_at=? "
                        "WHERE engagement=? AND refresh_key=? AND status='refreshing'",
                        (now, policy.engagement_id, refresh["refresh_key"]),
                    )
                # Even idempotent GETs may have unknown side effects: no blind resend
                # after a process loss. Explicit reconciliation/retest is required.
                oast_refs = (
                    [
                        evidence[0]
                        for evidence in db.execute(
                            "SELECT id FROM rj_evidence WHERE engagement=? AND job_id=? "
                            "ORDER BY created_at LIMIT 32",
                            (policy.engagement_id, row["id"]),
                        )
                    ]
                    if row["capability"] in {"oast_correlate", "oast_poll"}
                    else []
                )
                result = AdapterResult(
                    "failed",
                    "inconclusive",
                    summary={"evidence_refs": oast_refs} if oast_refs else {},
                    error={
                        **error_record(
                            "unknown_execution_outcome",
                            recovery_action="reconcile",
                            job_id=row["id"],
                        ),
                        "partial_evidence_refs": oast_refs,
                    },
                )
                db.execute(
                    (
                        "UPDATE rj_job SET "
                        "execution_status='failed',coverage_status='inconclusive',result=?,owner=NULL,lease_until=NULL,ended_at=?"
                        " WHERE id=?"
                    ),
                    (json_text(asdict(result)), now, row["id"]),
                )
                db.execute(
                    (
                        "UPDATE rj_attempt SET execution_status='failed',ended_at=?,error=? WHERE "
                        "job_id=? AND number=?"
                    ),
                    (now, json_text(result.error), row["id"], row["attempt"]),
                )
                self._audit(
                    db,
                    policy.engagement_id,
                    "lease_reconciled",
                    {"job_id": row["id"], "outcome": "unknown"},
                )
                count += 1
        # A worker death may bypass the auth adapter's finally block. No
        # private checkpoint is available here, so retain uncertainty rather
        # than reopening an admitted one-use challenge.
        if count:
            with self._lock:
                current_policy = self._capture_policy_fenced(self.db, policy)
            if current_policy:
                self.auth_flows.reconcile_expired(policy)
        return count

    def network_request_usage(self, policy: EngagementPolicy) -> int:
        with self._lock:
            if not self._capture_policy_fenced(self.db, policy):
                raise PolicyDenied("network_budget_policy_denied")
            row = self.db.execute(
                "SELECT used FROM rj_network_usage WHERE engagement=?", (policy.engagement_id,)
            ).fetchone()
            return int(row[0]) if row else 0

    def consume_network_requests(self, policy: EngagementPolicy, count: int = 1) -> None:
        if type(count) is not int or count < 1:
            raise ValueError("invalid_network_request_count")
        with self.transaction() as db:
            if not self._capture_policy_fenced(db, policy):
                raise PolicyDenied("network_budget_policy_denied")
            budget = getattr(policy, "network_request_budget", 0)
            row = db.execute(
                "SELECT used FROM rj_network_usage WHERE engagement=?", (policy.engagement_id,)
            ).fetchone()
            used = int(row[0]) if row else 0
            if budget <= 0 or count > budget - used:
                raise PolicyDenied("network_request_budget_exhausted")
            db.execute(
                "INSERT INTO rj_network_usage VALUES(?,?) ON CONFLICT(engagement) DO "
                "UPDATE SET used=excluded.used",
                (policy.engagement_id, used + count),
            )

    def request_usage(self, policy: EngagementPolicy) -> int:
        with self._lock:
            row = self.db.execute(
                "SELECT requests_used FROM rj_engagement WHERE id=?",
                (policy.engagement_id,),
            ).fetchone()
        if row is None:
            raise CapacityExceeded("request_usage_unavailable")
        return int(row[0])

    def consume_requests(self, policy: EngagementPolicy, count: int = 1) -> None:
        if count <= 0:
            raise ValueError("invalid_request_charge")
        with self.transaction() as db:
            changed = db.execute(
                (
                    "UPDATE rj_engagement SET requests_used=requests_used+? WHERE id=? AND "
                    "requests_used+?<=? AND stopped=0"
                ),
                (count, policy.engagement_id, count, policy.request_budget),
            ).rowcount
            if not changed:
                raise CapacityExceeded("request_budget_exhausted")

    def finish(
        self, job: dict[str, Any], result: AdapterResult, *, retry_after: float | None = None
    ) -> bool:
        with self.transaction() as db:
            row = db.execute(
                (
                    "SELECT * FROM rj_job WHERE id=? AND owner=? AND attempt=? AND "
                    "execution_status='running'"
                ),
                (job["id"], job["owner"], job["attempt"]),
            ).fetchone()
            if row is None:
                return False  # stale worker is fenced after reconciliation
            if row["cancel_requested"]:
                # Cancellation discards finding claims, but must retain actual
                # evidence already committed by this fenced worker. Query only
                # references owned by this engagement/job, never caller input.
                refs = [
                    item[0]
                    for item in db.execute(
                        "SELECT id FROM rj_evidence WHERE engagement=? AND job_id=? LIMIT 64",
                        (job["engagement"], job["id"]),
                    )
                ]
                cancel_error = error_record("cancelled", coverage_effect="partial")
                cancel_error["partial_evidence_refs"] = refs
                result = AdapterResult(
                    "cancelled",
                    "partial",
                    summary={"evidence_refs": refs},
                    error=cancel_error,
                )
                retry_after = None
            status = "retry_wait" if retry_after is not None else result.execution_status
            encoded = json_text(asdict(result))
            if len(encoded.encode()) > self.artifact_max_bytes:
                raise EvidenceWriteError("result_too_large")
            db.execute(
                (
                    "UPDATE rj_job SET "
                    "execution_status=?,coverage_status=?,result=?,owner=NULL,lease_until=NULL,ready_at=?,ended_at=?"
                    " WHERE id=?"
                ),
                (
                    status,
                    result.coverage_status,
                    encoded,
                    time.time() + (retry_after or 0),
                    None if retry_after is not None else time.time(),
                    job["id"],
                ),
            )
            db.execute(
                (
                    "UPDATE rj_attempt SET execution_status=?,ended_at=?,error=? WHERE job_id=? "
                    "AND number=?"
                ),
                (
                    result.execution_status,
                    time.time(),
                    json_text(result.error),
                    job["id"],
                    job["attempt"],
                ),
            )
            xss_confirmed = (
                row["capability"] == "browser_xss_confirmation"
                and status == "succeeded"
                and result.error is None
                and self._commit_browser_confirmation(db, row)
            )
            if (
                row["capability"] in {"naabu_ports", "nmap_services"}
                and status == "succeeded"
                and result.error is None
                and not row["cancel_requested"]
            ):
                from redjohn.assessment.network_observation import (  # noqa: PLC0415
                    commit_service_inventory,
                )

                commit_service_inventory(self, db, row, result)
            for raw_finding in () if xss_confirmed else result.findings:
                # Scanner matches require separate control/validation before confirmation.
                finding = {**raw_finding, "finding_status": "candidate"}
                finding_id = stable_key([job["id"], finding])
                db.execute(
                    "INSERT OR IGNORE INTO rj_finding VALUES(?,?,?,?,?)",
                    (
                        finding_id,
                        job["engagement"],
                        job["id"],
                        "candidate",
                        json_text(redact(finding)),
                    ),
                )
            self._audit(
                db,
                job["engagement"],
                "job_finished",
                {"job_id": job["id"], "status": status},
                f"finish:{job['id']}:{job['attempt']}",
            )
            if (
                status == "succeeded"
                and result.error is None
                and (
                    (
                        row["capability"] == "session_refresh"
                        and result.coverage_status == "completed"
                    )
                    or (
                        row["capability"] == "browser_post_capture"
                        and result.coverage_status in {"completed", "partial"}
                    )
                )
            ):
                # Parent completion and its continuation intent are one commit.
                # A browser can retain partial aggregate coverage while some
                # requests have complete, successful capture proof. The workflow
                # consumer must validate each selected request before replay.
                # Refresh requires completed coverage; failed/unknown execution
                # and capture errors never create continuation intent.
                spec = json.loads(row["spec"])
                event_id = stable_key(["followup", row["id"]])
                db.execute(
                    "INSERT OR IGNORE INTO rj_followup_event("
                    "id,engagement,policy_revision,job_id,capability,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        event_id,
                        row["engagement"],
                        spec["policy_revision"],
                        row["id"],
                        row["capability"],
                        time.time(),
                    ),
                )
            elif status == "failed" and self._admitted_auth_failure(db, row, result):
                spec = json.loads(row["spec"])
                db.execute(
                    "INSERT OR IGNORE INTO rj_followup_event("
                    "id,engagement,policy_revision,job_id,capability,created_at,kind) "
                    "VALUES(?,?,?,?,?,?,'auth_failure')",
                    (
                        stable_key(["auth_failure", row["id"]]),
                        row["engagement"],
                        spec["policy_revision"],
                        row["id"],
                        row["capability"],
                        time.time(),
                    ),
                )
        return True

    def _commit_browser_confirmation(self, db: sqlite3.Connection, job: sqlite3.Row) -> bool:
        """Promote the existing candidate only from separate host browser proof.

        Scanner result fields alone cannot promote anything. The host-owned
        outbox binds this job to a committed parent and immutable evidence from
        the confirmation attempt, containing both control and nonce execution.
        This runs inside the fenced finish transaction, including cancellation.
        """
        spec = json.loads(job["spec"])
        candidate = spec.get("options", {}).get("candidate_ref")
        if not isinstance(candidate, str):
            return False
        parent = db.execute(
            "SELECT f.parent_job FROM rj_specialist_followup f JOIN rj_job j ON j.id=f.parent_job "
            "WHERE f.engagement=? AND f.surface_id=? AND f.candidate_ref=? "
            "AND j.execution_status='succeeded' AND j.capability='dalfox_validate'",
            (job["engagement"], job["surface_id"], candidate),
        ).fetchone()
        if parent is None:
            return False
        proofs = db.execute(
            "SELECT id,payload FROM rj_evidence WHERE engagement=? AND job_id=? "
            "AND kind='browser_xss_confirmation' AND bytes<=32768 LIMIT 2",
            (job["engagement"], job["id"]),
        ).fetchall()
        if len(proofs) != 1:
            return False
        proof = json.loads(proofs[0]["payload"])
        if (
            proof.get("candidate_ref") != candidate
            or proof.get("confirmed") is not True
            or proof.get("baseline_nonce_dialogs") != 0
            or type(proof.get("proof_nonce_dialogs")) is not int
            or proof["proof_nonce_dialogs"] < 1
            or proof.get("upstream_tls_failures") != 0
            or proof.get("validation")
            != "target_delivered_javascript_nonce_alert_with_benign_control"
        ):
            return False
        findings = db.execute(
            "SELECT id,payload FROM rj_finding WHERE engagement=? AND job_id=? LIMIT 8",
            (job["engagement"], parent[0]),
        ).fetchall()
        promoted = False
        for finding in findings:
            payload = json.loads(finding["payload"])
            if payload.get("cwe") == "CWE-79" and payload.get("surface_id") == job["surface_id"]:
                payload.update(
                    finding_status="confirmed_weakness",
                    confirmation_job=job["id"],
                    validation="chromium_nonce_alert_and_control",
                )
                payload["evidence_refs"] = list(
                    dict.fromkeys([*payload.get("evidence_refs", []), candidate, proofs[0]["id"]])
                )[:64]
                db.execute(
                    "UPDATE rj_finding SET status=?,payload=? WHERE id=?",
                    ("confirmed_weakness", json_text(payload), finding["id"]),
                )
                promoted = True
                self._audit(
                    db,
                    job["engagement"],
                    "finding_confirmed",
                    {
                        "finding_id": finding["id"],
                        "confirmation_job": job["id"],
                        "evidence_ref": proofs[0]["id"],
                    },
                    f"xss-confirm:{job['id']}:{finding['id']}",
                )
        return promoted

    def retry_charge(self, policy: EngagementPolicy) -> bool:
        with self.transaction() as db:
            return bool(
                db.execute(
                    (
                        "UPDATE rj_engagement SET retries_used=retries_used+1 WHERE id=? AND "
                        "retries_used<?"
                    ),
                    (policy.engagement_id, policy.retry_budget),
                ).rowcount
            )

    def cancel(self, engagement: str, job_id: str | None = None) -> int:
        with self.transaction() as db:
            selector, params = "engagement=?", [engagement]
            if job_id:
                selector += " AND id=?"
                params.append(job_id)
            else:
                db.execute("UPDATE rj_engagement SET stopped=1 WHERE id=?", (engagement,))
            count = db.execute(
                f"UPDATE rj_job SET cancel_requested=1 WHERE {selector} "  # noqa: S608 - two constant selectors
                "AND execution_status IN ('queued','running','retry_wait')",
                params,
            ).rowcount
            db.execute(
                "UPDATE rj_job SET execution_status='cancelled',"  # noqa: S608 - two constant selectors
                "coverage_status='partial',ended_at=? "
                f"WHERE {selector} AND execution_status IN ('queued','retry_wait')",
                [time.time(), *params],
            )
            self._audit(db, engagement, "cancel_requested", {"job_id": job_id})
            return count

    def jobs(self, engagement: str, *, limit: int = 50, after: str = "") -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("page_limit_must_be_1_to_100")
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM rj_job WHERE engagement=? AND id>? ORDER BY id LIMIT ?",
                (engagement, after, limit),
            ).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["spec"] = json.loads(value["spec"])
            value["result"] = json.loads(value["result"]) if value["result"] else None
            result.append(value)
        return result

    def job_page_metadata(self, engagement: str) -> dict[str, int]:
        """Counts over the full engagement, independent of the report page."""
        with self._lock:
            row = self.db.execute(
                "SELECT count(*) AS total, COALESCE(sum(CASE WHEN execution_status NOT IN "
                "('succeeded','failed','cancelled','timed_out','resource_exhausted') "
                "THEN 1 ELSE 0 END), 0) AS active FROM rj_job WHERE engagement=?",
                (engagement,),
            ).fetchone()
        return {"jobs_total": int(row["total"]), "active_jobs": int(row["active"])}

    def findings_total(self, engagement: str) -> int:
        with self._lock:
            return int(
                self.db.execute(
                    "SELECT count(*) FROM rj_finding WHERE engagement=?", (engagement,)
                ).fetchone()[0]
            )

    def coverage(self, engagement: str) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(row)
                for row in self.db.execute(
                    (
                        "SELECT family,execution_status,coverage_status,count(*) "
                        "AS count FROM rj_job WHERE engagement=? "
                        "GROUP BY family,execution_status,coverage_status ORDER "
                        "BY family"
                    ),
                    (engagement,),
                )
            ]

    def evidence_put(
        self,
        engagement: str,
        value: object,
        *,
        job_id: str | None = None,
        kind: str = "observation",
        deduplicate: bool = False,
    ) -> str:
        payload = json_text(redact(value)).encode()
        if len(payload) > self.artifact_max_bytes:
            raise EvidenceWriteError("artifact_max_bytes_exceeded")
        ref = uuid.uuid4().hex
        try:
            with self.transaction() as db:
                if deduplicate:
                    existing = db.execute(
                        "SELECT id FROM rj_evidence WHERE engagement=? AND kind=? "
                        "AND digest=? LIMIT 1",
                        (engagement, kind, stable_key(redact(value))),
                    ).fetchone()
                    if existing is not None:
                        return str(existing[0])
                size = db.execute(
                    "SELECT COALESCE(sum(bytes),0) FROM rj_evidence WHERE engagement=?",
                    (engagement,),
                ).fetchone()[0]
                if size + len(payload) > self.evidence_quota_bytes:
                    raise EvidenceWriteError("evidence_quota_exhausted")
                db.execute(
                    "INSERT INTO rj_evidence VALUES(?,?,?,?,?,?,?,?)",
                    (
                        ref,
                        engagement,
                        job_id,
                        stable_key(redact(value)),
                        len(payload),
                        payload,
                        time.time(),
                        kind,
                    ),
                )
        except sqlite3.Error as exc:
            raise EvidenceWriteError("evidence_write_failed") from exc
        return ref

    def evidence_get(self, engagement: str, ref: str, *, max_bytes: int = 8192) -> dict[str, Any]:
        if not 128 <= max_bytes <= 65536:
            raise ValueError("invalid_evidence_preview_limit")
        with self._lock:
            row = self.db.execute(
                (
                    "SELECT id,digest,bytes,substr(payload,1,?) AS excerpt FROM rj_evidence WHERE"
                    " engagement=? AND id=?"
                ),
                (max_bytes, engagement, ref),
            ).fetchone()
        if not row:
            raise PolicyDenied("evidence_access_denied")
        value = dict(row)
        value["excerpt"] = bytes(value["excerpt"]).decode(errors="replace")
        value["truncated"] = value["bytes"] > max_bytes
        return value

    def findings(
        self, engagement: str, *, limit: int = 50, after: str = ""
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("invalid_page_limit")
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM rj_finding WHERE engagement=? AND id>? ORDER BY id LIMIT ?",
                (engagement, after, limit),
            ).fetchall()
        return [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]
