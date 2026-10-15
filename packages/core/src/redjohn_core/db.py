"""Persistence layer: SQLAlchemy 2 async tables + Store primitives.

Design notes
------------
* Canonical models are stored as JSON (``data`` column, Pydantic-validated on
  read/write) with indexed columns only where queries need them. This keeps
  the schema stable while the contract evolves.
* Every business mutation goes through :meth:`Store.write`, which serializes
  writers with a process-wide asyncio lock (the profile lock guarantees one
  engine per data directory, so in-process serialization is sufficient and
  deterministic) and commits state + event_store row + outbox row in ONE
  transaction.
* ``seq`` is assigned server-side per run via the ``run_counters`` upsert
  (first statement inside the write transaction, so concurrent writers
  serialize on the row lock as well); ``UniqueConstraint(run_id, seq)`` is
  the hard guard.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy import (
    event as sa_event,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from . import eventlog
from .errors import RJError, not_found
from .events import EventType, RunEvent
from .models import (
    Agent,
    AgentMessage,
    AgentStatus,
    Evidence,
    Finding,
    MCPConnection,
    MessageStatus,
    Project,
    Report,
    Run,
    ScopePolicy,
    SkillRef,
    Target,
    TerminalSession,
    ToolInvocation,
    ToolInvocationStatus,
    Workspace,
    utcnow,
)

meta = MetaData()

# ---------------------------------------------------------------------------
# Table definitions
# ---------------------------------------------------------------------------

workspaces = Table(
    "workspaces", meta,
    Column("workspace_id", String, primary_key=True),
    Column("slug", String, unique=True, nullable=False),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
)

projects = Table(
    "projects", meta,
    Column("project_id", String, primary_key=True),
    Column("workspace_id", String, index=True, nullable=False),
    Column("name", String, nullable=False),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
)

targets = Table(
    "targets", meta,
    Column("target_id", String, primary_key=True),
    Column("project_id", String, index=True, nullable=False),
    Column("value", String, nullable=False),
    Column("kind", String, nullable=False),
    Column("data", JSON, nullable=False),
)

scope_policies = Table(
    "scope_policies", meta,
    Column("scope_id", String, primary_key=True),
    Column("project_id", String, index=True, nullable=False),
    Column("version", Integer, nullable=False),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("project_id", "version", name="uq_scope_project_version"),
)

runs = Table(
    "runs", meta,
    Column("run_id", String, primary_key=True),
    Column("workspace_id", String, index=True, nullable=False),
    Column("project_id", String, index=True, nullable=False),
    Column("status", String, index=True, nullable=False),
    Column("idempotency_key", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
)

agents = Table(
    "agents", meta,
    Column("agent_id", String, primary_key=True),
    Column("run_id", String, index=True, nullable=False),
    Column("parent_agent_id", String, index=True, nullable=True),
    Column("status", String, index=True, nullable=False),
    Column("depth", Integer, nullable=False),
    Column("delegation_hash", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("run_id", "parent_agent_id", "delegation_hash", name="uq_agent_delegation"),
)

agent_messages = Table(
    "agent_messages", meta,
    Column("message_id", String, primary_key=True),
    Column("run_id", String, index=True, nullable=False),
    Column("from_agent_id", String, nullable=False),
    Column("to_agent_id", String, index=True, nullable=False),
    Column("status", String, nullable=False),
    Column("idempotency_key", String, nullable=True),
    Column("correlation_id", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
)

Index(
    "uq_msg_dedup",
    agent_messages.c.run_id,
    agent_messages.c.from_agent_id,
    agent_messages.c.idempotency_key,
    unique=True,
    sqlite_where=agent_messages.c.idempotency_key.is_not(None),
)

tool_invocations = Table(
    "tool_invocations", meta,
    Column("invocation_id", String, primary_key=True),
    Column("run_id", String, index=True, nullable=False),
    Column("agent_id", String, index=True, nullable=False),
    Column("status", String, index=True, nullable=False),
    Column("started_at", String, nullable=False),
    Column("data", JSON, nullable=False),
)

terminal_sessions = Table(
    "terminal_sessions", meta,
    Column("terminal_id", String, primary_key=True),
    Column("run_id", String, index=True, nullable=False),
    Column("agent_id", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
)

findings = Table(
    "findings", meta,
    Column("finding_id", String, primary_key=True),
    Column("run_id", String, index=True, nullable=False),
    Column("code", String, nullable=False),
    Column("severity", String, index=True, nullable=False),
    Column("status", String, index=True, nullable=False),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("run_id", "code", name="uq_finding_run_code"),
)

evidence = Table(
    "evidence", meta,
    Column("evidence_id", String, primary_key=True),
    Column("run_id", String, index=True, nullable=False),
    Column("sha256", String, nullable=False),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
)

skill_refs = Table(
    "skill_refs", meta,
    Column("skill_id", String, primary_key=True),
    Column("name", String, index=True, nullable=False),
    Column("data", JSON, nullable=False),
)

mcp_connections = Table(
    "mcp_connections", meta,
    Column("mcp_id", String, primary_key=True),
    Column("name", String, unique=True, nullable=False),
    Column("status", String, nullable=False),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
)

reports = Table(
    "reports", meta,
    Column("report_id", String, primary_key=True),
    Column("run_id", String, index=True, nullable=False),
    Column("format", String, nullable=False),
    Column("storage_ref", String, nullable=False),
    Column("created_at", String, nullable=False),
    Column("data", JSON, nullable=False),
)

event_store = Table(
    "event_store", meta,
    Column("event_id", String, primary_key=True),
    Column("run_id", String, index=True, nullable=False),
    Column("seq", Integer, nullable=False),
    Column("type", String, nullable=False),
    Column("occurred_at", String, nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("run_id", "seq", name="uq_event_run_seq"),
)

outbox = Table(
    "outbox", meta,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String, unique=True, nullable=False),
    Column("run_id", String, index=True, nullable=False),
    Column("published_at", String, nullable=True),
)

idempotency_keys = Table(
    "idempotency_keys", meta,
    Column("key", String, primary_key=True),
    Column("endpoint", String, primary_key=True),
    Column("payload_hash", String, nullable=False),
    Column("status_code", Integer, nullable=False),
    Column("response", JSON, nullable=False),
    Column("created_at", String, nullable=False),
)

run_counters = Table(
    "run_counters", meta,
    Column("run_id", String, primary_key=True),
    Column("next_seq", Integer, nullable=False),
)

workspace_counters = Table(
    "workspace_counters", meta,
    Column("workspace_id", String, primary_key=True),
    Column("next_ref", Integer, nullable=False),
)

engine_meta = Table(
    "engine_meta", meta,
    Column("key", String, primary_key=True),
    Column("value", JSON, nullable=False),
)


def _from(cls: Any, data: dict[str, Any]) -> Any:
    return cls.model_validate(data)


def _dump(model: Any) -> dict[str, Any]:
    return model.model_dump(mode="json", by_alias=False)


def encode_cursor(created_at: str, pk: str) -> str:
    raw = json.dumps({"c": created_at, "i": pk}).encode()
    return base64.urlsafe_b64encode(raw).decode()


def decode_cursor(cursor: str) -> tuple[str, str]:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return str(data["c"]), str(data["i"])
    except Exception as exc:
        raise RJError("invalid_cursor", "malformed pagination cursor", status=422) from exc


def payload_hash(parts: list[Any]) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(json.dumps(part, sort_keys=True, default=str).encode())
        h.update(b"\x00")
    return h.hexdigest()


class _SQLiteSession(AsyncSession):
    """Finish thread-backed SQL before cancellation tears down its connection."""

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        # Cancelling the await does not stop aiosqlite's worker. Invalidating
        # its connection first can strand the worker's open write transaction.
        return await Store._uncancellable(super().execute(*args, **kwargs))


class Store:
    """Async persistence primitives. All writes go through :meth:`write`."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        session_class = _SQLiteSession if engine.dialect.name == "sqlite" else AsyncSession
        self._sessions = async_sessionmaker(engine, class_=session_class, expire_on_commit=False)
        self._write_lock = asyncio.Lock()
        self._commit_hooks: list[Callable[[], None]] = []
        # Context propagates to spawned tasks, but sessions must never do so.
        # Only the owning task may join an outer request transaction.
        self._transaction: ContextVar[tuple[Any, AsyncSession, list[Callable[[], None]]] | None] = ContextVar(
            f"store_transaction_{id(self)}", default=None,
        )

    def _current_session(self) -> AsyncSession | None:
        current = self._transaction.get()
        if current is not None and current[0] is asyncio.current_task():
            return current[1]
        return None

    def defer_after_commit(self, callback: Callable[[], None]) -> bool:
        """Defer a runtime wakeup until its database mutation is visible.

        Return False outside an owned transaction, so the caller can act now.
        Rolled-back requests discard their callbacks along with their rows.
        """
        current = self._transaction.get()
        if current is not None and current[0] is asyncio.current_task():
            current[2].append(callback)
            return True
        return False

    @classmethod
    def open(cls, url: str) -> Store:
        engine = create_async_engine(url, echo=False)

        @sa_event.listens_for(engine.sync_engine, "connect")
        def _pragmas(dbapi_conn: Any, _record: Any) -> None:
            dbapi_conn.create_function("unicode_casefold", 1,
                                       lambda value: str(value or "").casefold(), deterministic=True)
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return cls(engine)

    def on_commit(self, hook: Callable[[], None]) -> None:
        """Register a callback fired after each successful write commit
        (used to wake the outbox relay)."""
        self._commit_hooks.append(hook)

    @staticmethod
    async def _uncancellable(coro: Any, *, cancellation: list[bool] | None = None) -> Any:
        """Await a DB commit/rollback to completion even if the surrounding
        task is cancelled — a cancelled commit would otherwise strand an open
        write transaction on the connection and lock the database file."""
        task = asyncio.ensure_future(coro)
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True
        exc = task.exception()
        if exc is not None:
            raise exc
        if cancelled:
            if cancellation is None:
                raise asyncio.CancelledError()
            cancellation.append(True)
        return task.result()

    @asynccontextmanager
    async def write(self) -> AsyncIterator[AsyncSession]:
        current = self._current_session()
        if current is not None:
            yield current
            return
        cancellation: list[bool] = []
        async with self._write_lock:
            session = self._sessions()
            callbacks: list[Callable[[], None]] = []
            token = self._transaction.set((asyncio.current_task(), session, callbacks))
            try:
                yield session
            except BaseException:
                await self._uncancellable(session.rollback())
                raise
            else:
                # A disconnected caller may cancel while the DB has already
                # committed. Finish post-commit wakeups before propagating it.
                await self._uncancellable(session.commit(), cancellation=cancellation)
            finally:
                self._transaction.reset(token)
                await self._uncancellable(session.close(), cancellation=cancellation)
        for hook in self._commit_hooks:
            hook()
        for callback in callbacks:
            callback()
        if cancellation:
            raise asyncio.CancelledError()

    @asynccontextmanager
    async def read(self) -> AsyncIterator[AsyncSession]:
        current = self._current_session()
        if current is not None:
            yield current
            return
        async with self._sessions() as session:
            yield session

    async def close(self) -> None:
        await self.engine.dispose()

    # ---------------------------------------------------------------- events
    async def emit(
        self,
        session: AsyncSession,
        event: RunEvent,
    ) -> RunEvent:
        """Assign per-run seq, validate against the contract schema, and
        append event + outbox rows inside the caller's transaction."""
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        stmt = (
            sqlite_insert(run_counters)
            .values(run_id=event.run_id, next_seq=1)
            .on_conflict_do_update(
                index_elements=["run_id"],
                set_={"next_seq": run_counters.c.next_seq + 1},
            )
            .returning(run_counters.c.next_seq)
        )
        seq = (await session.execute(stmt)).scalar_one()
        event.seq = seq
        eventlog.validate_event(event)
        await session.execute(event_store.insert().values(
            event_id=event.event_id,
            run_id=event.run_id,
            seq=event.seq,
            type=event.type.value,
            occurred_at=_dump(event)["occurred_at"],
            data=_dump(event),
        ))
        await session.execute(outbox.insert().values(
            event_id=event.event_id, run_id=event.run_id, published_at=None,
        ))
        return event

    async def emit_simple(
        self,
        session: AsyncSession,
        run: Run,
        type_: EventType,
        data: dict[str, Any],
        *,
        agent_id: str | None = None,
        correlation_id: str | None = None,
    ) -> RunEvent:
        return await self.emit(
            session, eventlog.make_event(run, type_, data, agent_id=agent_id,
                                         correlation_id=correlation_id)
        )

    async def list_events(self, run_id: str, *, after_seq: int = 0, limit: int = 500) -> list[RunEvent]:
        async with self.read() as s:
            rows = (await s.execute(
                select(event_store.c.data)
                .where(event_store.c.run_id == run_id, event_store.c.seq > after_seq)
                .order_by(event_store.c.seq)
                .limit(limit)
            )).all()
        return [RunEvent.model_validate(r.data) for r in rows]

    async def runtime_event_payloads(
        self, session: AsyncSession, run_id: str, *, type_: EventType,
    ) -> list[dict[str, Any]]:
        """Inner event payloads (the RunEvent ``data`` field) of a runtime
        ledger, without revalidating each row into a RunEvent. The stored column
        is the whole serialized event, so the payload lives under ``data``.
        Callers that only read payload fields (the budget ledger, re-read on
        every model turn) avoid the O(n) Pydantic validation that made those
        reads quadratic over a run."""
        rows = (await session.execute(
            select(event_store.c.data)
            .where(event_store.c.run_id == run_id, event_store.c.type == type_.value)
            .order_by(event_store.c.seq)
        )).all()
        return [row.data.get("data", {}) for row in rows]

    async def synced_memory_message_ids(
        self, session: AsyncSession, run_id: str, agent_id: str,
    ) -> set[str]:
        """Memory-message ids already synced for one agent, filtered in SQL.

        Replaces loading + revalidating every AGENT_ACTIVITY event of the run on
        each turn (which was quadratic): the engine only needs this agent's
        'memory message synchronized' markers. The stored column is the whole
        serialized event, so agent_id is top-level while the activity marker and
        memory_message_id live under the ``data`` payload."""
        rows = (await session.execute(
            select(func.json_extract(event_store.c.data, "$.data.memory_message_id"))
            .where(
                event_store.c.run_id == run_id,
                event_store.c.type == EventType.AGENT_ACTIVITY.value,
                func.json_extract(event_store.c.data, "$.agent_id") == agent_id,
                func.json_extract(event_store.c.data, "$.data.activity")
                == "memory message synchronized",
            )
        )).all()
        return {row[0] for row in rows if row[0] is not None}

    async def max_seq(self, run_id: str) -> int:
        async with self.read() as s:
            val = (await s.execute(
                select(func.max(event_store.c.seq)).where(event_store.c.run_id == run_id)
            )).scalar()
        return int(val or 0)

    async def min_seq(self, run_id: str) -> int:
        async with self.read() as s:
            val = (await s.execute(
                select(func.min(event_store.c.seq)).where(event_store.c.run_id == run_id)
            )).scalar()
        return int(val or 0)

    async def unpublished_outbox(self, limit: int = 200) -> list[tuple[int, str]]:
        async with self.read() as s:
            rows = (await s.execute(
                select(outbox.c.id, outbox.c.event_id)
                .where(outbox.c.published_at.is_(None))
                .order_by(outbox.c.id)
                .limit(limit)
            )).all()
        return [(r.id, r.event_id) for r in rows]

    async def unpublished_outbox_events(
        self, limit: int = 500
    ) -> list[tuple[int, RunEvent | None]]:
        """Fetch unpublished outbox entries joined with their event payloads in one query."""
        async with self.read() as s:
            rows = (await s.execute(
                select(outbox.c.id, event_store.c.data)
                .select_from(
                    outbox.outerjoin(
                        event_store, outbox.c.event_id == event_store.c.event_id
                    )
                )
                .where(outbox.c.published_at.is_(None))
                .order_by(outbox.c.id)
                .limit(limit)
            )).all()
        return [
            (r.id, RunEvent.model_validate(r.data) if r.data is not None else None)
            for r in rows
        ]

    async def get_event(self, event_id: str) -> RunEvent | None:
        async with self.read() as s:
            row = (await s.execute(
                select(event_store.c.data).where(event_store.c.event_id == event_id)
            )).first()
        return RunEvent.model_validate(row.data) if row else None

    async def mark_published(self, ids: list[int]) -> None:
        if not ids:
            return
        async with self.write() as s:
            await s.execute(
                outbox.update()
                .where(outbox.c.id.in_(ids))
                .values(published_at=utcnow().isoformat())
            )

    # ----------------------------------------------------------- idempotency
    async def idem_lookup(self, key: str, endpoint: str) -> tuple[str, int, dict[str, Any]] | None:
        async with self.read() as s:
            row = (await s.execute(
                select(idempotency_keys.c.payload_hash, idempotency_keys.c.status_code,
                       idempotency_keys.c.response)
                .where(idempotency_keys.c.key == key, idempotency_keys.c.endpoint == endpoint)
            )).first()
        return (row.payload_hash, row.status_code, row.response) if row else None

    async def idem_store(
        self, key: str, endpoint: str, phash: str, status_code: int, response: dict[str, Any]
    ) -> None:
        async with self.write() as s:
            await s.execute(idempotency_keys.insert().values(
                key=key, endpoint=endpoint, payload_hash=phash, status_code=status_code,
                response=response, created_at=utcnow().isoformat(),
            ))

    # -------------------------------------------------------------- generic
    async def _get(self, table: Table, pk_col: str, pk: str, cls: Any, label: str) -> Any:
        async with self.read() as s:
            row = (await s.execute(select(table.c.data).where(table.c[pk_col] == pk))).first()
        if not row:
            raise not_found(label, pk)
        return _from(cls, row.data)

    async def _page(
        self,
        table: Table,
        cls: Any,
        *,
        cursor: str | None,
        limit: int,
        pk_col: str,
        filters: list[Any] | None = None,
        order_col: str = "created_at",
    ) -> tuple[list[Any], str | None]:
        stmt = select(table.c.data, table.c[order_col], table.c[pk_col])
        for f in filters or []:
            stmt = stmt.where(f)
        if cursor:
            c_created, c_pk = decode_cursor(cursor)
            stmt = stmt.where(
                (table.c[order_col] > c_created)
                | ((table.c[order_col] == c_created) & (table.c[pk_col] > c_pk))
            )
        stmt = stmt.order_by(table.c[order_col], table.c[pk_col]).limit(limit + 1)
        async with self.read() as s:
            rows = (await s.execute(stmt)).all()
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = encode_cursor(getattr(last, order_col), getattr(last, pk_col))
        return [_from(cls, r.data) for r in rows], next_cursor

    # ------------------------------------------------------------ workspaces
    async def ensure_default_workspace(self, session: AsyncSession) -> Workspace:
        row = (await session.execute(
            select(workspaces.c.data).where(workspaces.c.slug == "local")
        )).first()
        if row:
            return _from(Workspace, row.data)
        ws = Workspace(name="Local", slug="local", kind="local")
        await session.execute(workspaces.insert().values(
            workspace_id=ws.workspace_id, slug=ws.slug,
            created_at=ws.created_at.isoformat(), data=_dump(ws),
        ))
        return ws

    async def get_workspace_by_slug(self, slug: str) -> Workspace | None:
        async with self.read() as s:
            row = (await s.execute(select(workspaces.c.data).where(workspaces.c.slug == slug))).first()
        return _from(Workspace, row.data) if row else None

    # -------------------------------------------------------------- projects
    async def insert_project(self, session: AsyncSession, project: Project) -> None:
        await session.execute(projects.insert().values(
            project_id=project.project_id, workspace_id=project.workspace_id,
            name=project.name, created_at=project.created_at.isoformat(), data=_dump(project),
        ))

    async def get_project(self, project_id: str) -> Project:
        return await self._get(projects, "project_id", project_id, Project, "project")

    async def list_projects(self, *, cursor: str | None, limit: int) -> tuple[list[Project], str | None]:
        return await self._page(projects, Project, cursor=cursor, limit=limit, pk_col="project_id")

    async def update_project_row(self, session: AsyncSession, project: Project) -> None:
        await session.execute(projects.update().where(
            projects.c.project_id == project.project_id
        ).values(name=project.name, data=_dump(project)))

    # --------------------------------------------------------------- targets
    async def insert_target(self, session: AsyncSession, target: Target) -> None:
        await session.execute(targets.insert().values(
            target_id=target.target_id, project_id=target.project_id, value=target.value,
            kind=target.kind.value, data=_dump(target),
        ))

    async def delete_target(self, session: AsyncSession, project_id: str, target_id: str) -> bool:
        res = await session.execute(targets.delete().where(
            targets.c.target_id == target_id, targets.c.project_id == project_id))
        return res.rowcount > 0  # type: ignore[union-attr]

    async def list_targets(self, project_id: str) -> list[Target]:
        async with self.read() as s:
            rows = (await s.execute(
                select(targets.c.data).where(targets.c.project_id == project_id)
                .order_by(targets.c.value)
            )).all()
        return [_from(Target, r.data) for r in rows]

    # ----------------------------------------------------------------- scope
    async def insert_scope(self, session: AsyncSession, scope: ScopePolicy) -> None:
        await session.execute(scope_policies.insert().values(
            scope_id=scope.scope_id, project_id=scope.project_id, version=scope.version,
            created_at=scope.created_at.isoformat(), data=_dump(scope),
        ))

    async def latest_scope(self, session: AsyncSession, project_id: str) -> ScopePolicy | None:
        row = (await session.execute(
            select(scope_policies.c.data)
            .where(scope_policies.c.project_id == project_id)
            .order_by(scope_policies.c.version.desc()).limit(1)
        )).first()
        return _from(ScopePolicy, row.data) if row else None

    # ------------------------------------------------------------------ runs
    async def insert_run(self, session: AsyncSession, run: Run) -> None:
        await session.execute(runs.insert().values(
            run_id=run.run_id, workspace_id=run.workspace_id, project_id=run.project_id,
            status=run.status.value, idempotency_key=run.idempotency_key,
            created_at=run.created_at.isoformat(), data=_dump(run),
        ))

    async def update_run_row(self, session: AsyncSession, run: Run) -> None:
        await session.execute(runs.update().where(runs.c.run_id == run.run_id).values(
            status=run.status.value, data=_dump(run),
        ))

    async def get_run(self, run_id: str) -> Run:
        return await self._get(runs, "run_id", run_id, Run, "run")

    async def list_runs(
        self, *, cursor: str | None, limit: int, project_id: str | None = None,
        status: str | None = None, archived: bool | None = None,
    ) -> tuple[list[Run], str | None]:
        filters: list[Any] = []
        if project_id:
            filters.append(runs.c.project_id == project_id)
        if status:
            filters.append(runs.c.status == status)
        if archived is True:
            filters.append(runs.c.data["archived_at"].as_string().is_not(None))
        elif archived is False:
            filters.append(runs.c.data["archived_at"].as_string().is_(None))
        return await self._page(runs, Run, cursor=cursor, limit=limit, pk_col="run_id", filters=filters)

    async def delete_run_rows(self, session: AsyncSession, run: Run) -> None:
        """Delete only rows owned by this stopped/terminal run."""
        for table in (outbox, event_store, agent_messages, tool_invocations, terminal_sessions,
                      findings, evidence, reports, agents, run_counters):
            await session.execute(table.delete().where(table.c.run_id == run.run_id))
        await session.execute(idempotency_keys.delete().where(
            idempotency_keys.c.endpoint.like(f"%/pentests/{run.run_id}/%")
        ))
        # Prevent creation replay from returning a resource that no longer
        # exists. Other run/project idempotency responses remain untouched.
        await session.execute(idempotency_keys.delete().where(
            idempotency_keys.c.response["run_id"].as_string() == run.run_id
        ))
        await session.execute(runs.delete().where(runs.c.run_id == run.run_id))
        if run.session_project:
            others = (await session.execute(select(func.count()).select_from(runs).where(
                runs.c.project_id == run.project_id
            ))).scalar_one()
            if not others:
                await session.execute(targets.delete().where(targets.c.project_id == run.project_id))
                await session.execute(scope_policies.delete().where(
                    scope_policies.c.project_id == run.project_id
                ))
                await session.execute(projects.delete().where(projects.c.project_id == run.project_id))

    # ---------------------------------------------------------------- agents
    async def insert_agent(
        self, session: AsyncSession, agent: Agent, delegation_hash: str | None = None
    ) -> None:
        await session.execute(agents.insert().values(
            agent_id=agent.agent_id, run_id=agent.run_id,
            parent_agent_id=agent.parent_agent_id, status=agent.status.value,
            depth=agent.depth, delegation_hash=delegation_hash,
            created_at=agent.created_at.isoformat(), data=_dump(agent),
        ))

    async def update_agent_row(self, session: AsyncSession, agent: Agent) -> None:
        await session.execute(agents.update().where(agents.c.agent_id == agent.agent_id).values(
            status=agent.status.value, data=_dump(agent),
        ))

    async def get_agent(self, agent_id: str) -> Agent:
        return await self._get(agents, "agent_id", agent_id, Agent, "agent")

    async def get_agent_session(self, session: AsyncSession, agent_id: str) -> Agent:
        row = (await session.execute(
            select(agents.c.data).where(agents.c.agent_id == agent_id)
        )).first()
        if not row:
            raise not_found("agent", agent_id)
        return _from(Agent, row.data)

    async def list_agents(self, run_id: str) -> list[Agent]:
        async with self.read() as s:
            rows = (await s.execute(
                select(agents.c.data).where(agents.c.run_id == run_id)
                .order_by(agents.c.created_at, agents.c.agent_id)
            )).all()
        return [_from(Agent, r.data) for r in rows]

    async def count_agents(self, session: AsyncSession, run_id: str) -> int:
        return int((await session.execute(
            select(func.count()).select_from(agents).where(agents.c.run_id == run_id)
        )).scalar_one())

    async def count_active(self, session: AsyncSession, run_id: str) -> int:
        """Slots consumed: RUNNING agents only. WAITING/QUEUED do not consume a
        slot — a waiting parent must never hold the last slot its child needs."""
        return int((await session.execute(
            select(func.count()).select_from(agents).where(
                agents.c.run_id == run_id, agents.c.status == AgentStatus.RUNNING.value
            )
        )).scalar_one())

    async def find_delegation(
        self, session: AsyncSession, run_id: str, parent_id: str, dhash: str
    ) -> Agent | None:
        row = (await session.execute(
            select(agents.c.data).where(
                agents.c.run_id == run_id, agents.c.parent_agent_id == parent_id,
                agents.c.delegation_hash == dhash,
            )
        )).first()
        return _from(Agent, row.data) if row else None

    async def children_of(self, session: AsyncSession, run_id: str, parent_id: str) -> list[Agent]:
        rows = (await session.execute(
            select(agents.c.data).where(
                agents.c.run_id == run_id, agents.c.parent_agent_id == parent_id
            )
        )).all()
        return [_from(Agent, r.data) for r in rows]

    # -------------------------------------------------------------- messages
    async def insert_message(self, session: AsyncSession, msg: AgentMessage) -> None:
        await session.execute(agent_messages.insert().values(
            message_id=msg.message_id, run_id=msg.run_id, from_agent_id=msg.from_agent_id,
            to_agent_id=msg.to_agent_id, status=msg.status.value,
            idempotency_key=msg.idempotency_key, correlation_id=msg.correlation_id,
            created_at=msg.created_at.isoformat(), data=_dump(msg),
        ))

    async def update_message_row(self, session: AsyncSession, msg: AgentMessage) -> None:
        await session.execute(agent_messages.update().where(
            agent_messages.c.message_id == msg.message_id
        ).values(status=msg.status.value, data=_dump(msg)))

    async def find_message_dedup(
        self, session: AsyncSession, run_id: str, sender: str, key: str
    ) -> AgentMessage | None:
        row = (await session.execute(
            select(agent_messages.c.data).where(
                agent_messages.c.run_id == run_id,
                agent_messages.c.from_agent_id == sender,
                agent_messages.c.idempotency_key == key,
            )
        )).first()
        return _from(AgentMessage, row.data) if row else None

    async def fetch_inbox(self, session: AsyncSession, agent_id: str) -> list[AgentMessage]:
        rows = (await session.execute(
            select(agent_messages.c.data).where(
                agent_messages.c.to_agent_id == agent_id,
                agent_messages.c.status == MessageStatus.QUEUED.value,
            ).order_by(agent_messages.c.created_at, agent_messages.c.message_id)
        )).all()
        return [_from(AgentMessage, r.data) for r in rows]

    async def list_messages(self, run_id: str) -> list[AgentMessage]:
        async with self.read() as s:
            rows = (await s.execute(
                select(agent_messages.c.data).where(agent_messages.c.run_id == run_id)
                .order_by(agent_messages.c.created_at, agent_messages.c.message_id)
            )).all()
        return [_from(AgentMessage, r.data) for r in rows]

    # -------------------------------------------------------- tool invocation
    async def insert_invocation(self, session: AsyncSession, inv: ToolInvocation) -> None:
        await session.execute(tool_invocations.insert().values(
            invocation_id=inv.invocation_id, run_id=inv.run_id, agent_id=inv.agent_id,
            status=inv.status.value, started_at=inv.started_at.isoformat(), data=_dump(inv),
        ))

    async def update_invocation_row(self, session: AsyncSession, inv: ToolInvocation) -> None:
        await session.execute(tool_invocations.update().where(
            tool_invocations.c.invocation_id == inv.invocation_id
        ).values(status=inv.status.value, data=_dump(inv)))

    async def get_invocation(self, invocation_id: str) -> ToolInvocation | None:
        async with self.read() as s:
            row = (await s.execute(
                select(tool_invocations.c.data).where(tool_invocations.c.invocation_id == invocation_id)
            )).first()
        return _from(ToolInvocation, row.data) if row else None

    async def list_invocations(self, run_id: str) -> list[ToolInvocation]:
        async with self.read() as s:
            rows = (await s.execute(
                select(tool_invocations.c.data).where(tool_invocations.c.run_id == run_id)
                .order_by(tool_invocations.c.started_at, tool_invocations.c.invocation_id)
            )).all()
        return [_from(ToolInvocation, r.data) for r in rows]

    async def invocations_started(self, session: AsyncSession) -> list[ToolInvocation]:
        rows = (await session.execute(
            select(tool_invocations.c.data).where(
                tool_invocations.c.status == ToolInvocationStatus.STARTED.value
            )
        )).all()
        return [_from(ToolInvocation, r.data) for r in rows]

    # -------------------------------------------------------------- findings
    async def next_finding_code(self, session: AsyncSession, run_id: str) -> str:
        n = int((await session.execute(
            select(func.count()).select_from(findings).where(findings.c.run_id == run_id)
        )).scalar_one())
        return f"F-{n + 1:03d}"

    async def insert_finding(self, session: AsyncSession, finding: Finding) -> None:
        await session.execute(findings.insert().values(
            finding_id=finding.finding_id, run_id=finding.run_id, code=finding.code,
            severity=finding.severity.value, status=finding.status.value,
            created_at=finding.created_at.isoformat(), data=_dump(finding),
        ))

    async def update_finding_row(self, session: AsyncSession, finding: Finding) -> None:
        await session.execute(findings.update().where(
            findings.c.finding_id == finding.finding_id
        ).values(severity=finding.severity.value, status=finding.status.value, data=_dump(finding)))

    async def get_finding(self, finding_id: str) -> Finding:
        return await self._get(findings, "finding_id", finding_id, Finding, "finding")

    async def list_findings(
        self, *, run_id: str, cursor: str | None, limit: int,
        severity: str | None = None, status: str | None = None,
    ) -> tuple[list[Finding], str | None]:
        filters: list[Any] = [findings.c.run_id == run_id]
        if severity:
            filters.append(findings.c.severity == severity)
        if status:
            filters.append(findings.c.status == status)
        return await self._page(findings, Finding, cursor=cursor, limit=limit,
                                pk_col="finding_id", filters=filters)

    async def all_findings(self, run_id: str) -> list[Finding]:
        async with self.read() as s:
            rows = (await s.execute(
                select(findings.c.data).where(findings.c.run_id == run_id)
                .order_by(findings.c.created_at, findings.c.finding_id)
            )).all()
        return [_from(Finding, r.data) for r in rows]

    # --------------------------------------------------------------- evidence
    async def insert_evidence(self, session: AsyncSession, ev: Evidence) -> None:
        await session.execute(evidence.insert().values(
            evidence_id=ev.evidence_id, run_id=ev.run_id, sha256=ev.sha256,
            created_at=ev.created_at.isoformat(), data=_dump(ev),
        ))

    async def get_evidence(self, evidence_id: str) -> Evidence:
        return await self._get(evidence, "evidence_id", evidence_id, Evidence, "evidence")

    async def list_evidence(self, run_id: str) -> list[Evidence]:
        async with self.read() as s:
            rows = (await s.execute(
                select(evidence.c.data).where(evidence.c.run_id == run_id)
            )).all()
        return [_from(Evidence, r.data) for r in rows]

    async def list_evidence_page(
        self, *, run_id: str, cursor: str | None, limit: int
    ) -> tuple[list[Evidence], str | None]:
        return await self._page(evidence, Evidence, cursor=cursor, limit=limit,
                                pk_col="evidence_id", filters=[evidence.c.run_id == run_id])

    # ---------------------------------------------------------- run ref seq
    async def next_workspace_ref(self, session: AsyncSession, workspace_id: str) -> int:
        """Atomic per-workspace counter for Run.ref ("RJ-%03d")."""
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        stmt = (
            sqlite_insert(workspace_counters)
            .values(workspace_id=workspace_id, next_ref=1)
            .on_conflict_do_update(
                index_elements=["workspace_id"],
                set_={"next_ref": workspace_counters.c.next_ref + 1},
            )
            .returning(workspace_counters.c.next_ref)
        )
        return int((await session.execute(stmt)).scalar_one())

    # ----------------------------------------------------------------- skills
    async def upsert_skill(self, session: AsyncSession, skill: SkillRef) -> None:
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        await session.execute(sqlite_insert(skill_refs).values(
            skill_id=skill.skill_id, name=skill.name, data=_dump(skill),
        ).on_conflict_do_update(index_elements=["skill_id"], set_={"data": _dump(skill), "name": skill.name}))

    async def get_skill(self, skill_id: str) -> SkillRef:
        return await self._get(skill_refs, "skill_id", skill_id, SkillRef, "skill")

    @staticmethod
    def _skill_filters(query: str | None, matching_ids: list[str] | None = None) -> list[Any]:
        if not query:
            return []
        match = (func.unicode_casefold(skill_refs.c.name).contains(query.casefold(), autoescape=True)
                 | func.unicode_casefold(skill_refs.c.data["description"].as_string()).contains(
                     query.casefold(), autoescape=True))
        if matching_ids:
            match = match | skill_refs.c.skill_id.in_(matching_ids)
        return [match]

    async def count_skills(self, query: str | None = None, matching_ids: list[str] | None = None) -> int:
        async with self.read() as session:
            return int((await session.execute(select(func.count()).select_from(skill_refs).where(
                *self._skill_filters(query, matching_ids)))).scalar_one())

    async def list_skills(self, *, cursor: str | None, limit: int,
                          query: str | None = None,
                          matching_ids: list[str] | None = None) -> tuple[list[SkillRef], str | None]:
        return await self._page(skill_refs, SkillRef, cursor=cursor, limit=limit,
                                pk_col="skill_id", order_col="name",
                                filters=self._skill_filters(query, matching_ids))

    # ------------------------------------------------------------------- mcp
    async def insert_mcp(self, session: AsyncSession, conn: MCPConnection) -> None:
        await session.execute(mcp_connections.insert().values(
            mcp_id=conn.mcp_id, name=conn.name, status=conn.status.value,
            created_at=conn.created_at.isoformat(), data=_dump(conn),
        ))

    async def update_mcp_row(self, session: AsyncSession, conn: MCPConnection) -> None:
        await session.execute(mcp_connections.update().where(
            mcp_connections.c.mcp_id == conn.mcp_id
        ).values(status=conn.status.value, data=_dump(conn)))

    async def get_mcp(self, mcp_id: str) -> MCPConnection:
        return await self._get(mcp_connections, "mcp_id", mcp_id, MCPConnection, "mcp_connection")

    async def get_mcp_by_name(self, session: AsyncSession, name: str) -> MCPConnection | None:
        row = (await session.execute(
            select(mcp_connections.c.data).where(mcp_connections.c.name == name)
        )).first()
        return _from(MCPConnection, row.data) if row else None

    async def list_mcps(self) -> list[MCPConnection]:
        async with self.read() as s:
            rows = (await s.execute(
                select(mcp_connections.c.data).order_by(mcp_connections.c.created_at)
            )).all()
        return [_from(MCPConnection, r.data) for r in rows]

    async def delete_mcp(self, session: AsyncSession, mcp_id: str) -> bool:
        res = await session.execute(mcp_connections.delete().where(mcp_connections.c.mcp_id == mcp_id))
        return res.rowcount > 0  # type: ignore[union-attr]

    # --------------------------------------------------------------- reports
    async def insert_report(self, session: AsyncSession, report_id: str, run_id: str,
                            fmt: str, storage_ref: str, data: dict[str, Any]) -> None:
        await session.execute(reports.insert().values(
            report_id=report_id, run_id=run_id, format=fmt, storage_ref=storage_ref,
            created_at=utcnow().isoformat(), data=data,
        ))

    async def get_report_row(self, report_id: str) -> dict[str, Any]:
        async with self.read() as s:
            row = (await s.execute(
                select(reports.c.data).where(reports.c.report_id == report_id)
            )).first()
        if not row:
            raise not_found("report", report_id)
        return row.data

    async def list_reports_page(
        self, *, run_id: str, cursor: str | None, limit: int
    ) -> tuple[list[Report], str | None]:
        return await self._page(reports, Report, cursor=cursor, limit=limit,
                                pk_col="report_id", filters=[reports.c.run_id == run_id])

    # -------------------------------------------------------------- terminals
    async def insert_terminal(self, session: AsyncSession, term: TerminalSession) -> None:
        await session.execute(terminal_sessions.insert().values(
            terminal_id=term.terminal_id, run_id=term.run_id, agent_id=term.agent_id,
            created_at=term.created_at.isoformat(), data=_dump(term),
        ))

    async def update_terminal_row(self, session: AsyncSession, term: TerminalSession) -> None:
        await session.execute(terminal_sessions.update().where(
            terminal_sessions.c.terminal_id == term.terminal_id
        ).values(data=_dump(term)))

    async def list_terminals(self, run_id: str) -> list[TerminalSession]:
        async with self.read() as s:
            rows = (await s.execute(
                select(terminal_sessions.c.data).where(terminal_sessions.c.run_id == run_id)
            )).all()
        return [_from(TerminalSession, r.data) for r in rows]

    # ------------------------------------------------------------ maintenance
    async def mark_started_invocations_unknown(self) -> list[ToolInvocation]:
        """Engine restart rule: invocations left 'started' move to 'unknown';
        they are never blindly re-executed."""
        changed: list[ToolInvocation] = []
        async with self.write() as s:
            stale = await self.invocations_started(s)
            for inv in stale:
                inv.status = ToolInvocationStatus.UNKNOWN
                inv.finished_at = utcnow()
                inv.error = "engine restarted while invocation was in flight"
                await self.update_invocation_row(s, inv)
                changed.append(inv)
        return changed
