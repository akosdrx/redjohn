"""FastAPI app factory — implements rj-cli/contracts/openapi.yaml (local profile).

* Loopback-only by default (127.0.0.1:8720), bearer token from the profile
  (``<profile>/token``, 0600, generated on first run). Tokens never appear in
  URLs or logs; WebSocket auth uses the same Authorization header.
* Origin header check: missing/null/loopback origins only.
* Typed errors ``{error:{code,message,details,request_id}}`` everywhere.
* Idempotency-Key honored on all mutating routes that declare it (run
  create/start, message post, agent create, project/target create, MCP
  create, report create): same key + same payload -> stored response replay;
  same key + different payload -> 409.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import TYPE_CHECKING, Any, Literal

from fastapi import Depends, FastAPI, Query, Request, Response, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketDisconnect

from . import CONTRACT_VERSION, __version__, mailbox, reports, supervisor
from .db import payload_hash
from .errors import RJError, forbidden, gone, not_found, unauthorized, unavailable, validation
from .events import EventType
from .hub import SubscriberDropped
from .logging import get_logger
from .models import (
    AgentRole,
    ErrorResponse,
    FindingSeverity,
    FindingStatus,
    MCPConnection,
    MCPTransport,
    PentestTargetKind,
    Project,
    RunEnvironment,
    ScanMode,
    ScopePolicy,
    Target,
    TargetKind,
)
from .runs import archive_run, create_run, delete_run, start_run, stop_run
from .supervisor import DelegationRequest

if TYPE_CHECKING:
    from .engine import Engine

API_PREFIX = "/api/v1"

IDEMPOTENT_ROUTES: list[tuple[str, str]] = [
    ("POST", "/api/v1/projects"),
    ("POST", "/api/v1/projects/{project_id}/targets"),
    ("POST", "/api/v1/pentests"),
    ("POST", "/api/v1/pentests/{run_id}/start"),
    ("POST", "/api/v1/pentests/{run_id}/agents"),
    ("POST", "/api/v1/pentests/{run_id}/messages"),
    ("POST", "/api/v1/pentests/{run_id}/reports"),
    ("POST", "/api/v1/mcps"),
]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectCreate(_Body):
    name: str
    description: str = ""


class ProjectPatch(_Body):
    name: str | None = None
    description: str | None = None


class TargetAdd(_Body):
    value: str
    kind: TargetKind
    note: str = ""


class TargetRemove(_Body):
    target_id: str


class RunCreate(_Body):
    project_id: str | None = None
    name: str
    task: str = ""
    scan_mode: ScanMode = ScanMode.STANDARD
    authorized_target: str | None = None
    target_kind: PentestTargetKind | None = None
    environment: RunEnvironment | None = None
    limits: dict[str, Any] | None = None


class AgentCreate(_Body):
    parent_agent_id: str
    name: str
    role: AgentRole
    task: str
    allowed_targets: list[str] = []
    allowed_tools: list[str] = []


class MessagePost(_Body):
    to_agent_id: str
    body: str
    correlation_id: str | None = None


class FindingPatch(_Body):
    status: FindingStatus | None = None
    severity: FindingSeverity | None = None
    remediation: str | None = None


class MCPCreate(_Body):
    name: str
    transport: MCPTransport
    command: list[str] = []
    env: dict[str, str] = {}
    url: str | None = None


class ReportCreate(_Body):
    format: Literal["html", "json", "pdf"]


class SettingsPatch(_Body):
    model_provider: str | None = None
    model_name: str | None = None
    openviking_url: str | None = None
    log_level: str | None = None


# ---------------------------------------------------------------------------
# middleware
# ---------------------------------------------------------------------------

class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Response:
        request.state.request_id = uuid.uuid4().hex[:16]
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """Local profile: only loopback/absent origins may call the engine."""

    _ALLOWED = re.compile(r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$")

    @classmethod
    def permits(cls, origin: str | None) -> bool:
        # Chromium serializes the packaged renderer as null for fetch and
        # file:// for WebSocket. Authentication is still mandatory for both.
        return origin in (None, "", "null", "file://") or bool(cls._ALLOWED.fullmatch(origin))

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        origin = request.headers.get("origin")
        if not self.permits(origin):
            return _error_response(
                forbidden("origin not allowed", code="origin_forbidden"),
                getattr(request.state, "request_id", None),
            )
        return await call_next(request)


class IdempotentRoute(APIRoute):
    """Authenticate before replay and commit each mutation with its response.

    The wrapper runs in the endpoint task, so nested Store writes/reads join
    one transaction. Spawned agent tasks wait for that transaction to commit.
    """

    def get_route_handler(self) -> Any:
        handler = super().get_route_handler()
        methods = self.methods or set()
        enabled = any(method in methods and path == self.path
                      for method, path in IDEMPOTENT_ROUTES)

        async def handle_idempotent(request: Request) -> Response:
            key = request.headers.get("idempotency-key")
            if not enabled or not key:
                return await handler(request)
            await require_auth(request)
            store = get_engine(request).store
            endpoint = f"{request.method} {request.url.path}"
            body = await request.body()
            try:
                payload = json.loads(body) if body else None
            except (ValueError, UnicodeDecodeError):
                payload = body.decode("utf-8", errors="replace")
            phash = payload_hash([endpoint, request.url.query, payload])
            async with store.write():
                found = await store.idem_lookup(key, endpoint)
                if found:
                    stored_hash, status_code, response = found
                    if stored_hash != phash:
                        raise RJError(
                            "idempotency_conflict",
                            "Idempotency-Key was already used with a different payload",
                            status=409, details={"endpoint": endpoint},
                        )
                    return JSONResponse(content=response, status_code=status_code,
                                        headers={"Idempotency-Replayed": "true"})
                response = await handler(request)
                if response.status_code in (200, 201):
                    parsed = json.loads(bytes(response.body))
                    await store.idem_store(key, endpoint, phash, response.status_code, parsed)
                return response

        async def handle(request: Request) -> Response:
            if self.path in (f"{API_PREFIX}/pentests/{{run_id}}/start",
                             f"{API_PREFIX}/pentests/{{run_id}}/reports"):
                # Always acquire the runtime lock before a possible request
                # transaction. Archive/delete take the same lock before SQL;
                # reversing that order for idempotent starts deadlocks.
                await require_auth(request)
                async with get_engine(request).configuration_lock:
                    return await handle_idempotent(request)
            return await handle_idempotent(request)

        return handle


def _error_response(exc: RJError, request_id: str | None) -> JSONResponse:
    body = ErrorResponse(error={
        "code": exc.code, "message": exc.message, "details": exc.details,
        "request_id": request_id,
    })
    return JSONResponse(content=body.model_dump(mode="json"), status_code=exc.status)


# ---------------------------------------------------------------------------
# app factory
# ---------------------------------------------------------------------------

def get_engine(request: Request) -> Engine:
    engine = request.app.state.engine
    if engine is None:
        raise unavailable("engine not attached (schema-export mode)", code="engine_detached")
    return engine


async def require_auth(request: Request) -> None:
    engine: Engine | None = getattr(request.app.state, "engine", None)
    if engine is None:
        return  # schema-export mode
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != engine.token:
        raise unauthorized()


def create_app(engine: Engine | None = None) -> FastAPI:
    app = FastAPI(title="RedJohn API", version="0.1.0", docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.engine = engine

    app.add_middleware(OriginCheckMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["null", "file://"],  # packaged sandboxed Electron renderer
        allow_origin_regex=OriginCheckMiddleware._ALLOWED.pattern,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
        expose_headers=["X-Request-ID", "Idempotency-Replayed"],
    )
    app.add_middleware(RequestIdMiddleware)  # outermost: request_id for all layers

    log = get_logger("api")

    @app.exception_handler(RJError)
    async def _rj_error(request: Request, exc: RJError) -> JSONResponse:
        return _error_response(exc, getattr(request.state, "request_id", None))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_response(
            validation("request validation failed", {"errors": [
                {"loc": e["loc"], "type": e["type"], "msg": e["msg"]} for e in exc.errors()
            ]}),
            getattr(request.state, "request_id", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled error", extra={"error": str(exc),
                                            "request_id": getattr(request.state, "request_id", None)})
        return _error_response(RJError("internal", "internal error", status=500),
                               getattr(request.state, "request_id", None))

    from fastapi import APIRouter

    router = APIRouter(prefix=API_PREFIX, dependencies=[Depends(require_auth)],
                       route_class=IdempotentRoute)

    # ---------------------------------------------------------------- meta
    @router.get("/status")
    async def get_status(request: Request) -> dict[str, Any]:
        from .models import ServiceStatus

        eng = get_engine(request)
        services = eng.service_snapshot()
        services.append(await eng.openviking_status())
        for conn in eng.mcp_manager.live_connections():
            services.append(ServiceStatus(
                service=f"mcp:{conn.mcp_id}", state=conn.status, detail=conn.error or ""))
        return {
            "contract_version": CONTRACT_VERSION,
            "engine_version": __version__,
            "services": [s.model_dump(mode="json") for s in services],
        }

    @router.get("/capabilities")
    async def get_capabilities(request: Request) -> dict[str, Any]:
        from .executor import executor_capability

        eng = get_engine(request)
        pdf = _pdf_available()
        return {
            "environment": "local",
            "executor": executor_capability(),
            "limits": {
                "max_concurrent_agents": 6,
                "max_total_agents": 24,
                "max_delegation_depth": 3,
                "time_budget_seconds": None,
                "token_budget": None,
            },
            "openviking": bool(eng.settings.openviking_url),
            "mcp_transports": ["stdio", "streamable_http"],
            "pty": False,
            "reports": ["html", "json"] + (["pdf"] if pdf else []),
        }

    # ------------------------------------------------------------ projects
    @router.get("/projects")
    async def list_projects(request: Request, cursor: str | None = None,
                            limit: int = Query(50, le=200)) -> dict[str, Any]:
        eng = get_engine(request)
        items, next_cursor = await eng.store.list_projects(cursor=cursor, limit=limit)
        return {"items": [_dump(p) for p in items], "next_cursor": next_cursor, "total": None}

    @router.post("/projects", status_code=201)
    async def create_project(request: Request, body: ProjectCreate) -> dict[str, Any]:
        eng = get_engine(request)
        async with eng.store.write() as s:
            ws = await eng.store.ensure_default_workspace(s)
            project = Project(workspace_id=ws.workspace_id, name=body.name,
                              description=body.description)
            await eng.store.insert_project(s, project)
        return _dump(project)

    @router.get("/projects/{project_id}")
    async def get_project(request: Request, project_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        project = await eng.store.get_project(project_id)
        targets = await eng.store.list_targets(project_id)
        async with eng.store.read() as s:
            scope = await eng.store.latest_scope(s, project_id)
        return {
            "project": _dump(project),
            "targets": [_dump(t) for t in targets],
            "scope": _dump(scope) if scope else None,
        }

    @router.patch("/projects/{project_id}")
    async def update_project(request: Request, project_id: str, body: ProjectPatch) -> dict[str, Any]:
        eng = get_engine(request)
        project = await eng.store.get_project(project_id)
        if body.name is not None:
            project.name = body.name
        if body.description is not None:
            project.description = body.description
        async with eng.store.write() as s:
            await eng.store.update_project_row(s, project)
        return _dump(project)

    @router.post("/projects/{project_id}/targets", status_code=201)
    async def add_target(request: Request, project_id: str, body: TargetAdd) -> dict[str, Any]:
        eng = get_engine(request)
        await eng.store.get_project(project_id)
        target = Target(project_id=project_id, value=body.value, kind=body.kind, note=body.note)
        async with eng.store.write() as s:
            await eng.store.insert_target(s, target)
        return _dump(target)

    @router.delete("/projects/{project_id}/targets", status_code=204)
    async def remove_target(request: Request, project_id: str, body: TargetRemove) -> Response:
        eng = get_engine(request)
        await eng.store.get_project(project_id)
        async with eng.store.write() as s:
            deleted = await eng.store.delete_target(s, project_id, body.target_id)
        if not deleted:
            raise not_found("target", body.target_id)
        return Response(status_code=204)

    @router.get("/projects/{project_id}/scope")
    async def get_scope(request: Request, project_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        await eng.store.get_project(project_id)
        async with eng.store.write() as s:
            scope = await eng.store.latest_scope(s, project_id)
            if scope is None:
                scope = ScopePolicy(project_id=project_id, version=1)
                await eng.store.insert_scope(s, scope)
        return _dump(scope)

    @router.put("/projects/{project_id}/scope")
    async def replace_scope(request: Request, project_id: str, body: ScopePolicy) -> dict[str, Any]:
        eng = get_engine(request)
        await eng.store.get_project(project_id)
        async with eng.store.write() as s:
            latest = await eng.store.latest_scope(s, project_id)
            scope = ScopePolicy(
                project_id=project_id,
                version=(latest.version + 1) if latest else 1,
                allowed_targets=body.allowed_targets,
                allowed_tools=body.allowed_tools,
                denied_tools=body.denied_tools,
                max_agents=body.max_agents,
                max_concurrent_agents=body.max_concurrent_agents,
                max_depth=body.max_depth,
                notes=body.notes,
            )
            await eng.store.insert_scope(s, scope)
        return _dump(scope)

    # ------------------------------------------------------------ pentests
    @router.get("/pentests")
    async def list_runs(request: Request, cursor: str | None = None,
                        limit: int = Query(50, le=200), project_id: str | None = None,
                        status: str | None = None, archived: bool = False) -> dict[str, Any]:
        eng = get_engine(request)
        items, next_cursor = await eng.store.list_runs(
            cursor=cursor, limit=limit, project_id=project_id, status=status, archived=archived,
        )
        return {"items": [_dump(r) for r in items], "next_cursor": next_cursor, "total": None}

    @router.post("/pentests", status_code=201)
    async def create_run_route(request: Request, body: RunCreate) -> dict[str, Any]:
        from .models import AgentLimits

        eng = get_engine(request)
        limits = AgentLimits(**body.limits) if body.limits else None
        run = await create_run(
            eng, project_id=body.project_id, name=body.name, task=body.task,
            scan_mode=body.scan_mode, authorized_target=body.authorized_target,
            target_kind=body.target_kind,
            environment=body.environment, limits=limits,
            idempotency_key=request.headers.get("idempotency-key"),
        )
        return _dump(run)

    @router.get("/pentests/{run_id}")
    async def get_run(request: Request, run_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        return _dump(await eng.store.get_run(run_id))

    @router.post("/pentests/{run_id}/start")
    async def start_run_route(request: Request, run_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        return _dump(await start_run(eng, run_id))

    @router.post("/pentests/{run_id}/stop")
    async def stop_run_route(request: Request, run_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        async with eng.configuration_lock:
            return _dump(await stop_run(eng, run_id))

    @router.post("/pentests/{run_id}/archive")
    async def archive_run_route(request: Request, run_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        async with eng.configuration_lock:
            return _dump(await archive_run(eng, run_id))

    @router.post("/pentests/{run_id}/unarchive")
    async def unarchive_run_route(request: Request, run_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        async with eng.configuration_lock:
            return _dump(await archive_run(eng, run_id, archived=False))

    @router.delete("/pentests/{run_id}", status_code=204)
    async def delete_run_route(request: Request, run_id: str) -> Response:
        eng = get_engine(request)
        async with eng.configuration_lock:
            await delete_run(eng, run_id)
        return Response(status_code=204)

    @router.get("/pentests/{run_id}/agents")
    async def list_agents(request: Request, run_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        await eng.store.get_run(run_id)
        items = await eng.store.list_agents(run_id)
        return {"items": [_dump(a) for a in items]}

    @router.post("/pentests/{run_id}/agents", status_code=201)
    async def create_agent_route(request: Request, run_id: str, body: AgentCreate,
                                 response: Response) -> dict[str, Any]:
        from .models import AgentStatus

        eng = get_engine(request)
        run = await eng.store.get_run(run_id)
        req = DelegationRequest(
            parent_agent_id=body.parent_agent_id, name=body.name, role=body.role,
            task=body.task, allowed_targets=tuple(body.allowed_targets),
            allowed_tools=tuple(body.allowed_tools),
        )
        agent, created = await supervisor.delegate(eng.store, run, req)
        if created and agent.status == AgentStatus.RUNNING:
            eng.spawn_agent(agent.agent_id)
        if not created:
            response.status_code = 200
        return _dump(agent)

    @router.post("/pentests/{run_id}/messages", status_code=201)
    async def post_message_route(request: Request, run_id: str, body: MessagePost) -> dict[str, Any]:
        eng = get_engine(request)
        run = await eng.store.get_run(run_id)
        # recipient must exist (explicit addressing; "user" for operator replies)
        if body.to_agent_id != "user":
            agent = await eng.store.get_agent(body.to_agent_id)
            if agent.run_id != run_id:
                raise not_found("agent", body.to_agent_id)
        msg, _ = await mailbox.post_message(
            eng.store, run, from_agent_id="user", to_agent_id=body.to_agent_id,
            body=body.body, kind="instruction", correlation_id=body.correlation_id,
            idempotency_key=request.headers.get("idempotency-key"),
        )
        if body.to_agent_id != "user":
            await eng.wake_agent(body.to_agent_id, "operator message")
        return _dump(msg)

    @router.get("/pentests/{run_id}/findings")
    async def list_run_findings(request: Request, run_id: str, cursor: str | None = None,
                                limit: int = Query(50, le=200), severity: str | None = None,
                                status: str | None = None) -> dict[str, Any]:
        eng = get_engine(request)
        await eng.store.get_run(run_id)
        items, next_cursor = await eng.store.list_findings(
            run_id=run_id, cursor=cursor, limit=limit, severity=severity, status=status
        )
        return {"items": [_dump(f) for f in items], "next_cursor": next_cursor, "total": None}

    @router.get("/pentests/{run_id}/targets")
    async def list_run_targets(request: Request, run_id: str) -> dict[str, Any]:
        from .scope import target_covered

        eng = get_engine(request)
        run = await eng.store.get_run(run_id)
        targets = await eng.store.list_targets(run.project_id)
        effective = [t for t in targets if target_covered(t.value, run.scope.allowed_targets)]
        return {"items": [_dump(t) for t in effective]}

    @router.get("/pentests/{run_id}/snapshot")
    async def get_run_snapshot(request: Request, run_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        run = await eng.store.get_run(run_id)
        agents = await eng.store.list_agents(run_id)
        findings = await eng.store.all_findings(run_id)
        cursor = await eng.store.max_seq(run_id)
        return {
            "run": _dump(run),
            "agents": [_dump(a) for a in agents],
            "findings": [_dump(f) for f in findings],
            "services": [s.model_dump(mode="json") for s in eng.service_snapshot()],
            "cursor": cursor,
        }

    @router.get("/pentests/{run_id}/events")
    async def get_run_events(request: Request, run_id: str, after_seq: int = 0,
                             limit: int = Query(50, le=200)) -> dict[str, Any]:
        eng = get_engine(request)
        await eng.store.get_run(run_id)
        if after_seq > 0:
            min_seq = await eng.store.min_seq(run_id)
            if min_seq and after_seq + 1 < min_seq:
                raise gone(
                    "event cursor expired by retention; refetch the snapshot",
                    {"after_seq": after_seq, "min_available_seq": min_seq},
                )
        items = await eng.store.list_events(run_id, after_seq=after_seq, limit=limit)
        cursor = items[-1].seq if items else await eng.store.max_seq(run_id)
        return {"items": [e.model_dump(mode="json") for e in items], "cursor": cursor}

    # -------------------------------------------------------------- findings
    @router.get("/findings/{finding_id}")
    async def get_finding(request: Request, finding_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        return _dump(await eng.store.get_finding(finding_id))

    @router.patch("/findings/{finding_id}")
    async def update_finding(request: Request, finding_id: str, body: FindingPatch) -> dict[str, Any]:
        eng = get_engine(request)
        finding = await eng.store.get_finding(finding_id)
        if body.status is not None:
            finding.status = body.status
        if body.severity is not None:
            finding.severity = body.severity
        if body.remediation is not None:
            finding.remediation = body.remediation
        from .models import utcnow

        finding.updated_at = utcnow()
        async with eng.store.write() as s:
            run = await eng.store.get_run(finding.run_id)
            await eng.store.update_finding_row(s, finding)
            await eng.store.emit_simple(s, run, EventType.FINDING_UPDATED, {
                "finding_id": finding.finding_id, "code": finding.code, "title": finding.title,
                "severity": finding.severity.value, "status": finding.status.value,
                "target": finding.target,
            })
        return _dump(finding)

    # -------------------------------------------------------------- evidence
    @router.get("/pentests/{run_id}/evidence")
    @router.get("/evidence")
    async def list_evidence(request: Request, run_id: str, cursor: str | None = None,
                            limit: int = Query(50, le=200)) -> dict[str, Any]:
        eng = get_engine(request)
        await eng.store.get_run(run_id)
        items, next_cursor = await eng.store.list_evidence_page(
            run_id=run_id, cursor=cursor, limit=limit
        )
        return {"items": [_dump(e) for e in items], "next_cursor": next_cursor, "total": None}

    @router.get("/evidence/{evidence_id}")
    async def get_evidence(request: Request, evidence_id: str,
                           download: int = 0) -> Any:
        eng = get_engine(request)
        ev = await eng.store.get_evidence(evidence_id)
        if not download:
            return _dump(ev)
        if ev.access == "restricted":
            raise forbidden("evidence is access-restricted", code="evidence_access_denied")
        root = eng.settings.evidence_dir.resolve()
        path = (root / ev.storage_ref).resolve()
        if not path.is_relative_to(root) or path == root or not path.is_file():
            raise not_found("evidence_content", evidence_id)
        from fastapi.responses import FileResponse

        return FileResponse(path, media_type=ev.mime, filename=path.name)

    # ------------------------------------------------------------------ mcps
    @router.get("/mcps")
    async def list_mcps(request: Request) -> dict[str, Any]:
        eng = get_engine(request)
        conns = await eng.store.list_mcps()
        live = {c.mcp_id: c for c in eng.mcp_manager.live_connections()}
        merged = [live.get(c.mcp_id, c) for c in conns]
        return {"items": [_dump(c) for c in merged]}

    @router.post("/mcps", status_code=201)
    async def create_mcp(request: Request, body: MCPCreate) -> dict[str, Any]:
        from .integrations import validate_endpoint
        if not body.name.strip():
            raise validation("MCP connection name is required.")
        if body.transport == MCPTransport.STDIO and (not body.command or any(not c for c in body.command)):
            raise validation("A stdio MCP requires a non-empty command argument array.")
        if body.transport == MCPTransport.STREAMABLE_HTTP:
            validate_endpoint(body.url or "")
        eng = get_engine(request)
        conn = MCPConnection(name=body.name, transport=body.transport, command=body.command,
                             env=body.env, url=body.url)
        async with eng.store.write() as s:
            await eng.store.insert_mcp(s, conn)
        conn = await eng.mcp_manager.connect(conn)
        return _dump(conn)

    @router.delete("/mcps/{mcp_id}", status_code=204)
    async def delete_mcp(request: Request, mcp_id: str) -> Response:
        eng = get_engine(request)
        await eng.store.get_mcp(mcp_id)
        await eng.mcp_manager.disconnect(mcp_id)
        async with eng.store.write() as s:
            await eng.store.delete_mcp(s, mcp_id)
        return Response(status_code=204)

    @router.post("/mcps/{mcp_id}")
    async def reconnect_mcp(request: Request, mcp_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        conn = await eng.mcp_manager.reconnect(mcp_id)
        return _dump(conn)

    # ---------------------------------------------------------------- skills
    @router.get("/skills")
    async def list_skills(request: Request, query: str | None = None,
                          cursor: str | None = None,
                          limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
        eng = get_engine(request)
        local_hits = eng.skill_registry.search(query) if query else []
        hit_ids = [skill.skill_id for skill in local_hits] if local_hits else (
            await _refresh_skills_from_ov(eng, query) if query else None
        )
        items, next_cursor = await eng.store.list_skills(
            cursor=cursor, limit=limit, query=query, matching_ids=hit_ids)
        return {"items": [_dump(s) for s in items], "next_cursor": next_cursor,
                "total": await eng.store.count_skills(query, hit_ids)}

    @router.get("/skills/{skill_id}")
    async def get_skill(request: Request, skill_id: str, include_content: int = 0) -> dict[str, Any]:
        eng = get_engine(request)
        skill = await eng.store.get_skill(skill_id)
        out: dict[str, Any] = {"skill": _dump(skill)}
        if include_content:
            if skill.source == "redjohn-local":
                out["content"] = eng.skill_registry.read(skill.skill_id)
                return out
            if not skill.ov_uri:
                raise validation("skill has no OpenViking URI; content unavailable")
            store = _memory(eng)
            try:
                out["content"] = await store.read(skill.ov_uri)
            finally:
                if hasattr(store, "close"):
                    await store.close()
        return out

    # -------------------------------------------------------------- settings
    @router.get("/settings")
    async def get_settings(request: Request) -> dict[str, Any]:
        eng = get_engine(request)
        r = eng.settings.redacted()
        return {
            "model_provider": r["model_provider"],
            "model_name": r["model_name"],
            "openviking_url": r["openviking_url"],
            "data_profile": r["data_profile"],
            "log_level": r["log_level"],
        }

    @router.patch("/settings")
    async def patch_settings(request: Request, body: SettingsPatch) -> dict[str, Any]:
        from .integration_routes import ensure_idle
        from .integrations import IntegrationStore
        from .logging import configure_logging
        from .model_gateway import gateway_from_settings
        eng = get_engine(request)
        patch = {k: v for k, v in body.model_dump().items() if v is not None}
        if "log_level" in patch:
            level = patch["log_level"].upper()
            patch["log_level"] = "WARNING" if level == "WARN" else level
            if patch["log_level"] not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                raise validation("Choose a supported log level.")
        async with eng.configuration_lock:
            if any(k in patch for k in ("model_provider", "model_name", "openviking_url")):
                await ensure_idle(eng)
            if "openviking_url" in patch:
                # The memory integration owns openviking_url via runtime_overlay,
                # which outranks settings.json on reload; accepting it here would
                # be silently overridden on the next restart. Reject instead,
                # mirroring the active-provider guard below.
                if IntegrationStore(eng.settings).read().get("memory", {}).get("openviking_url"):
                    raise validation("Update the OpenViking URL through the memory connection manager.")
            if "model_provider" in patch or "model_name" in patch:
                if IntegrationStore(eng.settings).read().get("active_provider"):
                    raise validation("Update the active provider through the provider connections manager.")
                new = eng.settings.model_copy(update=patch)
                gateway = gateway_from_settings(new)
                eng.settings.save_overlay(patch)
                eng.gateway = gateway
            else:
                eng.settings.save_overlay(patch)
            if "log_level" in patch:
                configure_logging(patch["log_level"].upper())
        return await get_settings(request)

    # --------------------------------------------------------------- reports
    @router.post("/pentests/{run_id}/reports", status_code=201)
    async def create_report(request: Request, run_id: str, body: ReportCreate) -> dict[str, Any]:
        eng = get_engine(request)
        await eng.store.get_run(run_id)
        report = await reports.generate_report(eng, run_id, body.format)
        return report.model_dump(mode="json")

    @router.get("/reports/{report_id}")
    async def get_report(request: Request, report_id: str) -> dict[str, Any]:
        eng = get_engine(request)
        return await eng.store.get_report_row(report_id)

    @router.get("/reports/{report_id}/download")
    async def download_report(request: Request, report_id: str) -> FileResponse:
        eng = get_engine(request)
        report = await eng.store.get_report_row(report_id)
        root = eng.settings.reports_dir.resolve()
        path = (root / report["storage_ref"]).resolve()
        if not path.is_relative_to(root) or path == root or not path.is_file():
            raise not_found("report artifact", report_id)
        types = {"html": "text/html", "json": "application/json", "pdf": "application/pdf"}
        return FileResponse(path, filename=path.name, media_type=types[report["format"]])

    @router.get("/reports")
    async def list_reports(request: Request, run_id: str, cursor: str | None = None,
                           limit: int = Query(50, le=200)) -> dict[str, Any]:
        eng = get_engine(request)
        await eng.store.get_run(run_id)
        items, next_cursor = await eng.store.list_reports_page(
            run_id=run_id, cursor=cursor, limit=limit
        )
        return {"items": [_dump(r) for r in items], "next_cursor": next_cursor, "total": None}

    from .integration_routes import install_integration_routes
    install_integration_routes(router)
    app.include_router(router)
    from .memory_model_proxy import install_memory_model_proxy
    install_memory_model_proxy(app)

    # ------------------------------------------------------------------- WS
    @app.websocket("/api/v1/pentests/{run_id}/stream")
    async def stream_run(ws: WebSocket, run_id: str, after_seq: int = 0) -> None:
        eng = ws.app.state.engine
        if eng is None:
            await ws.close(code=1011)
            return
        auth = ws.headers.get("authorization", "")
        accept_subprotocol: str | None = None
        token_ok = auth.startswith("Bearer ") and auth[7:] == eng.token
        if not token_ok:
            # Browser renderers cannot set headers on WebSocket; they offer the
            # token as a `rj-auth-<base64url(token)>` subprotocol instead.
            # Never accept ?token= query params (URLs leak into logs).
            import base64

            for proto in (ws.headers.get("sec-websocket-protocol") or "").split(","):
                proto = proto.strip()
                if proto.startswith("rj-auth-"):
                    try:
                        candidate = base64.urlsafe_b64decode(proto[8:] + "==").decode()
                    except Exception:
                        continue
                    if candidate == eng.token:
                        token_ok = True
                        accept_subprotocol = proto
                    break
        if not token_ok:
            await ws.close(code=4401)
            return
        origin = ws.headers.get("origin")
        if not OriginCheckMiddleware.permits(origin):
            await ws.close(code=4403)
            return
        try:
            await eng.store.get_run(run_id)
        except RJError:
            await ws.close(code=4404)
            return
        await ws.accept(subprotocol=accept_subprotocol)
        sub = await eng.hub.subscribe(run_id, after_seq=after_seq)

        async def receive_disconnect() -> None:
            # Reading is necessary even on a send-only stream: otherwise an
            # idle disconnected client strands the endpoint during shutdown.
            try:
                while (await ws.receive())["type"] != "websocket.disconnect":
                    pass
            except (WebSocketDisconnect, RuntimeError):
                pass

        disconnected = asyncio.create_task(receive_disconnect())
        pending_event: asyncio.Task | None = None
        try:
            while True:
                try:
                    pending_event = asyncio.create_task(sub.get(poll_timeout=1.0))
                    done, _ = await asyncio.wait(
                        (pending_event, disconnected), return_when=asyncio.FIRST_COMPLETED,
                    )
                    if disconnected in done:
                        return
                    event = pending_event.result()
                except SubscriberDropped:
                    await ws.send_text(json.dumps({
                        "control": "resync_required",
                        "run_id": run_id,
                        "message": "client too slow; refetch snapshot and resubscribe",
                    }))
                    await ws.close(code=1013)
                    return
                if event is None:
                    continue
                await ws.send_text(event.model_dump_json())
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            tasks = [disconnected, *([pending_event] if pending_event else [])]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await eng.hub.unsubscribe(sub)

    return app


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def iter_api_routes(app: FastAPI) -> list[tuple[str, set[str]]]:
    """(path, methods) for every route, resolving FastAPI's lazy
    ``_IncludedRouter`` wrappers. Used by contract tests and the exporter."""
    out: list[tuple[str, set[str]]] = []
    for route in app.routes:
        contexts = getattr(route, "effective_route_contexts", None)
        if callable(contexts):
            for ctx in contexts():
                methods = {m.lower() for m in (getattr(ctx, "methods", None) or set())}
                methods.discard("head")
                out.append((ctx.path, methods or {"get"}))
            continue
        path = getattr(route, "path", None)
        if not path:
            continue
        methods = getattr(route, "methods", None)
        if methods:
            out.append((path, {m.lower() for m in methods if m != "HEAD"}))
        else:  # websocket route
            out.append((path, {"get"}))
    return out


def _dump(model: Any) -> dict[str, Any]:
    data = model.model_dump(mode="json")
    if isinstance(model, MCPConnection):
        data["env"] = {key: "***" for key in model.env}
        if data.get("error"):
            for secret in model.env.values():
                if secret:
                    data["error"] = data["error"].replace(secret, "***")
    return data


def _pdf_available() -> bool:
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        return False
    return True


def _memory(eng: Engine) -> Any:
    from .ov import MemoryUnavailable
    from .ovsafe import safe_memory_store

    try:
        return safe_memory_store(eng.settings)
    except MemoryUnavailable as exc:
        raise unavailable(str(exc), code="memory_unavailable") from exc


async def _refresh_skills_from_ov(eng: Engine, query: str) -> list[str]:
    import hashlib

    from .models import SkillRef
    from .ov.protocol import MemoryUnavailable

    store = _memory(eng)
    try:
        hits = await store.find_skills(query, limit=50)
    except MemoryUnavailable as exc:
        raise unavailable(str(exc), code="memory_unavailable") from exc
    finally:
        if hasattr(store, "close"):
            await store.close()
    hit_ids = []
    async with eng.store.write() as s:
        for hit in hits:
            skill = SkillRef(
                skill_id="skl_" + hashlib.sha256(hit.uri.encode()).hexdigest()[:24],
                name=hit.name,
                version=hit.version or "0",
                description=hit.description,
                ov_uri=hit.uri,
                content_hash=hit.content_hash,
            )
            await eng.store.upsert_skill(s, skill)
            hit_ids.append(skill.skill_id)
    return hit_ids
