"""Shared fixtures for redjohn-core tests.

Two API fixture styles:
* ``api`` — httpx AsyncClient over ASGITransport, same event loop as the
  engine (no cross-thread asyncio hazards).
* ``server`` (in test_ws_stream.py) — real uvicorn on loopback + ``websockets``
  client, the honest end-to-end shape for the WS stream.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from redjohn_core.api import create_app
from redjohn_core.engine import Engine
from redjohn_core.settings import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES = REPO_ROOT / "fixtures"
LIFECYCLE_SCRIPT = FIXTURES / "core_fixture_script.json"
RESTART_SCRIPT = FIXTURES / "core_restart_script.json"
MCP_SERVER = FIXTURES / "core_mcp_server.py"


def make_settings(tmp_path: Path, *, fixture_script: Path | None = LIFECYCLE_SCRIPT,
                  profile: str = "t") -> Settings:
    environ = {
        "REDJOHN_HOME": str(tmp_path),
        "REDJOHN_PROFILE": profile,
        "RJ_MODEL_PROVIDER": "fixture",
        "RJ_OV_RETRY_SECONDS": "0.1",
        "RJ_LOG_LEVEL": "WARNING",
    }
    if fixture_script is not None:
        environ["RJ_FIXTURE_SCRIPT"] = str(fixture_script)
    return Settings.load(environ=environ)


async def wait_for(cond: Any, timeout: float = 30.0, interval: float = 0.05) -> Any:
    """Poll ``cond`` (sync or async callable) until truthy; returns its value."""
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        value = cond()
        if hasattr(value, "__await__"):
            value = await value
        if value:
            return value
        if asyncio.get_running_loop().time() > deadline:
            raise TimeoutError("wait_for timed out")
        await asyncio.sleep(interval)


@pytest_asyncio.fixture
async def store(tmp_path: Path) -> Any:
    """Bare migrated store (no engine background tasks)."""
    from redjohn_core.db import Store
    from redjohn_core.migrate import migrate

    settings = make_settings(tmp_path)
    settings.ensure_dirs()
    await migrate(settings.db_path)
    st = Store.open(settings.db_url)
    yield st
    await st.close()


@pytest_asyncio.fixture
async def run_factory(store: Any) -> Any:
    """Insert project + scope + a RUNNING run directly (no agent loop)."""

    async def _make(**kwargs: Any) -> Any:
        return await make_run_in(store, **kwargs)

    return _make


async def make_run_in(
    store: Any,
    *,
    targets: list[str] | None = None,
    tools: list[str] | None = None,
    denied: list[str] | None = None,
    limits: Any = None,
    max_agents: int = 24,
    max_concurrent: int = 6,
    max_depth: int = 3,
    status: Any = None,
) -> Any:
    from redjohn_core.models import (
        AgentLimits,
        Project,
        Run,
        RunStatus,
        ScopePolicy,
    )

    async with store.write() as s:
        ws = await store.ensure_default_workspace(s)
        project = Project(workspace_id=ws.workspace_id, name="Acme")
        await store.insert_project(s, project)
        scope = ScopePolicy(
            project_id=project.project_id, version=1,
            allowed_targets=targets or ["app.acme.test"],
            allowed_tools=tools or ["builtin:*"],
            denied_tools=denied or [],
            max_agents=max_agents, max_concurrent_agents=max_concurrent,
            max_depth=max_depth,
        )
        await store.insert_scope(s, scope)
        run = Run(
            workspace_id=ws.workspace_id, project_id=project.project_id,
            name="test-run", task="task", status=status or RunStatus.RUNNING, scope=scope,
            limits=limits or AgentLimits(),
        )
        await store.insert_run(s, run)
    return run


@pytest_asyncio.fixture
async def engine(tmp_path: Path) -> Any:
    eng = await Engine.create(make_settings(tmp_path))
    yield eng
    await eng.shutdown()


async def crash_engine(eng: Engine) -> None:
    """Simulate a hard engine kill (SIGKILL semantics): writes fail instantly,
    runner tasks are cancelled mid-flight; the DB keeps whatever committed.
    Connections are disposed afterwards so the next engine boot does not
    inherit dangling SQLite write locks (that part is crash-site cleanup —
    a real SIGKILL releases file locks by process death)."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _boom() -> Any:
        raise RuntimeError("engine crashed (simulated)")
        yield  # pragma: no cover

    eng.store.write = _boom  # type: ignore[method-assign]
    tasks = list(eng._runners.values())
    for task in tasks:
        task.cancel()
    if tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), timeout=10
            )
        except TimeoutError:
            pass
    if eng._sweep:
        eng._sweep.cancel()
    try:
        await eng.hub.stop()
    except Exception:
        pass
    try:
        await eng.store.close()  # release SQLite locks held by this process
    except Exception:
        pass
    if eng._ckpt_conn:
        try:
            await eng._ckpt_conn.close()
        except Exception:
            pass
    # force-release any stranded aiosqlite connections (cancelled mid-txn):
    # drop references and GC so connection __del__ closes them
    eng.store = None  # type: ignore[assignment]
    eng._ckpt_conn = None
    import gc
    import sqlite3

    gc.collect()
    for _ in range(50):  # wait until the db file accepts a write lock
        try:
            probe = sqlite3.connect(settings_db_path(eng), timeout=0.1)
            probe.execute("BEGIN IMMEDIATE")
            probe.execute("ROLLBACK")
            probe.close()
            break
        except sqlite3.OperationalError:
            gc.collect()
            await asyncio.sleep(0.1)
    if eng._lock:
        eng._lock.release()
        eng._lock = None


def settings_db_path(eng: Engine) -> Path:
    return eng.settings.db_path


@pytest_asyncio.fixture
async def api(engine: Engine) -> Any:
    import httpx

    transport = httpx.ASGITransport(app=create_app(engine))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://127.0.0.1:8720",
        headers={"Authorization": f"Bearer {engine.token}"},
    ) as client:
        yield client


@pytest_asyncio.fixture
async def project(api: Any) -> dict[str, Any]:
    resp = await api.post("/api/v1/projects", json={"name": "Acme", "description": "test"})
    assert resp.status_code == 201, resp.text
    project = resp.json()
    await api.post(f"/api/v1/projects/{project['project_id']}/targets",
                   json={"value": "app.acme.test", "kind": "domain"})
    await api.put(f"/api/v1/projects/{project['project_id']}/scope", json={
        "scope_id": "scp_ignored", "project_id": project["project_id"], "version": 0,
        "allowed_targets": ["app.acme.test"], "allowed_tools": ["builtin:*"],
        "denied_tools": [], "max_agents": 24, "max_concurrent_agents": 6, "max_depth": 3,
    })
    return project


@pytest.fixture
def auth_headers(engine: Engine) -> dict[str, str]:
    return {"Authorization": f"Bearer {engine.token}"}


def python_for_subprocess() -> str:
    return sys.executable
