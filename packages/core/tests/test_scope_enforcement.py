"""Integration (d): API-level authorization, origin checks, typed errors,
and supervisor rejection paths exposed over HTTP."""

from __future__ import annotations

import httpx
from redjohn_core.api import create_app


async def test_bearer_token_required(engine, project) -> None:
    transport = httpx.ASGITransport(app=create_app(engine))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8720") as anon:
        resp = await anon.get("/api/v1/status")
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "unauthorized"
        resp = await anon.get("/api/v1/status",
                              headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401


async def test_origin_header_check(engine) -> None:
    transport = httpx.ASGITransport(app=create_app(engine))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8720",
                                 headers={"Authorization": f"Bearer {engine.token}"}) as client:
        bad = await client.get("/api/v1/status", headers={"Origin": "https://evil.example.com"})
        assert bad.status_code == 403
        assert bad.json()["error"]["code"] == "origin_forbidden"
        ok = await client.get("/api/v1/status", headers={"Origin": "http://localhost:3000"})
        assert ok.status_code == 200


async def test_unauthorized_agent_creation_rejected(api, project) -> None:
    run = (await api.post("/api/v1/pentests", json={
        "project_id": project["project_id"], "name": "r", "task": "t",
    })).json()
    await api.post(f"/api/v1/pentests/{run['run_id']}/start")
    coord = (await api.get(f"/api/v1/pentests/{run['run_id']}/agents")).json()["items"][0]

    # coordinator role is run-manager-only
    resp = await api.post(f"/api/v1/pentests/{run['run_id']}/agents", json={
        "parent_agent_id": coord["agent_id"], "name": "rogue", "role": "coordinator", "task": "x",
    })
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "unauthorized_agent_creation"

    # child scope escaping parent scope
    resp = await api.post(f"/api/v1/pentests/{run['run_id']}/agents", json={
        "parent_agent_id": coord["agent_id"], "name": "rogue2", "role": "specialist",
        "task": "x", "allowed_targets": ["evil.com"],
    })
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "scope_violation"

    # unknown parent
    resp = await api.post(f"/api/v1/pentests/{run['run_id']}/agents", json={
        "parent_agent_id": "agt_missing", "name": "rogue3", "role": "specialist", "task": "x",
    })
    assert resp.status_code == 404

    # legal narrowing succeeds
    resp = await api.post(f"/api/v1/pentests/{run['run_id']}/agents", json={
        "parent_agent_id": coord["agent_id"], "name": "ok", "role": "specialist",
        "task": "x", "allowed_targets": ["app.acme.test"], "allowed_tools": ["builtin:echo"],
    })
    assert resp.status_code == 201, resp.text
    await api.post(f"/api/v1/pentests/{run['run_id']}/stop")


async def test_typed_error_shape_and_request_id(api) -> None:
    resp = await api.get("/api/v1/pentests/run_missing")
    assert resp.status_code == 404
    body = resp.json()
    assert set(body["error"]) >= {"code", "message", "details", "request_id"}
    assert body["error"]["code"] == "not_found"
    assert resp.headers["X-Request-ID"] == body["error"]["request_id"]


async def test_validation_error_typed(api) -> None:
    resp = await api.post("/api/v1/pentests", json={"name": "missing fields"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


async def test_cloud_environment_rejected_locally(api, project) -> None:
    resp = await api.post("/api/v1/pentests", json={
        "project_id": project["project_id"], "name": "r", "task": "t",
        "environment": "cloud_managed",
    })
    assert resp.status_code == 422
