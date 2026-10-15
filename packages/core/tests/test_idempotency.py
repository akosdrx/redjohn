"""Unit + API: idempotency replay and conflict behavior."""

from __future__ import annotations


async def test_run_create_idempotent_replay(api, project) -> None:
    body = {"project_id": project["project_id"], "name": "r1", "task": "t"}
    r1 = await api.post("/api/v1/pentests", json=body, headers={"Idempotency-Key": "k-1"})
    assert r1.status_code == 201, r1.text
    r2 = await api.post("/api/v1/pentests", json=body, headers={"Idempotency-Key": "k-1"})
    assert r2.status_code == 201
    assert r2.headers.get("Idempotency-Replayed") == "true"
    assert r1.json()["run_id"] == r2.json()["run_id"]

    runs = await api.get("/api/v1/pentests")
    assert len(runs.json()["items"]) == 1


async def test_idempotency_conflict_on_different_payload(api, project) -> None:
    r1 = await api.post("/api/v1/projects", json={"name": "A"}, headers={"Idempotency-Key": "pk-1"})
    assert r1.status_code == 201
    r2 = await api.post("/api/v1/projects", json={"name": "B"}, headers={"Idempotency-Key": "pk-1"})
    assert r2.status_code == 409
    err = r2.json()["error"]
    assert err["code"] == "idempotency_conflict"
    assert err["request_id"]


async def test_start_idempotent(api, project) -> None:
    run = (await api.post("/api/v1/pentests", json={
        "project_id": project["project_id"], "name": "r", "task": "t",
    })).json()
    s1 = await api.post(f"/api/v1/pentests/{run['run_id']}/start", headers={"Idempotency-Key": "sk-1"})
    assert s1.status_code == 200, s1.text
    s2 = await api.post(f"/api/v1/pentests/{run['run_id']}/start", headers={"Idempotency-Key": "sk-1"})
    assert s2.headers.get("Idempotency-Replayed") == "true"
    # without the key, starting a running run conflicts
    s3 = await api.post(f"/api/v1/pentests/{run['run_id']}/start")
    assert s3.status_code == 409
    assert s3.json()["error"]["code"] == "conflict"


async def test_message_post_dedup(api, engine, project) -> None:
    run = (await api.post("/api/v1/pentests", json={
        "project_id": project["project_id"], "name": "r", "task": "t",
    })).json()
    await api.post(f"/api/v1/pentests/{run['run_id']}/start")
    agents = (await api.get(f"/api/v1/pentests/{run['run_id']}/agents")).json()["items"]
    coord = agents[0]
    for _ in range(2):
        resp = await api.post(
            f"/api/v1/pentests/{run['run_id']}/messages",
            json={"to_agent_id": coord["agent_id"], "body": "ping"},
            headers={"Idempotency-Key": "mk-1"},
        )
        assert resp.status_code == 201
    msgs = await engine.store.list_messages(run["run_id"])
    assert len([m for m in msgs if m.body == "ping"]) == 1
