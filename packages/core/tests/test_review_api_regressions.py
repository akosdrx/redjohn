"""Regression coverage for audit findings 4, 5 and 6 at the real API/store seam."""

import asyncio

import httpx
import pytest
from redjohn_core.api import create_app
from redjohn_core.events import EventType
from redjohn_core.hub import Hub, SubscriberDropped


@pytest.mark.parametrize("origin", ["null", "file://"])
async def test_packaged_renderer_cors_preflight_and_authenticated_call(api, origin):
    preflight = await api.options("/api/v1/projects", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type,idempotency-key",
    })
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == origin
    response = await api.get("/api/v1/projects", headers={"Origin": origin})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin
    refused = await api.options("/api/v1/projects", headers={
        "Origin": "https://external.example", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization",
    })
    assert refused.status_code in (400, 403)
    assert "access-control-allow-origin" not in refused.headers


async def test_idempotency_replay_requires_current_auth(api, engine):
    body = {"name": "private project", "description": "private audit data"}
    headers = {"Idempotency-Key": "known-request-key"}
    assert (await api.post("/api/v1/projects", json=body, headers=headers)).status_code == 201
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(engine)), base_url=api.base_url,
    ) as anonymous:
        response = await anonymous.post("/api/v1/projects", json=body, headers=headers)
    assert response.status_code == 401
    assert "private audit data" not in response.text


async def test_concurrent_run_retries_create_exactly_one_row(api, project, engine):
    body = {"project_id": project["project_id"], "name": "retry run", "task": "fixture"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(engine), raise_app_exceptions=False),
        base_url=api.base_url, headers={"Authorization": f"Bearer {engine.token}"},
    ) as client:
        responses = await asyncio.gather(*[
            client.post("/api/v1/pentests", json=body, headers={"Idempotency-Key": "retry"})
            for _ in range(8)
        ])
    assert [r.status_code for r in responses] == [201] * 8
    assert len({r.json()["run_id"] for r in responses}) == 1
    assert len((await api.get("/api/v1/pentests")).json()["items"]) == 1


async def test_idempotency_storage_failure_rolls_back_business_mutation(api, engine, monkeypatch):
    async def unavailable(*args, **kwargs):
        raise RuntimeError("injected idempotency storage failure")

    monkeypatch.setattr(engine.store, "idem_store", unavailable)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(engine), raise_app_exceptions=False),
        base_url=api.base_url, headers={"Authorization": f"Bearer {engine.token}"},
    ) as client:
        response = await client.post(
            "/api/v1/projects", json={"name": "must roll back"},
            headers={"Idempotency-Key": "rollback"},
        )
    assert response.status_code == 500
    assert (await api.get("/api/v1/projects")).json()["items"] == []


async def test_idempotency_key_is_scoped_to_concrete_resource(api):
    projects = [(await api.post("/api/v1/projects", json={"name": name})).json()
                for name in ("one", "two")]
    targets = []
    for project in projects:
        response = await api.post(
            f"/api/v1/projects/{project['project_id']}/targets",
            json={"value": "app.acme.test", "kind": "domain"},
            headers={"Idempotency-Key": "same-key-different-project"},
        )
        assert response.status_code == 201
        targets.append(response.json())
    assert targets[0]["target_id"] != targets[1]["target_id"]
    assert targets[1]["project_id"] == projects[1]["project_id"]


async def test_failed_start_transaction_does_not_launch_an_agent(api, engine, project, monkeypatch):
    run = (await api.post("/api/v1/pentests", json={
        "project_id": project["project_id"], "name": "rollback start", "task": "fixture",
    })).json()

    async def unavailable(*args, **kwargs):
        raise RuntimeError("injected storage failure")

    monkeypatch.setattr(engine.store, "idem_store", unavailable)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(engine), raise_app_exceptions=False),
        base_url=api.base_url, headers={"Authorization": f"Bearer {engine.token}"},
    ) as client:
        response = await client.post(
            f"/api/v1/pentests/{run['run_id']}/start", headers={"Idempotency-Key": "start-rollback"},
        )
    assert response.status_code == 500
    assert (await engine.store.get_run(run["run_id"])).status.value == "created"
    assert await engine.store.list_agents(run["run_id"]) == []
    assert engine._runners == {}


async def test_cancel_during_commit_still_wakes_committed_work(store, monkeypatch):
    """A disconnected start caller must not strand a committed run without a runner."""
    committing, finish_commit = asyncio.Event(), asyncio.Event()
    notifications = []
    store.on_commit(lambda: notifications.append("outbox"))

    async def write():
        async with store.write() as session:
            original_commit = session.commit

            async def delayed_commit():
                committing.set()
                await finish_commit.wait()
                await original_commit()

            monkeypatch.setattr(session, "commit", delayed_commit)
            await store.ensure_default_workspace(session)
            assert store.defer_after_commit(lambda: notifications.append("runner"))

    task = asyncio.create_task(write())
    await committing.wait()
    task.cancel()
    finish_commit.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert notifications == ["outbox", "runner"]


async def test_large_backlog_requests_resync_without_unbounded_queue(store, run_factory):
    run = await run_factory()
    async with store.write() as session:
        for index in range(257):
            await store.emit_simple(session, run, EventType.RUN_STATUS,
                                    {"status": "running", "index": index})
    hub = Hub(store, queue_size=256)
    sub = await hub.subscribe(run.run_id)
    with pytest.raises(SubscriberDropped):
        await sub.get()
    assert sub.queue.qsize() <= 256
    assert await hub.subscriber_count(run.run_id) == 0


async def test_exact_capacity_backlog_replays_without_loss(store, run_factory):
    run = await run_factory()
    async with store.write() as session:
        for _ in range(8):
            await store.emit_simple(session, run, EventType.RUN_STATUS, {"status": "running"})
    hub = Hub(store, queue_size=8)
    sub = await hub.subscribe(run.run_id)
    assert [(await sub.get()).seq for _ in range(8)] == list(range(1, 9))
    await hub.unsubscribe(sub)
