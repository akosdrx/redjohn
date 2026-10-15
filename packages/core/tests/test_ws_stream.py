"""Integration (c): WS stream — replay + live handoff with no loss/duplication,
against a real uvicorn server (production threading shape) and the
``websockets`` client. Client dedups by event_id per the contract.
"""

from __future__ import annotations

import asyncio
import base64
import json
import queue
import socket
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
import websockets

from .conftest import LIFECYCLE_SCRIPT, make_settings, wait_for


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest_asyncio.fixture
async def server(tmp_path: Path) -> Any:
    """Run engine + app under real uvicorn in a background thread."""
    settings = make_settings(tmp_path, fixture_script=LIFECYCLE_SCRIPT)
    port = _free_port()
    settings.bind_host = "127.0.0.1"
    settings.port = port
    token = settings.load_or_create_token()
    handoff: queue.Queue[Any] = queue.Queue()

    def _thread() -> None:
        asyncio.run(_serve())

    async def _serve() -> None:
        import uvicorn
        from redjohn_core.api import create_app
        from redjohn_core.engine import Engine

        engine = await Engine.create(settings)
        config = uvicorn.Config(create_app(engine), host="127.0.0.1", port=port,
                                log_level="error")
        srv = uvicorn.Server(config)
        handoff.put((engine, srv))
        await srv.serve()
        await engine.shutdown()

    thread = threading.Thread(target=_thread, daemon=True)
    thread.start()
    engine, srv = await asyncio.to_thread(handoff.get, timeout=30)

    base = f"http://127.0.0.1:{port}"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(base_url=base, headers=headers) as probe:
        for _ in range(100):
            try:
                if (await probe.get("/api/v1/status")).status_code == 200:
                    break
            except httpx.TransportError:
                pass
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("server did not come up")

    yield {"base": base, "ws": f"ws://127.0.0.1:{port}", "token": token, "engine": engine}

    srv.should_exit = True
    await asyncio.to_thread(thread.join, timeout=15)


async def _collect(ws_url: str, token: str, run_id: str, after_seq: int,
                   stop_after_seq: int | None = None, idle: float = 3.0) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    async with websockets.connect(
        f"{ws_url}/api/v1/pentests/{run_id}/stream?after_seq={after_seq}",
        additional_headers={"Authorization": f"Bearer {token}"},
    ) as ws:
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=idle)
            except TimeoutError:
                break
            event = json.loads(raw)
            if "control" in event:
                continue
            events.append(event)
            if stop_after_seq is not None and event["seq"] >= stop_after_seq:
                break
    return events


async def test_packaged_renderer_origin_and_subprotocol_auth(server) -> None:
    headers = {"Authorization": f"Bearer {server['token']}"}
    async with httpx.AsyncClient(base_url=server["base"], headers=headers) as api:
        project = (await api.post("/api/v1/projects", json={"name": "native renderer"})).json()
        run = (await api.post("/api/v1/pentests", json={
            "project_id": project["project_id"], "name": "native", "task": "fixture",
        })).json()
    protocol = "rj-auth-" + base64.urlsafe_b64encode(server["token"].encode()).decode().rstrip("=")
    url = f"{server['ws']}/api/v1/pentests/{run['run_id']}/stream"
    async with websockets.connect(url, origin="file://", subprotocols=["redjohn-v1", protocol]) as ws:
        assert ws.subprotocol == protocol
        event = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        assert event["run_id"] == run["run_id"]
    async def disconnected():
        return await server["engine"].hub.subscriber_count(run["run_id"]) == 0

    await wait_for(disconnected, timeout=3)
    # A local file's Origin alone must never grant API access.
    with pytest.raises(websockets.exceptions.InvalidStatus):
        async with websockets.connect(url, origin="file://"):
            pytest.fail("unauthenticated renderer connected")


async def test_large_replay_sends_resync_then_resumes_from_snapshot(server) -> None:
    """Backlog overflow follows the wire contract and can recover immediately."""
    headers = {"Authorization": f"Bearer {server['token']}"}
    async with httpx.AsyncClient(base_url=server["base"], headers=headers) as api:
        project = (await api.post("/api/v1/projects", json={"name": "backlog"})).json()
        run = (await api.post("/api/v1/pentests", json={
            "project_id": project["project_id"], "name": "backlog", "task": "fixture",
        })).json()
        path = f"/api/v1/pentests/{run['run_id']}"
        for offset in range(0, 260, 20):
            replies = await asyncio.gather(*[
                api.post(f"{path}/messages", json={"to_agent_id": "user", "body": f"line {index}"})
                for index in range(offset, offset + 20)
            ])
            assert all(reply.status_code == 201 for reply in replies)
        async with websockets.connect(
            f"{server['ws']}{path}/stream?after_seq=0", additional_headers=headers,
        ) as ws:
            control = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert control["control"] == "resync_required"
            await ws.wait_closed()
            assert ws.close_code == 1013
        snapshot = (await api.get(f"{path}/snapshot")).json()
        async with websockets.connect(
            f"{server['ws']}{path}/stream?after_seq={snapshot['cursor']}",
            additional_headers=headers,
        ) as ws:
            await api.post(f"{path}/messages", json={"to_agent_id": "user", "body": "after recovery"})
            event = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert event["seq"] == snapshot["cursor"] + 1
            assert event["data"]["body"] == "after recovery"


async def test_ws_subprotocol_and_bearer_auth(server) -> None:
    """WS auth: Bearer header AND rj-auth-<base64url(token)> subprotocol both
    work (subprotocol echoed on accept); wrong tokens rejected."""
    import base64

    import websockets.exceptions

    base, ws_url, token = server["base"], server["ws"], server["token"]
    async with httpx.AsyncClient(base_url=base,
                                 headers={"Authorization": f"Bearer {token}"}) as api:
        project = (await api.post("/api/v1/projects", json={"name": "auth"})).json()
        run = (await api.post("/api/v1/pentests", json={
            "project_id": project["project_id"], "name": "auth-run", "task": "t",
        })).json()
    url = f"{ws_url}/api/v1/pentests/{run['run_id']}/stream"

    # 1. Bearer header path
    async with websockets.connect(
        url, additional_headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        assert ws.subprotocol is None  # header auth: no subprotocol echo

    # 2. subprotocol path (browser renderers cannot set headers)
    proto = "rj-auth-" + base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")
    async with websockets.connect(url, subprotocols=[proto]) as ws:
        assert ws.subprotocol == proto  # server echoes the accepted subprotocol

    # 3. wrong token via subprotocol -> rejected (pre-accept close -> 403 handshake)
    bad_proto = "rj-auth-" + base64.urlsafe_b64encode(b"wrong-token").decode().rstrip("=")
    try:
        async with websockets.connect(url, subprotocols=[bad_proto]):
            raise AssertionError("wrong subprotocol token was accepted")
    except websockets.exceptions.InvalidHandshake:
        pass

    # 4. wrong Bearer token -> rejected
    try:
        async with websockets.connect(
            url, additional_headers={"Authorization": "Bearer wrong-token"}
        ):
            raise AssertionError("wrong bearer token was accepted")
    except websockets.exceptions.InvalidHandshake:
        pass


async def test_ws_replay_live_handoff(server) -> None:
    base, ws_url, token = server["base"], server["ws"], server["token"]
    async with httpx.AsyncClient(base_url=base,
                                 headers={"Authorization": f"Bearer {token}"}) as api:
        project = (await api.post("/api/v1/projects", json={"name": "ws"})).json()
        await api.put(f"/api/v1/projects/{project['project_id']}/scope", json={
            "scope_id": "x", "project_id": project["project_id"], "version": 0,
            "allowed_targets": ["app.acme.test"], "allowed_tools": ["builtin:*"],
        })
        run = (await api.post("/api/v1/pentests", json={
            "project_id": project["project_id"], "name": "ws-run", "task": "t",
        })).json()

        # phase 1: connect before start, stream the whole scripted lifecycle live
        collector = asyncio.create_task(
            _collect(ws_url, token, run["run_id"], after_seq=0, idle=6.0)
        )
        await asyncio.sleep(0.5)  # let the subscription register
        await api.post(f"/api/v1/pentests/{run['run_id']}/start")
        live_events = await collector

        assert live_events, "expected streamed events"
        seqs = [e["seq"] for e in live_events]
        ids = [e["event_id"] for e in live_events]
        assert seqs == list(range(1, len(seqs) + 1)), f"gap in live stream: {seqs}"
        assert len(set(ids)) == len(ids), "duplicate event ids in live stream"

        total = seqs[-1]

        # phase 2: reconnect with after_seq mid-stream -> backlog then live,
        # no loss, no duplication across the handoff
        mid = total // 2
        await api.post(f"/api/v1/pentests/{run['run_id']}/messages", json={
            "to_agent_id": "user", "body": "post-reconnect ping",
        })
        replay = await _collect(ws_url, token, run["run_id"], after_seq=mid, idle=3.0)
        replay_seqs = [e["seq"] for e in replay]
        assert replay_seqs[0] == mid + 1
        assert replay_seqs == list(range(mid + 1, replay_seqs[-1] + 1))
        # union of live + replay is exactly 1..total+1 with overlap only in the
        # (mid, total] window — verify content equality on the overlap
        live_by_id = {e["event_id"]: e for e in live_events}
        for e in replay:
            if e["event_id"] in live_by_id:
                assert live_by_id[e["event_id"]]["seq"] == e["seq"]
        # the new message event arrived on the replayed stream (live handoff)
        assert any(e["type"] == "agent.message" and e["data"]["body"] == "post-reconnect ping"
                   for e in replay)

        # phase 3: snapshot cursor equals last event seq
        snap = (await api.get(f"/api/v1/pentests/{run['run_id']}/snapshot")).json()
        assert snap["cursor"] == replay_seqs[-1]

        await api.post(f"/api/v1/pentests/{run['run_id']}/stop")
