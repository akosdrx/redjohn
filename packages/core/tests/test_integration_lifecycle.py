"""Integration (a): full lifecycle — create -> start -> coordinator spawns 2
specialists -> one specialist requests a child -> messages exchanged -> stop.
Runs the real engine with the fixture model provider (deterministic script).
"""

from __future__ import annotations

from .conftest import wait_for


async def test_full_lifecycle(api, engine, project) -> None:
    # --- create (scope pinned) ------------------------------------------------
    resp = await api.post("/api/v1/pentests", json={
        "project_id": project["project_id"], "name": "lifecycle", "task": "pentest app.acme.test",
    }, headers={"Idempotency-Key": "lc-create-1"})
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["status"] == "created"
    assert run["ref"] == "RJ-001"  # per-workspace sequence, zero-padded
    assert run["scope"]["version"] == 1
    assert run["scope"]["allowed_targets"] == ["app.acme.test"]

    # --- start -> coordinator at depth 0 ---------------------------------------
    resp = await api.post(f"/api/v1/pentests/{run['run_id']}/start",
                          headers={"Idempotency-Key": "lc-start-1"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "running"

    # --- wait for the whole scripted flow to play out ---------------------------
    async def lifecycle_done() -> bool:
        msgs = await engine.store.list_messages(run["run_id"])
        return any(m.to_agent_id == "user" and "lifecycle complete" in m.body for m in msgs)

    await wait_for(lifecycle_done, timeout=60)

    # --- agents: coordinator + 2 specialists + 1 worker (depth 2) ---------------
    agents = (await api.get(f"/api/v1/pentests/{run['run_id']}/agents")).json()["items"]
    by_name = {a["name"]: a for a in agents}
    assert set(by_name) == {"Coordinator", "Web", "Recon", "Worker"}
    assert by_name["Coordinator"]["depth"] == 0
    assert by_name["Web"]["depth"] == 1
    assert by_name["Recon"]["depth"] == 1
    assert by_name["Worker"]["depth"] == 2
    assert by_name["Worker"]["parent_agent_id"] == by_name["Web"]["agent_id"]
    assert by_name["Web"]["status"] == "complete"
    assert by_name["Recon"]["status"] == "complete"
    assert by_name["Worker"]["status"] == "complete"

    # --- messages exchanged ------------------------------------------------------
    msgs = await engine.store.list_messages(run["run_id"])
    web, coord = by_name["Web"]["agent_id"], by_name["Coordinator"]["agent_id"]
    recon = by_name["Recon"]["agent_id"]
    assert any(m.body == "web results ready" and m.from_agent_id == web and m.to_agent_id == coord
               for m in msgs)
    assert any(m.body == "recon results ready" and m.from_agent_id == recon and m.to_agent_id == coord
               for m in msgs)
    # completion auto-share: summary + evidence refs to parent
    worker_done = [m for m in msgs if m.from_agent_id == by_name["Worker"]["agent_id"]
                   and m.kind == "result"]
    assert worker_done and worker_done[0].summary_ref

    # --- findings + evidence -------------------------------------------------------
    findings = (await api.get(f"/api/v1/pentests/{run['run_id']}/findings")).json()["items"]
    assert [f["code"] for f in findings] == ["F-001"]
    assert findings[0]["severity"] == "low"

    invs = await engine.store.list_invocations(run["run_id"])
    exec_inv = [i for i in invs if i.tool == "builtin:exec"]
    assert len(exec_inv) == 1 and exec_inv[0].exit_code == 0
    ev = await engine.store.get_evidence(exec_inv[0].output_ref)
    from pathlib import Path

    assert b"worker ran on app.acme.test" in Path(
        engine.settings.evidence_dir / ev.storage_ref).read_bytes()

    # --- evidence list route (v0.1.1) ---------------------------------------------
    page = (await api.get("/api/v1/evidence", params={"run_id": run["run_id"]})).json()
    assert any(e["evidence_id"] == ev.evidence_id for e in page["items"])
    assert "next_cursor" in page
    missing = await api.get("/api/v1/evidence", params={"run_id": "run_missing"})
    assert missing.status_code == 404

    # --- events: contiguous per-run seq --------------------------------------------
    async def coordinator_idle() -> bool:
        current = await engine.store.get_agent(coord)
        task = engine._runners.get(coord)
        return current.current_activity.startswith("idle") and (task is None or task.done())

    await wait_for(coordinator_idle)
    events = (await api.get(f"/api/v1/pentests/{run['run_id']}/events",
                            params={"limit": 200})).json()
    seqs = [e["seq"] for e in events["items"]]
    assert seqs == list(range(1, len(seqs) + 1))
    snapshot = (await api.get(f"/api/v1/pentests/{run['run_id']}/snapshot")).json()
    assert snapshot["cursor"] == max(seqs)

    # --- stop: delegation blocked, children stopped, findings remain ---------------
    resp = await api.post(f"/api/v1/pentests/{run['run_id']}/stop")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "stopped"

    agents = (await api.get(f"/api/v1/pentests/{run['run_id']}/agents")).json()["items"]
    assert all(a["status"] in ("stopped", "complete") for a in agents)

    # delegation rejected after stop
    resp = await api.post(f"/api/v1/pentests/{run['run_id']}/agents", json={
        "parent_agent_id": coord, "name": "late", "role": "specialist", "task": "too late",
    })
    assert resp.status_code == 409

    # findings remain readable after stop
    findings = (await api.get(f"/api/v1/pentests/{run['run_id']}/findings")).json()["items"]
    assert findings[0]["code"] == "F-001"
    f = (await api.get(f"/findings/{findings[0]['finding_id']}".replace("/findings", "/api/v1/findings")))
    assert f.status_code == 200

    # run is terminal; restart conflicts
    resp = await api.post(f"/api/v1/pentests/{run['run_id']}/start")
    assert resp.status_code == 409

    # second run in the same workspace increments the human ref
    r2 = (await api.post("/api/v1/pentests", json={
        "project_id": project["project_id"], "name": "second", "task": "t",
    })).json()
    assert r2["ref"] == "RJ-002"


async def test_reports_generated(api, engine, project) -> None:
    run = (await api.post("/api/v1/pentests", json={
        "project_id": project["project_id"], "name": "report-run", "task": "t",
    })).json()
    await api.post(f"/api/v1/pentests/{run['run_id']}/start")
    async def idle() -> bool:
        agents = await engine.store.list_agents(run["run_id"])
        return agents and agents[0].current_activity.startswith("idle")
    await wait_for(idle, timeout=30)

    r = await api.post(f"/api/v1/pentests/{run['run_id']}/reports", json={"format": "json"})
    assert r.status_code == 201, r.text
    report = r.json()
    assert report["format"] == "json"
    content = (engine.settings.reports_dir / report["storage_ref"]).read_text()
    import json as jsonlib

    data = jsonlib.loads(content)
    assert data["run"]["run_id"] == run["run_id"]

    r = await api.post(f"/api/v1/pentests/{run['run_id']}/reports", json={"format": "html"})
    assert r.status_code == 201
    html = (engine.settings.reports_dir / r.json()["storage_ref"]).read_text()
    assert "RedJohn pentest report" in html

    got = await api.get(f"/api/v1/reports/{report['report_id']}")
    assert got.status_code == 200 and got.json()["run_id"] == run["run_id"]

    # reports list route (v0.1.1): json + html reports for this run
    page = (await api.get("/api/v1/reports", params={"run_id": run["run_id"]})).json()
    formats = {r["format"] for r in page["items"]}
    assert {"json", "html"} <= formats
    assert all(r["run_id"] == run["run_id"] for r in page["items"])
    # cursor pagination: limit=1 pages through both
    p1 = (await api.get("/api/v1/reports", params={"run_id": run["run_id"], "limit": 1})).json()
    assert len(p1["items"]) == 1 and p1["next_cursor"]
    p2 = (await api.get("/api/v1/reports", params={"run_id": run["run_id"], "limit": 1,
                                                   "cursor": p1["next_cursor"]})).json()
    assert p2["items"] and p2["items"][0]["report_id"] != p1["items"][0]["report_id"]

    # pdf extra not installed in this environment -> typed error, not a crash
    r = await api.post(f"/api/v1/pentests/{run['run_id']}/reports", json={"format": "pdf"})
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "report_format_unavailable"
