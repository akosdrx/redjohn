"""Actual SQLite/API pagination; OV results are explicit unit-test fixtures."""

from redjohn_core.db import skill_refs
from redjohn_core.models import SkillRef
from redjohn_core.ov.protocol import MemoryUnavailable, SkillHit


class SkillMemory:
    def __init__(self, hits=()):
        self.hits = hits

    async def find_skills(self, query, *, limit):
        if query == "unavailable":
            raise MemoryUnavailable("fixture outage")
        return self.hits

    async def close(self):
        pass


async def test_search_before_limit_and_count(api, engine, monkeypatch):
    monkeypatch.setattr("redjohn_core.api._memory", lambda _: SkillMemory())
    initial_total = await engine.store.count_skills()
    rows = []
    for i in range(205):
        skill = SkillRef(skill_id=f"skl_{i:05d}", name=f"catalog-{i:05d}", version="1",
                         description=f"needle-{i:05d}")
        rows.append({"skill_id": skill.skill_id, "name": skill.name, "data": skill.model_dump(mode="json")})
    async with engine.store.write() as session:
        await session.execute(skill_refs.insert(), rows)
    found = await api.get("/api/v1/skills", params={"query": "NEEDLE-00204", "limit": 50})
    assert found.status_code == 200
    assert [s["skill_id"] for s in found.json()["items"]] == ["skl_00204"]
    assert found.json()["total"] == 1
    first = (await api.get("/api/v1/skills", params={"limit": 200})).json()
    assert first["total"] == initial_total + 205
    last = (await api.get("/api/v1/skills", params={"cursor": first["next_cursor"]})).json()
    assert len(last["items"]) == initial_total + 5 and last["next_cursor"] is None
    assert (await api.get("/api/v1/skills", params={"query": "%"})).json()["total"] == 0
    assert (await api.get("/api/v1/skills", params={"limit": 0})).status_code == 422


async def test_unicode_catalog_and_semantic_results(api, engine, monkeypatch):
    monkeypatch.setattr("redjohn_core.api._memory", lambda _: SkillMemory())
    async with engine.store.write() as session:
        await engine.store.upsert_skill(session, SkillRef(name="ÁRVÍZ", version="1"))
    response = await api.get("/api/v1/skills", params={"query": "árvíz"})
    assert [x["name"] for x in response.json()["items"]] == ["ÁRVÍZ"]
    monkeypatch.setattr("redjohn_core.api._memory", lambda _: SkillMemory([
        SkillHit(uri="viking://skills/auth", name="authentication-testing", version="1",
                 description="Check for insecure sign-in patterns")]))
    response = await api.get("/api/v1/skills", params={"query": "inspect login"})
    assert [x["name"] for x in response.json()["items"]] == ["authentication-testing"]


async def test_ov_skill_refresh_is_idempotent_and_failure_visible(api, engine, monkeypatch):
    monkeypatch.setattr("redjohn_core.api._memory", lambda _: SkillMemory([
        SkillHit(uri="viking://skills/needle", name="needle", version="1")]))
    for _ in range(2):
        response = await api.get("/api/v1/skills", params={"query": "needle"})
        assert response.status_code == 200
        assert len(response.json()["items"]) == 1
        assert response.json()["total"] == 1
    response = await api.get("/api/v1/skills", params={"query": "unavailable"})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "memory_unavailable"
