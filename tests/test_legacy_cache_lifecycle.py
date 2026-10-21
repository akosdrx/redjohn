"""Real SQLite/cache/concurrency tests and explicit sandbox/provider contracts.

The local HTTP test uses an owned loopback server. Sandbox lifecycle and upstream
advisory error tests use injected doubles; they are not live Docker/OSV/NVD tests.
"""

import asyncio
import gc
import json
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from agents.tool_context import ToolContext

from redjohn.assessment.cache import CacheBusyError
from redjohn.assessment.resources import ProcessTreeMemory, ResourceGovernor
from redjohn.runtime import session_manager as sessions
from redjohn.tools.cve import tool
from redjohn.tools.cve.cache import CveCache


def cache_for(tmp_path, **kwargs):
    return CveCache(tmp_path / "cache.sqlite3", **kwargs)


def test_ram_lru_bytes_oversize_and_mutation_isolation(tmp_path):
    cache = cache_for(tmp_path, max_bytes=21, max_items=2)
    cache._sqlite_ok = False
    assert cache.set("a", {"a": 1})
    assert cache.set("b", {"b": 2})
    assert cache.get("a") == {"a": 1}
    assert cache.set("c", {"c": 3})
    assert cache.get("b") is None
    assert cache.get("a") == {"a": 1}
    assert not cache.set("huge", "x" * 30)
    copy = cache.get("a")
    copy["a"] = 999
    assert cache.get("a") == {"a": 1}
    assert cache.stats()["bytes"] == 14
    assert cache.stats()["items"] == 2
    assert cache.stats()["eviction"] == 1
    assert cache.stats()["oversized"] == 1


def test_ttl_expires_both_ram_and_sqlite(tmp_path):
    clock = [100.0]
    cache = cache_for(tmp_path, wall_clock=lambda: clock[0], memory_clock=lambda: clock[0])
    assert cache.set("entry", {"source": "controlled"}, 2)
    assert cache.get("entry") == {"source": "controlled"}
    clock[0] += 3
    assert cache.get("entry") is None
    assert cache.stats()["bytes"] == 0
    with sqlite3.connect(cache.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0] == 0


def test_disk_lru_budget_and_query_keys_are_hashed(tmp_path):
    clock = [100.0]
    cache = cache_for(tmp_path, disk_max_bytes=16, disk_max_items=2, wall_clock=lambda: clock[0])
    for key in ("a", "b", "c"):
        clock[0] += 1
        assert cache.set(key, {"v": key})
    with sqlite3.connect(cache.db_path) as conn:
        rows = conn.execute("SELECT cache_key, payload_json FROM cve_cache").fetchall()
    # Nine bytes each: the serialized disk-byte cap admits one, not two.
    assert len(rows) == 1
    assert rows[0][0] == CveCache._key("c")
    assert len(rows[0][0]) == 64
    assert json.loads(rows[0][1]) == {"v": "c"}
    fresh = cache_for(tmp_path, wall_clock=lambda: clock[0])
    assert fresh.get("a") is None
    assert fresh.get("c") == {"v": "c"}
    assert cache.db_path.stat().st_mode & 0o777 == 0o600


def test_existing_sqlite_schema_migrates_without_removing_fresh_entry(tmp_path):
    path = tmp_path / "cache.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE cve_cache "
            "(cache_key TEXT PRIMARY KEY, payload_json TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
        conn.execute(
            "INSERT INTO cve_cache VALUES (?, ?, ?)",
            (CveCache._key("known"), '{"source":"fixture"}', 200.0),
        )
    cache = cache_for(tmp_path, wall_clock=lambda: 100.0)
    assert cache.get("known") == {"source": "fixture"}
    with sqlite3.connect(path) as conn:
        assert "accessed_at" in {row[1] for row in conn.execute("PRAGMA table_info(cve_cache)")}


def test_error_results_and_invalid_ttls_never_cache(tmp_path):
    cache = cache_for(tmp_path)
    assert not cache.set("outage", {"success": False, "error": "429"})
    for ttl in (0.0, -1.0, float("nan"), float("inf")):
        assert not cache.set("bad-ttl", {}, ttl)
    assert cache.get("outage") is None
    assert cache.get("bad-ttl") is None
    with sqlite3.connect(cache.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0] == 0


def test_shared_governor_budget_and_pressure_trim_actual_bytes(tmp_path):
    cache = cache_for(tmp_path, max_bytes=100)
    assert cache.set("a", "a" * 20)
    assert cache.set("b", "b" * 20)
    cache.restrict_budget(25)
    assert cache.max_bytes == 25
    assert cache.stats()["bytes"] == 22
    assert not cache.set("oversize-after-shrink", "x" * 26)
    cache.restrict_budget(100, pressure=True)
    assert cache.max_bytes == 25
    assert cache.stats()["bytes"] == 0
    assert cache.set("disk-only", {"fresh": 1})
    assert cache.get("disk-only") == {"fresh": 1}
    assert cache.stats()["bytes"] == 0


def test_refresh_expired_before_publication_leaves_ram_and_disk_untouched(tmp_path):
    cache = cache_for(tmp_path)
    assert not cache.set("late", {"late": True}, _deadline=time.monotonic() - 1)
    assert cache.get("late") is None
    assert cache.stats()["items"] == 0
    with sqlite3.connect(cache.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0] == 0


def test_sqlite_connections_close_without_waiting_for_garbage_collection(tmp_path):
    cache = cache_for(tmp_path, max_items=2)
    fd_root = Path("/proc/self/fd") if Path("/proc/self/fd").is_dir() else Path("/dev/fd")
    if not fd_root.is_dir():
        pytest.skip("process file descriptor inventory unavailable")
    before = len(tuple(fd_root.iterdir()))
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        for index in range(100):
            assert cache.set(f"entry-{index}", {"index": index})
            assert cache.get(f"entry-{index}") == {"index": index}
        assert len(tuple(fd_root.iterdir())) <= before + 1
    finally:
        if was_enabled:
            gc.enable()


async def test_bounded_singleflight_cancellation_and_waiter_deadline(tmp_path):
    cache = cache_for(tmp_path, max_refreshes=1)
    started, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def load():
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return {"value": 42}

    first = asyncio.create_task(cache.get_or_refresh("same", load, 60))
    await started.wait()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    with pytest.raises(TimeoutError):
        await cache.get_or_refresh("same", load, 60, waiter_timeout=0.01)
    with pytest.raises(CacheBusyError):
        await cache.get_or_refresh("other", load, 60)
    second = asyncio.create_task(cache.get_or_refresh("same", load, 60))
    await asyncio.sleep(0)
    release.set()
    result, _ = await second
    assert result == {"value": 42}
    assert calls == 1
    assert cache.stats()["inflight"] == 0
    assert cache.stats()["refresh_rejected"] == 1


async def test_expired_refresh_never_publishes_and_slot_is_released(tmp_path):
    cache = cache_for(tmp_path, max_refreshes=1)

    async def too_slow():
        await asyncio.sleep(60)
        return {"late": True}

    with pytest.raises(TimeoutError):
        await cache.get_or_refresh("late", too_slow, 60, refresh_timeout=0.01)
    assert cache.get("late") is None
    assert cache.stats()["inflight"] == 0

    async def fresh():
        return {"current": True}

    assert (await cache.get_or_refresh("fresh", fresh, 60))[0] == {"current": True}


async def test_refresh_retains_shared_governor_lease_after_waiter_cancellation(tmp_path):
    governor = ResourceGovernor(memory_reader=lambda: ProcessTreeMemory(0, 0, 1, time.time()))
    cache = cache_for(tmp_path)
    started, release = asyncio.Event(), asyncio.Event()

    async def load():
        started.set()
        await release.wait()
        return {"controlled": True}

    waiter = asyncio.create_task(
        cache.get_or_refresh(
            "shared",
            load,
            60,
            admit=lambda: governor.acquire("worker", 1024, owner_process_only=True),
        )
    )
    await started.wait()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert governor.snapshot()["active"] == {"worker": 1}
    release.set()
    assert (await cache.get_or_refresh("shared", load, 60))[0] == {"controlled": True}
    assert governor.snapshot()["active"] == {}
    governor.close()


@pytest.mark.parametrize("partial", [False, True])
async def test_mock_provider_outage_is_not_a_cached_negative(tmp_path, monkeypatch, partial):
    cache = cache_for(tmp_path)
    real_client = httpx.AsyncClient

    def route(request):
        if partial and request.url.host == "api.osv.dev":
            return httpx.Response(200, json={"vulns": []})
        return httpx.Response(503, json={"error": "fixture provider unavailable"})

    monkeypatch.setattr(tool, "_CACHE", cache)
    monkeypatch.setattr(
        tool.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(route), **kwargs),
    )
    result = await tool._lookup_product_or_package("owned-package", "1.0", "npm")
    assert result["success"] is False
    assert result["coverage_status"] == "blocked"
    assert cache.stats()["items"] == 0
    assert cache.stats()["inflight"] == 0


async def test_mock_cve_outage_cannot_turn_into_a_successful_record(tmp_path, monkeypatch):
    cache = cache_for(tmp_path)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(tool, "_CACHE", cache)
    monkeypatch.setattr(
        tool.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(lambda _req: httpx.Response(429)), **kwargs
        ),
    )
    result = await tool._lookup_single_cve("CVE-2026-12345")
    assert result["success"] is False
    assert result["error"] == "advisory_not_available"
    assert cache.stats()["items"] == 0


async def test_mock_complete_empty_intelligence_is_cacheable_with_freshness(tmp_path, monkeypatch):
    cache = cache_for(tmp_path)
    real_client = httpx.AsyncClient
    calls = []

    def route(request):
        calls.append(request.url.host)
        if request.url.host == "api.osv.dev":
            body = {"vulns": []}
        elif request.url.host in {"services.nvd.nist.gov", "www.cisa.gov"}:
            body = {"vulnerabilities": []}
        else:
            body = {"data": []}
        return httpx.Response(200, json=body)

    monkeypatch.setattr(tool, "_CACHE", cache)
    monkeypatch.setattr(
        tool.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(route), **kwargs),
    )
    result = await tool._lookup_product_or_package("owned-package", "1.0", "npm")
    assert result["success"] is True
    assert result["total_matches"] == 0
    assert result["source_status"]["coverage_status"] == "completed"
    assert result["retrieved_at"]
    first_count = len(calls)
    cached = await tool._lookup_product_or_package("owned-package", "1.0", "npm")
    assert cached["cache_hit"] is True
    assert len(calls) == first_count


async def test_mock_product_cache_keeps_case_sensitive_versions_separate(tmp_path, monkeypatch):
    cache = cache_for(tmp_path)
    calls = []

    async def fetch(pkg, version, ecosystem):
        calls.append((pkg, version, ecosystem))
        return {"success": True, "version": version}

    monkeypatch.setattr(tool, "_CACHE", cache)
    monkeypatch.setattr(tool, "_fetch_product_or_package", fetch)
    assert (await tool._lookup_product_or_package("Owned", "1.0-BETA", "Maven"))["version"] == (
        "1.0-BETA"
    )
    assert (await tool._lookup_product_or_package("Owned", "1.0-beta", "Maven"))["version"] == (
        "1.0-beta"
    )
    assert len(calls) == 2


async def test_mock_kev_catalog_expires_and_refreshes_instead_of_living_forever(
    tmp_path, monkeypatch
):
    clock = [100.0]
    cache = cache_for(tmp_path, wall_clock=lambda: clock[0], memory_clock=lambda: clock[0])
    calls = []

    def route(_request):
        calls.append(True)
        return httpx.Response(
            200,
            json={"vulnerabilities": [{"cveID": "CVE-2026-12345", "product": "owned-fixture"}]},
        )

    monkeypatch.setattr(tool, "_CACHE", cache)
    async with httpx.AsyncClient(transport=httpx.MockTransport(route)) as client:
        first = await tool._get_kev_catalog(client)
        assert first["CVE-2026-12345"]["product"] == "owned-fixture"
        assert await tool._get_kev_catalog(client) == first
        assert len(calls) == 1
        clock[0] += 43201
        refreshed = await tool._get_kev_catalog(client)
        assert refreshed["CVE-2026-12345"]["product"] == "owned-fixture"
        assert refreshed["CVE-2026-12345"]["source"] == "CISA KEV"
        assert len(calls) == 2


async def test_mock_provider_decoded_body_limit_is_enforced_before_json(monkeypatch):
    monkeypatch.setattr(tool, "_RESPONSE_MAX_BYTES", 64)
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"x" * 65))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ValueError, match="body_limit_exceeded"):
            await tool._bounded_request(client, "GET", "https://controlled-fixture.invalid/feed")


async def test_mock_malformed_provider_collection_is_not_cached_as_empty(tmp_path, monkeypatch):
    cache = cache_for(tmp_path)
    real_client = httpx.AsyncClient

    def route(request):
        if request.url.host == "api.osv.dev":
            return httpx.Response(200, json={"vulns": "malformed fixture"})
        return httpx.Response(200, json={"vulnerabilities": []})

    monkeypatch.setattr(tool, "_CACHE", cache)
    monkeypatch.setattr(
        tool.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(route), **kwargs),
    )
    wrapper = ToolContext(
        context={},
        tool_name="lookup_cve",
        tool_call_id="owned-provider-schema-contract",
        tool_arguments="{}",
    )
    encoded = await tool.lookup_cve.on_invoke_tool(
        wrapper, json.dumps({"product": "owned-package", "version": "1.0", "ecosystem": "npm"})
    )
    result = json.loads(encoded)
    assert result["success"] is False
    assert result["error"] == "advisory_refresh_unavailable"
    # The independently valid KEV empty catalog may cache, the malformed
    # package query must not become an empty successful lookup.
    key = json.dumps(["pkg_lookup", "owned-package", "1.0", "npm"], separators=(",", ":"))
    assert cache.get(key) is None
    assert cache.stats()["inflight"] == 0


@pytest.fixture
def _isolated_sessions(monkeypatch):
    monkeypatch.setattr(sessions, "_SESSION_CACHE", {})
    monkeypatch.setattr(sessions, "_SESSION_STARTING", set())
    monkeypatch.setattr(sessions, "_SESSION_DISCARDING", set())
    monkeypatch.setattr(sessions, "_CLEANUP_TASKS", {})
    monkeypatch.setattr(sessions, "_DISCARD_TASKS", set())
    monkeypatch.setenv("REDJOHN_MAX_CACHED_SESSIONS", "2")


def bundle_for(delete):
    return {
        "client": SimpleNamespace(delete=delete),
        "session": object(),
        "caido_client": SimpleNamespace(aclose=AsyncMock()),
        "protected_host_paths": (),
    }


async def test_mock_session_cleanup_serializes_delete_and_reuse(_isolated_sessions, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()

    async def delete(_session):
        entered.set()
        await release.wait()

    old = bundle_for(delete)
    sessions._SESSION_CACHE["scan"] = old
    cleanup = asyncio.create_task(sessions.cleanup("scan"))
    await entered.wait()
    created = []

    async def create(scan_id, **_kwargs):
        assert scan_id not in sessions._SESSION_CACHE
        created.append(True)
        fresh = bundle_for(AsyncMock())
        sessions._SESSION_CACHE[scan_id] = fresh
        return fresh

    monkeypatch.setattr(sessions, "_create_or_reuse_locked", create)
    reuse = asyncio.create_task(sessions.create_or_reuse("scan", image="double", local_sources=[]))
    await asyncio.sleep(0)
    assert not created
    assert sessions._SESSION_CACHE["scan"] is old
    release.set()
    await cleanup
    fresh = await reuse
    assert fresh is not old
    await sessions.cleanup("scan")


async def test_mock_failed_delete_keeps_ownership_and_retry_closes(_isolated_sessions):
    delete = AsyncMock(side_effect=[RuntimeError("owned-delete-failure"), None])
    bundle = bundle_for(delete)
    sessions._SESSION_CACHE["scan"] = bundle
    with pytest.raises(RuntimeError, match="owned-delete-failure"):
        await sessions.cleanup("scan")
    assert sessions._SESSION_CACHE["scan"] is bundle
    assert sessions.lifecycle_snapshot()["cleanup_failed"] == 1
    with pytest.raises(RuntimeError, match="cleanup_incomplete"):
        await sessions.create_or_reuse("scan", image="double", local_sources=[])
    await sessions.cleanup("scan")
    assert sessions._SESSION_CACHE == {}
    assert delete.await_count == 2


async def test_mock_cancelled_cleanup_keeps_running_until_owned_delete_finishes(_isolated_sessions):
    entered, release = asyncio.Event(), asyncio.Event()

    async def delete(_session):
        entered.set()
        await release.wait()

    sessions._SESSION_CACHE["scan"] = bundle_for(delete)
    waiter = asyncio.create_task(sessions.cleanup("scan"))
    await entered.wait()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert sessions.lifecycle_snapshot()["cleanup_tasks"] == 1
    assert sessions.lifecycle_snapshot()["active_sessions"] == 1
    release.set()
    await sessions.cleanup("scan")
    await asyncio.sleep(0)
    assert sessions.lifecycle_snapshot()["cleanup_tasks"] == 0
    assert sessions.lifecycle_snapshot()["active_sessions"] == 0


async def test_mock_active_session_capacity_never_evicts(_isolated_sessions):
    a, b = bundle_for(AsyncMock()), bundle_for(AsyncMock())
    sessions._SESSION_CACHE.update(a=a, b=b)
    with pytest.raises(sessions.SessionCapacityError):
        await sessions.create_or_reuse("third", image="double", local_sources=[])
    assert await sessions.create_or_reuse("a", image="double", local_sources=[]) is a
    assert {"a": a, "b": b} == sessions._SESSION_CACHE
    await sessions.cleanup("a")
    await sessions.cleanup("b")


async def test_mock_many_completed_sessions_release_historical_locks(
    _isolated_sessions, monkeypatch
):
    async def create(scan_id, **_kwargs):
        bundle = bundle_for(AsyncMock())
        sessions._SESSION_CACHE[scan_id] = bundle
        return bundle

    monkeypatch.setattr(sessions, "_create_or_reuse_locked", create)
    for index in range(200):
        await sessions.create_or_reuse(f"scan-{index}", image="double", local_sources=[])
        await sessions.cleanup(f"scan-{index}")
    await asyncio.sleep(0)
    gc.collect()
    snapshot = sessions.lifecycle_snapshot()
    assert snapshot["active_sessions"] == 0
    assert snapshot["locks"] == 0
    assert snapshot["cleanup_tasks"] == 0


async def test_mock_cancelled_provisioning_stays_owned_until_discard(_isolated_sessions):
    release = asyncio.Event()
    client = SimpleNamespace(delete=AsyncMock())
    session = object()

    async def create():
        await release.wait()
        return client, session

    pending = asyncio.create_task(sessions._create_or_discard(create(), scan_id="starting"))
    await asyncio.sleep(0)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert sessions.lifecycle_snapshot()["discarding_sessions"] == 1
    with pytest.raises(sessions.SessionCapacityError, match="still_owned"):
        await sessions.create_or_reuse("starting", image="double", local_sources=[])
    release.set()
    await asyncio.gather(*sessions._DISCARD_TASKS)
    client.delete.assert_awaited_once_with(session)
    assert sessions.lifecycle_snapshot()["discarding_sessions"] == 0


async def test_mock_failed_half_start_discard_remains_retryable(_isolated_sessions):
    client = SimpleNamespace(delete=AsyncMock(side_effect=[RuntimeError("delete-failed"), None]))
    session = object()
    await sessions._discard_session(client, session, scan_id="half-started")
    assert sessions._SESSION_CACHE["half-started"]["session"] is session
    assert sessions.lifecycle_snapshot()["cleanup_failed"] == 1
    await sessions.cleanup("half-started")
    assert sessions._SESSION_CACHE == {}


async def test_mock_cleanup_timeout_preserves_resource_and_releases_registry(
    _isolated_sessions, monkeypatch
):
    entered = asyncio.Event()

    async def never_finishes(_session):
        entered.set()
        await asyncio.sleep(60)

    bundle = bundle_for(never_finishes)
    sessions._SESSION_CACHE["timed-out"] = bundle
    monkeypatch.setattr(sessions, "_CLEANUP_TIMEOUT_SECONDS", 0.01)
    with pytest.raises(TimeoutError):
        await sessions.cleanup("timed-out")
    assert entered.is_set()
    assert sessions._SESSION_CACHE["timed-out"] is bundle
    await asyncio.sleep(0)
    assert sessions.lifecycle_snapshot()["cleanup_tasks"] == 0
    assert sessions.lifecycle_snapshot()["cleanup_failed"] == 1
    bundle["client"].delete = AsyncMock()
    await sessions.cleanup("timed-out")
    assert sessions.lifecycle_snapshot()["active_sessions"] == 0


async def test_mock_provisioning_reservations_are_bounded_across_scan_ids(
    _isolated_sessions, monkeypatch
):
    release = asyncio.Event()
    started = asyncio.Event()

    async def create(scan_id, **_kwargs):
        if len(sessions._SESSION_STARTING) == 2:
            started.set()
        await release.wait()
        bundle = bundle_for(AsyncMock())
        sessions._SESSION_CACHE[scan_id] = bundle
        return bundle

    monkeypatch.setattr(sessions, "_create_or_reuse_locked", create)
    first = asyncio.create_task(sessions.create_or_reuse("a", image="double", local_sources=[]))
    second = asyncio.create_task(sessions.create_or_reuse("b", image="double", local_sources=[]))
    await started.wait()
    with pytest.raises(sessions.SessionCapacityError):
        await sessions.create_or_reuse("c", image="double", local_sources=[])
    release.set()
    await asyncio.gather(first, second)
    assert sessions.lifecycle_snapshot()["provisioning"] == 0
    await sessions.cleanup("a")
    await sessions.cleanup("b")


async def test_mock_provision_timeout_keeps_late_result_owned_for_discard(
    _isolated_sessions, monkeypatch
):
    release = asyncio.Event()
    client = SimpleNamespace(delete=AsyncMock())
    session = object()

    async def create():
        await release.wait()
        return client, session

    monkeypatch.setattr(sessions, "_PROVISION_TIMEOUT_SECONDS", 0.01)
    with pytest.raises(TimeoutError):
        await sessions._create_or_discard(create(), scan_id="late-provision")
    assert sessions.lifecycle_snapshot()["discarding_sessions"] == 1
    release.set()
    await asyncio.gather(*sessions._DISCARD_TASKS)
    client.delete.assert_awaited_once_with(session)
    assert sessions.lifecycle_snapshot()["discarding_sessions"] == 0
