"""Bounded advisory cache; neither evidence nor a cached validation result.

RAM quotas count serialized JSON bytes. Object/key overhead is bounded by the
entry cap. Disk quotas count payload bytes, excluding SQLite page/WAL overhead.
Provider calls remain subject to their own deadlines in addition to the shared
refresh deadline. A cancelled waiter never cancels another caller's refresh.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import math
import os
import sqlite3
import threading
import time
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.cache import CacheBusyError, SmartCache


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator

    from redjohn.assessment.resources import ResourceLease


logger = logging.getLogger(__name__)
MIB = 1024 * 1024
_CACHE_VERSION = "advisory-v2"


class CveCache:
    """One bounded, expiring cache shared by legacy CVE/OSV/NVD/KEV lookups."""

    def __init__(
        self,
        db_path: Path | None = None,
        default_ttl_seconds: int = 21600,
        *,
        max_bytes: int = 8 * MIB,
        max_items: int = 128,
        disk_max_bytes: int = 64 * MIB,
        disk_max_items: int = 4096,
        max_refreshes: int = 8,
        wall_clock: Callable[[], float] = time.time,
        memory_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if any(
            type(value) is not int or value <= 0
            for value in (
                default_ttl_seconds,
                max_bytes,
                max_items,
                disk_max_bytes,
                disk_max_items,
                max_refreshes,
            )
        ):
            raise ValueError("CVE cache quotas and TTL must be positive integers")
        env_path = os.environ.get("REDJOHN_CVE_CACHE_DB", "").strip()
        self.db_path = db_path or (
            Path(env_path) if env_path else Path.home() / ".redjohn" / "cve_cache.sqlite3"
        )
        self.default_ttl = default_ttl_seconds
        self.max_bytes = max_bytes
        self.disk_max_bytes, self.disk_max_items = disk_max_bytes, disk_max_items
        self.max_refreshes = max_refreshes
        self._wall_clock = wall_clock
        self._mem = SmartCache(max_bytes, max_items, clock=memory_clock)
        self._lock = threading.RLock()
        self._flights: dict[tuple[asyncio.AbstractEventLoop, str], asyncio.Task[Any]] = {}
        self._metrics: Counter[str] = Counter()
        self._sqlite_ok = False
        self._pressure = False
        self._init_db()

    @staticmethod
    def _key(key: str) -> str:
        if not isinstance(key, str) or len(key.encode()) > 4096:
            raise ValueError("CVE cache lookup reference exceeds its limit")
        # Package searches can contain private names. Neither SQLite keys nor
        # metric labels contain the raw query, URL, cookie, token or API key.
        return hashlib.sha256(f"{_CACHE_VERSION}:{key}".encode()).hexdigest()

    def _serialize(self, value: Any) -> str | None:
        payload = bytearray()
        encoder = json.JSONEncoder(ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        for chunk in encoder.iterencode(value):
            if len(payload) + len(chunk) > self.max_bytes:
                self._metrics["oversized"] += 1
                return None
            payload.extend(chunk.encode("ascii"))
        return payload.decode("ascii")

    def _expired_refresh(self, deadline: float | None) -> bool:
        if deadline is not None and time.monotonic() >= deadline:
            self._metrics["refresh_expired"] += 1
            return True
        return False

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # Connection.__exit__ commits/rolls back but does not close the FD.
        with contextlib.closing(sqlite3.connect(self.db_path, timeout=1.0)) as conn:
            conn.execute("PRAGMA busy_timeout=1000")
            conn.execute("PRAGMA cache_size=-2048")
            conn.execute("PRAGMA temp_store=FILE")
            with conn:
                yield conn

    def _init_db(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS cve_cache ("
                    "cache_key TEXT PRIMARY KEY, payload_json TEXT NOT NULL, "
                    "expires_at REAL NOT NULL, accessed_at REAL NOT NULL DEFAULT 0)"
                )
                columns = {row[1] for row in conn.execute("PRAGMA table_info(cve_cache)")}
                if "accessed_at" not in columns:
                    conn.execute(
                        "ALTER TABLE cve_cache ADD COLUMN accessed_at REAL NOT NULL DEFAULT 0"
                    )
                self._prune(conn)
            self.db_path.chmod(0o600)
            self._sqlite_ok = True
        except (OSError, sqlite3.Error):
            logger.debug("Advisory disk cache unavailable; bounded RAM cache remains active")

    def _prune(self, conn: sqlite3.Connection) -> None:
        conn.execute("DELETE FROM cve_cache WHERE expires_at <= ?", (self._wall_clock(),))
        # Prune entirely in SQLite: an old unbounded database must not create
        # an unbounded Python list of expired/evicted keys during migration.
        oversized = conn.execute(
            "DELETE FROM cve_cache WHERE LENGTH(CAST(payload_json AS BLOB)) > ?",
            (self.disk_max_bytes,),
        ).rowcount
        evicted = conn.execute(
            "DELETE FROM cve_cache WHERE cache_key IN ("
            "SELECT cache_key FROM ("
            "SELECT cache_key, ROW_NUMBER() OVER (ORDER BY accessed_at DESC, rowid DESC) AS rank, "
            "SUM(LENGTH(CAST(payload_json AS BLOB))) OVER "
            "(ORDER BY accessed_at DESC, rowid DESC) AS running_size FROM cve_cache"
            ") WHERE rank > ? OR running_size > ?)",
            (self.disk_max_items, self.disk_max_bytes),
        ).rowcount
        self._metrics["disk_eviction"] += oversized + evicted

    def get(self, key: str) -> Any | None:
        digest = self._key(key)
        with self._lock:
            value = self._mem.get(digest)
            if value is not None or not self._sqlite_ok:
                return value
            try:
                with self._connect() as conn:
                    self._prune(conn)
                    # Reject legacy/foreign oversized rows before transferring
                    # their blob from SQLite into the Python process.
                    row = conn.execute(
                        "SELECT payload_json, expires_at FROM cve_cache "
                        "WHERE cache_key = ? AND LENGTH(CAST(payload_json AS BLOB)) <= ?",
                        (digest, self.max_bytes),
                    ).fetchone()
                    if row is None:
                        return None
                    payload, expires = row
                    value = json.loads(payload)
                    remaining = float(expires) - self._wall_clock()
                    if remaining <= 0:
                        return None
                    if not self._pressure:
                        self._mem.set(digest, value, remaining)
                    conn.execute(
                        "UPDATE cve_cache SET accessed_at = ? WHERE cache_key = ?",
                        (self._wall_clock(), digest),
                    )
                    self._metrics["disk_hit"] += 1
                    return value
            except (OSError, sqlite3.Error, ValueError, TypeError):
                self._metrics["disk_error"] += 1
                return None

    def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: float | None = None,
        *,
        _deadline: float | None = None,
    ) -> bool:
        ttl = self.default_ttl if ttl_seconds is None else ttl_seconds
        if not math.isfinite(ttl) or ttl <= 0:
            return False
        # A provider outage, parser error or unsupported lookup cannot become a
        # cached successful negative. KEV's map has no success field.
        if isinstance(value, dict) and value.get("success") is False:
            return False
        digest = self._key(key)
        with self._lock:
            payload = self._serialize(value)
            if payload is None or self._expired_refresh(_deadline):
                return False
            if self._sqlite_ok:
                try:
                    with self._connect() as conn:
                        now = self._wall_clock()
                        conn.execute(
                            "INSERT OR REPLACE INTO cve_cache "
                            "(cache_key, payload_json, expires_at, accessed_at) "
                            "VALUES (?, ?, ?, ?)",
                            (digest, payload, now + ttl, now),
                        )
                        self._prune(conn)
                        if self._expired_refresh(_deadline):
                            conn.rollback()
                            return False
                except (OSError, sqlite3.Error):
                    self._metrics["disk_error"] += 1
            if self._expired_refresh(_deadline):
                return False
            return self._pressure or self._mem.set(digest, value, ttl)

    def restrict_budget(self, max_bytes: int, *, pressure: bool = False) -> None:
        """Respect the shared governor; never grow a process cache mid-scan."""
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError("CVE memory quota must be positive")
        with self._lock:
            self.max_bytes = min(self.max_bytes, max_bytes)
            self._pressure = pressure
            self._mem.max_bytes = self.max_bytes
            self._mem.trim(0 if pressure else self.max_bytes)

    async def get_or_refresh(
        self,
        key: str,
        loader: Callable[[], Awaitable[Any]],
        ttl: float,
        *,
        refresh_timeout: float = 30.0,
        waiter_timeout: float = 33.0,
        admit: Callable[[], ResourceLease] | None = None,
    ) -> tuple[Any, bool]:
        if any(
            not math.isfinite(value) or value <= 0 for value in (refresh_timeout, waiter_timeout)
        ):
            raise ValueError("Advisory refresh and waiter deadlines must be positive")
        cached = await asyncio.to_thread(self.get, key)
        if cached is not None:
            return cached, True
        flight_key = (asyncio.get_running_loop(), self._key(key))
        with self._lock:
            pending = self._flights.get(flight_key)
            if pending is None:
                if len(self._flights) >= self.max_refreshes:
                    self._metrics["refresh_rejected"] += 1
                    raise CacheBusyError("advisory_refresh_capacity_exhausted")

                async def refresh() -> Any:
                    lease = None
                    try:
                        lease = admit() if admit is not None else None
                        deadline = time.monotonic() + refresh_timeout
                        async with asyncio.timeout(refresh_timeout):
                            result = await loader()
                        # Keep this flight's capacity until the bounded disk
                        # operation finishes; cancellation cannot kill a thread.
                        # Its deadline fence prevents late RAM/disk publication.
                        await asyncio.to_thread(self.set, key, result, ttl, _deadline=deadline)
                        if time.monotonic() >= deadline:
                            raise TimeoutError("advisory_refresh_deadline_exceeded")
                        return result
                    finally:
                        if lease is not None:
                            lease.release()
                        with self._lock:
                            self._flights.pop(flight_key, None)

                pending = asyncio.create_task(refresh(), name="redjohn-advisory-refresh")
                self._flights[flight_key] = pending
                self._metrics["refresh"] += 1
                # Observe errors even when every original waiter was cancelled.
                pending.add_done_callback(self._observe_refresh)
            else:
                self._metrics["singleflight_waiter"] += 1
        async with asyncio.timeout(waiter_timeout):
            return await asyncio.shield(pending), False

    @staticmethod
    def _observe_refresh(task: asyncio.Task[Any]) -> None:
        if not task.cancelled():
            task.exception()

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {**self._mem.stats(), **self._metrics, "inflight": len(self._flights)}
