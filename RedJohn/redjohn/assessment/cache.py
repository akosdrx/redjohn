"""Byte bounded JSON LRU/TTL cache, separate from durable test/evidence state."""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections import Counter, OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_MISSING = object()


@dataclass(frozen=True)
class CacheContext:
    tenant: str
    engagement: str
    asset: str
    actor: str
    session_revision: str
    policy_revision: str
    workflow_state: str
    input_fingerprint: str
    tool_version: str
    profile_version: str
    template_version: str
    deploy_revision: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or len(value) > 512 for value in asdict(self).values()):
            raise ValueError("cache context must contain bounded references and revisions")

    def key(self, namespace: str, operation: str) -> str:
        """References/revisions only: callers must never supply raw cookies/tokens."""
        payload = json.dumps(
            [namespace, operation, asdict(self)],
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class CacheBusyError(RuntimeError):
    code = "cache_refresh_capacity_exhausted"


@dataclass(frozen=True)
class _Entry:
    payload: bytes
    expires: float
    context: CacheContext | None


class SmartCache:
    """Serialized bytes are the stored value and exact quota accounting unit.

    Object/allocator/key overhead is additional, bounded by max_items. A bounded
    worker pool performs single-flight refresh. Timed-out callbacks cannot publish
    late results. Python callbacks are cooperative and must enforce their own I/O
    timeout; a timed-out callback keeps its slot until it exits, preventing an
    unbounded replacement storm.
    """

    NEVER_CACHE_FAMILIES = frozenset({"auth", "authz", "session", "csrf", "cors", "race", "oast"})

    def __init__(
        self,
        max_bytes: int,
        max_items: int = 256,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_refreshes: int = 4,
        refresh_workers: int = 2,
    ) -> None:
        if any(
            type(x) is not int or x <= 0
            for x in (max_bytes, max_items, max_refreshes, refresh_workers)
        ):
            raise ValueError("cache quotas must be positive integers")
        self.max_bytes, self.max_items = max_bytes, max_items
        self._clock = clock
        self._items: OrderedDict[str, _Entry] = OrderedDict()
        self._bytes = 0
        self._lock = threading.RLock()
        self._flights: dict[str, Future[object]] = {}
        self._slots = threading.BoundedSemaphore(max_refreshes)
        self._executor = ThreadPoolExecutor(
            max_workers=min(refresh_workers, max_refreshes), thread_name_prefix="redjohn-cache"
        )
        self._closed = False
        self._generation = 0
        self._metrics: Counter[str] = Counter()

    def _drop(self, key: str, reason: str) -> None:
        entry = self._items.pop(key, None)
        if entry is not None:
            self._bytes -= len(entry.payload)
            self._metrics[reason] += 1

    def _expire(self) -> None:
        now = self._clock()
        for key in [key for key, value in self._items.items() if value.expires <= now]:
            self._drop(key, "expired")

    @staticmethod
    def _validate_key(key: str) -> None:
        if not isinstance(key, str) or len(key.encode("utf-8")) > 512:
            raise ValueError("cache key must be a bounded reference or digest")

    def get(
        self, key: str, *, default: object = None, retest: bool = False, family: str = ""
    ) -> object:
        self._validate_key(key)
        if retest or family in self.NEVER_CACHE_FAMILIES:
            with self._lock:
                self._metrics["bypass"] += 1
            return default
        with self._lock:
            self._expire()
            item = self._items.get(key)
            if item is None:
                self._metrics["miss"] += 1
                return default
            self._items.move_to_end(key)
            self._metrics["hit"] += 1
            return json.loads(item.payload)

    def set(
        self,
        key: str,
        value: object,
        ttl: float,
        *,
        context: CacheContext | None = None,
        success: bool = True,
        family: str = "",
    ) -> bool:
        self._validate_key(key)
        if not math.isfinite(ttl) or ttl <= 0 or not success or family in self.NEVER_CACHE_FAMILIES:
            return False
        # JSON encoding rejects arbitrary executable/mutable user objects.
        buffer = bytearray()
        encoder = json.JSONEncoder(ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        for chunk in encoder.iterencode(value):
            # ensure_ascii makes character length equal to encoded byte length.
            if len(buffer) + len(chunk) > self.max_bytes:
                with self._lock:
                    self._metrics["oversized"] += 1
                return False
            buffer.extend(chunk.encode("ascii"))
        payload = bytes(buffer)
        with self._lock:
            if self._closed:
                return False
            if len(payload) > self.max_bytes:
                self._metrics["oversized"] += 1
                return False  # preserve useful hot entries when an oversized result arrives
            self._expire()
            self._drop(key, "replaced")
            while self._items and (
                len(self._items) >= self.max_items or self._bytes + len(payload) > self.max_bytes
            ):
                self._drop(next(iter(self._items)), "eviction")
            self._items[key] = _Entry(payload, self._clock() + ttl, context)
            self._bytes += len(payload)
            return True

    def invalidate(
        self, *, context: Mapping[str, str] | None = None, reason: str = "state_changed"
    ) -> int:
        # Metric keys use a closed set; no URL, request ID or secret labels.
        reason = (
            reason
            if reason
            in {
                "state_changed",
                "session_changed",
                "policy_changed",
                "deploy_changed",
                "explicit_retest",
            }
            else "state_changed"
        )
        if context is not None and not set(context).issubset(CacheContext.__dataclass_fields__):
            raise ValueError("unknown cache context field")
        with self._lock:
            self._generation += (
                1  # invalidation also fences every in-flight old-context publication
            )
            keys = [
                key
                for key, item in self._items.items()
                if context is None
                or (
                    item.context is not None
                    and all(getattr(item.context, k) == v for k, v in context.items())
                )
            ]
            for key in keys:
                self._drop(key, "invalidated")
            self._metrics[f"invalidation_{reason}"] += len(keys)
            return len(keys)

    def trim(self, target_bytes: int = 0) -> int:
        if target_bytes < 0:
            raise ValueError("target_bytes cannot be negative")
        with self._lock:
            old = self._bytes
            while self._items and self._bytes > target_bytes:
                self._drop(next(iter(self._items)), "pressure_eviction")
            return old - self._bytes

    def get_or_compute(
        self,
        key: str,
        loader: Callable[[], object],
        ttl: float,
        *,
        timeout: float = 5.0,
        refresh_timeout: float | None = None,
        context: CacheContext | None = None,
        retest: bool = False,
        family: str = "",
    ) -> object:
        self._validate_key(key)
        if (
            not math.isfinite(timeout)
            or timeout <= 0
            or (
                refresh_timeout is not None
                and (not math.isfinite(refresh_timeout) or refresh_timeout <= 0)
            )
        ):
            raise ValueError("refresh and waiter deadlines must be positive")
        bypass = retest or family in self.NEVER_CACHE_FAMILIES
        if not bypass:
            value = self.get(key, default=_MISSING)
            if value is not _MISSING:
                return value
        with self._lock:
            if self._closed:
                raise RuntimeError("cache is closed")
            # Retests never coalesce with an old active validation.
            flight_key = key if not bypass else f"bypass:{id(loader)}:{time.monotonic_ns()}"
            future = self._flights.get(flight_key)
            if future is None:
                if not self._slots.acquire(blocking=False):
                    self._metrics["refresh_rejected"] += 1
                    raise CacheBusyError("cache refresh capacity exhausted")
                generation = self._generation
                deadline = self._clock() + (
                    refresh_timeout if refresh_timeout is not None else timeout
                )

                def compute() -> object:
                    result = loader()
                    with self._lock:
                        if self._clock() >= deadline:
                            self._metrics["refresh_expired"] += 1
                            raise TimeoutError("cache refresh deadline exceeded")
                        if not bypass and generation == self._generation:
                            self.set(key, result, ttl, context=context, family=family)
                    return result

                future = self._executor.submit(compute)
                self._flights[flight_key] = future
                self._metrics["refresh"] += 1

                def finished(done: Future[object]) -> None:
                    with self._lock:
                        if self._flights.get(flight_key) is done:
                            self._flights.pop(flight_key, None)
                        self._slots.release()

                future.add_done_callback(finished)
            else:
                self._metrics["singleflight_waiter"] += 1
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            with self._lock:
                self._metrics["waiter_timeout"] += 1
            raise

    def stats(self) -> dict[str, int]:
        with self._lock:
            self._expire()
            return {
                **self._metrics,
                "bytes": self._bytes,
                "items": len(self._items),
                "inflight": len(self._flights),
            }

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._generation += 1
            # A closed runtime can remain referenced by diagnostic/scheduler
            # owners. Release serialized payloads now, without relying on GC.
            # Keep active flights/slots owned until their existing done callback
            # runs; generation and _closed still fence late publications.
            self._items.clear()
            self._bytes = 0
        self._executor.shutdown(wait=False, cancel_futures=True)
