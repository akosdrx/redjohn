"""WebSocket event hub: per-run subscriptions, replay+live handoff, backpressure.

Delivery model
--------------
* Business transactions commit event + outbox rows atomically (see db.Store);
  a single relay task drains the outbox in commit order and fans events out
  to in-memory subscriber queues. The relay is the ONLY live sender.
* ``subscribe()`` registers the subscriber and enqueues the backlog
  (``seq > after_seq``) under the same asyncio lock the relay publishes
  through, so the replay->live handoff can neither lose nor duplicate events.
  Clients additionally dedup by ``event_id`` as a safety net (contract rule).
* Backpressure: each subscriber has a bounded queue. A full queue marks the
  subscription dropped; the WS loop then sends a ``resync_required`` control
  frame and closes — slow clients resnapshot instead of blocking the relay.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field

from .db import Store
from .events import RunEvent
from .logging import get_logger


class SubscriberDropped(Exception):
    """Queue overflow — client must resnapshot (sent as control frame)."""


@dataclass
class Subscription:
    run_id: str
    queue: asyncio.Queue[RunEvent]
    next_seq: int
    sub_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    failed: bool = False

    async def get(self, poll_timeout: float = 1.0) -> RunEvent | None:
        """Next event, None on idle timeout; raises SubscriberDropped once
        the hub has dropped this subscription for backpressure."""
        if self.failed:
            raise SubscriberDropped
        try:
            event = await asyncio.wait_for(self.queue.get(), timeout=poll_timeout)
        except TimeoutError:
            if self.failed:
                raise SubscriberDropped from None
            return None
        return event


class Hub:
    def __init__(self, store: Store, *, queue_size: int = 256, idle_sleep: float = 0.05) -> None:
        self._store = store
        self._queue_size = queue_size
        self._idle_sleep = idle_sleep
        self._subs: dict[str, dict[str, Subscription]] = {}
        self._lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._relay: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        self._log = get_logger("hub")

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self._stopped.clear()
        self._store.on_commit(self._wake.set)
        self._relay = asyncio.create_task(self._relay_loop(), name="outbox-relay")

    async def stop(self) -> None:
        self._stopped.set()
        self._wake.set()
        if self._relay:
            # graceful: let the relay finish its in-flight batch (writes are
            # shielded, so no transaction is stranded), cancel only as fallback
            try:
                await asyncio.wait_for(asyncio.shield(self._relay), timeout=5.0)
            except (TimeoutError, asyncio.CancelledError):
                self._relay.cancel()
                try:
                    await self._relay
                except asyncio.CancelledError:
                    pass
            self._relay = None
        async with self._lock:
            self._subs.clear()

    # ---------------------------------------------------------- subscription
    async def subscribe(self, run_id: str, *, after_seq: int = 0) -> Subscription:
        """Register a subscriber; backlog (seq > after_seq) is enqueued first.

        The registration + backlog read is atomic wrt the relay's publish
        path (same lock), guaranteeing the no-loss/no-dup handoff.
        """
        async with self._lock:
            sub = Subscription(
                run_id=run_id,
                queue=asyncio.Queue(maxsize=self._queue_size),
                next_seq=after_seq + 1,
            )
            # Probe only one item beyond capacity. A long disconnection must
            # request a snapshot, never allocate the entire historical log or
            # raise QueueFull before the WebSocket can send its control frame.
            backlog = await self._store.list_events(
                run_id, after_seq=after_seq, limit=self._queue_size + 1,
            )
            if len(backlog) > self._queue_size:
                sub.failed = True
                return sub
            for event in backlog:
                sub.queue.put_nowait(event)
                sub.next_seq = event.seq + 1
            self._subs.setdefault(run_id, {})[sub.sub_id] = sub
            return sub

    async def unsubscribe(self, sub: Subscription) -> None:
        async with self._lock:
            self._subs.get(sub.run_id, {}).pop(sub.sub_id, None)

    async def subscriber_count(self, run_id: str) -> int:
        async with self._lock:
            return len(self._subs.get(run_id, {}))

    # ---------------------------------------------------------------- relay
    async def _relay_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                rows = await self._store.unpublished_outbox_events(limit=500)
            except Exception as exc:  # DB hiccup: log and retry, never die
                self._log.error("outbox poll failed", extra={"error": str(exc)})
                await asyncio.sleep(self._idle_sleep * 10)
                continue
            if not rows:
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=self._idle_sleep)
                except TimeoutError:
                    pass
                continue
            published: list[int] = []
            for outbox_id, event in rows:
                if self._stopped.is_set():
                    break  # graceful stop: unprocessed rows publish on next boot
                if event is not None:
                    await self._publish(event)
                published.append(outbox_id)
            await self._store.mark_published(published)

    async def _publish(self, event: RunEvent) -> None:
        async with self._lock:
            subs = list(self._subs.get(event.run_id, {}).values())
            for sub in subs:
                if event.seq < sub.next_seq:
                    continue  # already delivered via backlog
                if sub.failed:
                    continue
                try:
                    sub.queue.put_nowait(event)
                    sub.next_seq = event.seq + 1
                except asyncio.QueueFull:
                    sub.failed = True
                    self._subs.get(event.run_id, {}).pop(sub.sub_id, None)
                    self._log.warning(
                        "dropping slow subscriber",
                        extra={"run_id": event.run_id, "sub_id": sub.sub_id},
                    )
