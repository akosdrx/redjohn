"""Unit: outbox ordering, seq assignment, hub relay + backpressure."""

from __future__ import annotations

import asyncio

from redjohn_core import mailbox


async def test_seq_assigned_per_run_contiguously(store, run_factory) -> None:
    run_a = await run_factory()
    run_b = await run_factory()
    for i in range(3):
        await mailbox.post_message(store, run_a, from_agent_id="user",
                                   to_agent_id="agt_1", body=f"a{i}")
        await mailbox.post_message(store, run_b, from_agent_id="user",
                                   to_agent_id="agt_1", body=f"b{i}")
    seqs_a = [e.seq for e in await store.list_events(run_a.run_id)]
    seqs_b = [e.seq for e in await store.list_events(run_b.run_id)]
    assert seqs_a == [1, 2, 3]
    assert seqs_b == [1, 2, 3]


async def test_outbox_rows_follow_commit_order(store, run_factory) -> None:
    run = await run_factory()
    for i in range(5):
        await mailbox.post_message(store, run, from_agent_id="user",
                                   to_agent_id="agt_1", body=f"m{i}")
    rows = await store.unpublished_outbox()
    events = [await store.get_event(eid) for _, eid in rows]
    bodies = [e.data["body"] for e in events if e]
    assert bodies == ["m0", "m1", "m2", "m3", "m4"]


async def test_relay_publishes_backlog_then_live(engine) -> None:
    from .conftest import make_run_in

    store = engine.store
    run = await make_run_in(store)
    await mailbox.post_message(store, run, from_agent_id="user", to_agent_id="a", body="early")

    sub = await engine.hub.subscribe(run.run_id, after_seq=0)
    backlog = await sub.get()
    assert backlog is not None and backlog.data["body"] == "early" and backlog.seq == 1

    await mailbox.post_message(store, run, from_agent_id="user", to_agent_id="a", body="live")
    event = await wait_event(sub)
    assert event.data["body"] == "live" and event.seq == 2

    # relay drains the outbox
    async def drained() -> bool:
        return not await store.unpublished_outbox()

    from .conftest import wait_for

    await wait_for(drained)
    await engine.hub.unsubscribe(sub)


async def test_replay_after_seq_handoff(engine) -> None:
    from .conftest import make_run_in, wait_for

    store = engine.store
    run = await make_run_in(store)
    for i in range(4):
        await mailbox.post_message(store, run, from_agent_id="user", to_agent_id="a", body=f"m{i}")
    await wait_for(lambda: store.max_seq(run.run_id))

    sub = await engine.hub.subscribe(run.run_id, after_seq=2)
    first = await sub.get()
    assert first is not None and first.seq == 3  # backlog starts strictly after after_seq
    second = await sub.get()
    assert second is not None and second.seq == 4
    # live event arrives exactly once (relay skips seq < next_seq)
    await mailbox.post_message(store, run, from_agent_id="user", to_agent_id="a", body="m4")
    live = await wait_event(sub)
    assert live.seq == 5
    assert sub.queue.empty()
    await engine.hub.unsubscribe(sub)


async def test_slow_subscriber_dropped(engine) -> None:
    from .conftest import make_run_in

    store = engine.store
    run = await make_run_in(store)
    engine.hub._queue_size = 2  # shrink for the test
    sub = await engine.hub.subscribe(run.run_id, after_seq=0)
    for i in range(5):
        await mailbox.post_message(store, run, from_agent_id="user", to_agent_id="a", body=f"x{i}")
    from .conftest import wait_for

    await wait_for(lambda: sub.failed, timeout=5)
    assert await engine.hub.subscriber_count(run.run_id) == 0


async def wait_event(sub, timeout: float = 5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        event = await sub.get(poll_timeout=0.2)
        if event is not None:
            return event
    raise TimeoutError("no event received")
