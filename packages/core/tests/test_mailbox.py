"""Unit: mailbox persistence, dedup, delivery."""

from __future__ import annotations

from redjohn_core import mailbox
from redjohn_core.models import MessageStatus


async def test_post_and_deliver(store, run_factory) -> None:
    run = await run_factory()
    msg, created = await mailbox.post_message(
        store, run, from_agent_id="user", to_agent_id="agt_1", body="hello",
    )
    assert created
    assert msg.status == MessageStatus.QUEUED

    inbox = await mailbox.pending_inbox(store, "agt_1")
    assert [m.message_id for m in inbox] == [msg.message_id]
    assert inbox[0].status == MessageStatus.QUEUED  # pending read does not acknowledge

    await mailbox.acknowledge_inbox(store, "agt_1", [msg.message_id])
    # after ack: nothing queued anymore
    assert await mailbox.pending_inbox(store, "agt_1") == []


async def test_dedup_by_sender_idempotency_key(store, run_factory) -> None:
    run = await run_factory()
    msg1, created1 = await mailbox.post_message(
        store, run, from_agent_id="user", to_agent_id="agt_1", body="do it",
        idempotency_key="op-1",
    )
    msg2, created2 = await mailbox.post_message(
        store, run, from_agent_id="user", to_agent_id="agt_1", body="do it",
        idempotency_key="op-1",
    )
    assert created1 and not created2
    assert msg1.message_id == msg2.message_id

    # different key -> new message; different sender with same key -> new message
    msg3, created3 = await mailbox.post_message(
        store, run, from_agent_id="user", to_agent_id="agt_1", body="do it",
        idempotency_key="op-2",
    )
    msg4, created4 = await mailbox.post_message(
        store, run, from_agent_id="agt_9", to_agent_id="agt_1", body="do it",
        idempotency_key="op-1",
    )
    assert created3 and created4
    assert len({msg1.message_id, msg3.message_id, msg4.message_id}) == 3

    all_msgs = await store.list_messages(run.run_id)
    assert len(all_msgs) == 3


async def test_broadcast_is_explicit_and_addressed(store, run_factory) -> None:
    from redjohn_core.models import Agent

    run = await run_factory()
    async with store.write() as s:
        for name in ("a", "b"):
            await store.insert_agent(s, Agent(run_id=run.run_id, name=name, task="t"))
    agents = await store.list_agents(run.run_id)
    sent = await mailbox.broadcast(store, run, from_agent_id="user", body="stop everything")
    assert len(sent) == 2
    assert {m.to_agent_id for m in sent} == {a.agent_id for a in agents}
    assert all(m.kind == "broadcast" for m in sent)


async def test_message_event_emitted(store, run_factory) -> None:
    run = await run_factory()
    await mailbox.post_message(store, run, from_agent_id="user", to_agent_id="agt_1",
                               body="hi", correlation_id="corr-1")
    events = await store.list_events(run.run_id)
    assert len(events) == 1
    ev = events[0]
    assert ev.type.value == "agent.message"
    assert ev.seq == 1
    assert ev.correlation_id == "corr-1"
    assert ev.data["body"] == "hi"
