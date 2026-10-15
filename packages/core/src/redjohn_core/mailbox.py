"""Persistent agent mailbox.

* Messages are durable rows; delivery flips ``queued -> delivered`` when the
  recipient's loop consumes its inbox.
* Dedup: ``(run_id, from_agent_id, idempotency_key)`` — a re-post with the
  same key returns the original message unchanged.
* Explicit broadcast only: ``kind="broadcast"`` fans out one addressed copy
  per agent of the run at post time (no implicit fan-out anywhere else).
"""

from __future__ import annotations

from .db import Store
from .events import EventType
from .models import AgentMessage, MessageStatus, Run, utcnow


async def post_message(
    store: Store,
    run: Run,
    *,
    from_agent_id: str,
    to_agent_id: str,
    body: str,
    kind: str = "instruction",
    correlation_id: str | None = None,
    idempotency_key: str | None = None,
    summary_ref: str | None = None,
    evidence_refs: list[str] | None = None,
) -> tuple[AgentMessage, bool]:
    """Insert a message (+ agent.message event) atomically.

    Returns (message, created_new). Dedup hits return the stored original.
    """
    async with store.write() as s:
        if idempotency_key:
            existing = await store.find_message_dedup(s, run.run_id, from_agent_id, idempotency_key)
            if existing is not None:
                return existing, False
        msg = AgentMessage(
            run_id=run.run_id,
            from_agent_id=from_agent_id,
            to_agent_id=to_agent_id,
            correlation_id=correlation_id,
            kind=kind,  # type: ignore[arg-type]
            body=body,
            summary_ref=summary_ref,
            evidence_refs=evidence_refs or [],
            idempotency_key=idempotency_key,
        )
        await store.insert_message(s, msg)
        event_agent_id = to_agent_id if to_agent_id != "user" else from_agent_id
        await store.emit_simple(s, run, EventType.AGENT_MESSAGE, {
            "message_id": msg.message_id,
            "from_agent_id": msg.from_agent_id,
            "to_agent_id": msg.to_agent_id,
            "kind": msg.kind,
            "body": msg.body,
            "summary_ref": msg.summary_ref,
        }, agent_id=event_agent_id, correlation_id=correlation_id)
        return msg, True


async def pending_inbox(store: Store, agent_id: str) -> list[AgentMessage]:
    """Read without acknowledging; the graph checkpoints these messages first."""
    async with store.read() as session:
        return await store.fetch_inbox(session, agent_id)


async def acknowledge_inbox(store: Store, agent_id: str, message_ids: list[str]) -> None:
    """Only acknowledge IDs already present in the durable graph checkpoint."""
    wanted = set(message_ids)
    if not wanted:
        return
    async with store.write() as session:
        for message in await store.fetch_inbox(session, agent_id):
            if message.message_id in wanted:
                message.status = MessageStatus.DELIVERED
                message.delivered_at = utcnow()
                await store.update_message_row(session, message)


async def broadcast(
    store: Store,
    run: Run,
    *,
    from_agent_id: str,
    body: str,
    correlation_id: str | None = None,
) -> list[AgentMessage]:
    """Explicit broadcast: one addressed copy per current agent of the run."""
    agents = await store.list_agents(run.run_id)
    sent: list[AgentMessage] = []
    for agent in agents:
        if agent.agent_id == from_agent_id:
            continue
        msg, _ = await post_message(
            store, run, from_agent_id=from_agent_id, to_agent_id=agent.agent_id,
            body=body, kind="broadcast", correlation_id=correlation_id,
        )
        sent.append(msg)
    return sent
