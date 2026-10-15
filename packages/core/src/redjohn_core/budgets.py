"""Durable run-wide model reservations, atomically shared by every agent.

An interrupted request retains its full reservation. A retry needs a new,
funded reservation; a settled response is replayed without another API call.
The event store is the ledger, so the transaction/fencing rules of the Store
also govern budget claims in local and Cloud executors.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from .errors import RJError
from .events import EventType
from .model_gateway import ModelResponse, ToolCall
from .models import Agent, Run, RunStatus, utcnow


def remaining_seconds(run: Run, agent: Agent | None = None) -> float | None:
    deadlines: list[float] = []
    now = utcnow()
    for seconds, started in (
        (run.limits.time_budget_seconds, run.started_at),
        (agent.time_budget_seconds if agent else None, agent.created_at if agent else None),
    ):
        if seconds is not None and started is not None:
            if isinstance(started, str):
                started = datetime.fromisoformat(started)
            deadlines.append(seconds - (now - started).total_seconds())
    return min(deadlines) if deadlines else None


def check_time(run: Run, agent: Agent | None = None) -> float | None:
    remaining = remaining_seconds(run, agent)
    if remaining is not None and remaining <= 0:
        raise RJError("budget_exhausted", "time budget exhausted", status=409)
    return remaining


def _response(data: dict[str, Any]) -> ModelResponse:
    return ModelResponse(content=data["content"], done=data.get("done", False),
                         usage=data.get("usage", {}), metadata=data.get("metadata", {}),
                         tool_calls=tuple(ToolCall(**call) for call in data.get("tool_calls", [])))


@dataclass
class Reservation:
    operation_id: str
    max_output_tokens: int
    response: ModelResponse | None = None


async def reserve_model(store: Any, run: Run, agent: Agent, step: int,
                        input_tokens: int, max_output_tokens: int) -> Reservation:
    base = f"model:{agent.agent_id}:{step}"
    async with store.write() as session:
        records = await store.runtime_event_payloads(session, run.run_id, type_=EventType.USAGE)
        cached = next((r for r in records if r.get("kind") == "model.settled"
                       and r.get("request_id") == base and "response" in r), None)
        if cached:
            return Reservation(cached["operation_id"], 0, _response(cached["response"]))
        fresh = await store.get_run(run.run_id)
        if fresh.status != RunStatus.RUNNING:
            raise RJError("run_not_running", "run no longer accepts model calls", status=409)
        check_time(fresh, agent)
        reservations = {r["operation_id"]: r for r in records if r.get("kind") == "model.reserved"}
        settlements = {r["operation_id"]: r for r in records if r.get("kind") == "model.settled"}

        def used(agent_only: bool = False) -> int:
            return sum(settlements.get(key, {}).get("tokens", row["reserved_tokens"])
                       for key, row in reservations.items()
                       if not agent_only or row["agent_id"] == agent.agent_id)

        output = max_output_tokens
        for limit, consumed in ((fresh.limits.token_budget, used()), (agent.token_budget, used(True))):
            if limit is not None:
                output = min(output, limit - consumed - input_tokens)
        if output < 1:
            raise RJError("budget_exhausted", "insufficient token budget for bounded model request",
                          status=409)
        attempt = sum(1 for r in reservations.values() if r.get("request_id") == base)
        operation = f"{base}:{attempt}"
        await store.emit_simple(session, fresh, EventType.USAGE, {
            "kind": "model.reserved", "request_id": base, "operation_id": operation,
            "agent_id": agent.agent_id, "reserved_tokens": input_tokens + output,
        }, agent_id=agent.agent_id)
        return Reservation(operation, output)


async def settle_model(store: Any, run: Run, agent: Agent,
                       reservation: Reservation, response: ModelResponse) -> None:
    async with store.write() as session:
        rows = await store.runtime_event_payloads(session, run.run_id, type_=EventType.USAGE)
        if any(e.get("kind") == "model.settled"
               and e.get("operation_id") == reservation.operation_id for e in rows):
            return
        reserved = next(e for e in rows if e.get("kind") == "model.reserved"
                        and e.get("operation_id") == reservation.operation_id)
        usage = response.usage
        # No trustworthy usage means retain the upper bound, never silently refund it.
        tokens = (max(0, int(usage.get("input_tokens", 0))) + max(0, int(usage.get("output_tokens", 0))))
        if not usage:
            tokens = reserved["reserved_tokens"]
        await store.emit_simple(session, run, EventType.USAGE, {
            "kind": "model.settled", "request_id": reserved["request_id"],
            "operation_id": reservation.operation_id, "agent_id": agent.agent_id,
            "tokens": tokens, **usage, "response": asdict(response),
        }, agent_id=agent.agent_id)
