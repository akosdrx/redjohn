"""Agent execution: LangGraph session loop with durable checkpointing.

One graph (compiled once per engine, checkpointer = AsyncSqliteSaver on
``<profile>/checkpoints.db``) serves all agents; ``thread_id = agent_id``.

Loop shape::

    START -> turn -> (tools -> turn)* -> END

* ``turn``: control check (run/agent stopping), memory session (visible
  waiting when OpenViking is down), mailbox delivery, one model call via
  the ModelGateway, records usage/activity.
* ``tools``: executes tool calls via the ToolRunner (idempotent invocation
  ids — a resumed node never blindly re-executes), collects evidence refs,
  handles control signals (complete / wait_children).

An agent whose turn ends without tool calls goes idle (graph END, status
RUNNING); new mailbox deliveries re-invoke the graph on the same thread, so
conversation history survives across idle periods and engine restarts.
"""

from __future__ import annotations

import asyncio
import json
import operator
from dataclasses import replace
from typing import TYPE_CHECKING, Annotated, Any, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from .budgets import check_time, reserve_model, settle_model
from .logging import get_logger
from .mailbox import acknowledge_inbox, pending_inbox
from .models import Agent, AgentStatus, Run, RunStatus
from .prompts import agent_system_prompt
from .skill_registry import SkillRegistry

if TYPE_CHECKING:
    from .engine import Engine


class AgentState(TypedDict, total=False):
    messages: Annotated[list[Any], add_messages]
    steps: int
    tool_step: int
    pending_tools: list[dict[str, Any]]
    done: bool
    complete: bool
    wait_children: bool
    failed: str
    last_summary: str
    evidence_refs: Annotated[list[str], operator.add]
    pending_mail_ids: list[str]


def _to_dict_messages(messages: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        cls = type(m).__name__
        role = {
            "SystemMessage": "system",
            "AIMessage": "assistant",
            "HumanMessage": "user",
            "ToolMessage": "tool",
        }.get(cls, "user")
        content = m.content if isinstance(m.content, str) else str(m.content)
        item: dict[str, Any] = {"role": role, "content": content}
        if getattr(m, "tool_calls", None):
            item["tool_calls"] = m.tool_calls
        if getattr(m, "tool_call_id", None):
            item["tool_call_id"] = m.tool_call_id
        if getattr(m, "additional_kwargs", {}).get("reasoning_content"):
            item["reasoning_content"] = m.additional_kwargs["reasoning_content"]
        out.append(item)
    return out


class AgentRuntime:
    """Graph node implementations bound to an Engine."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._log = get_logger("agents")

    async def node_inbox(self, state: AgentState, config: RunnableConfig) -> dict[str, Any]:
        from langchain_core.messages import HumanMessage

        inbox = await pending_inbox(self.engine.store, config["configurable"]["thread_id"])
        return {
            "messages": [
                HumanMessage(
                    id=m.message_id, content=f"[mailbox from {m.from_agent_id} kind={m.kind}] {m.body}"
                )
                for m in inbox
            ],
            "pending_mail_ids": [m.message_id for m in inbox],
        }

    async def node_memory(self, state: AgentState, config: RunnableConfig) -> dict[str, Any]:
        agent = await self.engine.store.get_agent(config["configurable"]["thread_id"])
        run = await self.engine.store.get_run(agent.run_id)
        await self.engine.sync_memory_messages(agent, run, state.get("messages", []))
        return {}

    # ------------------------------------------------------------------ turn
    async def node_turn(self, state: AgentState, config: RunnableConfig) -> dict[str, Any]:
        from langchain_core.messages import AIMessage

        engine = self.engine
        agent_id = config["configurable"]["thread_id"]
        agent = await engine.store.get_agent(agent_id)
        run = await engine.store.get_run(agent.run_id)

        # control plane first: stopping runs/agents end the loop immediately
        if run.status in (RunStatus.STOPPING, RunStatus.STOPPED) or agent.status in (
            AgentStatus.STOPPED,
            AgentStatus.COMPLETE,
            AgentStatus.FAILED,
        ):
            return {"done": True}

        steps = state.get("steps", 0)
        if steps >= engine.settings.max_agent_steps:
            return {"done": True, "failed": f"step budget exceeded ({steps})"}

        # memory session (lazy): unconfigured -> skip; down -> visible waiting
        await engine.ensure_memory_session(agent, run)

        # The separate inbox node has already checkpointed these exact IDs.
        await acknowledge_inbox(engine.store, agent_id, state.get("pending_mail_ids", []))
        await engine.sync_memory_messages(agent, run, state.get("messages", []))
        agent = await engine.store.get_agent(agent_id)

        # Re-apply the current system instructions on every model turn, including
        # resumed checkpoints and child agents with older initial messages.
        convo = [
            message for message in _to_dict_messages(state.get("messages", [])) if message["role"] != "system"
        ]
        convo.insert(0, {"role": "system", "content": agent_system_prompt(agent, run, engine.skill_registry)})
        await engine.mcp_manager.ensure_run_connections(run)
        specs = engine.tool_specs_for(agent)
        specs = [spec for spec in specs if engine.mcp_manager.tool_visible_to_run(spec.name, run.run_id)]
        # MCP input schemas and descriptions must remain intact: generic object
        # placeholders prevent the model from supplying required tool arguments.
        specs = [
            replace(spec, input_schema=discovered["input_schema"], description=discovered["description"])
            if (discovered := engine.mcp_manager.tool_definition(spec.name))
            else spec
            for spec in specs
        ]
        check_time(run, agent)
        # The fixture fallback is deliberately conservative. Real adapters use
        # the official tokenizer; input plus capped output is reserved first.
        counter = getattr(engine.gateway, "input_tokens", None)
        tokens = (
            await counter(convo, specs)
            if counter
            else len(json.dumps(convo, ensure_ascii=False).encode()) + 1024
        )
        reservation = await reserve_model(
            engine.store, run, agent, steps, tokens, engine.settings.max_model_output_tokens
        )
        resp = reservation.response
        if resp is None:
            if steps == 0:
                task_text = (agent.task or run.task or "Assess the authorized target.").strip()
                first_task_line = task_text.splitlines()[0][:120] if task_text else "Starting assessment"
                await engine.set_activity(
                    agent,
                    run,
                    f"Task: {first_task_line}",
                    message=f"[TASK] {task_text}",
                    kind="task",
                )
            remaining = check_time(run, agent)
            async with asyncio.timeout(remaining):
                resp = await engine.gateway.complete(
                    agent=agent,
                    run=run,
                    step=steps,
                    messages=convo,
                    tools=specs,
                    max_output_tokens=reservation.max_output_tokens,
                )
            await settle_model(engine.store, run, agent, reservation, resp)
            reasoning = str((resp.metadata or {}).get("reasoning_content") or "").strip()
            if reasoning:
                first_thought = reasoning.splitlines()[0][:120]
                await engine.set_activity(
                    agent,
                    run,
                    first_thought,
                    message=f"[THOUGHT] {reasoning}",
                    kind="reasoning",
                )
            content = (resp.content or "").strip()
            if content:
                first_line = content.splitlines()[0][:120]
                await engine.set_activity(
                    agent,
                    run,
                    first_line,
                    message=content,
                    kind="assistant",
                )
            elif resp.tool_calls:
                calls_summary = ", ".join(tc.name for tc in resp.tool_calls)
                await engine.set_activity(
                    agent,
                    run,
                    f"Calling {calls_summary}"[:120],
                    message=f"[ACTION] Invoking {calls_summary}",
                    kind="action",
                )

        return {
            "messages": [
                AIMessage(
                    id=f"model:{agent_id}:{steps}",
                    content=resp.content,
                    additional_kwargs=resp.metadata,
                    tool_calls=[{"id": tc.id, "name": tc.name, "args": tc.args} for tc in resp.tool_calls],
                )
            ],
            "steps": steps + 1,
            "tool_step": steps,
            "pending_tools": [{"id": tc.id, "name": tc.name, "args": tc.args} for tc in resp.tool_calls],
            "done": resp.done,
            "complete": False,
            "wait_children": False,
            "last_summary": resp.content,
        }

    # ----------------------------------------------------------------- tools
    async def node_tools(self, state: AgentState, config: RunnableConfig) -> dict[str, Any]:
        from langchain_core.messages import HumanMessage, ToolMessage

        engine = self.engine
        agent_id = config["configurable"]["thread_id"]
        agent = await engine.store.get_agent(agent_id)
        run = await engine.store.get_run(agent.run_id)

        results: list[Any] = []
        evidence: list[str] = []
        complete = False
        wait_children = False
        tool_step = state.get("tool_step", max(state.get("steps", 1) - 1, 0))

        for i, call in enumerate(state.get("pending_tools", [])):
            res = await engine.tool_runner.execute(
                run=run,
                agent=agent,
                tool=call["name"],
                args=call["args"],
                step=tool_step,
                call_index=i,
            )
            evidence.extend(res.evidence_refs)
            results.append(
                ToolMessage(
                    id=f"tool:{res.invocation_id}",
                    tool_call_id=call["id"],
                    content=f"[tool result {call['name']} {res.invocation_id} "
                    f"status={res.status.value}]\n{res.output_text}",
                )
            )
            if res.control == "complete":
                complete = True
                if res.output_text:
                    results.append(HumanMessage(content=f"[task summary] {res.output_text}"))
            elif res.control == "wait_children":
                # only actually wait when there are live children
                async with engine.store.read() as s:
                    children = await engine.store.children_of(s, run.run_id, agent_id)
                from .supervisor import TERMINAL_AGENT_STATES

                if any(c.status not in TERMINAL_AGENT_STATES for c in children):
                    wait_children = True

        return {
            "messages": results,
            "pending_tools": [],
            "evidence_refs": evidence,
            "complete": complete,
            "wait_children": wait_children,
            "done": complete or wait_children or state.get("done", False),
        }


def route_after_turn(state: AgentState) -> str:
    if state.get("done"):
        return END
    if state.get("pending_tools"):
        return "tools"
    return END


def route_after_tools(state: AgentState) -> str:
    if state.get("done") or state.get("complete") or state.get("wait_children"):
        return END
    return "turn"


def build_agent_graph(engine: Engine) -> Any:
    engine.skill_registry = SkillRegistry()
    runtime = AgentRuntime(engine)
    graph = StateGraph(AgentState)
    graph.add_node("turn", runtime.node_turn)
    graph.add_node("inbox", runtime.node_inbox)
    graph.add_node("memory", runtime.node_memory)
    graph.add_node("tools", runtime.node_tools)
    graph.add_edge(START, "inbox")
    graph.add_edge("inbox", "turn")
    graph.add_edge("turn", "memory")
    graph.add_conditional_edges("memory", route_after_turn, ["tools", END])
    graph.add_conditional_edges(
        "tools", lambda state: "inbox" if route_after_tools(state) == "turn" else END, ["inbox", END]
    )
    return graph.compile(checkpointer=engine.checkpointer)


def initial_input(agent: Agent, run: Run) -> dict[str, Any]:
    from langchain_core.messages import HumanMessage, SystemMessage

    system = agent_system_prompt(agent, run)
    return {
        "messages": [
            SystemMessage(id="redjohn:system", content=system),
            HumanMessage(content=agent.task or run.task or "Assess the authorized target."),
        ],
        "steps": 0,
        "done": False,
        "pending_tools": [],
        "evidence_refs": [],
    }
