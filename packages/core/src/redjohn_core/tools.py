"""Tool Runner: validated, evidence-capturing tool execution.

Guarantees
----------
* Structured args only (dict) — never shell-string concatenation.
* Scope enforcement BEFORE execution: qualified tool name must pass the
  agent's allowed-tools list (minus scope-denied tools); target-ish args
  (``target``/``host``/``url``/``domain``/``ip``) must be covered by the
  agent's allowed targets. The same checks are applied on network access
  (MCP calls and subprocesses alike).
* Stable invocation ids: ``inv_<sha256(agent|step|index|tool|args)[:24]>``.
  A re-executed graph node after a crash finds the existing record:
  completed results are reused; ``unknown`` records are NEVER re-executed
  (the model gets an explicit note instead).
* Every execution captures output as content-hashed evidence under
  ``<profile>/evidence/`` with a size cap.
* Subprocesses run in their own process group with a scrubbed environment
  and a per-run working dir; stop/timeout kills the whole group.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from .budgets import check_time
from .db import Store, payload_hash
from .errors import RJError
from .events import EventType
from .executor import sandbox_command, scoped_http_get
from .logging import get_logger
from .models import (
    Agent,
    Evidence,
    Finding,
    FindingSeverity,
    FindingStatus,
    Run,
    ToolInvocation,
    ToolInvocationStatus,
    utcnow,
)
from .scope import target_covered, tool_allowed, url_in_scope
from .settings import Settings
from .skill_registry import SkillRegistry
from .source_inspection import ast_sink_search, github_source, list_source_files, read_source_file

if TYPE_CHECKING:
    from .mcp_manager import MCPManager


TARGET_ARG_KEYS = ("target", "host", "url", "domain", "ip")

BUILTIN_TOOL_SPECS: dict[str, dict[str, Any]] = {
    "builtin:search_skills": {
        "description": "Search local assessment skills by surface or topic.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
        },
    },
    "builtin:load_skill": {
        "description": "Load a local skill and list its references/scripts.",
        "input_schema": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}},
    },
    "builtin:read_skill_file": {
        "description": "Read a referenced skill file; never executes scripts.",
        "input_schema": {
            "type": "object",
            "required": ["name", "path"],
            "properties": {"name": {"type": "string"}, "path": {"type": "string"}},
        },
    },
    "builtin:lookup_cve": {
        "description": (
            "Query OSV.dev, NVD v2, CISA KEV, and FIRST EPSS for CVEs and exploit intelligence "
            "(composite risk score R_kompozit, SSVC v2 decision, and fast_path_rce prioritization)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "product": {"type": "string"},
                "version": {"type": "string"},
                "cve_id": {"type": "string"},
                "ecosystem": {"type": "string"},
            },
        },
    },
    "builtin:read_workspace_file": {
        "description": "Read a text artifact/snapshot inside this pentest's workspace.",
        "input_schema": {"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}},
    },
    "builtin:list_source_files": {
        "description": "List files inside the authorized local project read-only.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}},
        },
    },
    "builtin:read_source_file": {
        "description": (
            "Read a text file inside the authorized local project (automatically masks live secrets)."
        ),
        "input_schema": {"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}},
    },
    "builtin:ast_sink_search": {
        "description": (
            "Search authorized local source files for AST-level dangerous sinks "
            "(rce, deserialization, sqli, ssrf, path_traversal, xss) and enclosing symbols."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "category": {
                    "type": "string",
                    "enum": ["all", "rce", "deserialization", "sqli", "ssrf", "path_traversal", "xss"],
                },
                "limit": {"type": "integer"},
            },
        },
    },
    "builtin:repository_tree": {
        "description": "List the exact authorized GitHub repository read-only.",
        "input_schema": {
            "type": "object",
            "properties": {"ref": {"type": "string"}, "limit": {"type": "integer"}},
        },
    },
    "builtin:repository_read": {
        "description": "Read a text file from the authorized GitHub repository.",
        "input_schema": {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}, "ref": {"type": "string"}},
        },
    },
    "builtin:echo": {
        "description": "Echo text back (connectivity probe).",
        "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}},
    },
    "builtin:exec": {
        "description": "Run a local command (argv list, no shell).",
        "input_schema": {
            "type": "object",
            "properties": {
                "argv": {"type": "array", "items": {"type": "string"}},
                "target": {"type": "string"},
                "timeout_seconds": {"type": "number"},
            },
        },
    },
    "builtin:http_get": {
        "description": "Read an authorized HTTP URL with checked DNS and redirects.",
        "input_schema": {"type": "object", "required": ["url"], "properties": {"url": {"type": "string"}}},
    },
    "builtin:delegate": {
        "description": "Delegate a sub-task to a new child agent (supervisor-validated).",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "task": {"type": "string"},
                "role": {"type": "string"},
                "allowed_targets": {"type": "array"},
                "allowed_tools": {"type": "array"},
            },
        },
    },
    "builtin:send_message": {
        "description": "Send a mailbox message (to: 'parent'|'user'|agent_id).",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "body": {"type": "string"},
                "kind": {"type": "string"},
                "summary_ref": {"type": "string"},
                "evidence_refs": {"type": "array"},
            },
        },
    },
    "builtin:report_finding": {
        "description": (
            "Record a finding for the run. Medium/High/Critical findings require real "
            "evidence_refs from this session; verified findings also require a "
            "negative_control_ref (baseline/negative control) or >=2 distinct evidence_refs."
        ),
        "input_schema": {
            "type": "object",
            "required": ["title", "severity", "target", "description", "evidence_refs"],
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string"},
                "target": {"type": "string"},
                "description": {"type": "string"},
                "remediation": {"type": "string"},
                "evidence_refs": {"type": "array", "items": {"type": "string"}},
                "negative_control_ref": {"type": "string"},
                "verification_status": {
                    "type": "string",
                    "enum": ["observation", "suspected", "verified"],
                },
                "cve_id": {"type": "string"},
            },
        },
    },
    "builtin:memory_search": {
        "description": "Search long-term memory / knowledge (OpenViking).",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
        },
    },
    "builtin:wait_children": {
        "description": "Block until all child agents reach a terminal state.",
        "input_schema": {"type": "object", "properties": {}},
    },
    "builtin:complete_task": {
        "description": "Mark this agent's task complete with a summary.",
        "input_schema": {"type": "object", "properties": {"summary": {"type": "string"}}},
    },
}


class DelegateHook(Protocol):
    async def __call__(self, parent: Agent, args: dict[str, Any]) -> Agent: ...


class MessageHook(Protocol):
    async def __call__(self, sender: Agent, args: dict[str, Any]) -> str: ...


class MemoryWaitHook(Protocol):
    async def __call__(self, agent: Agent, run: Run) -> Any: ...  # returns MemoryStore


@dataclass
class ToolExecResult:
    invocation_id: str
    status: ToolInvocationStatus
    output_text: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    control: str | None = None  # "complete" | "wait_children"
    error: str | None = None


def deterministic_invocation_id(
    agent_id: str, step: int, call_index: int, tool: str, args: dict[str, Any]
) -> str:
    digest = hashlib.sha256(
        f"{agent_id}|{step}|{call_index}|{tool}|{payload_hash([args])}".encode()
    ).hexdigest()
    return f"inv_{digest[:24]}"


class ToolRunner:
    def __init__(
        self,
        store: Store,
        settings: Settings,
        *,
        mcp_manager: MCPManager | None = None,
        delegate_hook: DelegateHook | None = None,
        message_hook: MessageHook | None = None,
        memory_hook: MemoryWaitHook | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        self._mcp = mcp_manager
        self._skills = SkillRegistry()
        self._delegate_hook = delegate_hook
        self._message_hook = message_hook
        self._memory_hook = memory_hook
        self._inflight: dict[str, set[asyncio.Task[Any]]] = {}
        self._procs: dict[str, set[asyncio.subprocess.Process]] = {}
        self._log = get_logger("tools")

    # ------------------------------------------------------------ public API
    async def execute(
        self,
        *,
        run: Run,
        agent: Agent,
        tool: str,
        args: dict[str, Any],
        step: int,
        call_index: int,
    ) -> ToolExecResult:
        inv_id = deterministic_invocation_id(agent.agent_id, step, call_index, tool, args)

        # ---- idempotent resume: never blindly re-execute ---------------------
        existing = await self._store.get_invocation(inv_id)
        if existing is not None:
            if existing.status in (
                ToolInvocationStatus.COMPLETED,
                ToolInvocationStatus.FAILED,
                ToolInvocationStatus.TIMED_OUT,
                ToolInvocationStatus.CANCELLED,
            ):
                cached = await self._read_output(existing)
                return ToolExecResult(
                    invocation_id=inv_id,
                    status=existing.status,
                    output_text=f"(reused recorded result)\n{cached}",
                    evidence_refs=list(existing.evidence_refs),
                    error=existing.error,
                    control=(
                        "complete"
                        if tool == "builtin:complete_task"
                        else "wait_children"
                        if tool == "builtin:wait_children"
                        else None
                    ),
                )
            # STARTED (concurrent duplicate) or UNKNOWN (post-restart): no re-execution
            return ToolExecResult(
                invocation_id=inv_id,
                status=ToolInvocationStatus.UNKNOWN,
                output_text="invocation outcome unknown (engine restarted mid-execution); "
                "not re-executed — decide from the recorded state",
                error="invocation_unknown",
            )

        # ---- scope enforcement BEFORE execution ------------------------------
        run = await self._store.get_run(run.run_id)
        from .models import RunStatus

        if run.status != RunStatus.RUNNING:
            raise RJError("run_not_running", "run no longer accepts tool operations", status=409)
        check_time(run, agent)
        violation = self._scope_check(run, agent, tool, args)
        if violation is not None:
            violation = f"scope_violation: {violation}"
            inv = ToolInvocation(
                invocation_id=inv_id,
                run_id=run.run_id,
                agent_id=agent.agent_id,
                tool=tool,
                args=args,
                status=ToolInvocationStatus.FAILED,
                finished_at=utcnow(),
                error=violation,
            )
            async with self._store.write() as s:
                await self._store.insert_invocation(s, inv)
                await self._store.emit_simple(
                    s,
                    run,
                    EventType.TOOL_COMPLETED,
                    {
                        "invocation_id": inv_id,
                        "tool": tool,
                        "status": ToolInvocationStatus.FAILED.value,
                        "error": violation,
                    },
                    agent_id=agent.agent_id,
                )
            return ToolExecResult(
                invocation_id=inv_id,
                status=ToolInvocationStatus.FAILED,
                output_text=violation,
                error=violation,
            )

        # ---- record the attempt durably BEFORE executing ----------------------
        inv = ToolInvocation(
            invocation_id=inv_id,
            run_id=run.run_id,
            agent_id=agent.agent_id,
            tool=tool,
            args=args,
            status=ToolInvocationStatus.STARTED,
        )
        async with self._store.write() as s:
            agent.current_activity = f"Running {tool}"
            await self._store.update_agent_row(s, agent)
            await self._store.insert_invocation(s, inv)
            await self._store.emit_simple(
                s,
                run,
                EventType.TOOL_STARTED,
                {
                    "invocation_id": inv_id,
                    "tool": tool,
                    "status": ToolInvocationStatus.STARTED.value,
                    "args": args,
                },
                agent_id=agent.agent_id,
            )

        task = asyncio.current_task()
        self._inflight.setdefault(run.run_id, set()).add(task)  # type: ignore[arg-type]
        try:
            result = await self._dispatch(run, agent, inv, tool, args)
        except asyncio.CancelledError:
            await self._finalize(
                run, agent, inv, ToolInvocationStatus.CANCELLED, error="cancelled", output=b""
            )
            raise
        except Exception as exc:
            await self._finalize(run, agent, inv, ToolInvocationStatus.FAILED, error=str(exc), output=b"")
            return ToolExecResult(
                invocation_id=inv_id,
                status=ToolInvocationStatus.FAILED,
                output_text=f"tool error: {exc}",
                error=str(exc),
            )
        finally:
            self._inflight.get(run.run_id, set()).discard(task)  # type: ignore[arg-type]
        return result

    async def kill_run(self, run_id: str) -> None:
        """Stop path: kill process groups, cancel in-flight invocations."""
        for proc in list(self._procs.get(run_id, set())):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        processes = list(self._procs.pop(run_id, set()))
        tasks = [task for task in self._inflight.get(run_id, set()) if task is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if processes:
            await asyncio.gather(*(proc.wait() for proc in processes), return_exceptions=True)

    # -------------------------------------------------------------- internals
    def _scope_check(self, run: Run, agent: Agent, tool: str, args: dict[str, Any]) -> str | None:
        if not tool_allowed(tool, agent.allowed_tools, run.scope.denied_tools):
            return f"tool {tool!r} is not in the agent's allowed tools"
        if tool.startswith("mcp:") and self._mcp:
            violation = self._mcp.scope_violation(tool, args, run, agent)
            if violation:
                return violation
        # Playwright's `target` is a DOM selector/reference, not a network destination.
        target_keys = (
            ("url", "host", "domain", "ip")
            if self._mcp and self._mcp.is_browser_tool(tool)
            else TARGET_ARG_KEYS
        )
        for key in target_keys:
            value = args.get(key)
            if value is None:
                continue
            values = value if isinstance(value, list) else [value]
            for v in values:
                if not isinstance(v, str):
                    continue
                # builtin:http_get must honor the authorized URL path prefix,
                # exactly as the native assessment tools do; host-only coverage
                # would let an agent reach other paths/tenants on a shared host.
                if tool == "builtin:http_get" and key == "url":
                    covered = url_in_scope(v, agent.allowed_targets)
                else:
                    covered = target_covered(v, agent.allowed_targets)
                if not covered:
                    return f"target {v!r} is outside the agent's scope"
        return None

    async def _dispatch(
        self, run: Run, agent: Agent, inv: ToolInvocation, tool: str, args: dict[str, Any]
    ) -> ToolExecResult:
        timeout_s = min(
            float(args.get("timeout_seconds") or self._settings.tool_timeout_seconds),
            self._settings.tool_timeout_seconds,
        )
        remaining = check_time(run, agent)
        if remaining is not None:
            timeout_s = min(timeout_s, remaining)
        if tool == "builtin:exec":
            output, exit_code, streamed = await self._run_subprocess(run, agent, inv, args, timeout_s)
            status = ToolInvocationStatus.COMPLETED if exit_code == 0 else ToolInvocationStatus.FAILED
            return await self._finish_ok(
                run, agent, inv, status, output, exit_code=exit_code, streamed_output=streamed
            )

        coro = self._dispatch_nonproc(run, agent, tool, args)
        try:
            text, control = await asyncio.wait_for(coro, timeout=timeout_s)
        except TimeoutError:
            await self._finalize(
                run,
                agent,
                inv,
                ToolInvocationStatus.TIMED_OUT,
                error=f"timeout after {timeout_s}s",
                output=b"",
            )
            return ToolExecResult(
                invocation_id=inv.invocation_id,
                status=ToolInvocationStatus.TIMED_OUT,
                output_text=f"timed out after {timeout_s}s",
                error="timeout",
            )
        return await self._finish_ok(
            run, agent, inv, ToolInvocationStatus.COMPLETED, text.encode(), control=control
        )

    async def _dispatch_nonproc(
        self, run: Run, agent: Agent, tool: str, args: dict[str, Any]
    ) -> tuple[str, str | None]:
        if tool == "builtin:search_skills":
            return json.dumps(
                [
                    skill.model_dump(mode="json")
                    for skill in self._skills.search(str(args.get("query", "")), int(args.get("limit", 20)))
                ]
            ), None
        if tool == "builtin:load_skill":
            return self._skills.read(str(args.get("name", ""))), None
        if tool == "builtin:read_skill_file":
            return self._skills.read_file(str(args.get("name", "")), str(args.get("path", ""))), None
        if tool == "builtin:lookup_cve":
            from strix.tools.cve.tool import lookup_cve_json

            return await lookup_cve_json(
                product=str(args.get("product", "")),
                version=str(args.get("version", "")),
                cve_id=str(args.get("cve_id", "")),
                ecosystem=str(args.get("ecosystem", "")),
            ), None
        if tool == "builtin:read_workspace_file":

            def read_artifact() -> str:
                root = (self._settings.work_root / run.run_id).resolve()
                from pathlib import Path

                path = Path(str(args.get("path", "")))
                path = (root / path).resolve()
                if not path.is_relative_to(root) or not path.is_file():
                    raise RJError("scope_violation", "Artifact is outside this session workspace", status=403)
                with path.open("rb") as stream:
                    data = stream.read(min(self._settings.tool_output_cap_bytes, 262144) + 1)
                if b"\x00" in data:
                    raise RJError("validation_error", "Artifact must be a text file", status=422)
                cap = min(self._settings.tool_output_cap_bytes, 262144)
                return data[:cap].decode("utf-8", errors="replace") + (
                    "\n[truncated]" if len(data) > cap else ""
                )

            return await asyncio.to_thread(read_artifact), None
        if tool == "builtin:list_source_files":
            return await asyncio.to_thread(
                list_source_files, run, agent, str(args.get("path", ".")), int(args.get("limit", 250))
            ), None
        if tool == "builtin:read_source_file":
            return await asyncio.to_thread(
                read_source_file, run, agent, str(args.get("path", "")), self._settings.tool_output_cap_bytes
            ), None
        if tool == "builtin:ast_sink_search":
            return await asyncio.to_thread(
                ast_sink_search,
                run,
                agent,
                str(args.get("path", ".")),
                str(args.get("category", "all")),
                int(args.get("limit", 100)),
            ), None
        if tool == "builtin:repository_tree":
            return await github_source(
                run, agent, ref=str(args.get("ref", "HEAD")), limit=int(args.get("limit", 250))
            ), None
        if tool == "builtin:repository_read":
            return await github_source(
                run, agent, path=str(args.get("path", "")), ref=str(args.get("ref", "HEAD"))
            ), None
        if tool == "builtin:echo":
            return str(args.get("text", "")), None
        if tool == "builtin:http_get":
            output = await scoped_http_get(
                str(args.get("url", "")),
                agent.allowed_targets,
                output_cap=self._settings.tool_output_cap_bytes,
                timeout=self._settings.tool_timeout_seconds,
                cloud=run.environment.value == "cloud_managed",
            )
            return output.decode(errors="replace"), None
        if tool == "builtin:delegate":
            if not self._delegate_hook:
                raise RJError("tool_unavailable", "delegation hook not wired", status=500)
            child = await self._delegate_hook(agent, args)
            return f"delegated: {child.agent_id} name={child.name} status={child.status.value}", None
        if tool == "builtin:send_message":
            if not self._message_hook:
                raise RJError("tool_unavailable", "message hook not wired", status=500)
            return await self._message_hook(agent, args), None
        if tool == "builtin:report_finding":
            return await self._report_finding(run, agent, args), None
        if tool == "builtin:memory_search":
            if not self._memory_hook:
                raise RJError("tool_unavailable", "memory hook not wired", status=500)
            store = await self._memory_hook(agent, run)  # waits visibly when OV is down
            hits = await store.find(str(args.get("query", "")), limit=int(args.get("limit", 10)))
            return json.dumps(
                [{"uri": h.uri, "score": h.score, "abstract": h.abstract} for h in hits], indent=2
            ), None
        if tool == "builtin:wait_children":
            return "waiting for child agents", "wait_children"
        if tool == "builtin:complete_task":
            return str(args.get("summary", "")), "complete"
        if tool.startswith("mcp:"):
            if not self._mcp:
                raise RJError("tool_unavailable", "MCP manager not configured", status=503)
            return await self._mcp.call_tool(
                tool, args, timeout_seconds=self._settings.mcp_call_timeout_seconds
            ), None
        raise RJError("unknown_tool", f"no such tool: {tool}", status=422)

    async def _run_subprocess(
        self, run: Run, agent: Agent, inv: ToolInvocation, args: dict[str, Any], timeout_s: float
    ) -> tuple[bytes, int, bool]:
        argv = args.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise RJError("validation_error", "builtin:exec requires argv: list[str]", status=422)
        cap = self._settings.tool_output_cap_bytes
        workdir = self._settings.work_root / run.run_id
        workdir.mkdir(parents=True, exist_ok=True)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(workdir),
            "LANG": "C.UTF-8",
            "RJ_RUN_ID": run.run_id,
        }
        command = sandbox_command(argv, workdir)
        proc = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(workdir),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,  # own process group -> group kill
        )
        self._procs.setdefault(run.run_id, set()).add(proc)
        streamed = False
        try:
            try:

                async def bounded_output() -> bytes:
                    nonlocal streamed
                    output = bytearray()
                    discarded = 0
                    emitted_chars = 0
                    max_stream_chars = 65536
                    assert proc.stdout is not None
                    while chunk := await proc.stdout.read(8192):
                        keep = max(0, cap - len(output))
                        kept_bytes = chunk[:keep]
                        output.extend(kept_bytes)
                        discarded += max(0, len(chunk) - keep)
                        if kept_bytes and emitted_chars < max_stream_chars:
                            text_chunk = kept_bytes.decode("utf-8", errors="replace")
                            text_chunk = text_chunk[: max_stream_chars - emitted_chars]
                            if text_chunk:
                                emitted_chars += len(text_chunk)
                                streamed = True
                                async with self._store.write() as s:
                                    await self._store.emit_simple(
                                        s,
                                        run,
                                        EventType.TOOL_OUTPUT,
                                        {
                                            "invocation_id": inv.invocation_id,
                                            "tool": inv.tool,
                                            "chunk": text_chunk,
                                        },
                                        agent_id=agent.agent_id,
                                    )
                    await proc.wait()
                    if discarded:
                        output.extend(f"\n[... truncated {discarded} bytes]".encode())
                    return bytes(output)

                out = await asyncio.wait_for(bounded_output(), timeout=timeout_s)
            except TimeoutError:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
                await proc.wait()
                raise RJError(
                    "tool_timeout", f"timeout: killed process group after {timeout_s}s", status=408
                ) from None
            finally:
                self._procs.get(run.run_id, set()).discard(proc)
        except asyncio.CancelledError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            await proc.wait()
            raise
        return out, proc.returncode if proc.returncode is not None else -1, streamed

    async def _finish_ok(
        self,
        run: Run,
        agent: Agent,
        inv: ToolInvocation,
        status: ToolInvocationStatus,
        output: bytes,
        *,
        exit_code: int | None = None,
        control: str | None = None,
        streamed_output: bool = False,
    ) -> ToolExecResult:
        ev_refs: list[str] = []
        if output:
            ev = await self._capture_evidence(run, inv, output)
            ev_refs.append(ev.evidence_id)
        inv = await self._finalize(
            run,
            agent,
            inv,
            status,
            error=None,
            output=output,
            exit_code=exit_code,
            evidence_refs=ev_refs,
            streamed_output=streamed_output,
        )
        return ToolExecResult(
            invocation_id=inv.invocation_id,
            status=status,
            output_text=output.decode(errors="replace")[:4000],
            evidence_refs=ev_refs,
            control=control,
        )

    async def _capture_evidence(self, run: Run, inv: ToolInvocation, content: bytes) -> Evidence:
        ev = Evidence(
            run_id=run.run_id,
            sha256=hashlib.sha256(content).hexdigest(),
            mime="text/plain",
            size_bytes=len(content),
            source=f"tool:{inv.invocation_id}",
            storage_ref=f"{run.run_id}/",
        )
        path = self._settings.evidence_dir / f"{ev.evidence_id}.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        ev.storage_ref = path.name
        async with self._store.write() as s:
            await self._store.insert_evidence(s, ev)
        return ev

    async def _finalize(
        self,
        run: Run,
        agent: Agent,
        inv: ToolInvocation,
        status: ToolInvocationStatus,
        *,
        error: str | None,
        output: bytes,
        exit_code: int | None = None,
        evidence_refs: list[str] | None = None,
        streamed_output: bool = False,
    ) -> ToolInvocation:
        inv.status = status
        inv.error = error
        inv.exit_code = exit_code
        inv.finished_at = utcnow()
        inv.evidence_refs = evidence_refs or inv.evidence_refs
        if evidence_refs:
            inv.output_ref = evidence_refs[0]
        data: dict[str, Any] = {
            "invocation_id": inv.invocation_id,
            "tool": inv.tool,
            "status": status.value,
            "exit_code": exit_code,
        }
        if error:
            data["error"] = error
        async with self._store.write() as s:
            await self._store.update_invocation_row(s, inv)
            if output and not streamed_output:
                chunk_text = output.decode(errors="replace")[:8000]
                if chunk_text and not chunk_text.endswith("\n"):
                    chunk_text += "\n"
                await self._store.emit_simple(
                    s,
                    run,
                    EventType.TOOL_OUTPUT,
                    {
                        "invocation_id": inv.invocation_id,
                        "tool": inv.tool,
                        "chunk": chunk_text,
                    },
                    agent_id=agent.agent_id,
                )
            await self._store.emit_simple(s, run, EventType.TOOL_COMPLETED, data, agent_id=agent.agent_id)
        return inv

    async def _read_output(self, inv: ToolInvocation) -> str:
        if not inv.output_ref:
            return inv.error or ""
        evidence = await self._store.get_evidence(inv.output_ref)
        path = self._settings.evidence_dir / evidence.storage_ref
        try:
            return path.read_bytes()[:4000].decode(errors="replace")
        except OSError:
            return ""

    async def _verify_session_evidence_ref(self, run: Run, ref: str) -> str:
        """Verify that an evidence reference exists in the store or session workspace for this run."""
        cleaned = str(ref or "").strip()
        if not cleaned:
            raise RJError("validation_error", "evidence_ref must be a non-empty string", status=422)
        if cleaned.startswith("evd_"):
            try:
                ev = await self._store.get_evidence(cleaned)
            except RJError as exc:
                raise RJError(
                    "validation_error",
                    f"hallucinated or missing evidence_ref {cleaned!r}: not found in evidence store",
                    status=422,
                ) from exc
            if ev.run_id != run.run_id:
                raise RJError(
                    "validation_error",
                    f"evidence_ref {cleaned!r} belongs to a different pentest session",
                    status=422,
                )
            return cleaned

        workdir = (self._settings.work_root / run.run_id).resolve()
        candidate = (workdir / cleaned).resolve()
        if candidate.is_relative_to(workdir) and candidate.is_file() and candidate.stat().st_size > 0:
            return cleaned
        raise RJError(
            "validation_error",
            f"hallucinated or missing evidence_ref {cleaned!r}: must be a recorded evd_* ID "
            f"or non-empty workspace artifact inside run {run.run_id}",
            status=422,
        )

    async def _report_finding(self, run: Run, agent: Agent, args: dict[str, Any]) -> str:
        try:
            severity = FindingSeverity(str(args.get("severity", "info")).lower())
        except ValueError as exc:
            raise RJError(
                "validation_error", f"invalid severity {args.get('severity')!r}", status=422
            ) from exc

        raw_refs = args.get("evidence_refs")
        if raw_refs is None:
            raw_refs = []
        if not isinstance(raw_refs, list):
            raise RJError("validation_error", "evidence_refs must be a list of strings", status=422)

        verified_refs: list[str] = []
        for item in raw_refs:
            if not isinstance(item, str):
                raise RJError("validation_error", "every evidence_ref must be a string", status=422)
            valid_ref = await self._verify_session_evidence_ref(run, item)
            if valid_ref not in verified_refs:
                verified_refs.append(valid_ref)

        neg_ref_raw = str(args.get("negative_control_ref") or "").strip()
        neg_ref = ""
        if neg_ref_raw:
            neg_ref = await self._verify_session_evidence_ref(run, neg_ref_raw)
            if neg_ref not in verified_refs:
                verified_refs.append(neg_ref)

        high_sev = (FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM)
        if severity in high_sev and not verified_refs:
            raise RJError(
                "validation_error",
                f"{severity.value} findings require at least one valid session evidence_ref "
                "(version-only or unsubstantiated claims are rejected by the anti-hallucination gate)",
                status=422,
            )

        req_status_raw = str(args.get("verification_status") or "").strip().lower()
        status_map = {
            "observation": FindingStatus.OBSERVATION,
            "suspected": FindingStatus.SUSPECTED,
            "verified": FindingStatus.VERIFIED,
        }
        if req_status_raw and req_status_raw not in status_map:
            raise RJError(
                "validation_error",
                f"invalid verification_status {req_status_raw!r}; use observation, suspected, or verified",
                status=422,
            )

        has_differential_proof = bool(neg_ref) or len(verified_refs) >= 2
        clamped_note = ""
        if not verified_refs:
            final_status = FindingStatus.OBSERVATION
        elif req_status_raw == "verified":
            if has_differential_proof:
                final_status = FindingStatus.VERIFIED
            else:
                final_status = FindingStatus.SUSPECTED
                clamped_note = (
                    " [status clamped to suspected: verified status requires negative_control_ref "
                    "or >=2 distinct session evidence_refs]"
                )
        elif req_status_raw:
            final_status = status_map[req_status_raw]
        else:
            final_status = FindingStatus.VERIFIED if has_differential_proof else FindingStatus.SUSPECTED

        description = str(args.get("description", ""))
        cve_id = str(args.get("cve_id") or "").strip().upper()
        if cve_id and cve_id not in description and cve_id not in str(args.get("title", "")):
            description = f"[{cve_id}] {description}".strip()
        if clamped_note:
            description = f"{description}{clamped_note}".strip()

        async with self._store.write() as s:
            code = await self._store.next_finding_code(s, run.run_id)
            finding = Finding(
                run_id=run.run_id,
                code=code,
                title=str(args.get("title", "untitled")),
                severity=severity,
                status=final_status,
                target=str(args.get("target", "")),
                source_agent_id=agent.agent_id,
                description=description,
                remediation=str(args.get("remediation", "")),
                evidence_refs=verified_refs,
            )
            await self._store.insert_finding(s, finding)
            await self._store.emit_simple(
                s,
                run,
                EventType.FINDING_CREATED,
                {
                    "finding_id": finding.finding_id,
                    "code": finding.code,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                    "target": finding.target,
                },
                agent_id=agent.agent_id,
            )
        return (
            f"finding recorded: {finding.code} ({finding.finding_id}) "
            f"status={finding.status.value}{clamped_note}"
        )
