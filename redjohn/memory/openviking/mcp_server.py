"""Stdio MCP server entrypoint for OpenViking (volcengine/OpenViking) in RedJohn."""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import re
import sys
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from redjohn.config import load_settings
from redjohn.memory.openviking.config import CORE_OPENVIKING_TOOLS, probe_openviking_status
from redjohn.memory.openviking.runtime import (
    bind_default_mcp_identity,
    get_or_init_openviking_service,
    install_local_embedder_fallback,
)


logger = logging.getLogger(__name__)

_PREPARED_MCP: Any = None
_QUERY_TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:-]{2,}")


def _fallback_markdown_search(query: str, limit: int = 10, read_content: bool = False) -> str:
    """Direct filesystem fallback over viking:// markdown nodes so find/search never fail."""
    try:
        workspace = Path(load_settings().openviking.workspace).expanduser().resolve()
        viking_root = workspace / "viking" / "default"
        if not viking_root.is_dir():
            return "No results found."
        terms = [t.lower() for t in _QUERY_TOKEN_RE.findall(query or "")]
        candidates: list[tuple[float, float, str, str, str]] = []
        for md_path in viking_root.rglob("*.md"):
            if md_path.name in {".abstract.md", ".overview.md"}:
                continue
            try:
                text = md_path.read_text(encoding="utf-8", errors="ignore").strip()
            except OSError:
                continue
            if not text:
                continue
            rel = md_path.relative_to(viking_root).as_posix()
            if rel.startswith("user/redjohn/"):
                uri = "viking://" + rel.removeprefix("user/redjohn/")
            else:
                uri = f"viking://{rel}"
            haystack = f"{uri} {text}".lower()
            if terms:
                matched = sum(1 for t in terms if t in haystack)
                score = round(0.35 + 0.60 * (matched / max(len(terms), 1)), 4) if matched > 0 else 0.15
            else:
                score = 0.50
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            abstract = " ".join(lines[:3])[:260] if lines else md_path.name
            mtime = md_path.stat().st_mtime
            candidates.append((score, mtime, uri, abstract, text[:1500]))
        if not candidates:
            return "No results found."
        candidates.sort(key=lambda item: (-item[0], -item[1]))
        bounded = candidates[: max(1, min(int(limit or 10), 50))]
        out_lines = [f"Found {len(bounded)} result(s) in OpenViking memory:"]
        for idx, (score, _mtime, uri, abstract, full_txt) in enumerate(bounded, 1):
            out_lines.append(f"{idx}. [{score:.2f}] {uri} — {abstract}")
            if read_content:
                out_lines.append(f"   Content:\n{full_txt}")
        return "\n".join(out_lines)
    except Exception as exc:
        logger.debug("Markdown search fallback failed: %s", exc)
        return "No results found."


def _prepare_mcp_server() -> Any:
    """Configure the official OpenViking FastMCP instance for RedJohn MCP transport."""
    global _PREPARED_MCP  # noqa: PLW0603
    if _PREPARED_MCP is not None:
        return _PREPARED_MCP
    install_local_embedder_fallback()
    from openviking.server import mcp_endpoint
    from openviking.server.mcp_endpoint import mcp

    # Prune multi-tenant / ACL / cloud-only tools so only the 13 core memory & context tools remain
    allowed = set(CORE_OPENVIKING_TOOLS)
    tools_dict = getattr(mcp._tool_manager, "_tools", None)
    if isinstance(tools_dict, dict):
        for tool_name in list(tools_dict.keys()):
            if tool_name not in allowed:
                tools_dict.pop(tool_name, None)

    orig_remember = mcp_endpoint.remember

    async def _resilient_remember(
        messages: Any,
        session_id: str | None = None,
        wait: bool = True,
    ) -> dict[str, Any]:
        """Run OpenViking's remember tool, with direct viking:// markdown fallback if VLM is offline."""
        await get_or_init_openviking_service()
        bind_default_mcp_identity()
        try:
            res = await orig_remember(messages=messages, session_id=session_id, wait=wait)
            if isinstance(res, dict) and res.get("status") not in {"failed", "error"}:
                return res
        except Exception as exc:
            logger.debug("OpenViking VLM remember fallback triggered: %s", exc)

        # Fallback: persist directly into viking://resources/memories/ so nothing is ever lost
        text_chunks: list[str] = []
        if isinstance(messages, str):
            text_chunks.append(messages)
        elif isinstance(messages, list):
            for item in messages:
                if isinstance(item, dict):
                    role = item.get("role", "user")
                    content = item.get("content", "")
                    text_chunks.append(f"**{role}**: {content}")
                else:
                    text_chunks.append(str(item))
        body = "\n\n".join(text_chunks).strip()
        digest = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:10]
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        uri = f"viking://resources/memories/note-{ts}-{digest}.md"
        write_res = await mcp_endpoint.write(
            uri=uri,
            content=f"# Pentest Memory ({ts})\n\n{body}\n",
            mode="replace",
            wait=True,
        )
        return {
            "status": "committed_direct",
            "uri": uri,
            "write_result": write_res,
        }

    orig_find = mcp_endpoint.find
    orig_search = mcp_endpoint.search

    async def _resilient_find(
        query: str = "",
        target_uri: str = "",
        limit: int = 10,
        min_score: float = 0.05,
        level: list[int] | None = None,
        context_type: Any = None,
        read_content: bool = False,
        events_time_decay_protection: str | None = None,
    ) -> str:
        await get_or_init_openviking_service()
        bind_default_mcp_identity()
        try:
            res = await orig_find(
                query=query,
                target_uri=target_uri,
                limit=limit,
                min_score=min(float(min_score if min_score is not None else 0.05), 0.15),
                level=level,
                context_type=context_type,
                read_content=read_content,
                events_time_decay_protection=events_time_decay_protection,
            )
            if (
                isinstance(res, str)
                and res.strip()
                and not res.startswith(("Error:", "OpenViking MCP error"))
                and "No results found" not in res
                and "No matching context found" not in res
            ):
                return res
        except Exception as exc:
            logger.debug("OpenViking find fallback triggered: %s", exc)
        return _fallback_markdown_search(query=query, limit=limit, read_content=read_content)

    async def _resilient_search(
        query: str = "",
        *args: Any,
        limit: int = 10,
        read_content: bool = False,
        **kwargs: Any,
    ) -> str:
        await get_or_init_openviking_service()
        bind_default_mcp_identity()
        try:
            res = await orig_search(
                query=query,
                *args,
                limit=limit,
                read_content=read_content,
                **kwargs,
            )
            if (
                isinstance(res, str)
                and res.strip()
                and not res.startswith(("Error:", "OpenViking MCP error"))
                and "No results found" not in res
                and "No matching context found" not in res
            ):
                return res
        except Exception as exc:
            logger.debug("OpenViking search fallback triggered: %s", exc)
        return _fallback_markdown_search(query=query, limit=limit, read_content=read_content)

    # Wrap every registered tool so the embedded OpenVikingService & identity context
    # are guaranteed to be initialized before any stdio request executes.
    if isinstance(tools_dict, dict):
        for name, tool_obj in tools_dict.items():
            if name == "remember":
                tool_obj.fn = _resilient_remember
                continue
            if name == "find":
                tool_obj.fn = _resilient_find
                continue
            if name == "search":
                tool_obj.fn = _resilient_search
                continue
            if name == "health":
                orig_health = tool_obj.fn

                @wraps(orig_health)
                async def _enhanced_health(*args: Any, **kwargs: Any) -> str:
                    await get_or_init_openviking_service()
                    bind_default_mcp_identity()
                    base = await orig_health(*args, **kwargs)
                    status = probe_openviking_status()
                    try:
                        parsed = json.loads(base) if isinstance(base, str) else {"status": base}
                        if isinstance(parsed, dict):
                            parsed["openviking_config"] = status
                            return json.dumps(parsed, ensure_ascii=False)
                    except Exception:
                        pass
                    return json.dumps(
                        {"healthy": True, "raw": str(base), "openviking_config": status},
                        ensure_ascii=False,
                    )

                tool_obj.fn = _enhanced_health
                continue

            orig_fn = tool_obj.fn

            def _make_wrapper(fn: Any) -> Any:
                @wraps(fn)
                async def _wrapped(*args: Any, **kwargs: Any) -> Any:
                    await get_or_init_openviking_service()
                    bind_default_mcp_identity()
                    return await fn(*args, **kwargs)

                return _wrapped

            tool_obj.fn = _make_wrapper(orig_fn)

    _PREPARED_MCP = mcp
    return mcp


class InProcessOpenVikingMCPServer:
    """In-process MCPServer adapter wrapping OpenViking's FastMCP endpoint.

    Shares the process-local ``OpenVikingService`` singleton with RedJohn's
    automatic memory hooks so there is zero file-lock contention on
    ``~/.redjohn/openviking/data`` and zero subprocess spawn latency.
    """

    def __init__(self, config: Any) -> None:
        self.config = config
        self.name = getattr(config, "name", "openviking")
        self.use_structured_content = False
        self._mcp: Any = None
        self.server_initialize_result = SimpleNamespace(
            serverInfo=SimpleNamespace(name="openviking-mcp", version="0.5.1.1")
        )

    async def connect(self) -> None:
        self._mcp = _prepare_mcp_server()
        await get_or_init_openviking_service()

    async def cleanup(self) -> None:
        return None

    async def list_tools(self) -> list[Any]:
        if self._mcp is None:
            self._mcp = _prepare_mcp_server()
        tools = await self._mcp.list_tools()
        allowed = getattr(self.config, "allowed_tools", None)
        if allowed is not None:
            allowed_set = set(allowed)
            return [t for t in tools if t.name in allowed_set]
        return list(tools)

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None) -> Any:
        from mcp.types import CallToolResult, TextContent

        if self._mcp is None:
            self._mcp = _prepare_mcp_server()
        try:
            res = await self._mcp.call_tool(tool_name, arguments or {})
            if isinstance(res, tuple) and len(res) == 2:
                blocks, structured = res
                return CallToolResult(
                    content=list(blocks),
                    structuredContent=structured if isinstance(structured, dict) else None,
                    isError=False,
                )
            if isinstance(res, (list, tuple)):
                return CallToolResult(content=list(res), isError=False)
            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=json.dumps(res, ensure_ascii=False, default=str),
                    )
                ],
                isError=False,
            )
        except Exception as exc:
            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=f"OpenViking MCP error ({tool_name}): {exc}",
                    )
                ],
                isError=True,
            )


def main() -> None:
    """Run the OpenViking MCP server over stdio."""
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    server = _prepare_mcp_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
