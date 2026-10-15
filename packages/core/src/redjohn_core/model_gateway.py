"""Model gateway: thin adapters over official provider SDKs.

* ``anthropic`` — official ``anthropic`` SDK (optional extra). API key comes
  from settings (env/keyring), never logged.
* ``fixture`` — deterministic scripted provider for tests and demos ONLY.
  Selected via ``RJ_MODEL_PROVIDER=fixture``; responses come from a JSON
  script (``RJ_FIXTURE_SCRIPT``) keyed by agent name. The fixture is
  replay-safe: the response for a turn depends only on (agent name, step),
  so LangGraph resume after an engine restart never diverges.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .errors import RJError
from .logging import get_logger
from .models import Agent, Run
from .settings import Settings


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class ModelResponse:
    content: str
    tool_calls: tuple[ToolCall, ...] = ()
    done: bool = False
    usage: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class ModelGateway(Protocol):
    name: str

    async def complete(
        self,
        *,
        agent: Agent,
        run: Run,
        step: int,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        max_output_tokens: int = 4096,
        temperature: float | None = None,
    ) -> ModelResponse: ...


# ---------------------------------------------------------------------------
# fixture provider (tests only)
# ---------------------------------------------------------------------------

class FixtureUnavailable(RJError):
    def __init__(self, message: str) -> None:
        super().__init__("fixture_provider_error", message, status=500)


class FixtureGateway:
    """Deterministic scripted provider. FIXTURE-ONLY: never selectable in a
    production build unless RJ_MODEL_PROVIDER=fixture is explicitly set."""

    name = "fixture"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._script = self._load_script(settings.fixture_script)

    @staticmethod
    def _load_script(path: Path | None) -> dict[str, Any]:
        if path is None:
            # built-in minimal script: every agent immediately finishes
            return {"default": [{"content": "fixture: no script", "done": True}]}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FixtureUnavailable(f"cannot load fixture script {path}: {exc}") from exc

    async def complete(
        self,
        *,
        agent: Agent,
        run: Run,
        step: int,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        max_output_tokens: int = 4096,
        temperature: float | None = None,
    ) -> ModelResponse:
        script = self._script
        turns = script.get(agent.name) or script.get(agent.role.value) or script.get("default")
        if not turns:
            raise FixtureUnavailable(f"no fixture turns for agent {agent.name!r}")
        if step >= len(turns):
            return ModelResponse(content="", done=True)
        turn = turns[step]
        calls = tuple(
            ToolCall(id=f"call_{agent.agent_id}_{step}_{i}", name=c["name"], args=c.get("args", {}))
            for i, c in enumerate(turn.get("tool_calls", []))
        )
        done = bool(turn.get("done", not calls))
        return ModelResponse(content=turn.get("content", ""), tool_calls=calls, done=done)


# ---------------------------------------------------------------------------
# anthropic adapter
# ---------------------------------------------------------------------------

def tool_wire_name(name: str) -> str:
    """Stable, collision-resistant provider identifier; canonical names stay internal."""
    return "rj_" + hashlib.sha256(name.encode()).hexdigest()[:40]


class AnthropicGateway:
    """Thin adapter over the official anthropic SDK (optional extra)."""

    name = "anthropic"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._log = get_logger("gateway.anthropic")
        self._cached_client: Any = None

    def _client(self) -> Any:
        # Reuse one client (and its httpx connection pool) for the gateway's
        # lifetime: it is called twice per model step (count_tokens + create),
        # and constructing a fresh client each time leaked a pool per call.
        if self._cached_client is not None:
            return self._cached_client
        try:
            import anthropic  # optional dependency
        except ImportError as exc:
            raise RJError(
                "model_provider_unavailable",
                "the 'anthropic' extra is not installed (pip install redjohn-core[anthropic])",
                status=503,
            ) from exc
        if not self._settings.anthropic_api_key:
            raise RJError(
                "model_provider_unavailable",
                "no Anthropic API key configured (RJ_ANTHROPIC_API_KEY / keyring)",
                status=503,
            )
        self._cached_client = anthropic.AsyncAnthropic(
            api_key=self._settings.anthropic_api_key,
            **({"base_url": self._settings.model_base_url} if self._settings.model_base_url else {}),
        )
        return self._cached_client

    wire_name = staticmethod(tool_wire_name)

    def _request(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> dict[str, Any]:
        system = "\n".join(str(m["content"]) for m in messages if m["role"] == "system")
        convo: list[dict[str, Any]] = []
        for message in messages:
            role = message["role"]
            if role == "system":
                continue
            if role == "tool":
                blocks = [{"type": "tool_result", "tool_use_id": message["tool_call_id"],
                           "content": str(message["content"])}]
                role = "user"
            else:
                blocks = []
                if message.get("content"):
                    blocks.append({"type": "text", "text": str(message["content"])})
                blocks.extend({"type": "tool_use", "id": call["id"],
                               "name": self.wire_name(call["name"]), "input": call["args"]}
                              for call in message.get("tool_calls", []))
                if not blocks:
                    blocks = [{"type": "text", "text": "(no text)"}]
            # Consecutive parallel tool results must be in one user message.
            if convo and convo[-1]["role"] == role:
                convo[-1]["content"].extend(blocks)
            else:
                convo.append({"role": role, "content": blocks})
        return {"model": self._settings.model_name, "system": system, "messages": convo,
                "tools": [{"name": self.wire_name(t.name), "description": t.description,
                           "input_schema": t.input_schema or {"type": "object"}} for t in tools]}

    async def input_tokens(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> int:
        """Use the provider's tokenizer before reserving a bounded generation."""
        counted = await self._client().messages.count_tokens(**self._request(messages, tools))
        return int(counted.input_tokens)

    async def complete(
        self,
        *,
        agent: Agent,
        run: Run,
        step: int,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        max_output_tokens: int = 4096,
        temperature: float | None = None,
    ) -> ModelResponse:
        client = self._client()
        resp = await client.messages.create(
            **self._request(messages, tools), max_tokens=max_output_tokens,
            **({"temperature": temperature} if temperature is not None else {}),
        )
        content_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in resp.content:
            if block.type == "text":
                content_parts.append(block.text)
            elif block.type == "tool_use":
                canonical = {self.wire_name(t.name): t.name for t in tools}.get(block.name)
                if canonical is None:
                    raise RJError("invalid_tool_call", "provider returned an unadvertised tool", status=502)
                calls.append(ToolCall(id=block.id, name=canonical, args=dict(block.input)))
        usage = {
            "input_tokens": getattr(resp.usage, "input_tokens", 0),
            "output_tokens": getattr(resp.usage, "output_tokens", 0),
        }
        return ModelResponse(
            content="\n".join(content_parts),
            tool_calls=tuple(calls),
            done=resp.stop_reason != "tool_use",
            usage=usage,
        )


def gateway_from_settings(settings: Settings, *, request_timeout_seconds: float = 120) -> ModelGateway:
    if settings.model_provider == "fixture":
        return FixtureGateway(settings)
    if settings.model_provider == "anthropic":
        return AnthropicGateway(settings)
    if settings.model_provider in ("zai", "zai-coding-plan", "deepseek", "openai", "openrouter", "custom"):
        from .compat_gateway import OpenAICompatibleGateway
        return OpenAICompatibleGateway(settings, request_timeout_seconds=request_timeout_seconds)
    if settings.model_provider == "codex":
        from .codex_gateway import CodexGateway
        return CodexGateway(settings)
    raise RJError(
        "model_provider_unavailable",
        f"unknown model provider {settings.model_provider!r} "
        "(supported: anthropic, fixture)",
        status=503,
    )
