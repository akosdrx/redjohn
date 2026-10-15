"""OpenViking language requests through the selected saved provider, including OAuth."""

from __future__ import annotations

import ast
import secrets
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from .errors import unauthorized, validation
from .integrations import IntegrationStore
from .model_gateway import gateway_from_settings


class CompletionInput(BaseModel):
    model_config = ConfigDict(extra="allow")
    model: str
    messages: list[dict[str, Any]] = Field(min_length=1, max_length=100)
    max_tokens: int = Field(default=8192, ge=1, le=32768)
    max_completion_tokens: int | None = Field(default=None, ge=1, le=32768)
    stream: bool = False
    temperature: float | None = Field(default=None, ge=0, le=2)
    response_format: dict[str, Any] | None = None


async def authenticate(request: Request) -> None:
    from .api import get_engine

    store = IntegrationStore(get_engine(request).settings)
    configured = store.read().get("memory", {})
    key = store.decrypt(configured.get("model_proxy_secret"))
    bearer = request.headers.get("authorization", "")
    if not key or not secrets.compare_digest(bearer, "Bearer " + key):
        raise unauthorized()


def normalize_memory_output(content: str) -> str:
    """Repair a small model's whole-response quoting of the SDK operation DSL.

    No code is evaluated here. OpenViking still parses and validates operations.
    Summaries, JSON and malformed operation text retain their original content.
    """
    text = content.strip()
    for quote in ('"""', "'''"):
        if text.startswith(quote) and text.endswith(quote):
            inner = text[3:-3].strip()
            if inner.partition("\n")[0].strip() == "python":
                inner = inner.partition("\n")[2].lstrip()
            if inner.startswith("sdk."):
                try:
                    ast.parse(inner)
                except SyntaxError:
                    break
                return inner
    return content


def install_memory_model_proxy(app: Any) -> None:
    # This credential grants only language inference; it never grants engine API access.
    router = APIRouter(prefix="/memory-model/v1", dependencies=[Depends(authenticate)])

    @router.post("/chat/completions")
    async def complete(request: Request, body: CompletionInput) -> dict[str, Any]:
        from .api import get_engine

        engine = get_engine(request)
        store = IntegrationStore(engine.settings)
        memory = store.read().get("memory", {})
        identifier = memory.get("provider_connection_id")
        if not identifier or body.model != memory.get("selected_model"):
            raise validation("The request must use the saved OpenViking model.")
        if body.stream or getattr(body, "tools", None):
            raise validation("Memory inference uses non-streaming text requests without tools.")
        settings = engine.settings.model_copy(update=store.provider_settings(identifier))
        settings.model_name = body.model
        messages = body.messages
        response_format = getattr(body, "response_format", None)
        if response_format and response_format.get("type") in ("json_object", "json_schema"):
            import json

            messages = [
                {"role": "system", "content": "Return JSON only. " + json.dumps(response_format)},
                *messages,
            ]
        # Background extraction uses OpenViking's ten-minute model timeout.
        # CPU inference can exceed the foreground provider's shorter deadline.
        response = await gateway_from_settings(settings, request_timeout_seconds=600).complete(
            agent=None,
            run=None,
            step=0,
            messages=messages,
            tools=[],
            max_output_tokens=body.max_completion_tokens or body.max_tokens,
            temperature=body.temperature,
        )
        if response.tool_calls:
            raise validation("The memory model returned an unexpected tool call.")
        return {
            "id": "chatcmpl-" + uuid.uuid4().hex,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": normalize_memory_output(response.content)},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": response.usage.get("input_tokens", 0),
                "completion_tokens": response.usage.get("output_tokens", 0),
                "total_tokens": sum(response.usage.get(k, 0) for k in ("input_tokens", "output_tokens")),
            },
        }

    app.include_router(router)
