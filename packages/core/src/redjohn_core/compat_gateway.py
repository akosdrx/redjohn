"""OpenAI Chat Completions wire adapter, including z.ai API/Coding Plan."""

from __future__ import annotations

import json
from typing import Any

import httpx
import jsonschema
from openai import APIConnectionError, APIStatusError, AsyncOpenAI, Omit

from .errors import RJError
from .integrations import PROVIDERS, validate_endpoint
from .model_gateway import ModelResponse, ToolCall, ToolSpec, tool_wire_name


class OpenAICompatibleGateway:
    def __init__(self, settings: Any, *, transport: Any = None, request_timeout_seconds: float = 120):
        self._settings = settings
        self._transport = transport
        self._request_timeout_seconds = request_timeout_seconds
        self.name = settings.model_provider

    wire_name = staticmethod(tool_wire_name)

    async def input_tokens(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> int:
        # No shared remote tokenizer exists for compatible endpoints. Reserve
        # conservatively for the complete serialized request, including tools.
        return len(json.dumps(self._request(messages, tools, 1), ensure_ascii=False).encode()) + 1024

    def _request(self, messages: list[dict[str, Any]], tools: list[ToolSpec], limit: int) -> dict[str, Any]:
        convo = []
        for message in messages:
            item = {"role": message["role"], "content": message.get("content") or ""}
            if message.get("tool_call_id"):
                item["tool_call_id"] = message["tool_call_id"]
            if message.get("tool_calls"):
                item["tool_calls"] = [
                    {
                        "id": c["id"],
                        "type": "function",
                        "function": {
                            "name": self.wire_name(c["name"]),
                            "arguments": json.dumps(c["args"], ensure_ascii=False),
                        },
                    }
                    for c in message["tool_calls"]
                ]
            if message.get("reasoning_content"):
                item["reasoning_content"] = message["reasoning_content"]
            convo.append(item)
        body = {
            "model": self._settings.model_name,
            "messages": convo,
            "stream": False,
            "max_completion_tokens" if self.name == "openai" else "max_tokens": limit,
        }
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": self.wire_name(t.name),
                        "description": t.description,
                        "parameters": t.input_schema or {"type": "object"},
                    },
                }
                for t in tools
            ]
        if self.name in ("zai", "zai-coding-plan"):
            # z.ai requires preserved reasoning on tool continuations when
            # thinking is enabled. Explicitly select non-thinking mode here.
            body["thinking"] = {"type": "disabled"}
        return body

    async def complete(
        self,
        *,
        agent: Any,
        run: Any,
        step: int,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        max_output_tokens: int = 4096,
        temperature: float | None = None,
    ) -> ModelResponse:
        base = validate_endpoint(self._settings.model_base_url or PROVIDERS[self.name][1])
        key = self._settings.model_api_key
        if not key and self.name != "custom":
            raise RJError(
                "model_provider_unavailable",
                "Configure this provider's API key in Settings → Providers.",
                status=503,
            )
        try:
            body = self._request(messages, tools, max_output_tokens)
            if temperature is not None:
                body["temperature"] = temperature
            thinking = body.pop("thinking", None)
            async with AsyncOpenAI(
                api_key=key or "local-endpoint",
                base_url=base,
                max_retries=0,
                http_client=httpx.AsyncClient(
                    timeout=self._request_timeout_seconds, transport=self._transport, follow_redirects=False,
                ),
            ) as client:
                response = await client.chat.completions.create(
                    **body,
                    extra_headers=None if key else {"Authorization": Omit()},
                    **({"extra_body": {"thinking": thinking}} if thinking else {})
                )
            data = response.model_dump()
            choice = data["choices"][0]
            message = choice["message"]
            calls = []
            mapping = {self.wire_name(t.name): t for t in tools}
            for call in message.get("tool_calls") or []:
                tool = mapping.get(call["function"]["name"])
                if tool is None:
                    raise ValueError("unadvertised tool")
                args = json.loads(call["function"]["arguments"])
                jsonschema.validate(args, tool.input_schema or {"type": "object"})
                calls.append(ToolCall(id=call["id"], name=tool.name, args=args))
            usage = data.get("usage") or {}
            usage = (
                {
                    "input_tokens": int(usage["prompt_tokens"]),
                    "output_tokens": int(usage["completion_tokens"]),
                }
                if "prompt_tokens" in usage and "completion_tokens" in usage
                else {}
            )
            if choice.get("finish_reason") in ("length", "content_filter"):
                raise RJError(
                    "provider_incomplete_response",
                    "The provider stopped before completing its response; adjust the output limit or model.",
                    status=502,
                )
            if not calls and not message.get("content"):
                raise ValueError("empty response")
            return ModelResponse(
                content=message.get("content") or "",
                tool_calls=tuple(calls),
                done=not calls,
                usage=usage,
                metadata={"reasoning_content": message["reasoning_content"]}
                if message.get("reasoning_content")
                else {},
            )
        except RJError:
            raise
        except APIStatusError as exc:
            code = "provider_auth_failed" if exc.status_code in (401, 403) else "provider_request_failed"
            raise RJError(
                code,
                f"{self.name} returned HTTP {exc.status_code}; check credentials, model and quota.",
                status=502,
            ) from None
        except APIConnectionError:
            raise RJError(
                "provider_connection_failed",
                f"Cannot reach {self.name}; check the endpoint and network.",
                status=503,
            ) from None
        except httpx.HTTPError as exc:
            raise RJError(
                "provider_connection_failed",
                f"Cannot reach {self.name}; check the endpoint and network.",
                status=503,
            ) from exc
        except (ValueError, KeyError, TypeError, IndexError, jsonschema.ValidationError) as exc:
            raise RJError(
                "invalid_provider_response",
                "The provider returned invalid data or an unadvertised tool call.",
                status=502,
            ) from exc
