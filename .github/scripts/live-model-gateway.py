#!/usr/bin/env python3
"""Bounded, real OpenAI HTTPS relay for the opt-in CLI/TUI integration.

The upstream is fixed, TLS verification stays enabled, request bodies and
credentials are never evidence. The SDK receives only a per-run local token.
This is a transport budget, not a model double: every accepted call reaches
the real provider. Only the separately labelled contract tests stub transport.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_CALLS = 24
MAX_OUTPUT_TOKENS = 2048
MAX_REQUEST_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_SECONDS = 1200
PATHS = frozenset({"/v1/responses", "/v1/chat/completions"})
TOOLS = frozenset({"assessment_control", "finish_scan", "wait_for_user"})


class Gateway:
    def __init__(self, model: str, credential: str) -> None:
        if not model or len(model) > 128 or any(c.isspace() for c in model) or "/" in model:
            raise ValueError("blocked_model: use an explicit bare OpenAI model identifier")
        if not credential:
            raise ValueError("blocked_missing_credential")
        self.model, self._credential = model, credential
        self.local_token = secrets.token_urlsafe(32)
        self._lock = threading.Lock()
        self._started = time.monotonic()
        self._handlers = threading.BoundedSemaphore(2)
        self.accepted = 0
        self.completed = 0
        self.rejected = 0
        self.provider_errors = 0
        class Server(ThreadingHTTPServer):
            request_queue_size = 2

            def get_request(self):
                client, address = super().get_request()
                client.settimeout(5)
                return client, address

            def process_request(server, request, address):
                if not self._handlers.acquire(blocking=False):
                    with self._lock:
                        self.rejected += 1
                    server.shutdown_request(request)
                    return
                try:
                    super().process_request(request, address)
                except BaseException:
                    self._handlers.release()
                    raise

            def process_request_thread(server, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    self._handlers.release()

        self._server = Server(("127.0.0.1", 0), self._handler())
        self._server.daemon_threads = False
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/v1"

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "evidence_kind": "real_provider_https_relay",
                "model": self.model,
                "accepted_calls": self.accepted,
                "completed_calls": self.completed,
                "rejected_calls": self.rejected,
                "provider_errors": self.provider_errors,
                "max_calls": MAX_CALLS,
                "max_output_tokens_per_call": MAX_OUTPUT_TOKENS,
                "max_request_bytes": MAX_REQUEST_BYTES,
                "max_response_bytes": MAX_RESPONSE_BYTES,
                "max_total_seconds": MAX_TOTAL_SECONDS,
                "max_active_handlers": 2,
                "upstream": "https://api.openai.com",
                "upstream_tls_verified": True,
            }

    def _admit(self, body: dict, path: str) -> dict:
        if path not in PATHS or body.get("model") != self.model:
            raise ValueError("blocked_unapproved_provider_request")
        # Cap preflight and resumed/child agent calls too. These are the actual
        # provider request fields, not an instruction embedded in the prompt.
        field = "max_output_tokens" if path == "/v1/responses" else "max_completion_tokens"
        requested = body.pop("max_tokens", MAX_OUTPUT_TOKENS)
        requested = body.get(field, requested)
        if type(requested) is not int or requested < 1:
            raise ValueError("invalid_output_budget")
        body[field] = min(requested, MAX_OUTPUT_TOKENS)
        tools = body.get("tools", [])
        if not isinstance(tools, list) or any(not isinstance(tool, dict) for tool in tools):
            raise ValueError("invalid_tool_schema")
        selected = []
        for tool in tools:
            function = tool.get("function", {})
            if not isinstance(function, dict):
                raise ValueError("invalid_tool_schema")
            name = tool.get("name", function.get("name"))
            if name is not None and not isinstance(name, str):
                raise ValueError("invalid_tool_schema")
            if tool.get("type") == "function" and name in TOOLS:
                selected.append(tool)
        body["tools"] = selected
        with self._lock:
            if self.accepted >= MAX_CALLS or time.monotonic() - self._started >= MAX_TOTAL_SECONDS:
                raise ValueError("provider_budget_exhausted")
            self.accepted += 1
        return body

    @staticmethod
    def validate_response(payload: bytes, content_type: str) -> None:
        def item(value):
            if not isinstance(value, dict) or not isinstance(value.get("type", ""), str):
                raise ValueError("invalid_structured_model_item")
            kind = value.get("type", "")
            name = value.get("name")
            if kind.endswith("_call") and (kind != "function_call" or not isinstance(name, str) or name not in TOOLS):
                raise ValueError("unapproved_model_tool_call")
            if kind == "function":
                function = value.get("function")
                if (not isinstance(function, dict) or not isinstance(function.get("name"), str)
                        or function["name"] not in TOOLS):
                    raise ValueError("unapproved_chat_model_tool_call")

        def inspect(value):
            if not isinstance(value, dict):
                raise ValueError("invalid_model_response")
            for field in ("item",):
                if field in value:
                    item(value[field])
            if "output" in value:
                if not isinstance(value["output"], list):
                    raise ValueError("invalid_model_output")
                for child in value["output"]:
                    item(child)
            if "response" in value:
                inspect(value["response"])
            if "choices" in value:
                if not isinstance(value["choices"], list):
                    raise ValueError("invalid_chat_choices")
                for choice in value["choices"]:
                    if not isinstance(choice, dict):
                        raise ValueError("invalid_chat_choice")
                    for field in ("message", "delta"):
                        message = choice.get(field, {})
                        if not isinstance(message, dict) or not isinstance(message.get("tool_calls", []), list):
                            raise ValueError("invalid_chat_tool_calls")
                        for child in message.get("tool_calls", []):
                            item(child)
        try:
            if "text/event-stream" in content_type:
                for line in payload.splitlines():
                    if line.startswith(b"data: ") and line != b"data: [DONE]":
                        inspect(json.loads(line[6:]))
            else:
                inspect(json.loads(payload))
        except RecursionError:
            raise ValueError("model_response_json_depth_exceeded") from None

    def _handler(self):
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                connection = None
                try:
                    self.connection.settimeout(120)
                    if self.headers.get("Authorization") != f"Bearer {gateway.local_token}":
                        raise ValueError("invalid_local_gateway_authorization")
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= MAX_REQUEST_BYTES or self.headers.get("Transfer-Encoding"):
                        raise ValueError("invalid_request_size")
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict):
                        raise ValueError("invalid_json_object")
                    body = gateway._admit(body, self.path)
                    connection = http.client.HTTPSConnection("api.openai.com", timeout=60)
                    connection.request(
                        "POST", self.path, json.dumps(body).encode(),
                        {"Authorization": f"Bearer {gateway._credential}",
                         "Content-Type": "application/json", "Accept": self.headers.get("Accept", "application/json")},
                    )
                    response = connection.getresponse()
                    if response.status != 200:
                        with gateway._lock:
                            gateway.provider_errors += 1
                        self.send_error(502, "real_provider_request_failed")
                        return
                    total, started, chunks = 0, time.monotonic(), []
                    while chunk := response.read1(16384):
                        total += len(chunk)
                        if total > MAX_RESPONSE_BYTES or time.monotonic() - started > 120:
                            raise TimeoutError("real_provider_response_budget_exhausted")
                        chunks.append(chunk)
                    payload = b"".join(chunks)
                    content_type = response.getheader("Content-Type", "application/json")
                    gateway.validate_response(payload, content_type)
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
                    self.wfile.flush()
                    with gateway._lock:
                        gateway.completed += 1
                except (ValueError, RecursionError, OSError, TimeoutError, http.client.HTTPException):
                    with gateway._lock:
                        gateway.rejected += 1
                    with contextlib.suppress(OSError):
                        self.send_error(429, "bounded_provider_transport_rejected")
                finally:
                    self.close_connection = True
                    if connection is not None:
                        connection.close()

        return Handler

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("provider_gateway_cleanup_failed")
        with socket.socket() as check:
            check.settimeout(0.1)
            if check.connect_ex(self._server.server_address) == 0:
                raise RuntimeError("provider_gateway_listener_survived")
