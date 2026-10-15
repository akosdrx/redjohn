"""Official Codex app-server integration; OAuth is managed by the Codex CLI.

Each local RedJohn profile owns a separate Codex home. We never import another
application's login. Gateway turns use an empty environment and a structured
plan; actual tools remain in RedJohn's scope-checked tool runner.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

import jsonschema

from .errors import RJError
from .model_gateway import ModelResponse, ToolCall, ToolSpec


def codex_binary(settings: Any) -> str | None:
    from .tool_catalog import bundled_command

    if not settings.codex_binary and (bundled := bundled_command("codex")):
        return bundled[0]
    supplied = settings.codex_binary or shutil.which("codex")
    if supplied and Path(supplied).is_file() and os.access(supplied, os.X_OK):
        return supplied
    mac_app = Path("/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex")
    return str(mac_app) if mac_app.is_file() else None


class CodexAppServer:
    def __init__(self, settings: Any):
        self.settings = settings
        self.process: Any = None
        self.pending: dict[int, Any] = {}
        self.notifications: asyncio.Queue = asyncio.Queue(maxsize=2048)
        self.sequence = 0
        self.reader: Any = None
        self.login: dict[str, Any] | None = None
        self.login_results: dict[str, bool] = {}

    async def start(self) -> None:
        if self.process is not None and self.process.returncode is None:
            return
        binary = codex_binary(self.settings)
        if not binary:
            raise RJError(
                "codex_cli_unavailable",
                "Install the official Codex CLI or set RJ_CODEX_BINARY, then retry.",
                status=503,
            )
        home = self.settings.profile_dir / "codex"
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Environment overrides affect this child only. Credentials from the
        # launching app and OS keyring are not a fallback for RedJohn's login.
        environment = {
            k: os.environ[k] for k in ("HOME", "PATH", "TMPDIR", "SYSTEMROOT", "LANG") if k in os.environ
        }
        environment["CODEX_HOME"] = str(home)
        arguments = [
            binary,
            "-c",
            'cli_auth_credentials_store="file"',
            "-c",
            'web_search="disabled"',
            "-c",
            'sandbox_mode="read-only"',
            "-c",
            'approval_policy="never"',
        ]
        for feature in (
            "shell_tool",
            "unified_exec",
            "apps",
            "browser_use",
            "computer_use",
            "view_image",
            "multi_agent",
            "skills",
            "remote_plugin",
            "workspace_dependencies",
            "shell_snapshot",
        ):
            arguments += ["-c", f"features.{feature}=false"]
        self.process = await asyncio.create_subprocess_exec(
            *arguments,
            "app-server",
            cwd=home,
            env=environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=8 * 1024 * 1024,
        )
        self.reader = asyncio.create_task(self._read())
        try:
            await self.request(
                "initialize",
                {
                    "clientInfo": {"name": "redjohn", "title": "RedJohn", "version": "0.1.0"},
                    "capabilities": {"experimentalApi": True},
                },
            )
            await self._write({"method": "initialized", "params": {}})
        except BaseException:
            await self.close()
            raise

    async def _write(self, value: Any) -> None:
        self.process.stdin.write((json.dumps(value) + "\n").encode())
        await self.process.stdin.drain()

    async def _read(self) -> None:
        failure = RJError("codex_disconnected", "Codex disconnected; retry the operation.", status=503)
        try:
            while line := await self.process.stdout.readline():
                value = json.loads(line)
                if "id" in value and "method" not in value:
                    future = self.pending.pop(value["id"], None)
                    if future is not None and not future.done():
                        if value.get("error"):
                            future.set_exception(
                                RJError(
                                    "codex_request_failed",
                                    "Codex rejected the request; check CLI version, login and subscription.",
                                    status=502,
                                )
                            )
                        else:
                            future.set_result(value.get("result", {}))
                elif "id" in value:
                    # No execution/approval callback is delegated to this
                    # model-only gateway. Explicitly reject server requests.
                    await self._write(
                        {
                            "id": value["id"],
                            "error": {"code": -32601, "message": "RedJohn executes its own scoped tools"},
                        }
                    )
                else:
                    if value.get("method") == "account/login/completed":
                        params = value.get("params", {})
                        self.login_results[params.get("loginId", "")] = bool(params.get("success"))
                        if self.login and params.get("loginId") == self.login.get("loginId"):
                            self.login["state"] = "completed" if params.get("success") else "failed"
                    if self.notifications.full():
                        raise ValueError("event overflow")
                    self.notifications.put_nowait(value)
        except (ValueError, OSError, asyncio.CancelledError):
            pass
        finally:
            if self.login and self.login.get("state") == "pending":
                self.login["state"] = "failed"
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(failure)
            self.pending.clear()
            if not self.notifications.full():
                self.notifications.put_nowait({"method": "redjohn/disconnected"})

    async def request(self, method: str, params: Any) -> Any:
        self.sequence += 1
        identifier = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[identifier] = future
        try:
            await self._write({"id": identifier, "method": method, "params": params})
            return await asyncio.wait_for(future, 25)
        except TimeoutError as exc:
            raise RJError(
                "codex_timeout", "Codex did not respond in time; retry or restart the connection.", status=504
            ) from exc
        finally:
            self.pending.pop(identifier, None)

    async def status(self) -> dict[str, Any]:
        if not codex_binary(self.settings):
            return {"available": False, "authenticated": False, "models": [], "login": None}
        await self.start()
        result = await self.request("account/read", {"refreshToken": False})
        account = result.get("account")
        authenticated = bool(account and account.get("type") == "chatgpt")
        models = (await self.request("model/list", {"limit": 100})).get("data", []) if authenticated else []
        return {
            "available": True,
            "authenticated": authenticated,
            "plan": account.get("planType") if account else None,
            "models": [{"id": m["model"], "name": m.get("displayName", m["model"])} for m in models],
            "login": self.login,
        }

    async def login_start(self) -> dict[str, Any]:
        await self.start()
        if self.login and self.login.get("state") == "pending":
            return self.login
        result = await self.request("account/login/start", {"type": "chatgptDeviceCode"})
        if (
            result.get("type") != "chatgptDeviceCode"
            or result.get("verificationUrl") != "https://auth.openai.com/codex/device"
        ):
            raise RJError(
                "codex_login_invalid",
                "Codex returned an unsupported login flow. Update the official CLI.",
                status=502,
            )
        self.login = {
            "loginId": result["loginId"],
            "verificationUrl": result["verificationUrl"],
            "userCode": result["userCode"],
            "state": ("completed" if self.login_results[result["loginId"]] else "failed")
            if result["loginId"] in self.login_results
            else "pending",
        }
        return self.login

    async def logout(self) -> None:
        await self.start()
        if self.login and self.login.get("state") == "pending":
            await self.request("account/login/cancel", {"loginId": self.login["loginId"]})
        await self.request("account/logout", {})
        self.login = None

    async def close(self) -> None:
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 3)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()
        if self.reader:
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
        self.process = None


class CodexGateway:
    name = "codex"

    def __init__(self, settings: Any):
        self._settings = settings

    async def input_tokens(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> int:
        payload = {"messages": messages, "tools": [{"name": t.name, "description": t.description,
                   "schema": t.input_schema} for t in tools]}
        return len(json.dumps(payload, ensure_ascii=False).encode()) + 16384

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
        server = CodexAppServer(self._settings)
        identifier = turn_id = None
        completed = False
        try:
            status = await server.status()
            if not status["authenticated"]:
                raise RJError(
                    "codex_login_required", "Sign in to Codex in Settings → Providers first.", status=503
                )
            schema = {
                "type": "object",
                "additionalProperties": False,
                "required": ["content", "tool_calls"],
                "properties": {
                    "content": {"type": "string"},
                    "tool_calls": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["name", "arguments"],
                            "properties": {
                                "name": {"type": "string", "enum": [t.name for t in tools] or ["none"]},
                                "arguments": {"type": "string"},
                            },
                        },
                    },
                },
            }
            prompt = json.dumps(
                {
                    "messages": messages,
                    "available_tools": [
                        {"name": t.name, "description": t.description, "schema": t.input_schema}
                        for t in tools
                    ],
                },
                ensure_ascii=False,
            )
            with tempfile.TemporaryDirectory(prefix="codex-turn-", dir=self._settings.profile_dir) as scratch:
                thread = await server.request(
                    "thread/start",
                    {
                        "model": self._settings.model_name,
                        "cwd": scratch,
                        "approvalPolicy": "never",
                        "sandbox": "read-only",
                        "ephemeral": True,
                        "environments": [],
                        "serviceName": "redjohn",
                        "baseInstructions": (
                            "You are RedJohn's model planner. Return the requested JSON. "
                            "Propose only the listed tools. Do not execute tools yourself."
                        ),
                        "config": {
                            "web_search": "disabled",
                            "features": {"shell_tool": False, "unified_exec": False, "apps": False},
                        },
                    },
                )
                identifier = thread["thread"]["id"]
                turn = await server.request(
                    "turn/start",
                    {
                        "threadId": identifier,
                        "input": [{"type": "text", "text": prompt}],
                        "outputSchema": schema,
                    },
                )
                turn_id = turn["turn"]["id"]
                usage = {}
                text = ""
                async with asyncio.timeout(180):
                    while True:
                        event = await server.notifications.get()
                        method, params = event.get("method"), event.get("params", {})
                        if method == "redjohn/disconnected":
                            raise RJError(
                                "codex_disconnected", "Codex disconnected during the model turn.", status=503
                            )
                        if params.get("threadId") != identifier:
                            continue
                        if method == "thread/tokenUsage/updated":
                            tokens = params["tokenUsage"]["total"]
                            usage = {
                                "input_tokens": tokens["inputTokens"],
                                "output_tokens": tokens["outputTokens"],
                            }
                            if tokens["outputTokens"] > max_output_tokens:
                                await server.request(
                                    "turn/interrupt", {"threadId": identifier, "turnId": turn_id}
                                )
                                raise RJError(
                                    "codex_output_limit",
                                    "Codex exceeded the configured output budget.",
                                    status=502,
                                )
                        if method in ("item/started", "item/completed"):
                            item = params.get("item", {})
                            if item.get("type") in (
                                "commandExecution",
                                "fileChange",
                                "mcpToolCall",
                                "dynamicToolCall",
                                "webSearch",
                                "imageGeneration",
                            ):
                                raise RJError(
                                    "codex_unexpected_tool",
                                    "Codex attempted an internal tool; the model turn was interrupted.",
                                    status=502,
                                )
                            if method == "item/completed" and item.get("type") == "agentMessage":
                                text = item.get("text", "")
                        if method == "turn/completed":
                            if params.get("turn", {}).get("status") != "completed":
                                raise RJError(
                                    "codex_turn_failed",
                                    "Codex could not complete the turn; check subscription access and quota.",
                                    status=502,
                                )
                            completed = True
                            break
                payload = json.loads(text)
                jsonschema.validate(payload, schema)
                mapping = {t.name: t for t in tools}
                calls = []
                for call in payload["tool_calls"]:
                    tool = mapping[call["name"]]
                    arguments = json.loads(call["arguments"])
                    jsonschema.validate(arguments, tool.input_schema or {"type": "object"})
                    calls.append(ToolCall(uuid.uuid4().hex, tool.name, arguments))
                return ModelResponse(payload["content"], tuple(calls), done=not calls, usage=usage)
        except (ValueError, KeyError, jsonschema.ValidationError) as exc:
            raise RJError(
                "invalid_provider_response", "Codex returned an invalid structured tool plan.", status=502
            ) from exc
        except TimeoutError as exc:
            raise RJError(
                "codex_timeout", "Codex did not complete the model turn in time.", status=504
            ) from exc
        finally:
            if (
                not completed
                and identifier
                and turn_id
                and server.process
                and server.process.returncode is None
            ):
                try:
                    async with asyncio.timeout(1):
                        await server.request("turn/interrupt", {"threadId": identifier, "turnId": turn_id})
                except (RJError, TimeoutError):
                    pass
            # Always tear down the per-turn app-server subprocess. A fresh server
            # per turn is deliberate (concurrent agent turns each need their own
            # notification stream — the queue cannot be demultiplexed), but it
            # must be closed or every model step leaks an orphaned child process.
            await server.close()
