"""Real OpenViking adapter for RedJohn.

Implements the `MemoryStore` protocol (`redjohn_core.ov.protocol`) against the
official `openviking-sdk==0.1.14` `AsyncHTTPClient`, talking to a pinned
OpenViking server (`ghcr.io/volcengine/openviking:v0.5.0`). There is no local
substitute and no silent fallback: when the server is unreachable or a
background task fails or times out, a typed exception is raised and `status()`
reports reality.

Every mapping below was verified against the SDK source
(`sdk/python/openviking_sdk/client.py` @ upstream commit 92285e5) and the
server routers; see `rj-cli/docs/openviking-integration.md` for the full
investigation record.

Settings duck-type (any object with these attributes works):

- ``openviking_url``       — base URL, default ``http://127.0.0.1:1933``
- ``openviking_api_key``   — user/admin key, optional (local dev mode needs none)
- ``openviking_account``   — tenant account id, default ``"default"``
- ``openviking_user``      — per-account user id, default ``"redjohn"``
- ``openviking_actor_peer``— optional peer id scoping memories to a run/agent
- ``openviking_processing_mode`` — optional ``"vectors_only"`` for key-free
  servers without a VLM (skips L0/L1 semantic summarization on import)

Identity model (docs/en/guides/04-authentication.md, concepts/11-multi-tenant.md):
RedJohn workspace → OpenViking ``account`` (outer tenant boundary), RedJohn
operator → OpenViking ``user`` (memory/session isolation boundary), RedJohn
run/agent → OpenViking ``actor_peer`` (peer-scoped memories). Normal traffic
NEVER uses the root key; root is only accepted by `OpenVikingAdmin`, which
exists solely to provision accounts/users via the Admin REST API.
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from ..models import ServiceState, ServiceStatus
from .protocol import SearchHit, SkillHit

if TYPE_CHECKING:  # pragma: no cover - typing only, SDK imported lazily at runtime
    from openviking_sdk import AsyncHTTPClient

DEFAULT_URL = "http://127.0.0.1:1933"
DEFAULT_ACCOUNT = "default"
DEFAULT_USER = "redjohn"

_TERMINAL_OK = "completed"
_TERMINAL_BAD = {"failed", "cancelled"}
_TASK_ACTIVE = {"pending", "running", "cancelling"}

# Upstream identifier rules (openviking/core/identifiers.py):
# ^[a-zA-Z0-9_.@-]+$, at most one "@", account ids must not start with "_".
_IDENT_ALLOWED = re.compile(r"[^a-zA-Z0-9_.@-]+")


# ---------------------------------------------------------------------------
# Typed errors — failures propagate, nothing is faked or swallowed.
# ---------------------------------------------------------------------------


class OVError(RuntimeError):
    """Base class for OpenViking adapter failures."""


class OVUnavailable(OVError):
    """Server unreachable / connection failed."""


class OVTimeout(OVError):
    """A wait/poll deadline expired. A timeout is NEVER reported as success."""


class OVNotFound(OVError):
    """Task or resource not found (e.g. expired task id)."""


class OVTaskFailed(OVError):
    """A server-side background task reached failed/cancelled state."""

    def __init__(self, task_id: str, status: str, error: str = "") -> None:
        super().__init__(f"OpenViking task {task_id} ended as {status}: {error or 'no error detail'}")
        self.task_id = task_id
        self.status = status
        self.error = error


class OVResponseError(OVError):
    """The server returned a typed error envelope (carries upstream code)."""

    def __init__(self, message: str, *, code: str = "UNKNOWN", details: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


# ---------------------------------------------------------------------------
# Identity mapping helpers (RedJohn → OpenViking)
# ---------------------------------------------------------------------------


def sanitize_identifier(value: str, *, kind: str = "identifier") -> str:
    """Map an arbitrary RedJohn slug to a valid OpenViking identifier part.

    Mirrors upstream rules (`openviking/core/identifiers.py`): allowed charset
    ``[a-zA-Z0-9_.@-]``, at most one ``@``, account ids may not start with
    ``_``. Raises ValueError when nothing usable remains — never silently
    invents an identity.
    """
    cleaned = _IDENT_ALLOWED.sub("-", value.strip())
    if cleaned.count("@") > 1:
        head, _, tail = cleaned.partition("@")
        cleaned = head + "@" + tail.replace("@", "-")
    if kind == "account":
        cleaned = cleaned.lstrip("_")
    if not cleaned or cleaned in {".", ".."}:
        raise ValueError(f"{kind} {value!r} has no usable OpenViking identifier characters")
    return cleaned


def account_for_workspace(workspace_slug: str) -> str:
    """RedJohn workspace → OpenViking account (outer tenant boundary)."""
    return sanitize_identifier(workspace_slug, kind="account")


def user_for_operator(operator_id: str) -> str:
    """RedJohn app user → OpenViking user (memory/session isolation boundary)."""
    return sanitize_identifier(operator_id, kind="user")


def peer_for_run(run_id: str, *, agent: str | None = None) -> str:
    """RedJohn run/agent → OpenViking actor_peer (peer-scoped memories)."""
    combined = f"{run_id}-{agent}" if agent else run_id
    return sanitize_identifier(combined, kind="peer")


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class OpenVikingStore:
    """`MemoryStore` implementation backed by the real OpenViking server."""

    def __init__(self, settings: Any, *, poll_interval: float = 1.0) -> None:
        self._url = (getattr(settings, "openviking_url", None) or DEFAULT_URL).rstrip("/")
        self._configured = bool(getattr(settings, "openviking_url", None))
        self._api_key: str | None = getattr(settings, "openviking_api_key", None) or None
        self._account = getattr(settings, "openviking_account", None) or DEFAULT_ACCOUNT
        self._user = getattr(settings, "openviking_user", None) or DEFAULT_USER
        self._actor_peer: str | None = getattr(settings, "openviking_actor_peer", None) or None
        self._timeout = float(getattr(settings, "openviking_timeout", None) or 60.0)
        # Key-free servers have no VLM: "vectors_only" imports skip semantic
        # (L0/L1) summarization and still build vector indexes. None = server default.
        self._processing_mode: str | None = (
            getattr(settings, "openviking_processing_mode", None) or None
        )
        self._poll_interval = poll_interval
        self._client: AsyncHTTPClient | None = None
        self._client_lock = asyncio.Lock()
        # A commit archives its messages before extraction finishes. Preserve
        # accepted tasks across retryable polling errors: a second commit POST
        # may return skipped while the first task is still running or failed.
        self._pending_commits: dict[str, str] = {}
        # message_ids already attempted on this store; only a *retry* of one of
        # them needs the (expensive) server-side duplicate check.
        self._attempted: set[str] = set()

    # -- lifecycle -----------------------------------------------------------

    async def _sdk(self) -> AsyncHTTPClient:
        """Lazily create + initialize the real SDK client (no stub paths).

        Guarded by a lock with a double check so concurrent callers (the engine
        drives memory from several agent coroutines) initialize exactly one
        client instead of racing and leaking half-initialized ones."""
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is not None:
                return self._client
            try:
                from openviking_sdk import AsyncHTTPClient
            except ImportError as exc:  # pragma: no cover - dependency is pinned
                raise OVUnavailable(f"openviking-sdk not installed: {exc}") from exc
            client = AsyncHTTPClient(
                url=self._url,
                api_key=self._api_key,
                account=self._account,
                user=self._user,
                actor_peer_id=self._actor_peer,
                timeout=self._timeout,
            )
            await client.initialize()  # builds httpx.AsyncClient with auth headers
            self._client = client
            return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def __aenter__(self) -> OpenVikingStore:
        await self._sdk()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    @staticmethod
    def _map_sdk_error(exc: Exception) -> OVError:
        """Translate SDK/httpx errors into typed adapter errors."""
        code = getattr(exc, "code", None)
        details = getattr(exc, "details", None)
        if code:
            if code == "NOT_FOUND":
                return OVNotFound(str(exc))
            return OVResponseError(str(exc), code=str(code), details=details)
        if isinstance(exc, httpx.ConnectError | httpx.ConnectTimeout):
            return OVUnavailable(f"OpenViking unreachable: {exc}")
        if isinstance(exc, httpx.TimeoutException):
            return OVTimeout(f"OpenViking request timed out: {exc}")
        return OVResponseError(f"OpenViking call failed: {exc}")

    async def _call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        await self._sdk()  # ensures self._client exists for the lambda closures
        try:
            return await fn(*args, **kwargs)
        except OVError:
            raise
        except Exception as exc:
            raise self._map_sdk_error(exc) from exc

    # -- status ---------------------------------------------------------------

    async def status(self) -> ServiceStatus:
        """Real health + auth check. `live` only after a fresh authorized call."""
        if not self._configured:
            return ServiceStatus(
                service="openviking",
                state=ServiceState.NOT_CONFIGURED,
                detail="openviking_url not set",
            )
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=5.0) as probe:
                resp = await probe.get(f"{self._url}/health")
                resp.raise_for_status()
        except Exception as exc:
            return ServiceStatus(
                service="openviking",
                state=ServiceState.DOWN,
                detail=f"health check failed: {exc}",
                latency_ms=int((time.monotonic() - started) * 1000),
            )
        # Server answers; now prove an authorized, usable data call.
        try:
            client = await self._sdk()
            await client.list_sessions()
        except Exception as exc:
            mapped = self._map_sdk_error(exc)
            state = ServiceState.DOWN if isinstance(mapped, OVUnavailable) else ServiceState.DEGRADED
            return ServiceStatus(
                service="openviking",
                state=state,
                detail=f"authorized call failed: {mapped}",
                latency_ms=int((time.monotonic() - started) * 1000),
            )
        return ServiceStatus(
            service="openviking",
            state=ServiceState.LIVE,
            detail="health ok; authorized list_sessions ok",
            latency_ms=int((time.monotonic() - started) * 1000),
        )

    # -- task polling -----------------------------------------------------------

    async def _poll_task(self, task_id: str, timeout: float) -> dict[str, Any]:  # noqa: ASYNC109 — deadline param required by protocol
        """Poll GET /api/v1/tasks/{id} until terminal; timeout is never success."""
        deadline = time.monotonic() + timeout
        while True:
            task = await self._call(lambda: self._client.get_task(task_id))
            if task is None:
                raise OVNotFound(f"task {task_id} not found (expired or unknown)")
            status = str(task.get("status", ""))
            if status == _TERMINAL_OK:
                return task
            if status in _TERMINAL_BAD:
                raise OVTaskFailed(task_id, status, str(task.get("error") or ""))
            if time.monotonic() >= deadline:
                raise OVTimeout(
                    f"task {task_id} still {status or 'unknown'} after {timeout:.0f}s deadline"
                )
            await asyncio.sleep(self._poll_interval)

    async def task_status(self, task_id: str) -> str:
        """pending|running|cancelling|completed|failed|cancelled (server truth)."""
        task = await self._call(lambda: self._client.get_task(task_id))
        if task is None:
            raise OVNotFound(f"task {task_id} not found (expired or unknown)")
        return str(task.get("status", ""))

    async def wait_processed(self, timeout: float = 120.0) -> None:  # noqa: ASYNC109 — protocol signature
        """Block until the server queue drains (POST /api/v1/system/wait)."""
        await self._call(lambda: self._client.wait_processed(timeout=timeout))

    # -- documents / resources --------------------------------------------------

    async def import_resource(
        self, path: str | Path, *, to: str | None = None, wait: bool = True, timeout: float = 120.0  # noqa: ASYNC109 — protocol signature
    ) -> str:
        """Import a document; returns the OpenViking URI once searchable.

        Uses `add_resource(wait=False)` and polls the returned task id so that
        RedJohn's own deadline governs completion. A failed or timed-out import
        raises — it is never reported as success.
        """
        options: dict[str, Any] = {}
        if self._processing_mode:
            options["processing_mode"] = self._processing_mode
        result = await self._call(
            lambda: self._client.add_resource(
                str(path), to=to, wait=False, timeout=timeout, options=options or None
            )
        )
        root_uri = str(result.get("root_uri") or result.get("uri") or "")
        task_id = result.get("task_id")
        if wait:
            if task_id:
                await self._poll_task(str(task_id), timeout)
            else:
                # Synchronous import (no task): make sure queue side effects settle.
                await self.wait_processed(timeout)
        if not root_uri:
            raise OVResponseError(f"import returned no root_uri: {result!r}")
        return root_uri

    # -- retrieval (L0/L1/L2) ----------------------------------------------------

    async def find(self, query: str, *, limit: int = 10) -> list[SearchHit]:
        """Semantic retrieval; flattens memories/resources/skills hit groups."""
        result = await self._call(lambda: self._client.find(query=query, limit=limit))
        hits: list[SearchHit] = []
        groups = result if isinstance(result, dict) else {}
        for group in ("memories", "resources", "skills"):
            entries = groups.get(group) or []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                hits.append(
                    SearchHit(
                        uri=str(entry.get("uri", "")),
                        score=float(entry.get("score") or 0.0),
                        abstract=str(entry.get("abstract") or ""),
                        meta={
                            "group": group,
                            "context_type": entry.get("context_type"),
                            "level": entry.get("level"),
                            "category": entry.get("category"),
                            "match_reason": entry.get("match_reason"),
                        },
                    )
                )
        return hits

    async def abstract(self, uri: str) -> str:  # L0
        return str(await self._call(lambda: self._client.abstract(uri)))

    async def overview(self, uri: str) -> str:  # L1
        return str(await self._call(lambda: self._client.overview(uri)))

    async def read(self, uri: str) -> str:  # L2
        return str(await self._call(lambda: self._client.read(uri)))

    # -- sessions & memory ---------------------------------------------------------

    @staticmethod
    def _session_id(session_uri: str) -> str:
        return session_uri.strip().rstrip("/").rsplit("/", 1)[-1]

    async def create_session(self, *, session_id: str | None = None) -> str:
        """Create a session; returns the canonical session URI."""
        if session_id:
            try:
                await self._call(lambda: self._client.get_session(session_id))
                return f"viking://user/{self._user}/sessions/{session_id}"
            except OVNotFound:
                pass
        result = await self._call(lambda: self._client.create_session(session_id=session_id))
        uri = str(result.get("uri") or "")
        if uri:
            return uri
        session_id = str(result.get("session_id") or "")
        if not session_id:
            raise OVResponseError(f"create_session returned no uri/session_id: {result!r}")
        return f"viking://user/{self._user}/sessions/{session_id}"

    async def add_message(self, session_uri: str, role: str, content: str,
                          *, message_id: str | None = None) -> None:
        sid = self._session_id(session_uri)
        if message_id:
            import json

            # The pinned server has no message idempotency-key parameter, so a
            # retry of a write that was accepted just before an error surfaced
            # would duplicate the message. Guard against that by checking the
            # canonical session — but only on a *retry* of this message_id. The
            # first attempt cannot already be present (the engine skips synced
            # ids), so it skips the O(session) context fetch that previously ran
            # on every message. Only one executor owns each session (fence).
            marker = f"[redjohn-message-id:{message_id}]"
            if message_id in self._attempted:
                session = await self._call(lambda: self._client.get_session_context(sid))
                if marker in json.dumps(session, ensure_ascii=False):
                    return
            self._attempted.add(message_id)
            content = f"{marker}\n{content}"
        await self._call(lambda: self._client.add_message(sid, role, content))

    async def commit_session(
        self, session_uri: str, *, wait: bool = True, timeout: float = 120.0  # noqa: ASYNC109 — protocol signature
    ) -> str:
        """Trigger memory extraction; returns the server task id.

        A no-op commit (server status ``skipped``) returns "" — there is no
        task to poll. When ``wait`` is set and a task id exists, the task is
        polled to completion; failure/timeout raise typed errors.
        Retrying resumes its original task, including after a new Store is
        created: the provider's tenant/user-scoped task API is authoritative.
        Completed history with no active messages returns that task's ID
        without submitting a second, empty commit.
        """
        sid = self._session_id(session_uri)
        pending = self._pending_commits.get(sid)
        if not pending:
            tasks = await self._call(lambda: self._client.list_tasks(
                task_type="session_commit", resource_id=sid, limit=1))
            if tasks:
                latest = tasks[0]
                status = str(latest.get("status", ""))
                if status in _TASK_ACTIVE | _TERMINAL_BAD:
                    pending = str(latest.get("task_id") or "")
                    if not pending:
                        raise OVResponseError("session commit task has no task_id")
                    self._pending_commits[sid] = pending
                elif status != _TERMINAL_OK:
                    raise OVResponseError(f"unknown session commit task status: {status!r}")
                else:
                    session = await self._call(lambda: self._client.get_session(sid))
                    if session.get("message_count") == 0:
                        task_id = str(latest.get("task_id") or "")
                        if not task_id:
                            raise OVResponseError("completed session commit task has no task_id")
                        return task_id
            else:
                session = await self._call(lambda: self._client.get_session(sid))
                if int(session.get("commit_count") or 0) > 0:
                    raise OVNotFound(
                        f"session {sid} has commit history but no retained extraction task; "
                        "completion cannot be verified"
                    )
        if pending:
            if wait:
                await self._poll_task(pending, timeout)
                self._pending_commits.pop(sid, None)
            return pending
        result = await self._call(lambda: self._client.commit_session(sid))
        task_id = result.get("task_id")
        if not task_id:
            return ""
        self._pending_commits[sid] = str(task_id)
        if wait:
            await self._poll_task(str(task_id), timeout)
            self._pending_commits.pop(sid, None)
        return str(task_id)

    # -- skills ----------------------------------------------------------------------

    async def add_skill(
        self, path: str | Path, *, wait: bool = True, timeout: float = 120.0  # noqa: ASYNC109 — protocol signature
    ) -> str:
        """Import a skill (dir/file/text); returns the skill root URI."""
        result = await self._call(
            lambda: self._client.add_skill(str(path), wait=False, timeout=timeout)
        )
        root_uri = str(
            result.get("root_uri") or result.get("skill_uri") or result.get("uri") or ""
        )
        task_id = result.get("task_id")
        if wait:
            if task_id:
                await self._poll_task(str(task_id), timeout)
            else:
                await self.wait_processed(timeout)
        return root_uri

    async def find_skills(self, query: str, *, limit: int = 10) -> list[SkillHit]:
        result = await self._call(lambda: self._client.find_skills(query=query, limit=limit))
        entries = result.get("skills") if isinstance(result, dict) else None
        hits: list[SkillHit] = []
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            hits.append(
                SkillHit(
                    uri=str(entry.get("root_uri") or entry.get("uri") or ""),
                    name=str(entry.get("name") or ""),
                    version=str(entry.get("version") or ""),
                    description=str(entry.get("description") or ""),
                    content_hash=str(entry.get("content_sha256") or ""),
                )
            )
        return hits

    async def get_skill(self, uri: str, *, include_content: bool = False) -> SkillHit:
        """Fetch skill metadata by URI (server keys skills by name)."""
        name = uri.strip().rstrip("/").rsplit("/", 1)[-1]
        result = await self._call(
            lambda: self._client.get_skill(name, include_content=include_content)
        )
        data = result if isinstance(result, dict) else {}
        return SkillHit(
            uri=str(data.get("uri") or data.get("root_uri") or uri),
            name=str(data.get("name") or name),
            version=str(data.get("revision") or data.get("version") or ""),
            description=str(data.get("description") or ""),
            content_hash=str(data.get("content_sha256") or ""),
        )


# ---------------------------------------------------------------------------
# Admin helper — ROOT key, provisioning ONLY. Never use for tenant data traffic.
# ---------------------------------------------------------------------------


class OpenVikingAdmin:
    """Narrow provisioning helper using the server ROOT key.

    Root credentials unlock account/user administration and must never flow
    into normal RedJohn data traffic. Use this only to create accounts and
    mint per-user keys (Admin API: POST /api/v1/admin/accounts[.../users]).
    """

    def __init__(self, url: str, root_api_key: str, *, timeout: float = 10.0) -> None:
        if not root_api_key:
            raise ValueError("OpenVikingAdmin requires the server root_api_key")
        self._url = url.rstrip("/")
        self._root_key = root_api_key
        self._timeout = timeout

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as http:
            resp = await http.post(
                f"{self._url}{path}",
                json=body,
                headers={"X-API-Key": self._root_key},
            )
        data = resp.json() if resp.content else {}
        if resp.status_code >= 400 or data.get("status") == "error":
            err = data.get("error") or {}
            raise OVResponseError(
                err.get("message") or f"admin call failed: HTTP {resp.status_code}",
                code=str(err.get("code") or "UNKNOWN"),
                details=err.get("details") or {},
            )
        return data.get("result") or {}

    async def create_account(self, account_id: str, admin_user_id: str) -> dict[str, Any]:
        """Create an account with its first admin; response contains admin user_key."""
        return await self._post(
            "/api/v1/admin/accounts",
            {"account_id": account_for_workspace(account_id), "admin_user_id": admin_user_id},
        )

    async def register_user(self, account_id: str, user_id: str, *, role: str = "user") -> str:
        """Register a user in an account; returns the minted user key."""
        result = await self._post(
            f"/api/v1/admin/accounts/{account_for_workspace(account_id)}/users",
            {"user_id": user_for_operator(user_id), "role": role},
        )
        key = str(result.get("user_key") or "")
        if not key:
            raise OVResponseError(f"register_user returned no user_key: {result!r}")
        return key

    async def mint_user_key(self, account_id: str, user_id: str) -> str:
        """Mint/regenerate a user key (POST /api/v1/admin/accounts/{a}/users/{u}/key).

        Idempotent provisioning path: works whether or not the user already
        has a key. The previous key is replaced.
        """
        result = await self._post(
            f"/api/v1/admin/accounts/{account_for_workspace(account_id)}"
            f"/users/{user_for_operator(user_id)}/key",
            {},
        )
        key = str(result.get("user_key") or result.get("api_key") or "")
        if not key:
            raise OVResponseError(f"mint_user_key returned no key: {result!r}")
        return key
