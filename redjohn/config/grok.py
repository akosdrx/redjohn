"""SuperGrok subscription auth: device-code login, token refresh, and the client
that routes inference through the Grok CLI proxy.

Mirrors the public Grok CLI OAuth client (no client secret). The access token is
sent to ``cli-chat-proxy.grok.com``, which is the subscription surface, separate
from the metered ``api.x.ai`` key. Using a SuperGrok subscription outside xAI's
own products depends on that proxy accepting the public client.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import requests

from redjohn.config.codex import AUTH_PATH
from redjohn.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Iterator

    from openai import AsyncOpenAI


logger = logging.getLogger(__name__)


PROVIDER = "xai"
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
DEVICE_CODE_URL = "https://auth.x.ai/oauth2/device/code"
TOKEN_URL = "https://auth.x.ai/oauth2/token"  # noqa: S105  # nosec B105 - URL, not a secret
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
SCOPE = (
    "openid profile email offline_access grok-cli:access api:access "
    "conversations:read conversations:write"
)
PROXY_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
SUBSCRIPTION_PREFIX = "grok/"

_TOKEN_TIMEOUT = 30
_EXPIRY_SKEW_S = 300
_PENDING_ERRORS = frozenset({"authorization_pending"})
_SLOW_ERRORS = frozenset({"slow_down"})
_refresh_lock = threading.Lock()


class GrokAuthError(Exception):
    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


def _read_store() -> dict[str, Any]:
    try:
        data = json.loads(Path(AUTH_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_store(data: dict[str, Any]) -> None:
    write_secret_text(AUTH_PATH, json.dumps(data, indent=2))


def read_record() -> dict[str, Any] | None:
    record = _read_store().get(PROVIDER)
    if not isinstance(record, dict) or record.get("type") != "oauth":
        return None
    if not (record.get("access") and record.get("refresh")):
        return None
    return record


def is_authenticated() -> bool:
    return read_record() is not None


def save_record(record: dict[str, Any]) -> None:
    data = _read_store()
    data[PROVIDER] = record
    _write_store(data)


def logout() -> None:
    data = _read_store()
    if PROVIDER not in data:
        return
    del data[PROVIDER]
    if data:
        _write_store(data)
        return
    with contextlib.suppress(OSError):
        AUTH_PATH.unlink()


@contextlib.contextmanager
def _refresh_guard() -> Iterator[None]:
    """Serialize refresh so two processes don't both spend one refresh token."""
    with _refresh_lock:
        try:
            import fcntl

            lock_path = AUTH_PATH.with_suffix(".lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            handle = lock_path.open("w")
        except (ImportError, OSError):
            yield
            return
        try:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


def _post_form(url: str, payload: dict[str, str]) -> tuple[int, dict[str, Any]]:
    try:
        response = requests.post(
            url,
            data=payload,
            headers={"Accept": "application/json", "User-Agent": "redjohn"},
            timeout=_TOKEN_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise GrokAuthError("unavailable", str(exc)) from exc
    try:
        body = response.json()
    except json.JSONDecodeError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    return response.status_code, body


def start_device_code() -> dict[str, Any]:
    """Begin SuperGrok device-code login. The user enters ``user_code``."""
    status, payload = _post_form(
        DEVICE_CODE_URL,
        {"client_id": CLIENT_ID, "scope": SCOPE, "referrer": "redjohn"},
    )
    if status >= 400:
        detail = payload.get("error_description") or payload.get("error") or ""
        raise GrokAuthError("device_http_error", f"HTTP {status}: {detail}")
    started = interpret_device_start(payload)
    if started is None:
        raise GrokAuthError("bad_response", "device code response is missing user_code")
    return started


def interpret_device_start(payload: dict[str, Any]) -> dict[str, Any] | None:
    device_code = payload.get("device_code")
    user_code = payload.get("user_code")
    if not isinstance(device_code, str) or not isinstance(user_code, str):
        return None
    if not device_code or not user_code:
        return None
    verification = payload.get("verification_uri_complete") or payload.get("verification_uri")
    if not isinstance(verification, str) or not verification:
        verification = "https://auth.x.ai/oauth2/device"
    interval = _positive_int(payload.get("interval"), default=5)
    expires_in = _positive_int(payload.get("expires_in"), default=900)
    return {
        "device_code": device_code,
        "user_code": user_code,
        "interval": interval,
        "expires_in": expires_in,
        "verification_url": verification,
    }


def interpret_device_poll(status: int, payload: dict[str, Any]) -> str | dict[str, Any]:
    """``pending``, ``slow_down``, or a token record's raw token payload."""
    error = payload.get("error")
    if isinstance(error, str) and error in _PENDING_ERRORS:
        return "pending"
    if isinstance(error, str) and error in _SLOW_ERRORS:
        return "slow_down"
    if status >= 400 or error:
        detail = payload.get("error_description") or error or f"HTTP {status}"
        raise GrokAuthError("device_http_error", str(detail))
    access = payload.get("access_token")
    refresh = payload.get("refresh_token")
    if not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh:
        raise GrokAuthError("bad_response", "token response missing access or refresh token")
    return payload


def poll_device_code(device_code: str) -> str | dict[str, Any]:
    """One device-code poll. ``pending`` / ``slow_down`` or a saved-record dict."""
    status, payload = _post_form(
        TOKEN_URL,
        {
            "grant_type": DEVICE_GRANT,
            "client_id": CLIENT_ID,
            "device_code": device_code,
        },
    )
    result = interpret_device_poll(status, payload)
    if isinstance(result, str):
        return result
    return _record_from_token_response(result)


def _positive_int(value: object, *, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _record_from_token_response(
    data: dict[str, Any], refresh_fallback: str | None = None
) -> dict[str, Any]:
    access = data.get("access_token")
    refresh = data.get("refresh_token") or refresh_fallback
    if not isinstance(access, str) or not access:
        raise GrokAuthError("bad_response", "token response missing access_token")
    if not isinstance(refresh, str) or not refresh:
        raise GrokAuthError("bad_response", "token response missing refresh_token")
    ttl = _positive_int(data.get("expires_in"), default=3600)
    return {
        "type": "oauth",
        "provider": PROVIDER,
        "access": access,
        "refresh": refresh,
        "expires_at": time.time() + ttl,
    }


def refresh_tokens(refresh_token: str) -> dict[str, Any]:
    status, payload = _post_form(
        TOKEN_URL,
        {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
        },
    )
    if status >= 400:
        detail = payload.get("error_description") or payload.get("error") or ""
        raise GrokAuthError("token_http_error", f"HTTP {status}: {detail}")
    return _record_from_token_response(payload, refresh_fallback=refresh_token)


def _near_expiry(record: dict[str, Any]) -> bool:
    expires_at = record.get("expires_at")
    if not isinstance(expires_at, int | float):
        return True
    return expires_at - _EXPIRY_SKEW_S <= time.time()


def get_valid_token() -> str:
    """Return a usable access token, refreshing under the cross-process guard."""
    record = read_record()
    if record is None:
        raise GrokAuthError("not_authenticated", "not signed in to SuperGrok")
    if not _near_expiry(record):
        return str(record["access"])
    with _refresh_guard():
        record = read_record()
        if record is None:
            raise GrokAuthError("not_authenticated", "not signed in to SuperGrok")
        if not _near_expiry(record):
            return str(record["access"])
        try:
            refreshed = refresh_tokens(str(record["refresh"]))
        except GrokAuthError:
            latest = read_record()
            if latest and latest["refresh"] != record["refresh"] and not _near_expiry(latest):
                return str(latest["access"])
            raise
        save_record(refreshed)
        return str(refreshed["access"])


def build_openai_client() -> AsyncOpenAI:
    """An ``AsyncOpenAI`` for the SuperGrok proxy. A hook refreshes the bearer."""
    import httpx
    from openai import AsyncOpenAI

    from redjohn.llm import request_log

    async def _auth_hook(request: httpx.Request) -> None:
        access = await asyncio.to_thread(get_valid_token)
        request.headers["Authorization"] = f"Bearer {access}"
        request.headers["x-ai-token-auth"] = "xai-grok-cli"
        request.headers["x-grok-client-identifier"] = "grok-shell"
        request.headers["x-grok-client-version"] = "1.0.46"

    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(600.0, connect=30.0),
        event_hooks={"request": [_auth_hook]},
    )
    request_log.observe_http_client(http_client)
    return AsyncOpenAI(
        api_key="redjohn-grok-oauth",  # placeholder; the hook overwrites Authorization
        base_url=PROXY_BASE_URL,
        http_client=http_client,
        default_headers={"accept": "text/event-stream"},
    )


_subscription_client: AsyncOpenAI | None = None
_subscription_lock = threading.Lock()


def get_subscription_client() -> AsyncOpenAI:
    global _subscription_client  # noqa: PLW0603
    with _subscription_lock:
        if _subscription_client is None:
            _subscription_client = build_openai_client()
        return _subscription_client


def subscription_model(model_name: str | None) -> str | None:
    """The model slug behind a ``grok/<model>`` REDJOHN_LLM, or None."""
    name = (model_name or "").strip()
    if not name.lower().startswith(SUBSCRIPTION_PREFIX):
        return None
    return name[len(SUBSCRIPTION_PREFIX) :] or None
