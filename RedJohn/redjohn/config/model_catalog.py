"""Curated model providers for the TUI ``/models`` picker.

The menu is the provider list, not every model on the internet. After a
provider accepts a key or a sign-in, its own ``/models`` endpoint supplies the
choices. A short built-in list is used only when that endpoint does not answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import requests


Route = Literal["openai", "anthropic", "xai", "chatgpt", "grok"]
AuthKind = Literal["api_key", "oauth_browser", "oauth_device"]

EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max")

_FETCH_TIMEOUT = (5, 12)
_MAX_MODELS = 80
_NON_CHAT_MARKERS = (
    "embedding",
    "embed-",
    "whisper",
    "tts",
    "dall-e",
    "moderation",
    "realtime",
    "transcribe",
    "audio",
    "image",
    "sora",
)


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    label: str
    auth: AuthKind | None = None
    route: Route = "openai"
    api_base: str | None = None
    fallback_models: tuple[str, ...] = ()
    children: tuple[CatalogEntry, ...] = ()

    def public(self) -> dict[str, Any]:
        """The fields the TUI renders. Routes and keys stay on the backend."""
        payload: dict[str, Any] = {"id": self.id, "label": self.label, "auth": self.auth or ""}
        if self.children:
            payload["children"] = [child.public() for child in self.children]
        return payload


_XIAOMI_MODELS = (
    "mimo-v2.6-pro",
    "mimo-v2.6-flash",
    "mimo-v2.5-pro",
    "mimo-v2.5",
    "mimo-v2-pro",
    "mimo-v2-flash",
)
_CHATGPT_MODELS = ("gpt-5.4", "gpt-5.3-codex", "gpt-5.2", "gpt-5.1-codex", "gpt-5")
_OPENAI_MODELS = ("gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex", "gpt-4.1")
_ANTHROPIC_MODELS = ("claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5")
_XAI_MODELS = ("grok-4", "grok-4-fast", "grok-3", "grok-code-fast-1")


def _xiaomi(entry_id: str, label: str, api_base: str) -> CatalogEntry:
    return CatalogEntry(
        id=entry_id,
        label=label,
        auth="api_key",
        route="openai",
        api_base=api_base,
        fallback_models=_XIAOMI_MODELS,
    )


_OPENAI = CatalogEntry(
    id="openai",
    label="OpenAI",
    children=(
        CatalogEntry(
            id="openai.chatgpt",
            label="Sign in with ChatGPT",
            auth="oauth_browser",
            route="chatgpt",
            fallback_models=_CHATGPT_MODELS,
        ),
        CatalogEntry(
            id="openai.codex-browser",
            label="Codex Browser (Legacy)",
            auth="oauth_browser",
            route="chatgpt",
            fallback_models=_CHATGPT_MODELS,
        ),
        CatalogEntry(
            id="openai.codex-device",
            label="Codex Device Code (Legacy)",
            auth="oauth_device",
            route="chatgpt",
            fallback_models=_CHATGPT_MODELS,
        ),
        CatalogEntry(
            id="openai.api-key",
            label="API Key",
            auth="api_key",
            route="openai",
            api_base="https://api.openai.com/v1",
            fallback_models=_OPENAI_MODELS,
        ),
    ),
)

_XIAOMI = CatalogEntry(
    id="xiaomi",
    label="Xiaomi",
    children=(
        _xiaomi("xiaomi.api", "API", "https://api.xiaomimimo.com/v1"),
        _xiaomi("xiaomi.cn", "Token Plan (China)", "https://token-plan-cn.xiaomimimo.com/v1"),
        _xiaomi("xiaomi.eu", "Token Plan (Europe)", "https://token-plan-ams.xiaomimimo.com/v1"),
        _xiaomi(
            "xiaomi.sg",
            "Token Plan (Singapore)",
            "https://token-plan-sgp.xiaomimimo.com/v1",
        ),
    ),
)

_XAI = CatalogEntry(
    id="xai",
    label="xAI",
    children=(
        CatalogEntry(
            id="xai.subscription",
            label="SuperGrok Subscription",
            auth="oauth_device",
            route="grok",
            api_base="https://cli-chat-proxy.grok.com/v1",
            fallback_models=_XAI_MODELS,
        ),
        CatalogEntry(
            id="xai.api-key",
            label="API Key",
            auth="api_key",
            route="xai",
            api_base="https://api.x.ai/v1",
            fallback_models=_XAI_MODELS,
        ),
    ),
)


RECOMMENDED: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        id="abliteration",
        label="abliteration.ai",
        auth="api_key",
        api_base="https://api.abliteration.ai/v1",
    ),
    CatalogEntry(
        id="zai",
        label="z.ai",
        auth="api_key",
        api_base="https://api.z.ai/api/paas/v4",
    ),
    CatalogEntry(
        id="zai-coding",
        label="z.ai coding plan",
        auth="api_key",
        api_base="https://api.z.ai/api/coding/paas/v4",
    ),
    CatalogEntry(
        id="venice",
        label="Venice AI",
        auth="api_key",
        api_base="https://api.venice.ai/api/v1",
    ),
)

OTHER: tuple[CatalogEntry, ...] = (
    _OPENAI,
    CatalogEntry(
        id="anthropic",
        label="Anthropic",
        auth="api_key",
        route="anthropic",
        api_base="https://api.anthropic.com/v1",
        fallback_models=_ANTHROPIC_MODELS,
    ),
    CatalogEntry(
        id="kimi-ai",
        label="Kimi for Coding (kimi.ai)",
        auth="api_key",
        api_base="https://api.kimi.ai/coding/v1",
    ),
    CatalogEntry(
        id="kimi-com",
        label="Kimi for Coding (kimi.com)",
        auth="api_key",
        api_base="https://api.kimi.com/coding/v1",
    ),
    _XIAOMI,
    _XAI,
)


def catalog_payload() -> dict[str, Any]:
    return {
        "title": "Select model",
        "sections": [
            {
                "title": "Recommended",
                "entries": [entry.public() for entry in RECOMMENDED],
            },
            {
                "title": "Other models",
                "entries": [entry.public() for entry in OTHER],
            },
        ],
    }


def find_entry(entry_id: str) -> CatalogEntry | None:
    """The leaf or group with this id, searched depth-first."""
    for entry in (*RECOMMENDED, *OTHER):
        found = _find(entry, entry_id)
        if found is not None:
            return found
    return None


def _find(entry: CatalogEntry, entry_id: str) -> CatalogEntry | None:
    if entry.id == entry_id:
        return entry
    for child in entry.children:
        found = _find(child, entry_id)
        if found is not None:
            return found
    return None


def format_model_setting(route: Route, model_id: str) -> str:
    """The ``REDJOHN_LLM`` value for a model chosen from ``route``."""
    model_id = model_id.strip().strip("/")
    if not model_id:
        raise ValueError("model id is empty")
    if route == "chatgpt":
        slug = model_id.removeprefix("chatgpt/")
        return f"chatgpt/{slug}"
    if route == "grok":
        slug = model_id.removeprefix("grok/")
        return f"grok/{slug}"
    if route == "anthropic":
        slug = model_id.removeprefix("anthropic/")
        return f"anthropic/{slug}"
    if route == "xai":
        slug = model_id.removeprefix("xai/")
        return f"xai/{slug}"
    slug = model_id.removeprefix("openai/")
    return f"openai/{slug}"


def connection_clears_base(entry: CatalogEntry) -> bool:
    """Official and subscription routes must not keep a previous gateway URL."""
    if entry.route in {"chatgpt", "grok", "anthropic", "xai"}:
        return True
    return entry.id == "openai.api-key"


def list_models(entry: CatalogEntry, api_key: str | None) -> tuple[list[dict[str, str]], str]:
    """Return ``(models, source)`` where source is ``live`` or ``fallback``."""
    if entry.api_base and api_key:
        try:
            live = fetch_model_list(entry, api_key)
        except requests.RequestException:
            live = []
        except ValueError:
            live = []
        if live:
            return live, "live"
    fallback = [{"id": model_id, "label": model_id} for model_id in entry.fallback_models]
    if not fallback:
        raise ValueError(f"{entry.label} did not return a model list. Check the key and try again.")
    return fallback, "fallback"


def fetch_model_list(entry: CatalogEntry, api_key: str) -> list[dict[str, str]]:
    """GET the provider's model list. Raises when the call itself fails."""
    if not entry.api_base:
        return []
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    if entry.route == "anthropic":
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Accept": "application/json",
        }
    response = requests.get(
        entry.api_base.rstrip("/") + "/models",
        headers=headers,
        timeout=_FETCH_TIMEOUT,
    )
    if response.status_code >= 400:
        raise ValueError(f"HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError("model list was not JSON") from exc
    return models_from_payload(payload)


def models_from_payload(payload: object) -> list[dict[str, str]]:
    """Normalize an OpenAI- or Anthropic-shaped model list."""
    rows: list[object]
    if isinstance(payload, dict):
        data = payload.get("data", payload.get("models"))
        rows = data if isinstance(data, list) else []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    models: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        if isinstance(row, str):
            model_id, label = row, row
        elif isinstance(row, dict):
            raw_id = row.get("id") or row.get("name")
            if not isinstance(raw_id, str) or not raw_id.strip():
                continue
            model_id = raw_id.strip()
            raw_label = row.get("display_name") or row.get("name") or model_id
            label = model_id
            if isinstance(raw_label, str) and raw_label.strip():
                label = raw_label.strip()
        else:
            continue
        if _skips_model(model_id) or model_id in seen:
            continue
        seen.add(model_id)
        models.append({"id": model_id, "label": label})
        if len(models) >= _MAX_MODELS:
            break
    models.sort(key=lambda item: item["label"].casefold())
    return models


def _skips_model(model_id: str) -> bool:
    lowered = model_id.lower()
    return any(marker in lowered for marker in _NON_CHAT_MARKERS)
