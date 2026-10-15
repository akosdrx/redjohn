"""Bounded models.dev catalog cache, with packaged offline model metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from .integrations import PROVIDERS, atomic_private_json

CATALOG_URL = "https://models.dev/api.json"
MAX_CATALOG_BYTES = 16 * 1024 * 1024


def supported_catalog(data: dict[str, Any]) -> list[dict[str, Any]]:
    providers = []
    for key, (label, endpoint, default) in PROVIDERS.items():
        source = data.get("zai" if key == "zai-coding-plan" else key, {})
        models = [
            {
                "id": model.get("id", identifier),
                "name": model.get("name", identifier),
                "context": model.get("limit", {}).get("context"),
                "output": model.get("limit", {}).get("output"),
                "reasoning": bool(model.get("reasoning")),
                "tool_call": bool(model.get("tool_call")),
            }
            for identifier, model in source.get("models", {}).items()
            if "text" in model.get("modalities", {}).get("output", ["text"])
        ]
        if not models and default:
            models = [{"id": default, "name": default, "tool_call": True}]
        providers.append(
            {
                "id": key,
                "name": label,
                "base_url": endpoint,
                "default_model": default,
                "auth_method": "oauth" if key == "codex" else "api_key",
                "models": models,
            }
        )
    return providers


def read_catalog(settings: Any) -> dict[str, Any]:
    path = settings.profile_dir / "models-catalog.json"
    if path.exists():
        try:
            return json.loads(path.read_text()) | {"source": CATALOG_URL, "cached": True}
        except (OSError, ValueError):
            pass
    packaged = Path(__file__).with_name("data") / "models-catalog.json"
    data = json.loads(packaged.read_text()) if packaged.exists() else {"providers": supported_catalog({})}
    return data | {"source": CATALOG_URL, "cached": True}


async def refresh_catalog(settings: Any, *, transport: Any = None) -> dict[str, Any]:
    from .errors import RJError
    from .models import utcnow

    try:
        async with httpx.AsyncClient(timeout=20, transport=transport, follow_redirects=False) as client:
            async with client.stream("GET", CATALOG_URL) as response:
                response.raise_for_status()
                chunks = bytearray()
                async for part in response.aiter_bytes():
                    chunks.extend(part)
                    if len(chunks) > MAX_CATALOG_BYTES:
                        raise ValueError("catalog too large")
        data = json.loads(chunks)
        if not isinstance(data, dict) or not data.get("zai", {}).get("models"):
            raise ValueError("invalid catalog")
        result = {"providers": supported_catalog(data), "updated_at": utcnow().isoformat()}
        atomic_private_json(settings.profile_dir / "models-catalog.json", result)
        return result | {"source": CATALOG_URL, "cached": False}
    except (httpx.HTTPError, ValueError) as exc:
        raise RJError(
            "catalog_refresh_failed",
            "Cannot refresh models.dev. The saved catalog remains available.",
            status=503,
        ) from exc
