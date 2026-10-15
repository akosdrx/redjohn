"""Optional NVD credential in the same encrypted, profile-local integration store."""

from __future__ import annotations

from typing import Any

from .errors import validation
from .integrations import IntegrationStore, atomic_private_json


def nvd_key(settings: Any) -> str:
    store = IntegrationStore(settings)
    secret = store.read().get("nvd", {}).get("secret")
    return (store.decrypt(secret) or "") if secret else ""


def public_nvd(settings: Any) -> dict[str, Any]:
    configured = bool(IntegrationStore(settings).read().get("nvd", {}).get("secret"))
    return {"key_configured": configured, "requests_per_30_seconds": 50 if configured else 5}


def save_nvd(settings: Any, key: str | None) -> dict[str, Any]:
    if key is not None and (not key or len(key) > 256 or any(c.isspace() for c in key)):
        raise validation("Use an NVD API key without spaces or line breaks.")
    store = IntegrationStore(settings)
    data = store.read()
    data["nvd"] = {"secret": store.encrypt(key) if key else None}
    atomic_private_json(store.path, data)
    return public_nvd(settings)
