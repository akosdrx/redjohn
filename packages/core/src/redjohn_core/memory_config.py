"""Local OpenViking setup: service credentials and model credentials differ.

Generated server configurations belong to this profile; no existing server
configuration is overwritten. An external server must be configured by its
operator. Saving its URL never claims that model processing is ready.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from typing import Any

from .errors import validation
from .integrations import IntegrationStore, atomic_private_json, validate_endpoint


def memory_public(settings: Any) -> dict[str, Any]:
    data = IntegrationStore(settings).read().get("memory", {})
    path = settings.profile_dir / "openviking" / "ov.conf"
    applied = bool(
        path.exists()
        and data.get("applied_config_sha256") == hashlib.sha256(path.read_bytes()).hexdigest()
        and settings.openviking_url == f"http://127.0.0.1:{data.get('managed_port')}"
    )
    return {
        "configured": bool(
            data.get("server_config") or data.get("selected_model") or settings.openviking_url
        ),
        "mode": data.get("mode", "provider"),
        "provider_connection_id": data.get("provider_connection_id"),
        "language_model": data.get("selected_model") or data.get("server_models", {}).get(
            "language_model", ""
        ),
        # No local model runtime anymore; the field is retained (always False)
        # only so the published MemoryConfig contract stays stable.
        "local_models_installed": False,
        "openviking_url": settings.openviking_url or "",
        "openviking_account": settings.openviking_account,
        "openviking_user": settings.openviking_user,
        "openviking_processing_mode": settings.openviking_processing_mode,
        "service_key_configured": bool(settings.openviking_api_key),
        "generated_config": str(settings.profile_dir / "openviking" / "ov.conf")
        if data.get("server_config")
        else None,
        "server_models": {k: v for k, v in data.get("server_models", {}).items() if not k.endswith("secret")},
        "managed_process": data.get("managed_process"),
        "model_config_applied": applied,
    }


def memory_proxy_url(settings: Any) -> str:
    return f"http://127.0.0.1:{settings.port}/memory-model/v1"


def save_memory(settings: Any, values: dict[str, Any]) -> dict[str, Any]:
    config = IntegrationStore(settings)
    data = config.read()
    previous = data.get("memory", {})
    url = values.get("openviking_url", settings.openviking_url or "")
    url = validate_endpoint(url) if url else None
    account = values.get("openviking_account", settings.openviking_account)
    user = values.get("openviking_user", settings.openviking_user)
    for identifier in (account, user):
        if (
            not re.fullmatch(r"[a-zA-Z0-9_.@-]{1,120}", identifier)
            or identifier.count("@") > 1
            or identifier.startswith("_")
        ):
            raise validation("Use a valid OpenViking account/user identifier.")
    mode = values.get("openviking_processing_mode", settings.openviking_processing_mode)
    if mode not in ("", "vectors_only"):
        raise validation("Choose full processing or vectors-only imports.")
    key = values.get("service_api_key")
    if previous.get("service_secret") and previous.get("openviking_url") != url and not key:
        raise validation("Changing the OpenViking server requires re-entering its service key.")
    memory = {
        **previous,
        "openviking_url": url,
        "openviking_account": account,
        "openviking_user": user,
        "openviking_processing_mode": mode,
        "service_secret": config.encrypt(key) if key else previous.get("service_secret"),
    }
    data["memory"] = memory
    atomic_private_json(config.path, data)
    overlay = config.runtime_overlay()
    for field, value in overlay.items():
        if field.startswith("openviking_"):
            setattr(settings, field, value)
    return memory_public(settings)


def generate_server_config(settings: Any, values: dict[str, Any]) -> dict[str, Any]:
    config = IntegrationStore(settings)
    data = config.read()
    previous = data.get("memory", {}).get("server_models", {})
    models = {}
    for prefix in ("language", "embedding"):
        base = validate_endpoint(values.get(prefix + "_base_url", ""))
        model = str(values.get(prefix + "_model", "")).strip()
        key = values.get(prefix + "_api_key")
        if not model or len(model) > 200:
            raise validation("Both a memory language model and an embedding model are required.")
        if not key and previous.get(prefix + "_base_url") == base:
            key = config.decrypt(previous.get(prefix + "_secret"))
        if not key:
            raise validation(
                "Enter memory model and embedding credentials; local endpoints may use placeholder keys."
            )
        models.update(
            {prefix + "_base_url": base, prefix + "_model": model, prefix + "_secret": config.encrypt(key)}
        )
    dimension = values.get("embedding_dimension", 1536)
    if not isinstance(dimension, int) or not 1 <= dimension <= 65536:
        raise validation("Choose the embedding model's actual output dimension.")
    existing = data.get("memory", {}).get("server_models", {})
    if existing and any(
        existing.get(k) != v
        for k, v in models.items()
        if k.startswith("embedding_") and not k.endswith("secret")
    ):
        raise validation("Changing the embedding model requires a new OpenViking workspace and re-indexing.")
    if existing.get("embedding_dimension", dimension) != dimension:
        raise validation("Changing embedding dimensions requires a new OpenViking workspace.")
    models["embedding_dimension"] = dimension
    memory = data.setdefault("memory", {})
    root_key = config.decrypt(memory.get("root_secret")) or secrets.token_urlsafe(32)
    server = {
        "server": {"host": "127.0.0.1", "port": 1933, "root_api_key": root_key},
        "storage": {
            "workspace": str(settings.profile_dir / "openviking" / "data"),
            "vectordb": {"name": "context", "backend": "local"},
            "agfs": {
                "backend": "local",
                "queuefs": {"backend": "sqlite"},
                "pathlock": {"provider": "filesystem"},
            },
        },
        "embedding": {
            "dense": {
                "provider": "openai",
                "model": models["embedding_model"],
                "api_base": models["embedding_base_url"],
                "api_key": config.decrypt(models["embedding_secret"]),
                "dimension": dimension,
                "input": "text",
            },
            "text_source": "content_only",
        },
        "vlm": {
            "provider": "openai",
            "model": models["language_model"],
            "api_base": models["language_base_url"],
            "api_key": config.decrypt(models["language_secret"]),
            "max_tokens": 8192,
        },
        "memory": {"extraction_enabled": True, "session_skill_extraction_enabled": False},
        "encryption": {
            "enabled": True,
            "provider": "local",
            "local": {"key_file": str(settings.profile_dir / "openviking" / "master.key")},
        },
    }
    path = settings.profile_dir / "openviking" / "ov.conf"
    if path.exists():
        atomic_private_json(path.with_suffix(".conf.backup"), json.loads(path.read_text()))
    atomic_private_json(path, server)
    memory.update({"server_config": True, "server_models": models, "root_secret": config.encrypt(root_key)})
    atomic_private_json(config.path, data)
    return memory_public(settings)
