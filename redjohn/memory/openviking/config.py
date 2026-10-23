"""Configuration & model resolution for OpenViking (volcengine/OpenViking) in RedJohn."""

from __future__ import annotations

import json
import logging
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any

from redjohn.config import codex, grok, load_settings
from redjohn.config.model_catalog import short_model_label
from redjohn.tools.mcp.config import McpConnectionConfig


logger = logging.getLogger(__name__)

CORE_OPENVIKING_TOOLS: tuple[str, ...] = (
    "find",
    "search",
    "read",
    "list",
    "tree",
    "grep",
    "glob",
    "remember",
    "write",
    "edit",
    "add_resource",
    "forget",
    "health",
)

DEFAULT_OV_DIR = Path.home() / ".openviking"
DEFAULT_OV_CONF = DEFAULT_OV_DIR / "ov.conf"
DEFAULT_OVCLI_CONF = DEFAULT_OV_DIR / "ovcli.conf"


def _infer_vlm_from_redjohn() -> dict[str, Any]:
    """Resolve OpenViking VLM configuration from OpenVikingSettings or RedJohn's active LLM."""
    settings = load_settings()
    ov = settings.openviking
    llm = settings.llm

    raw_model = (ov.vlm_model or llm.model or "").strip()
    raw_provider = (ov.vlm_provider or "").strip().lower()
    api_key = (ov.vlm_api_key or llm.api_key or "").strip()
    api_base = (ov.vlm_api_base or llm.api_base or "").strip()

    if not raw_model:
        return {
            "provider": "litellm",
            "model": "gpt-4o-mini",
            "api_key": api_key or "local-no-key",
            "api_base": api_base or "https://api.openai.com/v1",
            "configured": False,
            "display_model": "unconfigured",
        }

    if codex.subscription_model(raw_model):
        bare_model = raw_model.split("/", 1)[-1] if "/" in raw_model else raw_model
        return {
            "provider": "openai-codex",
            "model": bare_model,
            "api_base": "https://chatgpt.com/backend-api/codex",
            "configured": True,
            "display_model": short_model_label(raw_model),
        }

    if grok.subscription_model(raw_model):
        bare_model = raw_model.split("/", 1)[-1] if "/" in raw_model else raw_model
        return {
            "provider": "litellm",
            "model": f"xai/{bare_model}",
            "api_key": api_key or "grok-subscription",
            "api_base": api_base or "https://api.x.ai/v1",
            "configured": True,
            "display_model": short_model_label(raw_model),
        }

    prefix = ""
    bare = raw_model
    if "/" in raw_model:
        prefix, bare = raw_model.split("/", 1)
        prefix = prefix.lower()

    if not raw_provider:
        if prefix in {"volcengine", "ark"}:
            raw_provider = "volcengine"
        elif prefix == "openai" and not api_base:
            raw_provider = "openai"
        else:
            raw_provider = "litellm"

    vlm_model = bare if raw_provider in {"openai", "volcengine"} else raw_model
    entry: dict[str, Any] = {
        "provider": raw_provider,
        "model": vlm_model,
        "api_key": api_key or os.environ.get("OPENAI_API_KEY") or "local-key",
        "temperature": 0.0,
        "max_retries": 2,
        "configured": True,
        "display_model": short_model_label(raw_model),
    }
    if api_base:
        entry["api_base"] = api_base
    elif prefix == "ollama":
        entry["api_base"] = "http://localhost:11434/v1"
    return entry


def _infer_embedding_from_redjohn(vlm_info: dict[str, Any]) -> dict[str, Any]:
    """Resolve OpenViking dense embedding configuration with automatic local fallback."""
    settings = load_settings()
    ov = settings.openviking
    llm = settings.llm

    emb_provider = (ov.embedding_provider or "").strip().lower()
    emb_model = (ov.embedding_model or "").strip()
    emb_key = (ov.embedding_api_key or "").strip()
    emb_base = (ov.embedding_api_base or "").strip()
    dim = ov.embedding_dimension or 512

    raw_llm = (ov.vlm_model or llm.model or "").strip().lower()
    llm_key = (ov.vlm_api_key or llm.api_key or os.environ.get("OPENAI_API_KEY") or "").strip()
    llm_base = (ov.vlm_api_base or llm.api_base or "").strip()
    has_real_openai_route = bool(
        emb_key
        or (
            raw_llm.startswith("openai/")
            and llm_key
            and not codex.subscription_model(raw_llm)
            and (not llm_base or "api.openai.com" in llm_base)
        )
    )

    if emb_provider == "local" or emb_model in {"local", "bge-small-zh-v1.5-f16", "redjohn-local"}:
        return {
            "provider": "local",
            "model": "bge-small-zh-v1.5-f16",
            "dimension": 512,
            "input": "text",
            "display": "local/bge-small (512d)",
        }

    if emb_provider and emb_model:
        # If OpenAI embedding was selected without a dedicated embedding_api_key while the
        # active LLM uses a non-OpenAI base URL (e.g. DeepSeek, OpenRouter, Grok), fall back
        # to the deterministic local embedder so find/search never fail with 401.
        if emb_provider == "openai" and not has_real_openai_route:
            return {
                "provider": "local",
                "model": "bge-small-zh-v1.5-f16",
                "dimension": 512,
                "input": "text",
                "display": "local/bge-small (512d)",
            }
        dense: dict[str, Any] = {
            "provider": emb_provider,
            "model": emb_model,
            "dimension": dim,
            "input": "text",
            "display": f"{emb_provider}/{emb_model}",
        }
        if emb_key or llm.api_key:
            dense["api_key"] = emb_key or llm.api_key
        if emb_base:
            dense["api_base"] = emb_base
        return dense

    return {
        "provider": "local",
        "model": "bge-small-zh-v1.5-f16",
        "dimension": 512,
        "input": "text",
        "display": "local/bge-small (512d)",
    }


def ensure_openviking_configured() -> Path:
    """Write and synchronize ``~/.openviking/ov.conf`` from RedJohn settings."""
    settings = load_settings()
    ov = settings.openviking
    workspace_dir = Path(ov.workspace).expanduser().resolve()
    workspace_dir.mkdir(parents=True, exist_ok=True)

    DEFAULT_OV_DIR.mkdir(parents=True, exist_ok=True)
    vlm_info = _infer_vlm_from_redjohn()
    emb_info = _infer_embedding_from_redjohn(vlm_info)

    vlm_conf = {
        k: v
        for k, v in vlm_info.items()
        if k not in {"configured", "display_model"} and v is not None
    }
    dense_conf = {
        k: v
        for k, v in emb_info.items()
        if k not in {"display"} and v is not None
    }

    # If an existing local VikingDB vector index has a different dimension than the active
    # embedding configuration, reset only the vector index cache (markdown files in viking/
    # are untouched) so OpenViking never fails with EmbeddingRebuildRequiredError.
    collection_meta_path = workspace_dir / "vectordb" / "context" / "collection_meta.json"
    if collection_meta_path.is_file():
        try:
            meta_obj = json.loads(collection_meta_path.read_text(encoding="utf-8"))
            existing_dim = meta_obj.get("Dimension")
            target_dim = dense_conf.get("dimension")
            if isinstance(existing_dim, int) and isinstance(target_dim, int) and existing_dim != target_dim:
                import shutil

                shutil.rmtree(workspace_dir / "vectordb" / "context", ignore_errors=True)
        except Exception:
            logger.debug("Could not inspect VikingDB collection_meta.json", exc_info=True)

    ov_conf_payload: dict[str, Any] = {
        "service_name": "openviking-server",
        "server": {
            "host": "127.0.0.1",
            "port": 1933,
            "root_api_key": None,
            "cors_origins": ["*"],
            "agent_evolution": {"enabled": False},
        },
        "storage": {
            "workspace": str(workspace_dir),
            "vectordb": {
                "name": "context",
                "backend": "local",
            },
            "agfs": {
                "backend": "local",
                "timeout": 10,
                "queuefs": {"backend": "sqlite"},
                "pathlock": {"provider": "filesystem", "lock_expire_secs": 30.0},
            },
        },
        "embedding": {
            "dense": dense_conf,
            "text_source": "content_only",
            "max_input_tokens": 4096,
        },
        "vlm": vlm_conf,
    }

    try:
        DEFAULT_OV_CONF.write_text(
            json.dumps(ov_conf_payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        os.environ["OPENVIKING_CONFIG_FILE"] = str(DEFAULT_OV_CONF)
    except OSError:
        logger.debug("Could not write ~/.openviking/ov.conf", exc_info=True)

    return DEFAULT_OV_CONF


def _check_external_http_server(url: str) -> bool:
    """Return True if an external OpenViking HTTP server is responding at ``url``."""
    health_url = f"{url.rstrip('/')}/health"
    try:
        req = urllib.request.Request(health_url, method="GET")  # noqa: S310
        with urllib.request.urlopen(req, timeout=0.6) as resp:  # nosec B310
            return int(getattr(resp, "status", 200)) < 500
    except Exception:
        return False


def probe_openviking_status() -> dict[str, Any]:
    """Return live availability and model routing status for OpenViking Memory MCP."""
    try:
        settings = load_settings()
        ov = settings.openviking
        if not ov.enabled:
            return {
                "enabled": False,
                "online": False,
                "mode": "disabled",
                "tool_count": 0,
                "vlm_model": "disabled",
                "short_vlm_model": "disabled",
                "embedding_model": "disabled",
                "workspace": ov.workspace,
            }

        conf_path = ensure_openviking_configured()
        vlm_info = _infer_vlm_from_redjohn()
        emb_info = _infer_embedding_from_redjohn(vlm_info)

        # Verify openviking package is importable
        import importlib.util

        ov_installed = importlib.util.find_spec("openviking") is not None
        ext_url = (ov.url or os.environ.get("OPENVIKING_URL") or "").strip()
        if ext_url and _check_external_http_server(ext_url):
            mode = "http"
            online = True
        elif _check_external_http_server("http://127.0.0.1:1933"):
            mode = "http"
            online = True
        else:
            mode = "stdio"
            online = ov_installed

        return {
            "enabled": True,
            "online": online,
            "mode": mode,
            "tool_count": len(CORE_OPENVIKING_TOOLS) if online else 0,
            "vlm_model": str(vlm_info.get("model") or ""),
            "short_vlm_model": str(vlm_info.get("display_model") or "auto"),
            "vlm_provider": str(vlm_info.get("provider") or ""),
            "embedding_model": str(emb_info.get("display") or "local/bge-small"),
            "embedding_provider": str(emb_info.get("provider") or "local"),
            "workspace": str(Path(ov.workspace).expanduser()),
            "config_path": str(conf_path),
        }
    except Exception as exc:
        logger.debug("OpenViking status probe failed: %s", exc)
        return {
            "enabled": True,
            "online": False,
            "mode": "error",
            "tool_count": 0,
            "vlm_model": "error",
            "short_vlm_model": "error",
            "embedding_model": "error",
            "error": str(exc),
        }


def get_openviking_mcp_config() -> McpConnectionConfig | None:
    """Build the built-in ``openviking`` McpConnectionConfig for RedJohn's McpRegistry."""
    settings = load_settings()
    if not settings.openviking.enabled:
        return None

    conf_path = ensure_openviking_configured()
    status = probe_openviking_status()
    vlm_label = status.get("short_vlm_model", "auto")
    emb_label = status.get("embedding_model", "local")

    notes = (
        f"OpenViking hierarchical long-term pentest memory (viking://). "
        f"Active VLM: {vlm_label}, Embedding: {emb_label}. "
        f"Use find/search/read at task start to recall prior target intelligence, "
        f"and remember/write/add_resource to persist verified findings, target profiles, "
        f"and reusable exploitation procedures."
    )

    ext_url = (settings.openviking.url or os.environ.get("OPENVIKING_URL") or "").strip()
    if ext_url and _check_external_http_server(ext_url):
        return McpConnectionConfig(
            name="openviking",
            transport="http",
            url=f"{ext_url.rstrip('/')}/mcp",
            allowed_tools=list(CORE_OPENVIKING_TOOLS),
            active_tools=["find", "search", "read", "remember", "write", "list", "health"],
            idempotent_tools=["find", "search", "read", "list", "tree", "grep", "glob", "health"],
            notes=notes,
        )

    env_vars: dict[str, str] = {
        "OPENVIKING_CONFIG_FILE": str(conf_path),
        "PYTHONUNBUFFERED": "1",
    }
    for key in (
        "REDJOHN_LLM",
        "LLM_API_KEY",
        "LLM_API_BASE",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "REDJOHN_OPENVIKING_MODEL",
        "REDJOHN_OPENVIKING_PROVIDER",
        "REDJOHN_OPENVIKING_API_KEY",
        "REDJOHN_OPENVIKING_API_BASE",
        "REDJOHN_OPENVIKING_EMBEDDING_MODEL",
        "REDJOHN_OPENVIKING_EMBEDDING_PROVIDER",
        "REDJOHN_OPENVIKING_EMBEDDING_API_KEY",
        "REDJOHN_OPENVIKING_EMBEDDING_API_BASE",
        "REDJOHN_OPENVIKING_WORKSPACE",
    ):
        val = os.environ.get(key)
        if val:
            env_vars[key] = val

    return McpConnectionConfig(
        name="openviking",
        transport="stdio",
        command=sys.executable,
        args=["-m", "redjohn.memory.openviking.mcp_server"],
        env=env_vars,
        allowed_tools=list(CORE_OPENVIKING_TOOLS),
        active_tools=["find", "search", "read", "remember", "write", "list", "health"],
        idempotent_tools=["find", "search", "read", "list", "tree", "grep", "glob", "health"],
        notes=notes,
    )
