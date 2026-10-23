"""Settings loader, override switch, and disk persistence."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import AliasChoices, BaseModel

from redjohn.config.settings import LlmSettings, Settings
from redjohn.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Mapping

    from pydantic.fields import FieldInfo


logger = logging.getLogger(__name__)


_DEFAULT_PATH: Path = Path.home() / ".redjohn" / "cli-config.json"
_override: Path | None = None
_cached: Settings | None = None

# Model, API key, and API base describe one provider connection. When the shell
# changes any of them, the stored values of the others no longer belong together
# and are dropped rather than mixed with the new value.
_LINKED_LLM_FIELDS = ("model", "api_key", "api_base")


def load_settings() -> Settings:
    """Resolve settings from env + JSON file + defaults. Memoized.

    Precedence: env vars win, then the JSON file, then field defaults.
    """
    global _cached  # noqa: PLW0603
    if _cached is None:
        source_path = _override or _DEFAULT_PATH
        init_kwargs: dict[str, Any] = _read_json_overrides(source_path)
        _cached = Settings(**init_kwargs)
        logger.debug(
            "load_settings: resolved (override=%s, file_used=%s, json_keys=%d)",
            _override is not None,
            source_path.exists(),
            sum(len(v) for v in init_kwargs.values()),
        )
    return _cached


def apply_config_override(path: Path) -> None:
    """Switch the JSON source to ``path`` and invalidate the cache."""
    global _override, _cached  # noqa: PLW0603
    _override = path
    _cached = None
    logger.info("config override applied: %s", path)


def invalidate_settings_cache() -> None:
    """Drop the memoized settings so the next load sees env and file changes."""
    global _cached  # noqa: PLW0603
    _cached = None


def save_llm_selection(
    *,
    model: str | None = None,
    model_label: str | None = None,
    supported_efforts: tuple[str, ...] | list[str] | None = None,
    api_key: str | None = None,
    api_base: str | None = None,
    reasoning_effort: str | None = None,
    clear_api_key: bool = False,
    clear_api_base: bool = False,
    propagate_to_swarm: bool = False,
) -> None:
    """Persist an LLM choice into this process and ``~/.redjohn/cli-config.json``.

    ``None`` leaves a field alone. Clearing a linked connection field writes an
    empty env value, which ``persist_current`` drops from the file. Env vars
    win over the file, so the process env is updated too; otherwise the next
    ``load_settings`` would keep the previous connection.
    When ``propagate_to_swarm`` is True, clears any separate Swarm override so
    Swarm sub-agents inherit the new Orchestrator connection.
    """
    if model is not None:
        os.environ["REDJOHN_LLM"] = model
        os.environ["REDJOHN_LLM_LABEL"] = (model_label or "").strip()
        if supported_efforts is not None:
            os.environ["REDJOHN_LLM_SUPPORTED_EFFORTS"] = ",".join(
                str(item).strip().lower() for item in supported_efforts if str(item).strip()
            )
        else:
            os.environ["REDJOHN_LLM_SUPPORTED_EFFORTS"] = ""
    if api_key is not None:
        os.environ["LLM_API_KEY"] = api_key
    elif clear_api_key:
        os.environ["LLM_API_KEY"] = ""
    if api_base is not None:
        os.environ["LLM_API_BASE"] = api_base
        os.environ["OPENAI_BASE_URL"] = api_base
    elif clear_api_base:
        os.environ["LLM_API_BASE"] = ""
        os.environ.pop("OPENAI_BASE_URL", None)
        os.environ.pop("OPENAI_API_BASE", None)
    if reasoning_effort is not None:
        os.environ["REDJOHN_REASONING_EFFORT"] = reasoning_effort
    if propagate_to_swarm:
        os.environ["REDJOHN_SWARM_LLM"] = ""
        os.environ["SWARM_LLM_API_KEY"] = ""
        os.environ["SWARM_LLM_API_BASE"] = ""
        os.environ["REDJOHN_SWARM_REASONING_EFFORT"] = ""
    invalidate_settings_cache()
    persist_current()


def save_swarm_llm_selection(
    *,
    swarm_model: str | None = None,
    swarm_api_key: str | None = None,
    swarm_api_base: str | None = None,
    swarm_reasoning_effort: str | None = None,
    swarm_profile: str | None = None,
    role: str | None = None,
    role_model: str | None = None,
    clear_swarm_model: bool = False,
    clear_swarm_api_key: bool = False,
    clear_swarm_api_base: bool = False,
    clear_role_models: bool = False,
) -> None:
    """Persist Swarm-specific LLM / role / profile settings."""
    if clear_swarm_model:
        os.environ["REDJOHN_SWARM_LLM"] = ""
        os.environ["REDJOHN_SWARM_REASONING_EFFORT"] = ""
    elif swarm_model is not None:
        os.environ["REDJOHN_SWARM_LLM"] = swarm_model
    if swarm_api_key is not None:
        os.environ["SWARM_LLM_API_KEY"] = swarm_api_key
    elif clear_swarm_api_key:
        os.environ["SWARM_LLM_API_KEY"] = ""
    if swarm_api_base is not None:
        os.environ["SWARM_LLM_API_BASE"] = swarm_api_base
    elif clear_swarm_api_base:
        os.environ["SWARM_LLM_API_BASE"] = ""
    if swarm_reasoning_effort is not None:
        os.environ["REDJOHN_SWARM_REASONING_EFFORT"] = swarm_reasoning_effort
    if swarm_profile is not None:
        os.environ["REDJOHN_SWARM_PROFILE"] = swarm_profile
    if clear_role_models:
        os.environ["REDJOHN_SWARM_ROLE_MODELS"] = ""
    elif role is not None:
        current = dict(load_settings().llm.swarm_role_models or {})
        if role_model:
            current[role] = role_model
        else:
            current.pop(role, None)
        os.environ["REDJOHN_SWARM_ROLE_MODELS"] = json.dumps(current) if current else ""
    invalidate_settings_cache()
    persist_current()


def save_openviking_selection(
    *,
    enabled: bool | None = None,
    vlm_model: str | None = None,
    vlm_provider: str | None = None,
    vlm_api_key: str | None = None,
    vlm_api_base: str | None = None,
    embedding_model: str | None = None,
    embedding_provider: str | None = None,
    embedding_api_key: str | None = None,
    embedding_api_base: str | None = None,
    embedding_dimension: int | None = None,
    clear_vlm: bool = False,
    clear_vlm_api_key: bool = False,
    clear_vlm_api_base: bool = False,
    clear_embedding: bool = False,
) -> None:
    """Persist OpenViking memory model & embedding configuration."""
    if enabled is not None:
        os.environ["REDJOHN_OPENVIKING_ENABLED"] = "true" if enabled else "false"
    if clear_vlm:
        os.environ["REDJOHN_OPENVIKING_MODEL"] = ""
        os.environ["REDJOHN_OPENVIKING_PROVIDER"] = ""
        os.environ["REDJOHN_OPENVIKING_API_KEY"] = ""
        os.environ["REDJOHN_OPENVIKING_API_BASE"] = ""
    else:
        if vlm_model is not None:
            os.environ["REDJOHN_OPENVIKING_MODEL"] = vlm_model
        if vlm_provider is not None:
            os.environ["REDJOHN_OPENVIKING_PROVIDER"] = vlm_provider
        if vlm_api_key is not None:
            os.environ["REDJOHN_OPENVIKING_API_KEY"] = vlm_api_key
        elif clear_vlm_api_key:
            os.environ["REDJOHN_OPENVIKING_API_KEY"] = ""
        if vlm_api_base is not None:
            os.environ["REDJOHN_OPENVIKING_API_BASE"] = vlm_api_base
        elif clear_vlm_api_base:
            os.environ["REDJOHN_OPENVIKING_API_BASE"] = ""
    if clear_embedding:
        os.environ["REDJOHN_OPENVIKING_EMBEDDING_MODEL"] = ""
        os.environ["REDJOHN_OPENVIKING_EMBEDDING_PROVIDER"] = ""
        os.environ["REDJOHN_OPENVIKING_EMBEDDING_API_KEY"] = ""
        os.environ["REDJOHN_OPENVIKING_EMBEDDING_API_BASE"] = ""
    else:
        if embedding_model is not None:
            os.environ["REDJOHN_OPENVIKING_EMBEDDING_MODEL"] = embedding_model
        if embedding_provider is not None:
            os.environ["REDJOHN_OPENVIKING_EMBEDDING_PROVIDER"] = embedding_provider
        if embedding_api_key is not None:
            os.environ["REDJOHN_OPENVIKING_EMBEDDING_API_KEY"] = embedding_api_key
        if embedding_api_base is not None:
            os.environ["REDJOHN_OPENVIKING_EMBEDDING_API_BASE"] = embedding_api_base
        if embedding_dimension is not None:
            os.environ["REDJOHN_OPENVIKING_EMBEDDING_DIMENSION"] = str(embedding_dimension)
    invalidate_settings_cache()
    persist_current()


def persist_current() -> None:
    """Merge currently-set env vars into the active config file (0o600).

    Values already in the file survive when their env var is unset, so a
    run that gets its settings from the file does not erase them. An env
    var set to the empty string clears the field from the file. A change to
    any linked LLM connection var drops the whole stored connection first.
    """
    s = load_settings()
    target = _override or _DEFAULT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)

    env_block = _drop_stale_llm_connection(_read_env_block(target))
    env_map = {k.upper(): k for k in os.environ}
    for sub_name in type(s).model_fields:
        sub_model = getattr(s, sub_name)
        if not isinstance(sub_model, BaseModel):
            continue
        for finfo in type(sub_model).model_fields.values():
            aliases = [alias.upper() for alias in _aliases_for(finfo)]
            active_upper = next((alias for alias in aliases if alias in env_map), None)
            if active_upper is None:
                continue
            active_actual = env_map[active_upper]
            for alias in aliases:
                env_block.pop(alias, None)
            if os.environ[active_actual]:
                env_block[active_upper] = os.environ[active_actual]

    write_secret_text(target, json.dumps({"env": env_block}, indent=2))


def _aliases_for(finfo: FieldInfo) -> list[str]:
    """Collect every env-var name that should populate ``finfo``."""
    aliases: list[str] = []
    if finfo.alias:
        aliases.append(finfo.alias)
    va = finfo.validation_alias
    if isinstance(va, AliasChoices):
        aliases.extend(c for c in va.choices if isinstance(c, str))
    elif isinstance(va, str):
        aliases.append(va)
    return aliases


def _value_from_sources(
    fname: str,
    aliases: list[str],
    section: Mapping[str, Any],
    env_block: Mapping[str, Any],
) -> Any | None:
    if fname in section:
        return section[fname]
    for a in aliases:
        low = a.lower()
        if low in section:
            return section[low]
        if a in section:
            return section[a]
    if env_block:
        for a in aliases:
            if a in env_block:
                return env_block[a]
    return None


def _is_llm_connection_changed(raw_llm: Mapping[str, Any], env_block: Mapping[str, Any]) -> bool:
    upper_env = {k.upper(): v for k, v in os.environ.items()}
    for name in _LINKED_LLM_FIELDS:
        finfo = LlmSettings.model_fields[name]
        aliases = [alias.upper() for alias in _aliases_for(finfo)] + [name.upper()]
        env_val = _first_alias_value(aliases, upper_env)
        if env_val is not None:
            file_val = _value_from_sources(name, aliases, raw_llm, env_block)
            if env_val != file_val:
                return True
    return False


def _read_json_overrides(path: Path) -> dict[str, dict[str, Any]]:
    """Read configuration overrides from ``path`` and map to nested kwargs.

    Supports direct nested sections (e.g. ``{"llm": {"model": ...}}``)
    as well as legacy ``{"env": {...}}`` blocks.
    """
    if not path.exists():
        return {}
    try:
        raw_data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        # A truncated config silently reverts the model/provider to defaults;
        # the user would later see a confusing provider 401 instead of the cause.
        logger.warning("config file %s unreadable; using env/defaults only: %s", path, exc)
        return {}
    if not isinstance(raw_data, dict):
        return {}

    env_present = {k.upper() for k in os.environ}
    env_block = _read_env_block(path)
    raw_llm_obj = raw_data.get("llm")
    raw_llm: dict[str, Any] = dict(raw_llm_obj) if isinstance(raw_llm_obj, dict) else {}
    llm_changed = _is_llm_connection_changed(raw_llm, env_block)

    nested: dict[str, dict[str, Any]] = {}
    for sub_name, sub_finfo in Settings.model_fields.items():
        sub_cls = sub_finfo.annotation
        if not (isinstance(sub_cls, type) and issubclass(sub_cls, BaseModel)):
            continue
        raw_sec_obj = raw_data.get(sub_name)
        raw_section: dict[str, Any] = dict(raw_sec_obj) if isinstance(raw_sec_obj, dict) else {}
        sub_data: dict[str, Any] = {}

        for fname, finfo in sub_cls.model_fields.items():
            if sub_name == "llm" and llm_changed and fname in _LINKED_LLM_FIELDS:
                continue
            aliases = [alias.upper() for alias in _aliases_for(finfo)] + [fname.upper()]
            if any(alias in env_present for alias in aliases):
                continue
            val = _value_from_sources(fname, aliases, raw_section, env_block)
            if val is not None:
                sub_data[fname] = val

        if sub_data:
            nested[sub_name] = sub_data

    return nested


def _first_alias_value(aliases: list[str], source: Mapping[str, Any]) -> Any | None:
    return next((source[alias] for alias in aliases if alias in source), None)


def _drop_stale_llm_connection(env_block: dict[str, Any]) -> dict[str, Any]:
    """Remove every linked LLM var from ``env_block`` if the shell changed any of them."""
    linked_aliases = [
        [alias.upper() for alias in _aliases_for(LlmSettings.model_fields[name])]
        for name in _LINKED_LLM_FIELDS
    ]
    upper_env = {k.upper(): v for k, v in os.environ.items()}
    upper_block = {str(k).upper(): v for k, v in env_block.items()}
    changed = any(
        (env_value := _first_alias_value(aliases, upper_env)) is not None
        and env_value != _first_alias_value(aliases, upper_block)
        for aliases in linked_aliases
    )
    if not changed:
        return env_block
    stale = {alias for aliases in linked_aliases for alias in aliases}
    return {k: v for k, v in env_block.items() if str(k).upper() not in stale}


def _read_env_block(path: Path) -> dict[str, Any]:
    """Return the ``env`` block stored in ``path`` with upper-cased keys, or ``{}``."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("config file %s unreadable; env block ignored: %s", path, exc)
        return {}
    env_block = data.get("env", {}) if isinstance(data, dict) else {}
    if not isinstance(env_block, dict):
        return {}
    return {str(k).upper(): v for k, v in env_block.items()}
