"""RedJohn application settings.

Public surface:

- :class:`Settings` — composite model. Get via :func:`load_settings`.
- :class:`LlmSettings`, :class:`RuntimeSettings`, :class:`TelemetrySettings`,
  :class:`IntegrationSettings` — sub-models, attribute-accessed off
  ``Settings``.
- :func:`load_settings` — memoized resolve (env > JSON file > defaults).
- :func:`apply_config_override` — switch the JSON source to a custom path.
- :func:`persist_current` — write currently-set env vars to the active file.
- :func:`save_llm_selection` — persist a model, key, base, or effort chosen in the TUI.
- :func:`invalidate_settings_cache` — drop the memoized settings.
"""

from redjohn.config.loader import (
    apply_config_override,
    invalidate_settings_cache,
    load_settings,
    persist_current,
    save_llm_selection,
)
from redjohn.config.settings import (
    ContextSettings,
    DedupeSettings,
    IntegrationSettings,
    LlmSettings,
    RuntimeSettings,
    Settings,
    TelemetrySettings,
)


__all__ = [
    "ContextSettings",
    "DedupeSettings",
    "IntegrationSettings",
    "LlmSettings",
    "RuntimeSettings",
    "Settings",
    "TelemetrySettings",
    "apply_config_override",
    "invalidate_settings_cache",
    "load_settings",
    "persist_current",
    "save_llm_selection",
]
