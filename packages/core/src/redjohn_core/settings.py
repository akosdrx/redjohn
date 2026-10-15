"""Engine settings: data-profile based configuration.

Resolution order (lowest to highest precedence):
  1. built-in defaults
  2. ``<profile>/settings.json`` overlay (written by PATCH /settings)
  3. environment variables

Config layout (per data profile)::

    <REDJOHN_HOME>/<REDJOHN_PROFILE>/
        redjohn.db          SQLite database (Alembic-managed)
        checkpoints.db      LangGraph durable checkpointer store
        token               API bearer token (file mode 0600, generated once)
        profile.lock        JSON {pid, port, token} single-engine lock
        settings.json       non-secret overlay written via the API
        evidence/           captured tool output (content-addressed rows in db)
        reports/            generated report artifacts
        work/               per-run working directories for tool execution

Secrets come from the environment or the OS keyring and are NEVER logged or
returned by the API; ``redacted()`` masks them for /settings responses.
"""

from __future__ import annotations

import json
import os
import secrets as _secrets
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8720

#: non-secret fields that PATCH /settings may persist into settings.json
MUTABLE_FIELDS = {"model_provider", "model_name", "openviking_url", "log_level"}

#: fields never serialized unredacted / never accepted from the API
SECRET_FIELDS = {"anthropic_api_key", "model_api_key", "auth_token", "openviking_api_key"}


class Settings(BaseModel):
    """Runtime configuration for one engine process (one data profile)."""

    redjohn_home: Path = Field(default_factory=lambda: Path.home() / ".redjohn")
    data_profile: str = "default"

    # model gateway -----------------------------------------------------------
    model_provider: str = "anthropic"  # default adapter name
    model_name: str = "claude-sonnet-4-5"
    anthropic_api_key: str | None = Field(default=None, repr=False)
    model_api_key: str | None = Field(default=None, repr=False)
    model_base_url: str | None = None
    codex_binary: str | None = None

    # openviking --------------------------------------------------------------
    openviking_url: str | None = None
    openviking_api_key: str | None = Field(default=None, repr=False)
    openviking_account: str = "redjohn"    # workspace/account mapping boundary
    openviking_user: str = "local-user"    # per-account memory isolation
    openviking_actor_peer: str | None = None
    openviking_processing_mode: str = "vectors_only"
    openviking_timeout: float = 120.0

    # server ------------------------------------------------------------------
    log_level: str = "INFO"
    bind_host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    auth_token: str | None = Field(default=None, repr=False)

    # fixtures (tests only) ---------------------------------------------------
    fixture_script: Path | None = None  # RJ_FIXTURE_SCRIPT; fixture provider only

    # limits / tuning ---------------------------------------------------------
    tool_output_cap_bytes: int = 1_048_576
    tool_timeout_seconds: float = 120.0
    mcp_call_timeout_seconds: float = 60.0
    ws_queue_size: int = 256
    max_agent_steps: int = 64
    max_model_output_tokens: int = Field(default=4096, ge=1, le=131072)
    ov_retry_seconds: float = 2.0
    relay_idle_sleep: float = 0.05

    # ------------------------------------------------------------------ paths
    @property
    def profile_dir(self) -> Path:
        return self.redjohn_home / self.data_profile

    @property
    def db_path(self) -> Path:
        return self.profile_dir / "redjohn.db"

    @property
    def db_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"

    @property
    def checkpoints_path(self) -> Path:
        return self.profile_dir / "checkpoints.db"

    @property
    def token_path(self) -> Path:
        return self.profile_dir / "token"

    @property
    def lock_path(self) -> Path:
        return self.profile_dir / "profile.lock"

    @property
    def settings_path(self) -> Path:
        return self.profile_dir / "settings.json"

    @property
    def evidence_dir(self) -> Path:
        return self.profile_dir / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.profile_dir / "reports"

    @property
    def work_root(self) -> Path:
        return self.profile_dir / "work"

    # ---------------------------------------------------------------- loading
    @classmethod
    def load(cls, environ: dict[str, str] | None = None) -> Settings:
        """Build settings: defaults < <profile>/settings.json < environment."""
        env = os.environ if environ is None else environ
        base: dict[str, Any] = {}

        home = env.get("REDJOHN_HOME")
        if home:
            base["redjohn_home"] = Path(home)
        profile = env.get("REDJOHN_PROFILE")
        if profile:
            base["data_profile"] = profile

        provisional = cls(**base)
        overlay = cls._read_overlay(provisional.settings_path)
        from .integrations import IntegrationStore
        merged = {**base, **overlay, **IntegrationStore(provisional).runtime_overlay()}

        env_map = {
            "RJ_MODEL_PROVIDER": ("model_provider", str),
            "RJ_MODEL_NAME": ("model_name", str),
            "RJ_MODEL_API_KEY": ("model_api_key", str),
            "RJ_MODEL_BASE_URL": ("model_base_url", str),
            "RJ_CODEX_BINARY": ("codex_binary", str),
            "RJ_OPENVIKING_URL": ("openviking_url", str),
            "RJ_OPENVIKING_API_KEY": ("openviking_api_key", str),
            "RJ_OPENVIKING_ACCOUNT": ("openviking_account", str),
            "RJ_OPENVIKING_USER": ("openviking_user", str),
            "RJ_OPENVIKING_ACTOR_PEER": ("openviking_actor_peer", str),
            "RJ_OPENVIKING_PROCESSING_MODE": ("openviking_processing_mode", str),
            "RJ_OPENVIKING_TIMEOUT": ("openviking_timeout", float),
            "RJ_LOG_LEVEL": ("log_level", str),
            "RJ_BIND_HOST": ("bind_host", str),
            "RJ_PORT": ("port", int),
            "RJ_TOKEN": ("auth_token", str),
            "RJ_FIXTURE_SCRIPT": ("fixture_script", Path),
            "RJ_TOOL_OUTPUT_CAP_BYTES": ("tool_output_cap_bytes", int),
            "RJ_TOOL_TIMEOUT_SECONDS": ("tool_timeout_seconds", float),
            "RJ_MCP_CALL_TIMEOUT_SECONDS": ("mcp_call_timeout_seconds", float),
            "RJ_WS_QUEUE_SIZE": ("ws_queue_size", int),
            "RJ_MAX_AGENT_STEPS": ("max_agent_steps", int),
            "RJ_MAX_MODEL_OUTPUT_TOKENS": ("max_model_output_tokens", int),
            "RJ_OV_RETRY_SECONDS": ("ov_retry_seconds", float),
        }
        for var, (field, cast) in env_map.items():
            if var in env and env[var] != "":
                merged[field] = cast(env[var])

        # anthropic key: RJ_ANTHROPIC_API_KEY > ANTHROPIC_API_KEY > OS keyring
        key = env.get("RJ_ANTHROPIC_API_KEY") or env.get("ANTHROPIC_API_KEY")
        if not key:
            key = _keyring_lookup()
        if key:
            merged["anthropic_api_key"] = key

        return cls(**merged)

    @staticmethod
    def _read_overlay(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return {k: v for k, v in data.items() if k in MUTABLE_FIELDS}

    # --------------------------------------------------------------- overlay
    def save_overlay(self, patch: dict[str, Any]) -> None:
        """Persist mutable, non-secret fields to <profile>/settings.json."""
        clean = {k: v for k, v in patch.items() if k in MUTABLE_FIELDS and k not in SECRET_FIELDS}
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        current = self._read_overlay(self.settings_path)
        current.update(clean)
        from .integrations import atomic_private_json
        atomic_private_json(self.settings_path, current)
        for k, v in clean.items():
            object.__setattr__(self, k, v)

    # -------------------------------------------------------------- redacted
    def redacted(self) -> dict[str, Any]:
        """Serialization safe for API responses and logs: secrets masked."""
        data = self.model_dump(mode="json")
        for field in SECRET_FIELDS:
            if data.get(field):
                data[field] = "***"
        data["redjohn_home"] = str(self.redjohn_home)
        if data.get("fixture_script"):
            data["fixture_script"] = str(self.fixture_script)
        return data

    # ----------------------------------------------------------------- misc
    def ensure_dirs(self) -> None:
        for d in (self.profile_dir, self.evidence_dir, self.reports_dir, self.work_root):
            d.mkdir(parents=True, exist_ok=True)
        self.profile_dir.chmod(0o700)

    def load_or_create_token(self) -> str:
        """Return the API bearer token; generate once with file mode 0600."""
        if self.auth_token:
            return self.auth_token
        if self.token_path.exists():
            return self.token_path.read_text(encoding="utf-8").strip()
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        token = _secrets.token_urlsafe(32)
        fd = os.open(self.token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token)
        object.__setattr__(self, "auth_token", token)
        return token


def _keyring_lookup() -> str | None:
    """Optional OS keyring lookup; absent keyring support is not an error."""
    try:
        import keyring  # type: ignore[import-not-found]  # optional extra

        return keyring.get_password("redjohn", "anthropic")
    except Exception:
        return None
