"""Local-profile integrations; Cloud uses its own operator-managed settings.

Credentials are encrypted in atomic mode-0600 profile files. The key is also
mode 0600: this protects local storage, not a remote vault. Public DTOs expose
only a configured flag. Codex owns its separate OAuth token store.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

from .errors import RJError, not_found, validation

# Catalog refreshes cannot silently redirect stored credentials.
PROVIDERS = {
    "zai": ("Z.ai API", "https://api.z.ai/api/paas/v4", "glm-4.7"),
    "zai-coding-plan": ("Z.ai Coding Plan", "https://api.z.ai/api/coding/paas/v4", "glm-4.7"),
    "deepseek": ("DeepSeek", "https://api.deepseek.com", "deepseek-chat"),
    "openai": ("OpenAI API", "https://api.openai.com/v1", ""),
    "anthropic": ("Anthropic API", "https://api.anthropic.com", "claude-sonnet-4-5"),
    "openrouter": ("OpenRouter", "https://openrouter.ai/api/v1", ""),
    "custom": ("OpenAI-compatible endpoint", "", ""),
    "codex": ("Codex · ChatGPT subscription", "", ""),
}


def validate_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("https", "http")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise validation("Use an HTTP(S) base URL without credentials, query or fragment.")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise validation("Remote endpoints require HTTPS; HTTP is allowed only on loopback.")
    return value.rstrip("/")


def atomic_private_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".rj-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class IntegrationStore:
    def __init__(self, settings: Any):
        self.settings = settings
        self.path = settings.profile_dir / "integrations.json"
        self.key_path = settings.profile_dir / "integration.key"

    def read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"providers": [], "active_provider": None, "memory": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RJError(
                "integration_config_invalid",
                "Cannot read the integration configuration; restore its backup.",
                status=503,
            ) from exc

    def _cipher(self) -> Fernet:
        self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.key_path.exists():
            try:
                fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(Fernet.generate_key())
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError:
                pass
        return Fernet(self.key_path.read_bytes())

    def encrypt(self, value: str) -> str:
        return self._cipher().encrypt(value.encode()).decode()

    def decrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        try:
            return self._cipher().decrypt(value.encode()).decode()
        except Exception as exc:
            raise RJError(
                "integration_secret_unavailable",
                "The profile credential store cannot be decrypted.",
                status=503,
            ) from exc

    @staticmethod
    def provider_public(item: dict[str, Any]) -> dict[str, Any]:
        return {k: item[k] for k in ("id", "label", "provider", "model", "base_url")} | {
            "credential_configured": bool(item.get("secret")),
            "auth_method": "oauth" if item["provider"] == "codex" else "api_key",
        }

    def public(self) -> dict[str, Any]:
        data = self.read()
        return {
            "items": [self.provider_public(p) for p in data["providers"]],
            "active_provider": data.get("active_provider"),
        }

    def provider(self, provider_id: str) -> dict[str, Any]:
        item = next((p for p in self.read()["providers"] if p["id"] == provider_id), None)
        if item is None:
            raise not_found("provider", provider_id)
        return item

    def save_provider(self, values: dict[str, Any]) -> dict[str, Any]:
        data = self.read()
        provider = values.get("provider", "")
        if provider not in PROVIDERS:
            raise validation("Choose a supported provider or an OpenAI-compatible endpoint.")
        identifier = values.get("id") or "provider_" + uuid.uuid4().hex[:16]
        old = self.provider(identifier) if values.get("id") else {}
        base = values.get("base_url") or PROVIDERS[provider][1]
        base = validate_endpoint(base) if provider != "codex" else ""
        model = str(values.get("model", "")).strip()
        if not model or len(model) > 200:
            raise validation("A model identifier is required.")
        key = values.get("api_key")
        if old and (old["base_url"] != base or old["provider"] != provider) and not key:
            raise validation("Changing a credential destination requires re-entering its API key.")
        secret = self.encrypt(key) if key else old.get("secret")
        if (
            provider != "codex"
            and not secret
            and not (provider == "custom" and urlsplit(base).hostname in ("localhost", "127.0.0.1", "::1"))
        ):
            raise validation("An API key is required for this provider.")
        item = {
            "id": identifier,
            "label": str(values.get("label") or PROVIDERS[provider][0])[:120],
            "provider": provider,
            "base_url": base,
            "model": model,
            "secret": secret,
        }
        data["providers"] = [p for p in data["providers"] if p["id"] != identifier] + [item]
        atomic_private_json(self.path, data)
        return self.provider_public(item)

    def activate(self, identifier: str) -> None:
        self.provider(identifier)
        data = self.read()
        data["active_provider"] = identifier
        atomic_private_json(self.path, data)

    def delete(self, identifier: str) -> None:
        data = self.read()
        self.provider(identifier)
        if data.get("active_provider") == identifier:
            raise validation("Select another provider before removing the active connection.")
        if data.get("memory", {}).get("provider_connection_id") == identifier:
            raise validation("Select another OpenViking provider in Memory before removing this connection.")
        data["providers"] = [p for p in data["providers"] if p["id"] != identifier]
        atomic_private_json(self.path, data)

    def provider_settings(self, identifier: str) -> dict[str, Any]:
        item = self.provider(identifier)
        secret = self.decrypt(item.get("secret"))
        return {
            "model_provider": item["provider"],
            "model_name": item["model"],
            "model_base_url": item["base_url"] or None,
            "model_api_key": secret,
            "anthropic_api_key": secret if item["provider"] == "anthropic" else None,
        }

    def runtime_overlay(self) -> dict[str, Any]:
        data = self.read()
        result = self.provider_settings(data["active_provider"]) if data.get("active_provider") else {}
        memory = data.get("memory", {})
        for field in (
            "openviking_url",
            "openviking_account",
            "openviking_user",
            "openviking_processing_mode",
        ):
            if field in memory:
                result[field] = memory[field]
        if memory.get("service_secret"):
            result["openviking_api_key"] = self.decrypt(memory["service_secret"])
        return result
