"""Approve/persist a host binding without putting private config in prompts.

CLI/TUI host arguments or their private per-run snapshot establish authority.
Model input, workspace content and client engagement IDs cannot create a binding.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from redjohn.assessment.configuration import validate_configuration
from redjohn.assessment.host import HostAssessment
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied, origin_for


_STATE_NAME = "assessment-host.json"
_SNAPSHOT_VERSION = 2


def approval_key_path() -> Path:
    configured = os.environ.get("REDJOHN_ASSESSMENT_APPROVAL_KEY")
    path = (
        Path(configured) if configured else Path.home() / ".redjohn/assessment-approvals/host.key"
    )
    if not path.is_absolute():
        raise PolicyDenied("assessment_approval_key_path_invalid")
    return path


def _approval_key(*, create: bool) -> bytes:
    try:
        return _load_approval_key(create=create)
    except OSError:
        raise PolicyDenied("assessment_approval_key_unavailable") from None


def _load_approval_key(*, create: bool) -> bytes:
    path = approval_key_path()
    if create:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PolicyDenied("assessment_approval_key_not_private")
    if create:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size != 32
        ):
            raise PolicyDenied("assessment_approval_key_not_private")
        return os.read(fd, 33)
    finally:
        os.close(fd)


def _signature(value: dict[str, Any], *, create_key: bool) -> str:
    payload = {key: field for key, field in value.items() if key != "approval_mac"}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hmac.new(_approval_key(create=create_key), raw, hashlib.sha256).hexdigest()


def _read_owned(path: Path, *, private: bool, maximum: int) -> Any:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        forbidden = 0o077 if private else 0o022
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & forbidden
            or info.st_size > maximum
        ):
            raise PolicyDenied("assessment_configuration_not_owner_approved")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("configuration_too_large")
        return json.loads(raw)
    finally:
        os.close(fd)


def _configuration_hash(config: dict[str, Any]) -> str:
    raw = json.dumps(config, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > 65536:
        raise ValueError("configuration_too_large")
    return hashlib.sha256(raw).hexdigest()


def _absolute_files(config: dict[str, Any], base: Path) -> dict[str, Any]:
    """Resolve only schema-known host file references; URL/input paths stay raw."""
    config = json.loads(json.dumps(config))

    def file_field(document: dict[str, Any], name: str) -> None:
        value = document.get(name)
        if isinstance(value, str) and value and not Path(value).is_absolute():
            document[name] = str(base / value)

    for name in ("auth_vault_file", "refresh_provider_file", "browser_capture_file"):
        file_field(config, name)
    if isinstance(tls := config.get("tls"), dict):
        file_field(tls, "upstream_ca_file")
    documents = [
        config.get(name)
        for name in (
            "nuclei_lock",
            "ffuf",
            "httpx",
            "katana",
            "vulnx",
            "arjun",
            "sqlmap",
            "dalfox",
            "tinja",
            "schemathesis",
            "interactsh",
        )
    ]
    for document in documents:
        if not isinstance(document, dict):
            continue
        if isinstance(binary := document.get("binary"), dict):
            file_field(binary, "path")
        for name in ("schema_file", "token_file", "ca_file", "upstream_ca_file"):
            file_field(document, name)
    if isinstance(lock := config.get("nuclei_lock"), dict) and isinstance(
        bundle := lock.get("bundle"), dict
    ):
        file_field(bundle, "root")
    return config


def host_urls(scan_config: dict[str, Any]) -> tuple[str, ...]:
    """Original host URLs, before the legacy sandbox's localhost alias rewrite."""
    urls: list[str] = []
    for target in scan_config.get("targets", []) or []:
        if target.get("type") == "web_application":
            original = target.get("original", "")
            value = (
                original
                if urlsplit(original).scheme in {"http", "https"}
                else (target.get("details") or {}).get("target_url", "")
            )
            if value:
                origin_for(value)
                urls.append(value)
        elif target.get("type") == "api_spec":
            for value in (target.get("details") or {}).get("base_urls", []):
                origin_for(value)
                urls.append(value)
    if len(urls) > 64:
        raise PolicyDenied("assessment_target_limit")
    return tuple(dict.fromkeys(urls))


class PreparedHostAssessment:
    def __init__(self, config: dict[str, Any], output: Path, *, caller: str, source: str) -> None:
        self.host = HostAssessment(validate_configuration(config), output, caller=caller)
        self.source = source
        self.fingerprint = _configuration_hash(config)
        self._snapshot = {
            "version": _SNAPSHOT_VERSION,
            "operator_uid": os.getuid(),
            "run_directory": str(output.resolve()),
            "caller": caller,
            "configuration": config,
            "configuration_sha256": self.fingerprint,
        }

    def metadata(self) -> dict[str, Any]:
        policy = self.host.configured.policy
        return {
            "available": True,
            "engagement_id": policy.engagement_id,
            "policy_revision": policy.revision,
            "profile": policy.profile,
            "source": self.source,
            "configuration_ref": self.fingerprint,
            "control_tool": "assessment_control",
        }

    def protected_paths(self) -> tuple[Path, ...]:
        config = self.host.configured.config
        paths = [self.host.configured.output.resolve()]
        paths.extend(
            Path(value).resolve()
            for field in ("auth_vault_file", "refresh_provider_file", "browser_capture_file")
            if (value := config.get(field))
        )
        if isinstance(oast := config.get("interactsh"), dict) and oast.get("token_file"):
            paths.append(Path(oast["token_file"]).resolve())
        return tuple(paths)

    def check_workspace_authority(self, sources: list[dict[str, Any]]) -> None:
        key = approval_key_path().resolve()
        for source in sources:
            if (value := source.get("source_path")) and key.is_relative_to(
                Path(value).expanduser().resolve()
            ):
                raise PolicyDenied("assessment_approval_key_exposed_by_workspace")

    def _persist(self) -> None:
        directory = self.host.configured.output / ".state"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise PolicyDenied("assessment_state_directory_not_private")
        path = directory / _STATE_NAME
        if path.exists() or path.is_symlink():
            _read_owned(path, private=True, maximum=131072)
        # Resolve signing failures before opening an output descriptor.
        self._snapshot["approval_mac"] = _signature(self._snapshot, create_key=True)
        temporary = directory / (".assessment-host-" + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(json.dumps(self._snapshot, allow_nan=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)

    async def start(self) -> HostAssessment:
        # Approval is durable before the task can launch a selected worker.
        self._persist()
        return await self.host.__aenter__()


def prepare_host_assessment(
    scan_config: dict[str, Any],
    scan_id: str,
    output: Path,
    *,
    config_path: str | Path | None = None,
    caller: str | None = None,
) -> PreparedHostAssessment | None:
    urls = host_urls(scan_config)
    state = output / ".state" / _STATE_NAME
    if config_path is not None:
        config = validate_configuration(
            _read_owned(Path(config_path), private=False, maximum=65536)
        )
        config = _absolute_files(config, Path.cwd())
        policy = EngagementPolicy.from_mapping(config["policy"])
        caller = policy.owner_id if caller is None else caller
        source = "operator_configuration"
    elif state.exists() or state.is_symlink():
        saved = _read_owned(state, private=True, maximum=131072)
        if (
            not isinstance(saved, dict)
            or set(saved)
            != {
                "version",
                "operator_uid",
                "run_directory",
                "caller",
                "configuration",
                "configuration_sha256",
                "approval_mac",
            }
            or type(saved["version"]) is not int
            or saved["version"] != _SNAPSHOT_VERSION
            or type(saved["operator_uid"]) is not int
            or saved["operator_uid"] != os.getuid()
        ):
            raise PolicyDenied("assessment_snapshot_invalid")
        if saved["run_directory"] != str(output.resolve()):
            raise PolicyDenied("assessment_snapshot_run_mismatch")
        mac = saved["approval_mac"]
        if (
            not isinstance(mac, str)
            or re.fullmatch(r"[0-9a-f]{64}", mac) is None
            or not hmac.compare_digest(mac, _signature(saved, create_key=False))
        ):
            raise PolicyDenied("assessment_snapshot_changed_without_approval")
        config = validate_configuration(saved["configuration"])
        if saved["configuration_sha256"] != _configuration_hash(config):
            raise PolicyDenied("assessment_snapshot_changed_without_approval")
        saved_caller = saved["caller"]
        if not isinstance(saved_caller, str) or (caller is not None and caller != saved_caller):
            raise PolicyDenied("engagement_access_denied")
        caller, source = saved_caller, "approved_run_snapshot"
        policy = EngagementPolicy.from_mapping(config["policy"])
    else:
        if not urls:
            return None
        caller = caller or f"local-uid:{os.getuid()}"
        policy = EngagementPolicy(
            scan_id,
            caller,
            tuple(dict.fromkeys(origin_for(url) for url in urls)),
            egress_mode="enforced",
            deadline=time.time() + 3600,
        )
        config = {
            "policy": policy.to_dict(),
            # Importing an approved seed performs no HTTP request. The model
            # must explicitly submit reviewed jobs through the bound API.
            "seeds": [{"url": url, "capabilities": []} for url in urls],
        }
        source = "host_scan_targets_safe_production"
    approved_origins = {origin_for(url) for url in urls}
    if not {origin_for(url) for url in policy.allowed_origins} <= approved_origins:
        raise PolicyDenied("assessment_scope_mismatch")
    policy.authorize(caller)
    return PreparedHostAssessment(config, output, caller=caller, source=source)
