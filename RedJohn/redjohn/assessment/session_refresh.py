"""Explicit, fenced session refresh with credentials confined to private host files.

A refresh is a separate non-idempotent scheduler job. An unknown delivery never
causes a retry or anonymous fallback. The private vault replacement and SQLite
commit cannot form one atomic transaction: a crash between them deliberately
leaves the identity blocked for operator reconciliation.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import fcntl
import json
import math
import os
import stat
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault
from redjohn.assessment.body_tokens import (
    BodyTokenDenied,
    rotate_body_tokens,
    validate_response_body_tokens,
    validate_rotation_token_budget,
)
from redjohn.assessment.models import AdapterResult, error_record
from redjohn.assessment.policy import PolicyDenied, origin_for


if TYPE_CHECKING:
    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.cache import SmartCache
    from redjohn.assessment.models import JobSpec, Surface
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore

_MAX_CONFIG = 256 * 1024
_MAX_BODY = 64 * 1024
_MAX_RESPONSE = 64 * 1024
_IDENTITY = ("engagement_id", "owner_id", "actor_id", "tenant_id", "policy_revision")
_AUTH_HEADERS = frozenset(
    {"authorization", "x-api-key", "x-auth-token", "cookie", "x-csrf-token", "x-xsrf-token"}
)


class SessionRefreshDenied(ValueError):  # noqa: N818 - stable policy error contract
    """Secret-free host-selected failure code."""


def _deny(code: str) -> NoReturn:
    raise SessionRefreshDenied(code) from None


def _private_json(path: Path) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > _MAX_CONFIG
            ):
                _deny("session_refresh_private_config_required")
            raw = stream.read(_MAX_CONFIG + 1)
        if len(raw) > _MAX_CONFIG:
            _deny("session_refresh_config_too_large")
        data = json.loads(raw)
        if not isinstance(data, dict):
            _deny("session_refresh_invalid_config")
    except SessionRefreshDenied:
        raise
    except (OSError, ValueError, TypeError):
        _deny("session_refresh_config_unavailable")
    return data


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size


def _atomic_private_json(
    path: Path, value: dict[str, Any], expected: tuple[int, int, int, int]
) -> None:
    """Replace a private, single-link regular file without a permissive window."""
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False).encode()
    if len(raw) > _MAX_CONFIG:
        _deny("session_refresh_rotated_vault_too_large")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = ".redjohn-session-" + uuid.uuid4().hex
    try:
        parent_info = os.fstat(parent)
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            parent_info.st_uid != os.getuid()
            or stat.S_IMODE(parent_info.st_mode) & 0o022
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            _deny("session_refresh_private_vault_required")
        if _fingerprint(info) != expected:
            _deny("session_refresh_vault_changed")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if _fingerprint(info) != _fingerprint(current):
            _deny("session_refresh_vault_changed")
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


class SessionRefreshService:
    resource_class = "worker"
    owner_process_only = True

    def __init__(
        self,
        policy: EngagementPolicy,
        store: AssessmentStore,
        vault_file: str | Path,
        providers_file: str | Path,
        *,
        tls_config: BrowserTLSConfig | None = None,
        rate_limits: Any = None,
        cache: SmartCache | None = None,
    ) -> None:
        self.policy, self.store = policy, store
        self.vault_file, self.providers_file = Path(vault_file), Path(providers_file)
        self.tls_config, self.rate_limits = tls_config, rate_limits
        self.cache = cache

    @staticmethod
    def _rotation_entries(
        vault: AuthReplayVault, surface: Surface, provider: dict[str, Any]
    ) -> list[dict[str, Any]]:
        matching = [
            entry
            for entry in vault.to_mapping()["entries"]
            if (
                entry["actor_id"] == surface.actor_id
                and entry["tenant_id"] == surface.tenant_id
                and entry["session_revision"] == surface.session_revision
            )
        ]
        if not matching:
            _deny("session_refresh_vault_identity_mismatch")
        if any(entry["origin"] != origin_for(provider["refresh_url"]) for entry in matching):
            _deny("session_refresh_cross_origin_rotation_unsupported")
        return matching

    def _provider(self, surface: Surface) -> dict[str, Any]:  # noqa: PLR0912 - bounded config schema
        data = _private_json(self.providers_file)
        if (
            set(data) != {"version", "providers"}
            or type(data["version"]) is not int
            or data["version"] != 1
            or not isinstance(data["providers"], list)
            or not 1 <= len(data["providers"]) <= 64
        ):
            _deny("session_refresh_invalid_config")
        identity = {
            "engagement_id": self.policy.engagement_id,
            "owner_id": self.policy.owner_id,
            "actor_id": surface.actor_id,
            "tenant_id": surface.tenant_id,
            "policy_revision": self.policy.revision,
        }
        required = {*_IDENTITY, "refresh_url", "headers", "body_base64", "content_type"}
        matches = []
        for provider in data["providers"]:
            if not isinstance(provider, dict) or set(provider) != required:
                _deny("session_refresh_invalid_provider")
            if any(not isinstance(provider[key], str) for key in _IDENTITY):
                _deny("session_refresh_invalid_provider")
            if all(provider[key] == value for key, value in identity.items()):
                matches.append(provider)
        if len(matches) != 1:
            _deny("session_refresh_identity_or_provider_mismatch")
        provider = matches[0]
        self.policy.check_refresh_request(provider["refresh_url"], "POST")
        if provider["content_type"] not in {
            "application/json",
            "application/x-www-form-urlencoded",
        }:
            _deny("session_refresh_content_type_unsupported")
        headers = provider["headers"]
        if not isinstance(headers, dict) or len(headers) > 6:
            _deny("session_refresh_invalid_headers")
        names = set()
        for name, value in headers.items():
            if (
                not isinstance(name, str)
                or name.lower() not in _AUTH_HEADERS
                or name.lower() in names
                or not isinstance(value, str)
                or not 0 < len(value) <= 8192
                or any(ord(char) < 32 or ord(char) > 126 for char in value)
            ):
                _deny("session_refresh_invalid_headers")
            names.add(name.lower())
        if sum(len(value) for value in headers.values()) > 8192:
            _deny("session_refresh_header_budget_exceeded")
        try:
            encoded = provider["body_base64"]
            if not isinstance(encoded, str) or len(encoded) > 4 * ((_MAX_BODY + 2) // 3):
                _deny("session_refresh_invalid_body")
            body = base64.b64decode(encoded, validate=True)
            if not body or len(body) > _MAX_BODY:
                _deny("session_refresh_invalid_body")
        except (ValueError, TypeError):
            _deny("session_refresh_invalid_body")
        return {**provider, "body": body}

    def _replacement(
        self,
        vault: AuthReplayVault,
        surface: Surface,
        provider: dict[str, Any],
        response: object,
        next_revision: str,
    ) -> dict[str, Any]:
        if (
            not isinstance(response, dict)
            or not {"headers", "cookies", "expires_at"} <= set(response)
            or set(response) - {"headers", "cookies", "expires_at", "body_tokens"}
        ):
            _deny("session_refresh_invalid_response")
        if "body_tokens" in response:
            validate_response_body_tokens(response["body_tokens"])
        expiry = response["expires_at"]
        if (
            isinstance(expiry, bool)
            or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry)
            or not time.time() < expiry <= time.time() + 86400
        ):
            _deny("session_refresh_invalid_response_expiry")
        mapping = vault.to_mapping()
        matches = [
            entry
            for entry in mapping["entries"]
            if (
                entry["actor_id"] == surface.actor_id
                and entry["tenant_id"] == surface.tenant_id
                and entry["session_revision"] == surface.session_revision
            )
        ]
        if not matches:
            _deny("session_refresh_vault_identity_mismatch")
        if any(entry["origin"] != origin_for(provider["refresh_url"]) for entry in matches):
            _deny("session_refresh_cross_origin_rotation_unsupported")
        for entry in matches:
            entry.update(
                {
                    "session_revision": next_revision,
                    "expires_at": expiry,
                    "headers": response["headers"],
                    "cookies": response["cookies"],
                }
            )
        # Revalidate every body, request, policy, actor and credential before any
        # bytes replace the operator's private vault.
        AuthReplayVault.for_rotation_mapping(mapping, self.policy)
        validate_rotation_token_budget(
            [request for entry in matches for request in entry["allowed_requests"]], response
        )
        for entry in matches:
            entry["allowed_requests"] = [
                rotate_body_tokens(request, response) if "body_tokens" in request else request
                for request in entry["allowed_requests"]
            ]
        AuthReplayVault.for_rotation_mapping(mapping, self.policy)
        return mapping

    async def run(  # noqa: PLR0912, PLR0915 - one fenced refresh lifecycle
        self, job: dict[str, Any], surface: Surface, spec: JobSpec
    ) -> AdapterResult:
        import httpx  # noqa: PLC0415 - explicitly configured adapter only

        from redjohn.assessment.browser_proxy import BrowserEgressProxy  # noqa: PLC0415

        if (
            spec.capability != "session_refresh"
            or spec.idempotent
            or spec.options
            or surface.actor_id == "anonymous"
        ):
            return self._result("session_refresh_requires_nonidempotent_named_job", uncertain=False)
        reservation = None
        lock_descriptor = None
        sent = False
        proxy = None
        try:
            provider = self._provider(surface)
            vault = AuthReplayVault.read_for_rotation(self.vault_file, self.policy)
            # Reading is host-only, and the private file is the rotation input;
            # an expired credential is allowed here but cannot authorize replay.
            self._rotation_entries(vault, surface, provider)
            lock_path = self.vault_file.with_name(self.vault_file.name + ".refresh.lock")
            lock_descriptor = os.open(
                lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
            )
            info = os.fstat(lock_descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                _deny("session_refresh_private_lock_required")
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _deny("session_refresh_already_running")
            # Reload after the cross-database private-vault lock is held.
            expected = _fingerprint(self.vault_file.stat(follow_symlinks=False))
            vault = AuthReplayVault.read_for_rotation(self.vault_file, self.policy)
            if _fingerprint(self.vault_file.stat(follow_symlinks=False)) != expected:
                _deny("session_refresh_vault_changed")
            self._rotation_entries(vault, surface, provider)
            if (
                self.rate_limits is not None
                and self.rate_limits.remaining(origin_for(provider["refresh_url"])) > 0
            ):
                _deny("session_refresh_rate_limited")
            # Missing or invalid host configuration performs no I/O and does
            # not poison a previously usable session. A reserved refresh is
            # never automatically retried after any terminal outcome.
            reservation = self.store.begin_session_refresh(self.policy, job, surface)
            timeout = min(spec.timeout_seconds, 30.0)
            if self.policy.deadline:
                timeout = min(timeout, self.policy.deadline - time.time())
            if timeout <= 0:
                _deny("session_refresh_deadline_exceeded")

            def replay(
                url: str, method: str, headers: list[tuple[str, str]], body: bytes
            ) -> tuple[list[tuple[str, str]], bytes]:
                if (
                    self.policy._request_url(url)
                    != self.policy._request_url(provider["refresh_url"])
                    or method != "POST"
                    or body != provider["body"]
                ):
                    _deny("session_refresh_request_mismatch")
                clean = [
                    (name, value)
                    for name, value in headers
                    if (name.lower() not in _AUTH_HEADERS | {"content-type", "content-length"})
                ]
                return clean + list(provider["headers"].items()) + [
                    ("Content-Type", provider["content_type"])
                ], body

            def admit(url: str) -> None:
                nonlocal sent
                if self.policy._request_url(url) != self.policy._request_url(
                    provider["refresh_url"]
                ):
                    _deny("session_refresh_request_mismatch")
                if self.rate_limits is not None and not self.rate_limits.admit(origin_for(url)):
                    _deny("session_refresh_rate_limited")
                self.store.consume_requests(self.policy)
                # Admission precedes numeric connect. Treat all subsequent I/O
                # failures conservatively as possibly delivered.
                sent = True

            def observe(url: str, status: int, headers: dict[str, str]) -> None:
                if self.rate_limits is not None:
                    self.rate_limits.observe(origin_for(url), status, headers)

            proxy = BrowserEgressProxy(
                self.policy,
                timeout_seconds=timeout,
                max_wire_bytes=256 * 1024,
                tls_config=self.tls_config,
                request_admission=admit,
                request_policy=self.policy.check_refresh_request,
                request_replay=replay,
                on_response=observe,
            )
            try:
                await proxy.start()
                async with asyncio.timeout(timeout):
                    async with (
                        httpx.AsyncClient(
                            proxy=proxy.url,
                            verify=proxy.client_tls_context,
                            trust_env=False,
                            follow_redirects=False,
                            timeout=timeout,
                        ) as client,
                        client.stream(
                            "POST",
                            provider["refresh_url"],
                            content=provider["body"],
                            headers={
                                "Content-Type": provider["content_type"],
                                "Accept-Encoding": "identity",
                            },
                        ) as response,
                    ):
                        if proxy.upstream_tls_failures:
                            _deny("session_refresh_upstream_tls_failed")
                        if response.status_code != 200:
                            _deny("session_refresh_http_rejected")
                        if response.headers.get("content-encoding", "identity") != "identity":
                            raise SessionRefreshDenied("session_refresh_encoded_response_denied")
                        if (
                            response.headers.get("content-type", "").split(";", 1)[0].strip()
                            != "application/json"
                        ):
                            _deny("session_refresh_json_response_required")
                        raw = bytearray()
                        async for chunk in response.aiter_raw(chunk_size=4096):
                            if len(raw) + len(chunk) > _MAX_RESPONSE:
                                _deny("session_refresh_response_too_large")
                            raw.extend(chunk)
                try:
                    body = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    _deny("session_refresh_invalid_response")
                replacement = self._replacement(
                    vault, surface, provider, body, reservation["next_revision"]
                )
                _atomic_private_json(self.vault_file, replacement, expected)
                if not self.store.finish_session_refresh(
                    self.policy, job, surface, reservation["refresh_key"]
                ):
                    _deny("session_refresh_commit_uncertain")
                invalidated = 0
                if self.cache is not None:
                    invalidated = self.cache.invalidate(
                        context={
                            "engagement": self.policy.engagement_id,
                            "actor": surface.actor_id,
                            "tenant": surface.tenant_id,
                            "session_revision": surface.session_revision,
                        },
                        reason="session_changed",
                    )
                return AdapterResult(
                    "succeeded",
                    "completed",
                    summary={
                        "requests": proxy.forwarded_requests,
                        "requests_admitted": int(sent),
                        "actor_id": surface.actor_id,
                        "tenant_id": surface.tenant_id,
                        "from_revision": surface.session_revision,
                        "session_revision": reservation["next_revision"],
                        "refresh_key": reservation["refresh_key"],
                        "credentials_rotated": True,
                        "body_credentials_rotated": any(
                            "body_tokens" in request
                            for entry in replacement["entries"]
                            if entry["actor_id"] == surface.actor_id
                            and entry["tenant_id"] == surface.tenant_id
                            and entry["session_revision"] == reservation["next_revision"]
                            for request in entry["allowed_requests"]
                        ),
                        "body_token_requests": sum(
                            "body_tokens" in request
                            for entry in replacement["entries"]
                            if entry["actor_id"] == surface.actor_id
                            and entry["tenant_id"] == surface.tenant_id
                            and entry["session_revision"] == reservation["next_revision"]
                            for request in entry["allowed_requests"]
                        ),
                        "cache_invalidated": invalidated,
                    },
                )
            finally:
                await proxy.close()
        except asyncio.CancelledError:
            if reservation:
                self.store.fail_session_refresh(
                    self.policy,
                    job,
                    surface,
                    reservation["refresh_key"],
                    uncertain=sent,
                    code="session_refresh_cancelled",
                )
            raise
        except (SessionRefreshDenied, AuthReplayDenied, BodyTokenDenied, PolicyDenied) as exc:
            # Exception messages here originate only from host constant codes.
            code = str(exc)
            uncertain = sent and code not in {
                "session_refresh_http_rejected",
                "session_refresh_upstream_tls_failed",
            }
            if reservation:
                self.store.fail_session_refresh(
                    self.policy,
                    job,
                    surface,
                    reservation["refresh_key"],
                    uncertain=uncertain,
                    code=code,
                )
            return self._result(
                code,
                uncertain,
                proxy.forwarded_requests if proxy is not None else 0,
                int(sent),
            )
        except Exception:  # noqa: BLE001 - never persist remote data or exception text
            if reservation:
                self.store.fail_session_refresh(
                    self.policy,
                    job,
                    surface,
                    reservation["refresh_key"],
                    uncertain=sent,
                    code="session_refresh_transport_error",
                )
            return self._result(
                "session_refresh_transport_error",
                sent,
                proxy.forwarded_requests if proxy is not None else 0,
                int(sent),
            )
        finally:
            if lock_descriptor is not None:
                os.close(lock_descriptor)

    @staticmethod
    def _result(
        code: str, uncertain: bool, requests: int = 0, requests_admitted: int = 0
    ) -> AdapterResult:
        return AdapterResult(
            "failed",
            "inconclusive" if uncertain else "blocked",
            {"requests": requests, "requests_admitted": requests_admitted},
            error=error_record(
                code,
                category="auth",
                coverage_effect="inconclusive" if uncertain else "blocked",
                retryable=False,
                terminal=True,
                recovery_action="reconcile" if uncertain else "stop",
            ),
        )

    async def cancel(self) -> None:
        # The scheduler cancels the owned task. Context managers close all live
        # HTTP sockets before run() propagates cancellation.
        return None

    async def cleanup(self) -> None:
        return None
