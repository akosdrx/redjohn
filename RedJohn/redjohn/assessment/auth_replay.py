"""Host-only, exact-request credential and approved POST-body replay.

Jobs persist opaque actor/revision/request references. Credentials remain in an
operator-supplied private file and in this host process; they never become
scanner arguments, template files, scheduler payloads or ordinary evidence.
POST additionally requires a versioned private body contract, an exact captured body
hash, explicit operator approval, and the engagement's POST URL allowlist.
"""

from __future__ import annotations

import copy
import html
import json
import math
import os
import re
import stat
import time
from base64 import b64encode
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, NoReturn
from urllib.parse import quote, urlsplit

from redjohn.assessment.body_tokens import (
    BodyTokenBinding,
    BodyTokenDenied,
    validate_body_token_bindings,
)
from redjohn.assessment.media_type import replay_media_type, same_replay_media_type
from redjohn.assessment.policy import origin_for
from redjohn.assessment.request_body import (
    HOST_REPLAY_BODY_MARKER,
    HOST_REPLAY_MULTIPART_CONTENT_TYPE,
    ApprovedRequestBody,
    RequestBodyDenied,
)


if TYPE_CHECKING:
    from pathlib import Path

    from redjohn.assessment.models import Surface
    from redjohn.assessment.policy import EngagementPolicy


_REFERENCE = re.compile(r"[A-Za-z0-9_.:-]{1,256}\Z")
_COOKIE_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
_AUTH_HEADERS = frozenset(
    {"authorization", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"}
)
_MAX_FILE = 256 * 1024


class AuthReplayDenied(ValueError):  # noqa: N818 - public policy error contract
    """A secret-free denial; callers may safely persist the code."""


def _deny(code: str) -> NoReturn:
    raise AuthReplayDenied(code)


def _text(value: object, *, limit: int = 8192) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or any(ord(char) < 32 or ord(char) > 126 for char in value)
    ):
        _deny("auth_replay_invalid_secret_schema")
    return value


def _wire_request_url(url: str) -> str:
    """Normalize authority spelling only; retain exact encoded path and query.

    CONNECT uses an explicit port, including 443. An approved URL commonly
    omits that default port. These spellings identify the same HTTP request;
    decoding percent escapes or reordering a query would identify another one.
    """
    parsed = urlsplit(url)
    if parsed.fragment:
        _deny("auth_replay_request_mismatch")
    return origin_for(url) + (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")


@dataclass(frozen=True, repr=False)
class AuthReplayBinding:
    """A private capability for one observed HTTP request, never a job object."""

    engagement_id: str
    owner_id: str
    actor_id: str
    tenant_id: str
    session_revision: str
    policy_revision: str
    request_ref: str
    url: str
    method: str
    expires_at: float
    _headers: tuple[tuple[str, str], ...] = field(repr=False)
    _secret_values: tuple[str, ...] = field(repr=False)
    _body: ApprovedRequestBody | None = field(default=None, repr=False)
    _body_tokens: tuple[BodyTokenBinding, ...] = field(default=(), repr=False)
    _redaction_pattern: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        variants = set()
        for secret in self._secret_values:
            variants.update(
                {
                    secret,
                    quote(secret, safe=""),
                    b64encode(secret.encode()).decode(),
                    json.dumps(secret, ensure_ascii=True)[1:-1],
                    html.escape(secret),
                }
            )
        if variants:
            object.__setattr__(
                self,
                "_redaction_pattern",
                re.compile(
                    "|".join(
                        re.escape(secret)
                        for secret in sorted(variants, key=len, reverse=True)
                        if secret
                    )
                ),
            )

    @property
    def content_type(self) -> str:
        return self._body.content_type if self._body else ""

    @property
    def body_sha256(self) -> str:
        return self._body.sha256 if self._body else ""

    def metadata(self) -> dict[str, str | float]:
        metadata: dict[str, str | float] = {
            "engagement_id": self.engagement_id,
            "actor_id": self.actor_id,
            "tenant_id": self.tenant_id,
            "session_revision": self.session_revision,
            "policy_revision": self.policy_revision,
            "request_ref": self.request_ref,
            "expires_at": self.expires_at,
        }
        if self._body:
            metadata.update(content_type=self.content_type, body_sha256=self.body_sha256)
        return metadata

    def validate(self, url: str, method: str, policy: EngagementPolicy | None = None) -> None:
        if time.time() >= self.expires_at:
            _deny("auth_replay_expired")
        if method != self.method or _wire_request_url(url) != _wire_request_url(self.url):
            _deny("auth_replay_request_mismatch")
        if policy is not None:
            if (
                policy.engagement_id != self.engagement_id
                or policy.owner_id != self.owner_id
                or policy.revision != self.policy_revision
            ):
                _deny("auth_replay_policy_mismatch")
            policy.check_actor(self.actor_id)
            if method == "POST":
                policy.check_replay_request(url, method)
            else:
                policy.check_readonly_request(url, method)

    def validate_capture(self, content_type: str, body_sha256: str) -> None:
        """Tie private bytes to the observed, secret-free capture metadata."""
        if content_type != self.content_type or body_sha256 != self.body_sha256:
            _deny("auth_replay_capture_body_mismatch")

    def body_for_mutation(self) -> tuple[ApprovedRequestBody, tuple[BodyTokenBinding, ...]]:
        """Host-only approved bytes and protected token selectors, never job data."""
        self.validate(self.url, self.method)
        if self.method != "POST" or self._body is None:
            _deny("auth_replay_approved_post_body_required")
        return self._body, self._body_tokens

    def validate_template_request(
        self,
        url: str,
        method: str,
        body: str | None,
        content_type: str | None,
        policy: EngagementPolicy,
    ) -> None:
        self.validate(url, method, policy)
        if method == "POST":
            if (
                not self._body
                or body != HOST_REPLAY_BODY_MARKER
                or not self._template_content_type(content_type)
            ):
                _deny("auth_replay_worker_body_mismatch")
        elif body not in {None, ""} or content_type not in {None, ""}:
            _deny("auth_replay_worker_body_mismatch")

    def _template_content_type(self, content_type: str | None) -> bool:
        if self._body is not None and self._body.body_contract_version >= 2 and content_type:
            version = self._body.body_contract_version
            if (
                replay_media_type(self.content_type, contract_version=version).media_type
                == "multipart/form-data"
                and content_type == HOST_REPLAY_MULTIPART_CONTENT_TYPE
            ):
                return True
            return same_replay_media_type(content_type, self.content_type, contract_version=version)
        return content_type == self.content_type or (
            self._body is not None
            and self.content_type.startswith("multipart/form-data; boundary=")
            and content_type == HOST_REPLAY_MULTIPART_CONTENT_TYPE
        )

    def headers_for(self, url: str, method: str) -> tuple[tuple[str, str], ...]:
        self.validate(url, method)
        return self._headers

    def rewrite_headers(
        self, url: str, method: str, headers: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        """Proxy hook: replace all client credentials only for the bound request."""
        additions = self.headers_for(url, method)
        return [
            (name, value)
            for name, value in headers
            if name.lower() not in _AUTH_HEADERS | {"cookie", "proxy-authorization"}
        ] + list(additions)

    def rewrite_request(
        self, url: str, method: str, headers: list[tuple[str, str]], body: bytes
    ) -> tuple[list[tuple[str, str]], bytes]:
        """Host proxy hook: inject private POST bytes after exact worker checks."""
        if method != "POST":
            if body:
                _deny("auth_replay_worker_body_mismatch")
            return self.rewrite_headers(url, method, headers), body
        self.validate(url, method)
        content_types = [value for name, value in headers if name.lower() == "content-type"]
        if (
            self._body is None
            or body != HOST_REPLAY_BODY_MARKER.encode("ascii")
            or len(content_types) != 1
            or not self._template_content_type(content_types[0])
        ):
            _deny("auth_replay_worker_body_mismatch")
        rewritten = self.rewrite_headers(url, method, headers)
        rewritten = [
            (name, value)
            for name, value in rewritten
            if name.lower() not in {"content-type", "content-length", "transfer-encoding"}
        ]
        rewritten += [
            ("Content-Type", self.content_type),
            ("Content-Length", str(len(self._body.data))),
        ]
        return rewritten, self._body.data

    def redact_raw(self, value: Any) -> Any:
        """Remove known credential values if a target reflects them in output."""
        if isinstance(value, dict):
            return {self.redact_raw(key): self.redact_raw(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.redact_raw(item) for item in value]
        if isinstance(value, str):
            return (
                self._redaction_pattern.sub("[redacted]", value)
                if self._redaction_pattern
                else value
            )
        return value

    def redact_worker_output(self, value: dict[str, Any]) -> dict[str, Any]:
        """Mask private values without renaming trusted transport field names.

        Interpret the original bounded worker output before calling this for
        persistence. Redaction is deliberately lossy and cannot serve as scan
        evidence normalization: a secret coinciding with ``stdout`` must never
        remove the candidate stream or manufacture a completed negative check.
        Public schema names may coincide with private values without being a
        disclosure of content originating from those values.
        """

        def json_values(item: Any) -> Any:
            if isinstance(item, dict):
                # Engine JSON field names and typed counts/flags are public
                # protocol. Reflected response/extractor content is text.
                return {key: json_values(child) for key, child in item.items()}
            if isinstance(item, (list, tuple)):
                return [json_values(child) for child in item]
            return self.redact_raw(item) if isinstance(item, str) else item

        def stream_text(item: str) -> str:
            lines = []
            for line in item.splitlines(keepends=True):
                try:
                    parsed = json.loads(line)
                    if not isinstance(parsed, dict):
                        raise TypeError  # noqa: TRY301 - unsupported protocol line
                    masked = json.dumps(json_values(parsed), ensure_ascii=True, allow_nan=False)
                    lines.append(masked + ("\n" if line.endswith(("\r", "\n")) else ""))
                except (ValueError, TypeError, RecursionError):
                    lines.append(self.redact_raw(line))
            return "".join(lines)

        return {
            key: stream_text(item)
            if key in {"stdout", "stderr"} and isinstance(item, str)
            else json_values(item)
            for key, item in value.items()
        }


class AuthReplayVault:
    """Bounded host-side credentials, loaded only on explicit configuration."""

    def __init__(
        self,
        entries: tuple[dict[str, Any], ...],
        policy: EngagementPolicy,
        source_mapping: dict[str, Any] | None = None,
    ) -> None:
        self._entries = entries
        self.policy = policy
        self._source_mapping = copy.deepcopy(source_mapping)

    def to_mapping(self) -> dict[str, Any]:
        """Private copy for a trusted host rotation provider, never job data."""
        if self._source_mapping is None:
            _deny("auth_replay_rotation_source_unavailable")
        return copy.deepcopy(self._source_mapping)

    @classmethod
    def from_file(cls, path: str | Path, policy: EngagementPolicy) -> AuthReplayVault:
        return cls.from_mapping(cls._read_private_file(path), policy)

    @classmethod
    def read_for_rotation(cls, path: str | Path, policy: EngagementPolicy) -> AuthReplayVault:
        """Validate a private vault for rotation; expired bindings remain unusable."""
        return cls._from_mapping(cls._read_private_file(path), policy, allow_expired=True)

    @classmethod
    def for_rotation_mapping(cls, data: object, policy: EngagementPolicy) -> AuthReplayVault:
        """Validate replacement structure while retaining unrelated expired actors."""
        return cls._from_mapping(data, policy, allow_expired=True)

    @classmethod
    def from_file_for_surface(
        cls, path: str | Path, policy: EngagementPolicy, surface: Surface
    ) -> AuthReplayVault:
        """Load all private structure, requiring only the selected binding to live."""
        vault = cls.read_for_rotation(path, policy)
        vault.authorize(surface)
        return vault

    @staticmethod
    def _read_private_file(path: str | Path) -> object:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                    or info.st_size > _MAX_FILE
                ):
                    _deny("auth_replay_secret_file_not_private")
                raw = stream.read(_MAX_FILE + 1)
            if len(raw) > _MAX_FILE:
                _deny("auth_replay_secret_file_too_large")
            data = json.loads(raw)
        except AuthReplayDenied:
            raise
        except (OSError, ValueError, TypeError):
            _deny("auth_replay_secret_file_unavailable")
        return data

    @classmethod
    def from_mapping(cls, data: object, policy: EngagementPolicy) -> AuthReplayVault:
        """For existing host-owned providers; never accept this from job options."""
        return cls._from_mapping(data, policy, allow_expired=False)

    @classmethod
    def _from_mapping(
        cls, data: object, policy: EngagementPolicy, *, allow_expired: bool
    ) -> AuthReplayVault:
        if (
            not isinstance(data, dict)
            or set(data) != {"version", "entries"}
            or type(data.get("version")) is not int
            or data.get("version") not in {1, 2}
            or not isinstance(data.get("entries"), list)
            or not 1 <= len(data["entries"]) <= 64
        ):
            _deny("auth_replay_invalid_vault_schema")
        try:
            # Copy the host provider input so later mutations cannot expand an
            # already reviewed request/identity binding.
            raw = json.dumps(data, allow_nan=False)
            if len(raw.encode()) > _MAX_FILE:
                _deny("auth_replay_secret_file_too_large")
            copied = json.loads(raw)
            source_mapping = copy.deepcopy(copied)
            entries = tuple(
                cls._entry(value, policy, copied["version"], allow_expired=allow_expired)
                for value in copied["entries"]
            )
        except AuthReplayDenied:
            raise
        except (TypeError, ValueError, KeyError):
            _deny("auth_replay_invalid_vault_schema")
        return cls(entries, policy, source_mapping)

    @staticmethod
    def _entry(  # noqa: PLR0912, PLR0915 - explicit bounded vault schema checks
        value: object, policy: EngagementPolicy, version: int, *, allow_expired: bool
    ) -> dict[str, Any]:
        required = {
            "engagement_id",
            "owner_id",
            "actor_id",
            "tenant_id",
            "session_revision",
            "policy_revision",
            "expires_at",
            "origin",
            "allowed_requests",
            "headers",
            "cookies",
        }
        if not isinstance(value, dict) or set(value) != required:
            _deny("auth_replay_invalid_entry_schema")
        entry = dict(value)
        for key in required - {"expires_at", "allowed_requests", "headers", "cookies", "tenant_id"}:
            _text(entry[key], limit=256 if key != "origin" else 1024)
        if not isinstance(entry["tenant_id"], str) or len(entry["tenant_id"]) > 128:
            _deny("auth_replay_invalid_entry_schema")
        if entry["actor_id"] == "anonymous":
            _deny("auth_replay_anonymous_credentials_denied")
        if (
            entry["engagement_id"] != policy.engagement_id
            or entry["owner_id"] != policy.owner_id
            or entry["policy_revision"] != policy.revision
        ):
            _deny("auth_replay_policy_mismatch")
        policy.check_actor(entry["actor_id"])
        expiry = entry["expires_at"]
        if (
            isinstance(expiry, bool)
            or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry)
        ):
            _deny("auth_replay_invalid_expiry")
        if not allow_expired and expiry <= time.time():
            _deny("auth_replay_expired")
        getattr(policy, "check_scope_url", policy.check_url)(entry["origin"])
        if urlsplit(entry["origin"]).scheme != "https":
            _deny("auth_replay_https_required")
        if origin_for(entry["origin"]) != entry["origin"] or urlsplit(entry["origin"]).path:
            _deny("auth_replay_origin_must_be_canonical")
        requests = entry["allowed_requests"]
        if not isinstance(requests, list) or not 1 <= len(requests) <= 128:
            _deny("auth_replay_invalid_requests")
        for request in requests:
            post = isinstance(request, dict) and request.get("method") == "POST"
            request_fields = {"url", "method", "request_ref"}
            if post:
                request_fields |= {"content_type", "body_base64", "body_sha256", "replay_safety"}
                if "body_tokens" in request:
                    request_fields.add("body_tokens")
                if "body_contract_version" in request:
                    request_fields.add("body_contract_version")
            if (
                not isinstance(request, dict)
                or set(request) != request_fields
                or request["method"]
                not in ({"GET", "HEAD", "POST"} if version == 2 else {"GET", "HEAD"})
                or not isinstance(request["request_ref"], str)
                or not _REFERENCE.fullmatch(request["request_ref"])
                or origin_for(request["url"]) != entry["origin"]
                or urlsplit(request["url"]).fragment
            ):
                _deny("auth_replay_invalid_requests")
            if post:
                if request["replay_safety"] not in {"operator-approved", "fresh-capture-required"}:
                    _deny("auth_replay_operator_approval_required")
                if request["replay_safety"] == "fresh-capture-required" and (
                    "body_tokens" not in request
                    or request["request_ref"] != "pending-capture:" + request["body_sha256"]
                ):
                    _deny("auth_replay_invalid_pending_capture")
                policy.check_replay_request(request["url"], request["method"])
                try:
                    request["_body"] = ApprovedRequestBody.from_mapping(request)
                    if "body_tokens" in request:
                        validate_body_token_bindings(request["_body"], request["body_tokens"])
                except (RequestBodyDenied, BodyTokenDenied) as exc:
                    _deny(str(exc))
            else:
                policy.check_readonly_request(request["url"], request["method"])
        headers = entry["headers"]
        if not isinstance(headers, dict) or len(headers) > len(_AUTH_HEADERS):
            _deny("auth_replay_invalid_headers")
        normalized = set()
        for name, secret in headers.items():
            if (
                not isinstance(name, str)
                or name.lower() not in _AUTH_HEADERS
                or name.lower() in normalized
            ):
                _deny("auth_replay_invalid_headers")
            normalized.add(name.lower())
            _text(secret)
        cookies = entry["cookies"]
        if not isinstance(cookies, list) or len(cookies) > 32:
            _deny("auth_replay_invalid_cookies")
        names = set()
        for cookie in cookies:
            if (
                not isinstance(cookie, dict)
                or set(cookie) != {"name", "value"}
                or not isinstance(cookie["name"], str)
                or not _COOKIE_NAME.fullmatch(cookie["name"])
                or cookie["name"] in names
            ):
                _deny("auth_replay_invalid_cookies")
            names.add(cookie["name"])
            secret = _text(cookie["value"], limit=4096)
            if any(char in secret for char in ';,"\\'):
                _deny("auth_replay_invalid_cookies")
        if not headers and not cookies:
            _deny("auth_replay_credentials_missing")
        if (
            sum(len(value) for value in headers.values())
            + sum(len(cookie["value"]) for cookie in cookies)
            > 8192
        ):
            _deny("auth_replay_header_budget_exceeded")
        return entry

    def authorize(self, surface: Surface, request_ref: str | None = None) -> AuthReplayBinding:
        if surface.actor_id == "anonymous" or surface.source != "observed":
            _deny("auth_replay_observed_named_actor_required")
        ref = request_ref if request_ref is not None else surface.request_ref
        if not ref or not _REFERENCE.fullmatch(ref):
            _deny("auth_replay_captured_request_ref_required")
        matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for entry in self._entries:
            if (
                entry["actor_id"] == surface.actor_id
                and entry["tenant_id"] == surface.tenant_id
                and entry["session_revision"] == surface.session_revision
            ):
                matches.extend(
                    (entry, request)
                    for request in entry["allowed_requests"]
                    if request["url"] == surface.url
                    and request["method"] == surface.method
                    and request["request_ref"] == ref
                )
        if len(matches) != 1:
            _deny("auth_replay_identity_or_request_mismatch")
        entry, request = matches[0]
        if request.get("replay_safety") == "fresh-capture-required":
            _deny("auth_replay_fresh_capture_required")
        headers = tuple(entry["headers"].items())
        if entry["cookies"]:
            headers += (
                ("Cookie", "; ".join(f"{c['name']}={c['value']}" for c in entry["cookies"])),
            )
        secrets = tuple(entry["headers"].values()) + tuple(
            cookie["value"] for cookie in entry["cookies"]
        )
        secrets += tuple(
            value.split(" ", 1)[1]
            for name, value in entry["headers"].items()
            if name.lower() == "authorization" and " " in value
        )
        body = request.get("_body")
        if body:
            secrets += body.redaction_values
        binding = AuthReplayBinding(
            **{
                key: entry[key]
                for key in (
                    "engagement_id",
                    "owner_id",
                    "actor_id",
                    "tenant_id",
                    "session_revision",
                    "policy_revision",
                    "expires_at",
                )
            },
            request_ref=ref,
            url=surface.url,
            method=surface.method,
            _headers=headers,
            _secret_values=secrets,
            _body=body,
            _body_tokens=validate_body_token_bindings(body, request["body_tokens"])
            if body and "body_tokens" in request
            else (),
        )
        binding.validate(surface.url, surface.method, self.policy)
        if body:
            binding.validate_capture(surface.content_type, surface.body_sha256)
        return binding
