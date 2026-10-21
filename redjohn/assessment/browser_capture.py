"""Explicit private approval of bounded POST bytes observed by the host proxy.

The browser supplies traffic, never proof. Only a durable reservation and a
fully framed successful proxy response can publish a body digest/request ref.
Credentials and bodies are written solely to the existing private replay vault.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import fcntl
import hashlib
import json
import math
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault
from redjohn.assessment.media_type import MediaTypeDenied, parse_media_type, replay_media_type
from redjohn.assessment.models import Surface
from redjohn.assessment.policy import PolicyDenied, origin_for
from redjohn.assessment.request_body import ApprovedRequestBody, RequestBodyDenied
from redjohn.assessment.session_refresh import (
    _activate_staged_private_json,
    _discard_staged_private_json,
    _fingerprint,
    _private_json,
    _stage_private_json,
)


if TYPE_CHECKING:
    from redjohn.assessment.persistent_rate_limit import PersistentRateLimitDetector
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


_AUTH_NAMES = frozenset(
    {"authorization", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"}
)
_IDENTITY = ("engagement_id", "owner_id", "actor_id", "tenant_id", "policy_revision")


class BrowserCaptureDenied(ValueError):  # noqa: N818 - constant capability error codes
    """Automatic capture was not explicitly authorized or needs reconciliation."""


def _deny(code: str) -> NoReturn:
    raise BrowserCaptureDenied(code) from None


def _approved_wire_body(request: dict[str, Any]) -> ApprovedRequestBody:
    try:
        return ApprovedRequestBody.from_mapping(request)
    except RequestBodyDenied as exc:
        if "body_contract_version" in request:
            raise
        if str(exc) not in {
            "auth_replay_body_unsupported_content_type",
            "auth_replay_body_invalid_multipart_boundary",
            "auth_replay_body_invalid_multipart_content_type",
        }:
            raise
        request["body_contract_version"] = 2
        return ApprovedRequestBody.from_mapping(request)


def _valid_rule_media(rule: dict[str, Any]) -> bool:
    version = rule.get("body_contract_version", 2)
    if type(version) is not int or version not in {2, 3}:
        return False
    if rule["content_type"] in {
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    }:
        return True
    if version != 3:
        return False
    try:
        parsed = parse_media_type(rule["content_type"])
    except MediaTypeDenied:
        return False
    # Rules select a base MIME, not a target-provided widening of approval.
    return (
        parsed.family in {"json", "xml"}
        and parsed.media_type == rule["content_type"]
        and not parsed.parameters
    )


def _rule_matches_media(rule: dict[str, Any], content_type: str) -> bool:
    try:
        return bool(
            replay_media_type(
                content_type, contract_version=rule.get("body_contract_version", 2)
            ).media_type
            == rule["content_type"]
        )
    except MediaTypeDenied:
        return False


def _has_expired_capture_binding(
    entries: list[dict[str, Any]], rules: tuple[dict[str, Any], ...], start_url: str
) -> bool:
    relevant = tuple(rule for rule in rules if not start_url or rule.get("start_url") == start_url)
    if start_url and not relevant:
        _deny("browser_capture_start_not_reviewed")
    requests = {("POST", rule["url"]) for rule in relevant}
    requests.update(("GET", rule["start_url"]) for rule in relevant if rule.get("start_url"))
    return any(
        entry["expires_at"] <= time.time()
        and any(
            (request["method"], request["url"]) in requests for request in entry["allowed_requests"]
        )
        for entry in entries
    )


@dataclass
class _Context:
    actor_id: str
    tenant_id: str
    revision: str
    rules: tuple[dict[str, Any], ...]
    observed: list[Surface] = field(default_factory=list)
    failures: set[str] = field(default_factory=set)
    requests: int = 0
    statuses: dict[str, int] = field(default_factory=dict)


class BrowserPostCaptureService:
    """Host-owned approval provider, activated for one explicit browser job."""

    def __init__(
        self,
        policy: EngagementPolicy,
        store: AssessmentStore,
        vault_file: str | Path,
        rules_file: str | Path,
        *,
        rate_limits: PersistentRateLimitDetector | None = None,
        max_captures: int = 16,
    ) -> None:
        if type(max_captures) is not int or not 1 <= max_captures <= 64:
            raise ValueError("browser_capture_invalid_limit")
        self.policy, self.store = policy, store
        self.vault_file, self.rules_file = Path(vault_file), Path(rules_file)
        self.rate_limits, self.max_captures = rate_limits, max_captures
        self._active: _Context | None = None
        self._tickets: set[_CaptureTicket] = set()

    def bootstrap_authenticated_context(
        self,
        actor_id: str,
        tenant_id: str,
        revision: str,
        storage_state: dict[str, Any],
        evidence_ref: str,
        *,
        private_state_file: Path,
    ) -> None:
        """Host-only verified login bridge; does not infer POST replay authority."""
        from redjohn.assessment.capture_bootstrap import bootstrap_authenticated_context  # noqa: PLC0415 - optional authentication flow only

        bootstrap_authenticated_context(
            self,
            actor_id,
            tenant_id,
            revision,
            storage_state,
            evidence_ref,
            private_state_file=private_state_file,
        )

    def _rules(self) -> tuple[dict[str, Any], ...]:
        try:
            data = _private_json(self.rules_file)
            if (
                set(data) != {"version", "rules"}
                or type(data["version"]) is not int
                or data["version"] != 1
                or not isinstance(data["rules"], list)
                or not 1 <= len(data["rules"]) <= 64
            ):
                _deny("browser_capture_invalid_rules")
            required = {
                *_IDENTITY,
                "session_revision",
                "url",
                "content_type",
                "expires_at",
                "automatic_approval",
            }
            for rule in data["rules"]:
                if (
                    not isinstance(rule, dict)
                    or not required
                    <= set(rule)
                    <= required | {"start_url", "body_tokens", "body_contract_version"}
                    or any(
                        not isinstance(rule[key], str) or len(rule[key]) > 4096
                        for key in required - {"expires_at", "automatic_approval"}
                    )
                    or rule["automatic_approval"] is not True
                    or rule["actor_id"] == "anonymous"
                    or not _valid_rule_media(rule)
                    or isinstance(rule["expires_at"], bool)
                    or not isinstance(rule["expires_at"], (int, float))
                    or not math.isfinite(rule["expires_at"])
                    or rule["expires_at"] <= 0
                    or not rule["session_revision"]
                ):
                    _deny("browser_capture_invalid_rule")
                if (
                    rule["engagement_id"] != self.policy.engagement_id
                    or rule["owner_id"] != self.policy.owner_id
                    or rule["policy_revision"] != self.policy.revision
                ):
                    _deny("browser_capture_rule_policy_mismatch")
                self.policy.check_actor(rule["actor_id"])
                self.policy.check_replay_request(rule["url"], "POST")
                if "start_url" in rule:
                    if not isinstance(rule["start_url"], str) or len(rule["start_url"]) > 4096:
                        _deny("browser_capture_invalid_start_url")
                    self.policy.check_readonly_request(rule["start_url"], "GET")
                    if origin_for(rule["start_url"]) != origin_for(rule["url"]):
                        _deny("browser_capture_start_origin_mismatch")
            return tuple(data["rules"])
        except (BrowserCaptureDenied, PolicyDenied):
            raise
        except (ValueError, OSError, TypeError, KeyError):
            _deny("browser_capture_private_rules_unavailable")

    def _vault(self) -> dict[str, Any]:
        try:
            data = _private_json(self.vault_file)
            if data == {"version": 2, "entries": []}:
                return data
            return AuthReplayVault.for_rotation_mapping(data, self.policy).to_mapping()
        except (ValueError, OSError, TypeError):
            _deny("browser_capture_private_vault_unavailable")

    def context_metadata(
        self,
        actor_id: str,
        tenant_id: str = "",
        session_revision: str = "current",
        *,
        _allow_blocked: bool = False,
        detect_expiry: bool = False,
        start_url: str = "",
    ) -> dict[str, Any]:
        rules = tuple(
            rule
            for rule in self._rules()
            if rule["actor_id"] == actor_id and rule["tenant_id"] == tenant_id
        )
        if not rules:
            _deny("browser_capture_identity_not_approved")
        self.policy.check_actor(actor_id)
        revision = str(session_revision)
        entries = [
            entry
            for entry in self._vault()["entries"]
            if entry["actor_id"] == actor_id and entry["tenant_id"] == tenant_id
        ]
        if revision == "current":
            probe = Surface(rules[0]["url"], actor_id=actor_id, tenant_id=tenant_id)
            state = self.store.session_state(self.policy, probe)
            revisions = {entry["session_revision"] for entry in entries}
            if state:
                if state["status"] != "ready" and not _allow_blocked:
                    _deny("browser_capture_session_not_ready")
                revision = state["revision"]
                if revision not in revisions and not _allow_blocked:
                    _deny("browser_capture_current_vault_missing")
            elif len(revisions) == 1:
                revision = revisions.pop()
            elif _allow_blocked:
                revision = "current"
            else:
                _deny("browser_capture_current_revision_ambiguous")
        selected = tuple(
            rule
            for rule in rules
            if rule["session_revision"] in {revision, "current"}
            and (_allow_blocked or rule["expires_at"] > time.time())
        )
        if not selected:
            _deny("browser_capture_revision_or_rule_expired")
        probe = Surface(
            selected[0]["url"], actor_id=actor_id, tenant_id=tenant_id, session_revision=revision
        )
        if not _allow_blocked:
            self.store.assert_session_revision(self.policy, probe)
            current = [entry for entry in entries if entry["session_revision"] == revision]
            if detect_expiry and _has_expired_capture_binding(current, selected, start_url):
                _deny("browser_capture_credentials_expired")
            if entries and not any(entry["expires_at"] > time.time() for entry in current):
                _deny("browser_capture_credentials_expired_or_superseded")
        return {
            "actor_id": actor_id,
            "tenant_id": tenant_id,
            "session_revision": revision,
            "start_urls": tuple(
                dict.fromkeys(rule["start_url"] for rule in selected if rule.get("start_url"))
            ),
        }

    def scheduled_contexts(self) -> tuple[dict[str, Any], ...]:
        """Return explicit seeds even if execution must later report a block."""
        contexts: dict[tuple[str, str, str], dict[str, Any]] = {}
        for rule in self._rules():
            if not rule.get("start_url"):
                continue
            metadata = self.context_metadata(
                rule["actor_id"], rule["tenant_id"], rule["session_revision"], _allow_blocked=True
            )
            key = (metadata["actor_id"], metadata["tenant_id"], metadata["session_revision"])
            contexts[key] = metadata
        return tuple(contexts.values())

    def reviewed_rule_metadata(self) -> tuple[dict[str, Any], ...]:
        """Expose reviewed routing metadata without credentials or token bindings."""
        fields = (*_IDENTITY, "session_revision", "url", "content_type", "expires_at")
        return tuple(
            {**{key: rule[key] for key in fields}, "start_url": rule.get("start_url", "")}
            for rule in self._rules()
        )

    def bind_context(self, actor_id: str, tenant_id: str, session_revision: str) -> None:
        if self._active is not None:
            _deny("browser_capture_context_already_bound")
        metadata = self.context_metadata(actor_id, tenant_id, session_revision)
        revision = metadata["session_revision"]
        rules = tuple(
            rule
            for rule in self._rules()
            if rule["actor_id"] == actor_id
            and rule["tenant_id"] == tenant_id
            and rule["session_revision"] in {revision, "current"}
            and rule["expires_at"] > time.time()
        )
        self._active = _Context(actor_id, tenant_id, revision, rules)

    def _entries(self, url: str) -> list[dict[str, Any]]:
        context = self._active
        if context is None:
            _deny("browser_capture_context_required")
        entries = [
            entry
            for entry in self._vault()["entries"]
            if entry["actor_id"] == context.actor_id
            and entry["tenant_id"] == context.tenant_id
            and entry["origin"] == origin_for(url)
        ]
        selected = [entry for entry in entries if entry["session_revision"] == context.revision]
        if entries and not selected:
            _deny("browser_capture_session_superseded")
        return selected

    def _credential_group_key(self, entry: dict[str, Any]) -> str:
        return json.dumps(
            sorted(
                (request["method"], self.policy._request_url(request["url"]))
                for request in entry["allowed_requests"]
            )
        )

    def _request_entries(self, url: str, method: str) -> list[dict[str, Any]]:
        entries = self._entries(url)
        exact = [
            entry
            for entry in entries
            if any(
                self.policy._request_url(request["url"]) == self.policy._request_url(url)
                and request["method"] == method
                for request in entry["allowed_requests"]
            )
        ]
        return exact or entries

    def _credential_snapshot(self, url: str) -> dict[str, tuple[str, ...]]:
        groups: dict[str, list[str]] = {}
        for entry in self._entries(url):
            key = self._credential_group_key(entry)
            value = json.dumps(
                {
                    "headers": entry["headers"],
                    "cookies": entry["cookies"],
                    "expires_at": entry["expires_at"],
                },
                sort_keys=True,
            )
            groups.setdefault(key, []).append(value)
        return {key: tuple(sorted(set(values))) for key, values in groups.items()}

    def headers_for_request(
        self, url: str, method: str, headers: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        context = self._active
        if context is None:
            _deny("browser_capture_context_required")
        self.policy.check_replay_request(url, method)
        if origin_for(url) not in {
            origin_for(rule["url"]) for rule in context.rules if rule["expires_at"] > time.time()
        }:
            _deny("browser_capture_credential_origin_denied")
        self.store.assert_session_revision(
            self.policy,
            Surface(
                url,
                actor_id=context.actor_id,
                tenant_id=context.tenant_id,
                session_revision=context.revision,
            ),
        )
        entries = self._request_entries(url, method)
        if not entries:
            return headers  # Initial operator-provided Chromium storage state.
        if any(entry["expires_at"] <= time.time() for entry in entries):
            _deny("browser_capture_credentials_expired")
        credentials = [(entry["headers"], entry["cookies"]) for entry in entries]
        if any(value != credentials[0] for value in credentials):
            _deny("browser_capture_session_credentials_ambiguous")
        additions = list(entries[0]["headers"].items())
        if entries[0]["cookies"]:
            additions.append(
                (
                    "Cookie",
                    "; ".join(
                        f"{cookie['name']}={cookie['value']}" for cookie in entries[0]["cookies"]
                    ),
                )
            )
        return [
            (name, value)
            for name, value in headers
            if name.lower() not in _AUTH_NAMES | {"cookie", "proxy-authorization"}
        ] + additions

    def before_request(
        self, url: str, method: str, headers: list[tuple[str, str]], body: bytes
    ) -> _CaptureTicket:
        context = self._active
        if context is None or method != "POST":
            _deny("browser_capture_named_context_required")
        if context.requests >= self.max_captures:
            context.failures.add("browser_capture_request_limit")
            _deny("browser_capture_request_limit")
        context.requests += 1
        try:
            return self._before_request(context, url, headers, body)
        except (BrowserCaptureDenied, AuthReplayDenied, PolicyDenied, RequestBodyDenied) as exc:
            context.failures.add(str(exc))
            raise
        except (ValueError, OSError, TypeError):
            context.failures.add("browser_capture_request_rejected")
            _deny("browser_capture_request_rejected")

    def _before_request(
        self, context: _Context, url: str, headers: list[tuple[str, str]], body: bytes
    ) -> _CaptureTicket:
        self.policy.check_replay_request(url, "POST")
        types = [value for name, value in headers if name.lower() == "content-type"]
        if len(types) != 1 or len(body) > 65536:
            _deny("browser_capture_invalid_request_body")
        content_type = types[0]
        rules = [
            rule
            for rule in context.rules
            if self.policy._request_url(rule["url"]) == self.policy._request_url(url)
            and _rule_matches_media(rule, content_type)
            and rule["expires_at"] > time.time()
        ]
        if len(rules) != 1:
            _deny("browser_capture_exact_rule_required")
        rule = rules[0]
        request = {
            "url": self.policy._request_url(url),
            "method": "POST",
            "request_ref": "capture-in-progress",
            "content_type": content_type,
            "body_base64": base64.b64encode(body).decode(),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "replay_safety": "operator-approved",
        }
        if "body_contract_version" in rule:
            request["body_contract_version"] = rule["body_contract_version"]
        if "body_tokens" in rule:
            request["body_tokens"] = copy.deepcopy(rule["body_tokens"])
        approved = _approved_wire_body(request)
        private_headers = {name: value for name, value in headers if name.lower() in _AUTH_NAMES}
        cookies = []
        for name, value in headers:
            if name.lower() == "cookie":
                for piece in value.split(";"):
                    cookie_name, separator, cookie_value = piece.strip().partition("=")
                    if not separator:
                        _deny("browser_capture_cookie_invalid")
                    cookies.append({"name": cookie_name, "value": cookie_value})
        entry = {
            "engagement_id": self.policy.engagement_id,
            "owner_id": self.policy.owner_id,
            "actor_id": context.actor_id,
            "tenant_id": context.tenant_id,
            "session_revision": context.revision,
            "policy_revision": self.policy.revision,
            "expires_at": rule["expires_at"],
            "origin": origin_for(url),
            "allowed_requests": [request],
            "headers": private_headers,
            "cookies": cookies,
        }
        current_entries = self._request_entries(url, "POST")
        if current_entries:
            entry["expires_at"] = min(
                rule["expires_at"], *(value["expires_at"] for value in current_entries)
            )
        snapshot = self._credential_snapshot(url)
        AuthReplayVault.from_mapping({"version": 2, "entries": [entry]}, self.policy)
        pending = self._pending_request(url, approved)
        if pending is not None and "body_tokens" in pending:
            request["body_tokens"] = copy.deepcopy(pending["body_tokens"])
        surface = Surface(
            request["url"],
            method="POST",
            content_type=content_type,
            actor_id=context.actor_id,
            tenant_id=context.tenant_id,
            session_revision=context.revision,
            body_sha256=approved.sha256,
        )
        reservation = self.store.reserve_capture(self.policy, surface, timeout_seconds=15)
        if reservation["completed_surface_id"]:
            context.observed.append(
                self.store.surface(self.policy.engagement_id, reservation["completed_surface_id"])
            )
            _deny("browser_capture_already_observed")
        ticket = _CaptureTicket(self, context, surface, entry, reservation, pending, snapshot)
        self._tickets.add(ticket)
        return ticket

    def _pending_request(self, url: str, approved: ApprovedRequestBody) -> dict[str, Any] | None:
        pending: list[dict[str, Any]] = [
            request
            for entry in self._entries(url)
            for request in entry["allowed_requests"]
            if request["method"] == "POST"
            and self.policy._request_url(request["url"]) == self.policy._request_url(url)
            and request["replay_safety"] == "fresh-capture-required"
        ]
        if not pending:
            return None
        from redjohn.assessment.body_tokens import matches_refreshed_capture  # noqa: PLC0415

        matches = [
            request
            for request in pending
            if matches_refreshed_capture(
                request["content_type"],
                base64.b64decode(request["body_base64"], validate=True),
                approved.content_type,
                approved.data,
                expected_body_contract_version=request.get("body_contract_version", 1),
                actual_body_contract_version=approved.body_contract_version,
            )
        ]
        if len(matches) != 1:
            _deny("browser_capture_refreshed_body_mismatch")
        return copy.deepcopy(matches[0])

    def observations(self) -> tuple[Surface, ...]:
        return tuple(self._active.observed) if self._active else ()

    def response_status(self, request_ref: str) -> int | None:
        return self._active.statuses.get(request_ref) if self._active else None

    def failure_codes(self) -> tuple[str, ...]:
        return tuple(sorted(self._active.failures)) if self._active else ()

    def end_context(self) -> None:
        for ticket in tuple(self._tickets):
            ticket.fail()
        self._active = None


@dataclass(eq=False)
class _CaptureTicket:
    service: BrowserPostCaptureService
    context: _Context
    surface: Surface
    entry: dict[str, Any] = field(repr=False)
    reservation: dict[str, Any]
    pending: dict[str, Any] | None = field(repr=False)
    credential_snapshot: dict[str, tuple[str, ...]] = field(repr=False)
    ended: bool = False

    def admit(self) -> None:
        if self.ended or self.service._active is not self.context:
            _deny("browser_capture_context_lost")
        limits = self.service.rate_limits
        if limits is not None and not limits.admit(
            origin_for(self.surface.url), account=self.context.actor_id
        ):
            _deny("browser_capture_rate_limited")
        if not self.service.store.mark_capture_admitted(
            self.service.policy, self.reservation["key"], self.reservation["owner"]
        ):
            _deny("browser_capture_admission_fenced")

    def complete(self, status: int, headers: dict[str, str]) -> None:  # noqa: PLR0912, PLR0915
        if self.ended:
            return
        if self.service.rate_limits is not None:
            self.service.rate_limits.observe(
                origin_for(self.surface.url), status, headers, account=self.context.actor_id
            )
        if status == 401:
            # The transport completed, but this request is never replay approval.
            # Retain the old mutating reservation; only a new reviewed session
            # generation can capture again after bounded authentication recovery.
            self.service.store.fail_capture(
                self.service.policy,
                self.reservation["key"],
                self.reservation["owner"],
                "browser_capture_unauthorized",
            )
            self.context.failures.add("browser_capture_http_401")
            self.ended = True
            self.service._tickets.discard(self)
            return
        if not 200 <= status < 300:
            self.context.failures.add("browser_capture_response_unverified")
            self.fail()
            return
        descriptor = None
        try:
            service, surface = self.service, self.surface
            lock_path = service.vault_file.with_name(service.vault_file.name + ".refresh.lock")
            descriptor = os.open(
                lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                _deny("browser_capture_private_lock_required")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            expected = _fingerprint(service.vault_file.stat(follow_symlinks=False))
            vault = service._vault()
            if _fingerprint(service.vault_file.stat(follow_symlinks=False)) != expected:
                _deny("browser_capture_vault_changed")
            service.store.assert_session_revision(service.policy, surface)
            current_snapshot = service._credential_snapshot(surface.url)
            if any(
                current_snapshot.get(key) != value
                for key, value in self.credential_snapshot.items()
            ):
                _deny("browser_capture_session_credentials_changed")
            for current in service._entries(surface.url):
                if service._credential_group_key(current) not in self.credential_snapshot and (
                    current["headers"] != self.entry["headers"]
                    or current["cookies"] != self.entry["cookies"]
                ):
                    _deny("browser_capture_session_credentials_changed")
            metadata = {
                "url": surface.url,
                "method": "POST",
                "actor_id": surface.actor_id,
                "tenant_id": surface.tenant_id,
                "session_revision": surface.session_revision,
                "engagement_id": service.policy.engagement_id,
                "policy_revision": service.policy.revision,
                "content_type": surface.content_type,
                "request_content_type": surface.content_type,
                "body_sha256": surface.body_sha256,
                "body_bytes": len(
                    base64.b64decode(self.entry["allowed_requests"][0]["body_base64"])
                ),
                "sent": True,
                "status": status,
                "response_complete": True,
            }
            reference = service.store.evidence_put(
                service.policy.engagement_id, metadata, kind="authenticated_request_metadata"
            )
            observed = Surface(**{**self.surface.__dict__, "request_ref": reference})
            request = self.entry["allowed_requests"][0]
            request["request_ref"] = reference
            replaced = False
            if self.pending is not None:
                for entry in vault["entries"]:
                    if (
                        entry["actor_id"] == surface.actor_id
                        and entry["tenant_id"] == surface.tenant_id
                        and entry["session_revision"] == surface.session_revision
                    ):
                        for index, old in enumerate(entry["allowed_requests"]):
                            if old == self.pending:
                                entry["allowed_requests"][index] = request
                                replaced = True
                if not replaced:
                    _deny("browser_capture_pending_vault_changed")
            else:
                vault["entries"].append(self.entry)
            vault["version"] = 2
            AuthReplayVault.for_rotation_mapping(vault, service.policy)
            _stage_private_json(service.vault_file, vault, expected)
            if not service.store.finish_capture(
                service.policy, self.reservation["key"], self.reservation["owner"], observed
            ):
                _deny("browser_capture_commit_uncertain")
            _activate_staged_private_json(service.vault_file)
            self.context.observed.append(observed)
            self.context.statuses[reference] = status
            self.ended = True
            service._tickets.discard(self)
        except Exception:  # noqa: BLE001 - preserve constant codes, never private transport data
            self.context.failures.add("browser_capture_commit_uncertain")
            self.fail()
        finally:
            with contextlib.suppress(OSError):
                _discard_staged_private_json(service.vault_file)
            if descriptor is not None:
                os.close(descriptor)

    def fail(self) -> None:
        if self.ended:
            return
        with contextlib.suppress(Exception):
            self.service.store.fail_capture(
                self.service.policy,
                self.reservation["key"],
                self.reservation["owner"],
                "browser_capture_request_failed",
            )
        self.context.failures.add("browser_capture_request_inconclusive")
        self.ended = True
        self.service._tickets.discard(self)
