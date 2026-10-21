"""Strict declarative browser actions: no script, generic click or action template."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from redjohn.assessment.models import stable_key
from redjohn.assessment.policy import EngagementPolicy, origin_for
from redjohn.assessment.workflow_models import bounded_name


_SELECTOR = re.compile(r'(?:#[A-Za-z][A-Za-z0-9_-]{0,63}|\[name="[A-Za-z][A-Za-z0-9_-]{0,63}"\])\Z')


@dataclass(frozen=True)
class ReviewedBrowserAction:
    kind: str
    selector: str = ""
    input_ref: str = ""
    url: str = ""
    nonce_selector: str = ""
    nonce_field: str = ""
    fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in {"navigate", "fill", "submit", "wait"}:
            raise ValueError("unsupported_reviewed_browser_action")
        if self.kind == "navigate":
            if not self.url or any(
                (self.selector, self.input_ref, self.nonce_selector, self.nonce_field, self.fields)
            ):
                raise ValueError("invalid_reviewed_navigation")
        elif not isinstance(self.selector, str) or not _SELECTOR.fullmatch(self.selector):
            raise ValueError("reviewed_unique_id_or_name_selector_required")
        if self.kind == "fill":
            bounded_name(self.input_ref)
        elif self.input_ref:
            raise ValueError("unexpected_reviewed_browser_input")
        if self.kind == "submit":
            if not self.url or not _SELECTOR.fullmatch(self.nonce_selector):
                raise ValueError("reviewed_form_nonce_required")
            bounded_name(self.nonce_field)
            if not isinstance(self.fields, tuple) or not 1 <= len(self.fields) <= 16:
                raise ValueError("reviewed_form_fields_required")
            for name in self.fields:
                bounded_name(name)
            if self.nonce_field not in self.fields or len(set(self.fields)) != len(self.fields):
                raise ValueError("invalid_reviewed_form_fields")
        elif self.kind != "navigate" and any(
            (self.url, self.nonce_selector, self.nonce_field, self.fields)
        ):
            raise ValueError("unexpected_reviewed_browser_action_fields")


@dataclass(frozen=True)
class BrowserAuthPlan:
    name: str
    revision: str
    actor_id: str
    tenant_id: str
    actions: tuple[ReviewedBrowserAction, ...]
    allowed_get_urls: tuple[str, ...]
    identity_url: str
    outcome: str = "authenticated"

    def __post_init__(self) -> None:
        for name in (self.name, self.revision, self.actor_id):
            bounded_name(name)
        bounded_name(self.tenant_id, empty=True)
        if (
            self.actor_id == "anonymous"
            or self.outcome not in {"authenticated", "logged_out"}
            or not isinstance(self.actions, tuple)
            or not 1 <= len(self.actions) <= 8
            or self.actions[0].kind != "navigate"
        ):
            raise ValueError("invalid_browser_auth_plan")
        if (
            not isinstance(self.allowed_get_urls, tuple)
            or not 1 <= len(self.allowed_get_urls) <= 16
            or self.identity_url not in self.allowed_get_urls
        ):
            raise ValueError("invalid_auth_read_boundary")
        if not any(action.kind == "submit" for action in self.actions):
            raise ValueError("auth_plan_requires_explicit_form_submission")
        origins = {origin_for(url) for url in self.allowed_get_urls}
        if len(origins) != 1 or any(
            action.kind == "navigate" and action.url not in self.allowed_get_urls
            for action in self.actions
        ):
            raise ValueError("auth_plan_requires_one_explicit_origin")
        for action in self.actions:
            if action.url and origin_for(action.url) not in origins:
                raise ValueError("auth_action_origin_mismatch")

    @property
    def key(self) -> str:
        return stable_key(asdict(self))

    def authorize(self, policy: EngagementPolicy) -> None:
        policy.check_actor(self.actor_id)
        for url in self.allowed_get_urls:
            policy.check_readonly_request(url, "GET")
        for action in self.actions:
            if action.kind == "submit":
                policy.check_replay_request(action.url, "POST")

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> BrowserAuthPlan:
        if not isinstance(raw, dict) or set(raw) - set(cls.__dataclass_fields__):
            raise ValueError("invalid_auth_plan_fields")
        value = dict(raw)
        value["actions"] = tuple(
            ReviewedBrowserAction(**{**action, "fields": tuple(action.get("fields", ()))})
            for action in value["actions"]
        )
        value["allowed_get_urls"] = tuple(value["allowed_get_urls"])
        return cls(**value)
