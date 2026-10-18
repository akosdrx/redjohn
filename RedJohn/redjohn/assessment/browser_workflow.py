"""Reconcile explicitly configured capture starts into the durable job queue."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.input_replay import BODY_CAPABILITIES, MEDIA_LOCATIONS
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.session_recovery import (
    SessionRecoveryOptions,
    reviewed_refresh_seed,
    validate_recovery_event,
)
from redjohn.assessment.store import CapacityExceeded


if TYPE_CHECKING:
    from pathlib import Path

    from redjohn.assessment.browser_capture import BrowserPostCaptureService
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.registry import ExecutionVersions
    from redjohn.assessment.store import AssessmentStore


def enqueue_browser_capture_contexts(
    service: BrowserPostCaptureService,
    store: AssessmentStore,
    policy: EngagementPolicy,
) -> tuple[str, ...]:
    """Queue each private-rule start once per current identity/session revision.

    Reconciliation runs on coordinator startup. Its deterministic job identity
    also closes the crash gap between successful refresh and follow-up enqueue;
    it never changes an old job or retries an uncertain POST.
    """
    return tuple(store.submit(policy, _capture_specs(service.scheduled_contexts(), store, policy)))


def _capture_specs(
    contexts: tuple[dict[str, Any], ...],
    store: AssessmentStore,
    policy: EngagementPolicy,
) -> list[JobSpec]:
    specs: list[JobSpec] = []
    if len(contexts) > 64:
        raise ValueError("browser_capture_context_limit")
    for context in contexts:
        actor, tenant, revision = (
            context["actor_id"],
            context["tenant_id"],
            context["session_revision"],
        )
        urls = context["start_urls"]
        if (
            not all(isinstance(item, str) for item in (actor, tenant, revision))
            or not isinstance(urls, (list, tuple))
            or len(urls) > 8
        ):
            raise ValueError("invalid_browser_capture_context")
        for url in urls:
            if not isinstance(url, str):
                raise TypeError("invalid_browser_capture_start")
            policy.check_readonly_request(url, "GET")
            surface_id = store.upsert_surface(
                policy.engagement_id,
                Surface(
                    url,
                    actor_id=actor,
                    tenant_id=tenant,
                    session_revision=revision,
                    source="imported",
                    workflow_state="approved_seed",
                ),
            )
            specs.append(
                JobSpec(
                    surface_id,
                    "discovery",
                    "browser_post_capture",
                    policy_revision=policy.revision,
                    idempotent=False,
                    priority=5,
                )
            )
    return specs


@dataclass(frozen=True)
class _ReplayRule:
    actor_id: str
    tenant_id: str
    url: str
    content_type: str
    template_id: str

    def matches(self, surface: Surface) -> bool:
        return (
            surface.actor_id == self.actor_id
            and surface.tenant_id == self.tenant_id
            and surface.url == self.url
            and surface.content_type.split(";", 1)[0].strip().lower() == self.content_type
        )


@dataclass(frozen=True)
class _AdapterRule:
    actor_id: str
    tenant_id: str
    url: str
    content_type: str
    capability: str
    input_location: str
    input_name: str

    def matches(self, surface: Surface) -> bool:
        return (
            all(getattr(surface, k) == getattr(self, k) for k in ("actor_id", "tenant_id", "url"))
            and surface.content_type.partition(";")[0].strip().lower() == self.content_type
        )


class ContinuousBrowserWorkflow:
    """Publish reviewed children from durable successful-completion events.

    The scheduler invokes reconciliation while holding its coordinator lock.
    A committed refresh never depends on a callback succeeding: its outbox
    event remains pending until child submission and acknowledgement commit in
    one transaction. Only explicitly configured replay selections are admitted.
    """

    def __init__(
        self,
        service: BrowserPostCaptureService,
        store: AssessmentStore,
        policy: EngagementPolicy,
        configuration: dict[str, Any],
        nuclei_lock: dict[str, Any] | None,
        auth_vault_file: str | Path,
        *,
        refresh_provider_file: str | Path | None = None,
        adapter_versions: dict[str, ExecutionVersions] | None = None,
    ) -> None:
        from redjohn.tools.hunt.nuclei import NucleiLock  # noqa: PLC0415 - explicit opt-in

        self.service, self.store, self.policy = service, store, policy
        self.lock = NucleiLock.from_mapping(nuclei_lock) if nuclei_lock is not None else None
        self.auth_vault_file = auth_vault_file
        self.adapter_versions = adapter_versions or {}
        self.rules = self._rules(configuration)
        self.adapter_rules = self._adapter_rules(configuration.get("adapter_rules", []))
        self.session_recovery = (
            SessionRecoveryOptions.from_mapping(configuration["session_recovery"])
            if "session_recovery" in configuration
            else None
        )
        if self.session_recovery is not None and refresh_provider_file is None:
            raise ValueError("session_recovery_provider_configuration_missing")
        self.capture_job_ids: tuple[str, ...] = ()
        self.replay_job_ids: tuple[str, ...] = ()
        self.refresh_job_ids: tuple[str, ...] = ()
        self._cursor = ""

    def _rules(self, value: dict[str, Any]) -> tuple[_ReplayRule, ...]:
        if (
            not isinstance(value, dict)
            or not {"version", "rules"}
            <= set(value)
            <= {"version", "rules", "session_recovery", "adapter_rules"}
            or type(value["version"]) is not int
            or value["version"] != 1
            or not isinstance(value["rules"], list)
            or not 0 <= len(value["rules"]) <= 64
            or (not value["rules"] and not value.get("adapter_rules"))
        ):
            raise ValueError("continuous_replay_invalid_configuration")
        reviewed = self.service.reviewed_rule_metadata()
        selections = {item.template_id: item for item in self.lock.templates} if self.lock else {}
        rules: list[_ReplayRule] = []
        for raw in value["rules"]:
            if (
                not isinstance(raw, dict)
                or set(raw) != {"actor_id", "tenant_id", "url", "content_type", "template_id"}
                or any(not isinstance(item, str) or len(item) > 4096 for item in raw.values())
            ):
                raise ValueError("continuous_replay_invalid_rule")
            rule = _ReplayRule(**raw)
            self.policy.check_actor(rule.actor_id)
            self.policy.check_replay_request(rule.url, "POST")
            if rule.actor_id == "anonymous" or rule.content_type not in {
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
            }:
                raise ValueError("continuous_replay_named_actor_and_post_required")
            selection = selections.get(rule.template_id)
            if (
                selection is None
                or selection.effect != "authenticated-replay"
                or self.policy.profile not in selection.profiles
                or sum(
                    item.template_id.upper() == rule.template_id.upper()
                    for item in (self.lock.templates if self.lock else ())
                )
                != 1
            ):
                raise ValueError("continuous_replay_template_not_reviewed")
            if not any(
                all(
                    candidate[key] == getattr(rule, key)
                    for key in ("actor_id", "tenant_id", "url", "content_type")
                )
                and candidate["start_url"]
                for candidate in reviewed
            ):
                raise ValueError("continuous_replay_capture_rule_missing")
            if rule in rules:
                raise ValueError("continuous_replay_duplicate_rule")
            rules.append(rule)
        return tuple(rules)

    def _adapter_rules(self, value: object) -> tuple[_AdapterRule, ...]:
        if not isinstance(value, list) or len(value) + len(self.rules) > 64:
            raise ValueError("continuous_adapter_invalid_rules")
        rules: list[_AdapterRule] = []
        for raw in value:
            if (
                not isinstance(raw, dict)
                or set(raw) != set(_AdapterRule.__dataclass_fields__)
                or any(not isinstance(v, str) or len(v.encode()) > 4096 for v in raw.values())
            ):
                raise ValueError("continuous_adapter_invalid_rule")
            rule = _AdapterRule(**raw)
            self.policy.check_actor(rule.actor_id)
            self.policy.check_replay_request(rule.url, "POST")
            if (
                rule.actor_id == "anonymous"
                or rule.capability not in BODY_CAPABILITIES
                or rule.capability not in self.adapter_versions
                or rule.input_location != MEDIA_LOCATIONS.get(rule.content_type)
                or not rule.input_name
                or len(rule.input_name.encode()) > 512
                or rule in rules
                or not any(
                    all(
                        candidate[k] == getattr(rule, k)
                        for k in ("actor_id", "tenant_id", "url", "content_type")
                    )
                    and candidate["start_url"]
                    for candidate in self.service.reviewed_rule_metadata()
                )
            ):
                raise ValueError("continuous_adapter_reviewed_capture_and_profile_required")
            rules.append(rule)
        return tuple(rules)

    def _capture_children(self, event: dict[str, Any]) -> list[JobSpec]:
        parent = self.store.surface(self.policy.engagement_id, event["surface_id"])
        state = self.store.session_state(self.policy, parent)
        if state is None or state["status"] != "ready":
            raise PolicyDenied("continuous_refresh_session_not_ready")
        metadata = self.service.context_metadata(parent.actor_id, parent.tenant_id, "current")
        if metadata["session_revision"] != state["revision"]:
            raise PolicyDenied("continuous_refresh_session_revision_mismatch")
        # An explicitly restricted old rule cannot be silently widened to the
        # refreshed revision. context_metadata checks rule and credential TTLs.
        return _capture_specs((metadata,), self.store, self.policy)

    def _validate_observation(self, surface: Surface) -> None:
        self.store.assert_session_revision(self.policy, surface)
        evidence = self.store.evidence_get(self.policy.engagement_id, surface.request_ref)
        captured = json.loads(evidence["excerpt"])
        if (
            not isinstance(captured, dict)
            or any(
                captured.get(key) != getattr(surface, key)
                for key in (
                    "url",
                    "method",
                    "actor_id",
                    "tenant_id",
                    "session_revision",
                    "body_sha256",
                )
            )
            or captured.get("engagement_id") != self.policy.engagement_id
            or captured.get("policy_revision") != self.policy.revision
            or captured.get("sent") is not True
            or captured.get("response_complete") is not True
            or type(captured.get("status")) is not int
            or not 200 <= captured["status"] < 300
            or captured.get("request_content_type", captured.get("content_type"))
            != surface.content_type
        ):
            raise PolicyDenied("continuous_replay_capture_unverified")
        # Reload the private file on every admission: a refresh or host change
        # must never leave an old in-memory credential binding authorized.
        AuthReplayVault.from_file_for_surface(self.auth_vault_file, self.policy, surface).authorize(
            surface
        )

    def _replay_children(self, event: dict[str, Any]) -> list[JobSpec]:
        ids = event["result"].get("summary", {}).get("surface_ids")
        if not isinstance(ids, list) or len(ids) > 512 or any(not isinstance(x, str) for x in ids):
            raise ValueError("continuous_replay_invalid_capture_result")
        parent = self.store.surface(self.policy.engagement_id, event["surface_id"])
        specs: list[JobSpec] = []
        for surface_id in dict.fromkeys(ids):
            surface = self.store.surface(self.policy.engagement_id, surface_id)
            if surface.method != "POST" or surface.source != "observed" or not surface.body_sha256:
                continue
            matches = tuple(rule for rule in self.rules if rule.matches(surface))
            adapter_matches = tuple(rule for rule in self.adapter_rules if rule.matches(surface))
            if not matches and not adapter_matches:
                continue
            if any(
                getattr(surface, key) != getattr(parent, key)
                for key in ("actor_id", "tenant_id", "session_revision")
            ):
                raise PolicyDenied("continuous_replay_capture_parent_mismatch")
            self._validate_observation(surface)
            if not any(
                candidate["expires_at"] > time.time()
                and candidate["session_revision"] in {"current", surface.session_revision}
                and all(
                    candidate[key] == getattr(surface, key)
                    for key in ("actor_id", "tenant_id", "url")
                )
                and candidate["content_type"]
                == surface.content_type.split(";", 1)[0].strip().lower()
                for candidate in self.service.reviewed_rule_metadata()
            ):
                raise PolicyDenied("continuous_replay_capture_rule_expired_or_changed")
            for rule in matches:
                assert self.lock is not None
                specs.append(
                    JobSpec(
                        surface_id,
                        "known_vulnerability",
                        "nuclei_scan",
                        tool_version=self.lock.binary_version,
                        template_version=self.lock.bundle_sha256,
                        policy_revision=self.policy.revision,
                        idempotent=False,
                        timeout_seconds=45,
                        priority=4,
                        options={"cve_id": rule.template_id},
                    )
                )
            for adapter in adapter_matches:
                selected = replace(
                    surface, input_location=adapter.input_location, input_name=adapter.input_name
                )
                selected_id = self.store.upsert_surface(self.policy.engagement_id, selected)
                hint = self.store.evidence_put(
                    self.policy.engagement_id,
                    {
                        "signal": {
                            "tinja_validate": "ssti",
                            "schemathesis_validate": "schema",
                            "oast_correlate": "oast_http",
                        }[adapter.capability],
                        "request_ref": selected.request_ref,
                        "input_name": selected.input_name,
                    },
                    kind="reviewed_adapter_capture_hint",
                )
                specs.append(
                    JobSpec(
                        selected_id,
                        {
                            "tinja_validate": "ssti",
                            "schemathesis_validate": "api_schema",
                            "oast_correlate": "oast",
                        }[adapter.capability],
                        adapter.capability,
                        idempotent=False,
                        timeout_seconds=60,
                        policy_revision=self.policy.revision,
                        priority=4,
                        options={"hint_ref": hint},
                        **self.adapter_versions[adapter.capability],
                    )
                )
        if not specs and any(
            rule.actor_id == parent.actor_id
            and rule.tenant_id == parent.tenant_id
            and any(
                candidate["start_url"] == parent.url
                and candidate["session_revision"] in {"current", parent.session_revision}
                and all(
                    candidate[key] == getattr(rule, key)
                    for key in ("actor_id", "tenant_id", "url", "content_type")
                )
                for candidate in self.service.reviewed_rule_metadata()
            )
            for rule in self._all_rules()
        ):
            raise ValueError("continuous_replay_capture_missing")
        return specs

    def _children(self, event: dict[str, Any]) -> list[JobSpec]:
        if event["capability"] == "session_refresh":
            return self._capture_children(event)
        if event["capability"] == "browser_post_capture":
            return self._replay_children(event)
        raise ValueError("continuous_replay_unknown_event")

    def _all_rules(self) -> tuple[_ReplayRule | _AdapterRule, ...]:
        return (*self.rules, *self.adapter_rules)

    def _recover_session(self, event: dict[str, Any]) -> tuple[str, ...]:
        if self.session_recovery is None:
            raise PolicyDenied("session_recovery_not_enabled")
        parent = self.store.surface(self.policy.engagement_id, event["surface_id"])
        validate_recovery_event(event, parent)
        routes = tuple(
            candidate
            for candidate in self.service.reviewed_rule_metadata()
            if candidate["start_url"]
            and candidate["expires_at"] > time.time()
            and candidate["session_revision"] in {"current", parent.session_revision}
            and candidate["actor_id"] == parent.actor_id
            and candidate["tenant_id"] == parent.tenant_id
            and (
                (parent.method == "GET" and parent.url == candidate["start_url"])
                or (
                    parent.method == "POST"
                    and parent.url == candidate["url"]
                    and parent.content_type.split(";", 1)[0].strip().lower()
                    == candidate["content_type"]
                )
            )
            and any(
                all(
                    candidate[key] == getattr(rule, key)
                    for key in ("actor_id", "tenant_id", "url", "content_type")
                )
                for rule in self._all_rules()
            )
        )
        seed = reviewed_refresh_seed(self.policy, self.store, self.auth_vault_file, parent, routes)
        surface_id = self.store.upsert_surface(self.policy.engagement_id, seed)
        spec = JobSpec(
            surface_id,
            "authentication",
            "session_refresh",
            policy_revision=self.policy.revision,
            idempotent=False,
            timeout_seconds=45,
            priority=6,
        )
        return tuple(
            self.store.complete_auth_recovery(
                self.policy,
                event["id"],
                spec,
                max_refreshes=self.session_recovery.max_refreshes,
                cooldown_seconds=self.session_recovery.cooldown_seconds,
            )
        )

    def reconcile(self) -> None:
        events = self.store.pending_followups(self.policy, limit=64, after=self._cursor)
        if not events:
            self._cursor = ""
            events = self.store.pending_followups(self.policy, limit=64)
        for event in events:
            self._cursor = event["id"]
            try:
                if event.get("kind", "completion") == "auth_failure":
                    ids = self._recover_session(event)
                    self.refresh_job_ids = tuple(dict.fromkeys((*self.refresh_job_ids, *ids)))[-64:]
                    continue
                specs = self._children(event)
                ids = tuple(self.store.complete_followup(self.policy, event["id"], specs))
                if event["capability"] == "session_refresh":
                    self.capture_job_ids = tuple(dict.fromkeys((*self.capture_job_ids, *ids)))[-64:]
                else:
                    self.replay_job_ids = tuple(dict.fromkeys((*self.replay_job_ids, *ids)))[-64:]
            except (ValueError, KeyError, TypeError, OSError, CapacityExceeded) as exc:
                code = str(exc)
                if not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
                    code = "continuous_replay_reconciliation_failed"
                self.store.record_followup_error(self.policy, event["id"], code)

    def status(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "capture_job_ids": list(self.capture_job_ids),
            "replay_job_ids": list(self.replay_job_ids),
            "refresh_job_ids": list(self.refresh_job_ids),
            "session_recovery": {
                "enabled": self.session_recovery is not None,
                **(
                    {
                        "max_refreshes": self.session_recovery.max_refreshes,
                        "cooldown_seconds": self.session_recovery.cooldown_seconds,
                        **self.store.recovery_status(self.policy),
                    }
                    if self.session_recovery is not None
                    else {}
                ),
            },
            **self.store.followup_status(self.policy),
        }
