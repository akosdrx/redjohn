"""Bounded automatic-refresh admission for trusted authentication failures.

The failed request is never retried. Admission selects an already reviewed GET
anchor for a separate refresh job; the persistent store owns deduplication,
budget charging and cooldowns across processes and session revisions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.models import Surface
from redjohn.assessment.policy import PolicyDenied


if TYPE_CHECKING:
    from pathlib import Path

    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


RECOVERY_CAPABILITIES = frozenset(
    {
        "browser_post_capture",
        "nuclei_scan",
        "tinja_validate",
        "schemathesis_validate",
        "oast_correlate",
    }
)


def auth_recovery_marker(surface: Surface, signal: str) -> dict[str, Any]:
    marker: dict[str, Any] = {
        "admitted": True,
        "signal": signal,
        **{key: getattr(surface, key) for key in ("actor_id", "tenant_id", "session_revision")},
    }
    if signal == "http_401":
        marker.update(response_complete=True, status=401)
    return marker


@dataclass(frozen=True)
class SessionRecoveryOptions:
    max_refreshes: int
    cooldown_seconds: int

    @classmethod
    def from_mapping(cls, value: object) -> SessionRecoveryOptions:
        if (
            not isinstance(value, dict)
            or set(value) != {"max_refreshes", "cooldown_seconds"}
            or type(value["max_refreshes"]) is not int
            or not 1 <= value["max_refreshes"] <= 3
            or type(value["cooldown_seconds"]) is not int
            or not 0 <= value["cooldown_seconds"] <= 3600
        ):
            raise ValueError("session_recovery_invalid_configuration")
        return cls(value["max_refreshes"], value["cooldown_seconds"])


def validate_recovery_event(event: dict[str, Any], parent: Surface) -> None:
    """Require the adapter's host-generated signal and the unchanged identity."""
    result = event["result"]
    marker = result.get("summary", {}).get("auth_recovery")
    code = (result.get("error") or {}).get("code")
    if (
        parent.actor_id == "anonymous"
        or result.get("execution_status") != "failed"
        or result.get("coverage_status") != "blocked"
        or event["capability"] not in RECOVERY_CAPABILITIES
        or not isinstance(marker, dict)
        or marker.get("admitted") is not True
        or any(
            marker.get(key) != getattr(parent, key)
            for key in ("actor_id", "tenant_id", "session_revision")
        )
    ):
        raise PolicyDenied("session_recovery_untrusted_failure")
    if code == "authentication_expired":
        if (
            marker.get("signal") != "http_401"
            or marker.get("response_complete") is not True
            or type(marker.get("status")) is not int
            or marker["status"] != 401
        ):
            raise PolicyDenied("session_recovery_untrusted_failure")
    elif marker.get("signal") != "credential_expired" or (event["capability"], code) not in {
        ("browser_post_capture", "browser_capture_credentials_expired"),
        ("nuclei_scan", "auth_replay_expired"),
        ("tinja_validate", "auth_replay_expired"),
        ("schemathesis_validate", "auth_replay_expired"),
        ("oast_correlate", "auth_replay_expired"),
    }:
        raise PolicyDenied("session_recovery_untrusted_failure")


def reviewed_refresh_seed(
    policy: EngagementPolicy,
    store: AssessmentStore,
    vault_file: str | Path,
    parent: Surface,
    routes: tuple[dict[str, Any], ...],
) -> Surface:
    """Resolve an exact reviewed private GET anchor, allowing known expiry.

    An already superseded failure needs no obsolete private credential. The
    atomic store admission acknowledges that event without queuing a refresh.
    """
    if not re.fullmatch(r"[1-9][0-9]{0,17}", parent.session_revision):
        raise PolicyDenied("session_refresh_numeric_revision_required")
    if not routes:
        raise PolicyDenied("session_recovery_reviewed_start_missing")
    starts = sorted({route["start_url"] for route in routes})
    state = store.session_state(policy, parent)
    superseded = bool(
        state
        and state["status"] == "ready"
        and re.fullmatch(r"[1-9][0-9]{0,17}", state["revision"])
        and int(state["revision"]) > int(parent.session_revision)
    )
    if not superseded:
        if state and state["status"] in {"uncertain", "blocked"}:
            raise PolicyDenied("session_refresh_" + state["status"])
        vault = AuthReplayVault.read_for_rotation(vault_file, policy).to_mapping()
        anchors = {
            request["url"]
            for entry in vault["entries"]
            if all(
                entry[key] == getattr(parent, key)
                for key in ("actor_id", "tenant_id", "session_revision")
            )
            for request in entry["allowed_requests"]
            if request["method"] == "GET" and request["url"] in starts
        }
        starts = sorted(anchors)
        if not starts:
            raise PolicyDenied("session_recovery_private_get_anchor_missing")
    policy.check_readonly_request(starts[0], "GET")
    return Surface(
        starts[0],
        actor_id=parent.actor_id,
        tenant_id=parent.tenant_id,
        session_revision=parent.session_revision,
        source="imported",
        workflow_state="approved_seed",
    )
