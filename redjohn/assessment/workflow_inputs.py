"""Bounded host-private authentication inputs and browser state, never job data."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.session_refresh import _atomic_private_json, _fingerprint, _private_json
from redjohn.assessment.workflow_models import bounded_name


class WorkflowInputUnavailable(ValueError):  # noqa: N818 - stable state signal
    """An explicitly referenced private input is absent or expired."""


@dataclass(frozen=True, repr=False)
class PrivateWorkflowInput:
    reference: str
    purpose: str
    value: str = field(repr=False)
    single_use: bool = True


class WorkflowInputVault:
    def __init__(self, path: Path, policy: EngagementPolicy) -> None:
        self.path, self.policy = Path(path), policy
        raw = _private_json(self.path)
        if (
            not isinstance(raw, dict)
            or set(raw)
            != {
                "version",
                "engagement_id",
                "owner_id",
                "policy_revision",
                "state_key_base64",
                "inputs",
            }
            or raw["version"] != 1
            or (raw["engagement_id"], raw["owner_id"], raw["policy_revision"])
            != (policy.engagement_id, policy.owner_id, policy.revision)
            or not isinstance(raw["inputs"], list)
            or len(raw["inputs"]) > 64
        ):
            raise ValueError("invalid_private_workflow_inputs")
        try:
            self._key = base64.b64decode(raw["state_key_base64"], validate=True)
        except (ValueError, TypeError):
            raise ValueError("invalid_private_workflow_state_key") from None
        if len(self._key) != 32 or len(json.dumps(raw).encode()) > 32768:
            raise ValueError("private_workflow_input_budget_exceeded")
        self._inputs: dict[str, dict[str, Any]] = {}
        total = 0
        for item in raw["inputs"]:
            if (
                not isinstance(item, dict)
                or set(item)
                != {
                    "reference",
                    "actor_id",
                    "tenant_id",
                    "purpose",
                    "value",
                    "single_use",
                    "expires_at",
                }
                or item["purpose"] not in {"username", "password", "mfa_code", "nonce"}
                or not isinstance(item["value"], str)
                or not 1 <= len(item["value"].encode()) <= 4096
                or type(item["single_use"]) is not bool
                or (item["purpose"] in {"mfa_code", "nonce"} and not item["single_use"])
                or type(item["expires_at"]) not in {float, int}
                or not 0 < item["expires_at"] < 1e12
            ):
                raise ValueError("invalid_private_workflow_input")
            bounded_name(item["reference"])
            bounded_name(item["tenant_id"], empty=True)
            policy.check_actor(item["actor_id"])
            if item["actor_id"] == "anonymous" or item["reference"] in self._inputs:
                raise ValueError("invalid_private_workflow_input_identity")
            total += len(item["value"].encode())
            self._inputs[item["reference"]] = item
        if total > 16384:
            raise ValueError("private_workflow_input_budget_exceeded")

    def get(self, reference: str, actor: str, tenant: str) -> PrivateWorkflowInput:
        item = self._inputs.get(reference)
        if not item or item["expires_at"] <= time.time():
            raise WorkflowInputUnavailable("workflow_private_input_required")
        if (item["actor_id"], item["tenant_id"]) != (actor, tenant):
            raise PolicyDenied("workflow_private_input_identity_denied")
        return PrivateWorkflowInput(reference, item["purpose"], item["value"], item["single_use"])

    def nonce_reference(self, actor: str, tenant: str, url: str, value: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value.encode()) <= 4096:
            raise ValueError("invalid_workflow_dom_nonce")
        binding = json.dumps([self.policy.engagement_id, actor, tenant, url, value]).encode()
        return hmac.new(self._key, binding, hashlib.sha256).hexdigest()


class PrivateWorkflowState:
    """Atomic owner-only checkpoints; SQLite remains the execution authority."""

    def __init__(self, path: Path, policy: EngagementPolicy) -> None:
        self.path, self.policy = Path(path), policy
        self._expected_fingerprint = _fingerprint(self.path.stat(follow_symlinks=False))
        raw = _private_json(self.path)
        if _fingerprint(self.path.stat(follow_symlinks=False)) != self._expected_fingerprint:
            raise ValueError("private_workflow_state_changed_during_read")
        if (
            not isinstance(raw, dict)
            or set(raw) != {"version", "engagement_id", "owner_id", "policy_revision", "flows"}
            or raw["version"] != 1
            or (raw["engagement_id"], raw["owner_id"], raw["policy_revision"])
            != (policy.engagement_id, policy.owner_id, policy.revision)
            or not isinstance(raw["flows"], dict)
            or len(raw["flows"]) > 64
        ):
            raise ValueError("invalid_private_workflow_state")
        if len(json.dumps(raw).encode()) > 256 * 1024:
            raise ValueError("private_workflow_state_budget_exceeded")
        self.data = raw

    def get(self, flow_id: str) -> dict[str, Any]:
        value = self.data["flows"].get(flow_id, {})
        if not isinstance(value, dict):
            raise TypeError("invalid_private_workflow_checkpoint")
        return dict(value)

    def put(self, flow_id: str, value: dict[str, Any]) -> None:
        if flow_id not in self.data["flows"] and len(self.data["flows"]) >= 64:
            raise ValueError("private_workflow_state_capacity_exhausted")
        expected = self._expected_fingerprint
        self.data["flows"][flow_id] = value
        if len(json.dumps(self.data).encode()) > 256 * 1024:
            raise ValueError("private_workflow_state_budget_exceeded")
        _atomic_private_json(self.path, self.data, expected)
        self._expected_fingerprint = _fingerprint(self.path.stat(follow_symlinks=False))
