"""Bounded inventory and workflow metadata; no request or action executor.

These contracts describe host-approved observations and state transitions. They
never grant network permission, choose credentials, or contain executable code.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

from redjohn.assessment.models import stable_key
from redjohn.assessment.policy import EngagementPolicy, origin_for


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
ASSET_KINDS = frozenset(
    {
        "http_origin",
        "dns_name",
        "ip_address",
        "ip_network",
        "source_artifact",
        "cloud_account",
        "kubernetes_cluster",
    }
)
SOURCES = frozenset({"observed", "imported", "inferred"})


def bounded_name(value: object, *, empty: bool = False) -> str:
    if not isinstance(value, str) or not ((empty and value == "") or _NAME.fullmatch(value)):
        raise ValueError("invalid_inventory_name")
    return value


def canonical_asset_locator(kind: str, locator: str) -> str:
    """Canonicalize identity only; never resolve a name or authorize execution."""
    if kind not in ASSET_KINDS or not isinstance(locator, str) or len(locator) > 1024:
        raise ValueError("invalid_asset_identity")
    if kind == "http_origin":
        canonical = origin_for(locator)
        parsed = urlsplit(locator)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("asset_requires_origin_not_endpoint")
        return canonical
    if kind == "ip_address":
        return str(ipaddress.ip_address(locator))
    if kind == "ip_network":
        return str(ipaddress.ip_network(locator, strict=False))
    if kind == "source_artifact":
        digest = locator.removeprefix("sha256:")
        if not _SHA256.fullmatch(digest):
            raise ValueError("source_artifact_requires_manifest_sha256")
        return "sha256:" + digest
    if kind == "dns_name":
        value = locator.rstrip(".").encode("idna").decode("ascii").lower()
        labels = value.split(".")
        if len(value) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
        ):
            raise ValueError("invalid_inventory_dns_name")
        return value
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}", locator):
        raise ValueError("invalid_inventory_external_identity")
    return locator


def asset_identity(engagement: str, kind: str, locator: str) -> str:
    return stable_key([engagement, kind, canonical_asset_locator(kind, locator)])


def evidence_references(values: tuple[str, ...], *, required: bool = False) -> None:
    if (
        not isinstance(values, tuple)
        or len(values) > 16
        or (required and not values)
        or any(not isinstance(value, str) or not value or len(value) > 128 for value in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("invalid_inventory_evidence_references")


@dataclass(frozen=True)
class InventoryLimits:
    assets: int = 4096
    services: int = 8192
    surface_links: int = 32768
    observations: int = 16384
    workflow_definitions: int = 128
    workflow_instances: int = 512
    workflow_history: int = 8192

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or not 1 <= value <= 65536 for value in asdict(self).values()
        ):
            raise ValueError("invalid_inventory_limits")


@dataclass(frozen=True)
class WorkflowStep:
    name: str
    from_state: str
    to_state: str
    method: str
    url: str
    effect: str = "read_only"
    expected_statuses: tuple[int, ...] = (200,)
    response_sha256: str = ""
    graphql_contract: str = ""

    def __post_init__(self) -> None:
        for name in (self.name, self.from_state, self.to_state):
            bounded_name(name)
        bounded_name(self.graphql_contract, empty=True)
        if (
            not isinstance(self.response_sha256, str)
            or (self.response_sha256 and not _SHA256.fullmatch(self.response_sha256))
            or self.effect not in {"read_only", "mutation", "cleanup"}
            or (
                self.effect == "read_only"
                and self.method not in {"GET", "HEAD", "OPTIONS"}
                and not (self.method == "POST" and self.graphql_contract)
            )
            or (self.effect != "read_only" and self.method != "POST")
            or not isinstance(self.url, str)
            or len(self.url) > 4096
            or not isinstance(self.expected_statuses, tuple)
            or not 1 <= len(self.expected_statuses) <= 8
            or any(
                type(status) is not int or not 200 <= status <= 499 or status in {401, 403, 429}
                for status in self.expected_statuses
            )
        ):
            raise ValueError("invalid_workflow_step")
        origin_for(self.url)

    def authorize(self, policy: EngagementPolicy) -> None:
        policy.check_replay_request(self.url, self.method)


@dataclass(frozen=True)
class WorkflowDefinition:
    name: str
    revision: str
    initial_state: str
    terminal_states: tuple[str, ...]
    steps: tuple[WorkflowStep, ...]

    def __post_init__(self) -> None:
        for value in (self.name, self.revision, self.initial_state, *self.terminal_states):
            bounded_name(value)
        if (
            not isinstance(self.steps, tuple)
            or not 1 <= len(self.steps) <= 64
            or any(not isinstance(step, WorkflowStep) for step in self.steps)
            or not isinstance(self.terminal_states, tuple)
            or not 1 <= len(self.terminal_states) <= 16
            or len({step.name for step in self.steps}) != len(self.steps)
            or len(json.dumps(asdict(self)).encode()) > 32768
        ):
            raise ValueError("invalid_workflow_definition")
        states = {
            self.initial_state,
            *(step.from_state for step in self.steps),
            *(step.to_state for step in self.steps),
        }
        if len(states) > 64 or not set(self.terminal_states) <= states:
            raise ValueError("invalid_workflow_states")
        reachable = {self.initial_state}
        for _ in range(len(states)):
            reachable.update(step.to_state for step in self.steps if step.from_state in reachable)
        if reachable != states:
            raise ValueError("workflow_has_unreachable_states")
        if any(step.effect == "mutation" for step in self.steps) and not any(
            step.effect == "cleanup" and step.to_state in self.terminal_states
            for step in self.steps
        ):
            raise ValueError("mutating_workflow_requires_cleanup_transition")

        if any(step.from_state in self.terminal_states for step in self.steps):
            raise ValueError("workflow_terminal_state_has_outgoing_step")
        # Every mutation must have a route that actually performs cleanup,
        # rather than an unrelated cleanup edge somewhere in the graph.
        cleanup_reachable = {
            step.from_state
            for step in self.steps
            if step.effect == "cleanup" and step.to_state in self.terminal_states
        }
        for _ in range(len(states)):
            cleanup_reachable.update(
                step.from_state for step in self.steps if step.to_state in cleanup_reachable
            )
        if any(
            step.effect == "mutation" and step.to_state not in cleanup_reachable
            for step in self.steps
        ):
            raise ValueError("workflow_mutation_has_no_cleanup_path")

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> WorkflowDefinition:
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid_workflow_definition_fields")
        converted = dict(value)
        converted["terminal_states"] = tuple(value["terminal_states"])
        converted["steps"] = tuple(
            WorkflowStep(
                **{**step, "expected_statuses": tuple(step.get("expected_statuses", (200,)))}
            )
            for step in value["steps"]
        )
        return cls(**converted)

    def step(self, name: str) -> WorkflowStep:
        for step in self.steps:
            if step.name == name:
                return step
        raise ValueError("workflow_step_not_defined")

    def to_mapping(self) -> dict[str, Any]:
        """Preserve persisted legacy payloads when additive fields are empty."""
        result = asdict(self)
        for step in result["steps"]:
            if not step["graphql_contract"]:
                del step["graphql_contract"]
        return result


def lease_seconds(value: float) -> float:
    if isinstance(value, bool) or not math.isfinite(value) or not 1 <= value <= 600:
        raise ValueError("invalid_workflow_lease_duration")
    return value
