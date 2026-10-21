"""Host-only contracts for the restricted owned header-regression capability.

These objects are never accepted from job arguments or target output. Public
runtime accepts these live process bindings only through its host API.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from redjohn.assessment.host_resources import process_identity
from redjohn.assessment.models import stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied


Phase = Literal["candidate", "fixed_control"]
CAPABILITY = "owned_lab_regression"
VERSION = "redjohn-owned-header-lab-1"
ORIGINAL_RCE = "not_reproduced_missing_fixture"
HEADER = "x-content-type-options"
EXPECTED = "nosniff"
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.\-/]{0,127}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")


class LabDenied(ValueError):  # noqa: N818 - stable secret-free component error
    pass


def reference(value: str) -> str:
    if not isinstance(value, str) or _REF.fullmatch(value) is None:
        raise LabDenied("lab_invalid_reference")
    return value


def local_url(value: str) -> str:
    if not isinstance(value, str) or len(value.encode()) > 2048:
        raise LabDenied("lab_literal_loopback_required")
    parsed = urlsplit(value)
    try:
        valid = (
            parsed.scheme == "http"
            and parsed.username is None
            and parsed.password is None
            and parsed.port is not None
            and 1 <= parsed.port <= 65535
            and ipaddress.ip_address(parsed.hostname or "").is_loopback
            and not parsed.fragment
            and not parsed.query
            and parsed.path == "/regression"
            and all(32 < ord(c) < 127 for c in value)
        )
    except ValueError:
        valid = False
    if not valid:
        raise LabDenied("lab_literal_loopback_required")
    return value


@dataclass(frozen=True)
class FixtureProof:
    fixture_ref: str
    asset_ref: str
    url: str
    phase: Phase
    source_sha256: str
    deployment_ref: str
    pid: int
    process_start: str

    def __post_init__(self) -> None:
        reference(self.fixture_ref)
        reference(self.asset_ref)
        reference(self.deployment_ref)
        local_url(self.url)
        if (
            self.phase not in {"candidate", "fixed_control"}
            or not isinstance(self.source_sha256, str)
            or _SHA.fullmatch(self.source_sha256) is None
            or type(self.pid) is not int
            or self.pid <= 1
            or not isinstance(self.process_start, str)
            or not 1 <= len(self.process_start) <= 256
        ):
            raise LabDenied("lab_invalid_fixture_proof")

    @property
    def key(self) -> str:
        return stable_key(asdict(self))


def _owned_process(process: object) -> bool:
    return isinstance(process, asyncio.subprocess.Process)


class OwnedFixtureBinding:
    """An explicit trusted host holds the actual child object, not a PID label."""

    def __init__(
        self,
        process: asyncio.subprocess.Process,
        *,
        fixture_ref: str,
        asset_ref: str,
        url: str,
        phase: Phase,
        source: bytes,
        deployment_ref: str,
    ) -> None:
        if not _owned_process(process):
            raise LabDenied("lab_owned_child_process_object_required")
        identity = process_identity(process.pid)
        if process.returncode is not None or identity is None or not 1 <= len(source) <= 65536:
            raise LabDenied("lab_owned_fixture_not_live")
        self.process = process
        self.proof = FixtureProof(
            fixture_ref,
            asset_ref,
            url,
            phase,
            hashlib.sha256(source).hexdigest(),
            deployment_ref,
            process.pid,
            identity,
        )

    def require_live(self) -> FixtureProof:
        if (
            not _owned_process(self.process)
            or self.process.pid != self.proof.pid
            or self.process.returncode is not None
            or process_identity(self.proof.pid) != self.proof.process_start
        ):
            raise LabDenied("lab_owned_fixture_not_live")
        return self.proof


@dataclass(frozen=True)
class LabPlan:
    engagement_id: str
    policy_revision: str
    candidate_ref: str
    candidate_job: str
    surface_id: str
    capture_ref: str
    fixture_ref: str
    asset_ref: str
    url: str
    actor_id: str
    session_revision: str
    workflow_state: str
    candidate_deployment: str
    template_sha256: str

    @property
    def key(self) -> str:
        return stable_key(asdict(self))

    def authorize(self, policy: EngagementPolicy) -> None:
        policy.check_capability(domains=("web",), profiles=("isolated-lab",))
        if (
            policy.engagement_id != self.engagement_id
            or policy.revision != self.policy_revision
            or self.actor_id != "anonymous"
            or _SHA.fullmatch(self.template_sha256) is None
        ):
            raise PolicyDenied("lab_policy_or_actor_mismatch")
        policy.check_actor(self.actor_id)
        policy.check_readonly_request(local_url(self.url), "GET")

    def context(self) -> dict[str, Any]:
        return {
            "plan_ref": self.key,
            "policy_revision": self.policy_revision,
            "actor_id": self.actor_id,
            "session_revision": self.session_revision,
            "workflow_state": self.workflow_state,
            "fixture_ref": self.fixture_ref,
            "asset_ref": self.asset_ref,
            "template_sha256": self.template_sha256,
            "candidate_ref": self.candidate_ref,
            "original_rce_status": ORIGINAL_RCE,
        }
