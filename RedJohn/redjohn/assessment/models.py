"""Versioned normalized inventory, job, result and evidence contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, get_args


ExecutionStatus = Literal[
    "queued",
    "running",
    "retry_wait",
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "resource_exhausted",
]
CoverageStatus = Literal[
    "not_tested", "completed", "partial", "blocked", "unsupported", "inconclusive"
]
FindingStatus = Literal[
    "candidate",
    "confirmed_weakness",
    "confirmed_impact",
    "false_positive",
    "fixed",
    "reopened",
]
EXECUTION_STATES = frozenset(get_args(ExecutionStatus))
COVERAGE_STATES = frozenset(get_args(CoverageStatus))
FINDING_STATES = frozenset(get_args(FindingStatus))


def stable_key(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


@dataclass(frozen=True)
class Surface:
    url: str
    method: str = "GET"
    content_type: str = ""
    input_location: str = ""
    input_name: str = ""
    actor_id: str = "anonymous"
    tenant_id: str = ""
    session_revision: str = "1"
    workflow_state: str = "initial"
    source: str = "observed"
    request_ref: str = ""
    body_sha256: str = ""

    def __post_init__(self) -> None:
        if self.source not in {"observed", "imported", "inferred"}:
            raise ValueError("invalid_surface_source")
        if self.method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ValueError("unsupported_http_method")
        if self.body_sha256 and not re.fullmatch(r"[0-9a-f]{64}", self.body_sha256):
            raise ValueError("invalid_request_body_digest")
        if any(
            not isinstance(value, str) or len(value.encode()) > 8192
            for value in asdict(self).values()
        ):
            raise ValueError("surface_field_too_large")

    @property
    def key(self) -> str:
        # Preserve the exact URL/query order, duplicate params and percent encoding.
        return stable_key(
            {
                k: v
                for k, v in asdict(self).items()
                if k not in {"request_ref", "source"} and not (k == "body_sha256" and not v)
            }
        )


@dataclass(frozen=True)
class JobSpec:
    surface_id: str
    family: str
    capability: str
    tool_version: str = "1"
    template_version: str = ""
    profile_version: str = "1"
    policy_revision: str = "1"
    retest_revision: str = ""
    timeout_seconds: float = 30
    idempotent: bool = True
    priority: float = 1.0
    options: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            not all(
                isinstance(x, str) and 0 < len(x) <= 128
                for x in (self.surface_id, self.family, self.capability, self.policy_revision)
            )
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 600
            or not math.isfinite(self.priority)
            or not 0 <= self.priority <= 100
            or not isinstance(self.idempotent, bool)
            or not isinstance(self.options, dict)
            or len(json.dumps(self.options).encode()) > 8192
        ):
            raise ValueError("invalid_job_schema")

    @property
    def key(self) -> str:
        data = asdict(self)
        # Scheduling weights/timeouts do not authorize a duplicate active test.
        for field_name in ("priority", "timeout_seconds", "idempotent"):
            data.pop(field_name)
        if self.capability in {
            "sqlmap_validate",
            "dalfox_validate",
            "tinja_validate",
            "schemathesis_validate",
            "oast_correlate",
        }:
            # A reviewed hint is provenance, not a new probe. Re-recording the
            # same hypothesis must not repeat network traffic. Surface, session,
            # tool/profile revisions and explicit retest remain in the key.
            data["options"].pop("hint_ref", None)
        return stable_key(data)


@dataclass(frozen=True)
class AdapterResult:
    execution_status: ExecutionStatus
    coverage_status: CoverageStatus
    summary: dict[str, Any] = field(default_factory=dict)
    findings: tuple[dict[str, Any], ...] = ()
    error: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if (
            self.execution_status not in EXECUTION_STATES
            or self.coverage_status not in COVERAGE_STATES
        ):
            raise ValueError("invalid_result_status")
        if self.execution_status in {"queued", "running", "retry_wait"}:
            raise ValueError("adapter_result_must_be_terminal")
        if any(
            item.get("finding_status", "candidate") not in FINDING_STATES for item in self.findings
        ):
            raise ValueError("invalid_finding_status")
        if self.execution_status != "succeeded" and self.coverage_status == "completed":
            raise ValueError("failed_execution_cannot_complete_coverage")


def error_record(
    code: str,
    *,
    category: str = "execution",
    retryable: bool = False,
    terminal: bool = True,
    coverage_effect: str = "inconclusive",
    recovery_action: str = "stop",
    **refs: object,
) -> dict[str, Any]:
    return {
        "code": code,
        "category": category,
        "message": code,
        "retryable": retryable,
        "terminal": terminal,
        "job_id": refs.get("job_id"),
        "attempt_id": refs.get("attempt_id"),
        "tool_id": refs.get("tool_id"),
        "cause_ref": refs.get("cause_ref"),
        "retry_after": refs.get("retry_after"),
        "partial_evidence_refs": [],
        "coverage_effect": coverage_effect,
        "recovery_action": recovery_action,
    }
