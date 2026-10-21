"""Explicit, inert configuration and proof-joined owned-lab status."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from redjohn.assessment.lab_contract import ORIGINAL_RCE, VERSION, LabDenied
from redjohn.assessment.os_memory import LinuxMemoryBoundary
from redjohn.assessment.policy import PolicyDenied


if TYPE_CHECKING:
    from redjohn.assessment.lab_validation import LabValidation
    from redjohn.assessment.policy import EngagementPolicy


def validate_lab_configuration(
    value: object, memory: object, budget: int, policy: EngagementPolicy
) -> dict[str, Any]:
    """Validate schema without entering a namespace or starting a worker."""
    if not isinstance(value, dict) or value != {"version": VERSION}:
        raise ValueError("owned_lab_exact_version_configuration_required")
    policy.check_capability(domains=("web",), profiles=("isolated-lab",))
    if not isinstance(memory, dict):
        raise TypeError("owned_lab_os_memory_configuration_required")
    LinuxMemoryBoundary(memory, budget)
    return dict(memory)


def owned_lab_status(validation: LabValidation | None) -> dict[str, Any]:
    """Historical labels are never promoted without current durable proof."""
    base: dict[str, Any] = {
        "enabled": validation is not None,
        "original_rce_status": ORIGINAL_RCE,
        "scope": "owned_local_response_header_only",
        "assertions": [],
        "invalid_assertions": 0,
        "canonical_candidates_promoted": False,
    }
    if validation is None:
        return {**base, "coverage_status": "blocked", "reason": "owned_lab_not_configured"}
    from redjohn.assessment.lab_validation import LabValidation  # noqa: PLC0415
    from redjohn.assessment.proof_bound_correlation import ProofBoundCorrelation  # noqa: PLC0415

    if type(validation) is not LabValidation:
        raise TypeError("owned_lab_typed_validation_required")
    proof = ProofBoundCorrelation(validation)
    try:
        validation._policy()
        with validation.store._lock:
            rows = validation.store.db.execute(
                "SELECT assertion_ref FROM rj_lab_assertion WHERE engagement=? "
                "ORDER BY assertion_ref LIMIT 33",
                (validation.policy.engagement_id,),
            ).fetchall()
        if len(rows) > 32:
            raise LabDenied("lab_assertion_quota")  # noqa: TRY301 - bounded persisted status
        assertions = []
        for row in rows:
            try:
                edge = proof.edge(row[0])
                assertion = validation.store.evidence_get(
                    validation.policy.engagement_id, edge.validation_assertion_ref, max_bytes=16384
                )
                # edge() verifies kind, exact payload, jobs, context and current
                # policy; return its stored assertion rather than a caller label.
                assertions.append(json.loads(assertion["excerpt"]))
            except (LabDenied, PolicyDenied, ValueError, KeyError, TypeError):
                base["invalid_assertions"] += 1
        base["assertions"] = assertions
        return {
            **base,
            "coverage_status": "inconclusive"
            if base["invalid_assertions"]
            else "completed"
            if assertions
            else "blocked",
            "reason": "paired_proof_verified" if assertions else "paired_proof_not_available",
        }
    except (LabDenied, PolicyDenied):
        return {**base, "coverage_status": "blocked", "reason": "owned_lab_current_proof_required"}
