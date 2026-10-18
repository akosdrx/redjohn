"""Lazy RedJohn-native skill metadata and verified capability eligibility.

The manifest indexes reference contracts. It neither imports scanner workers nor
loads every SKILL body into the model, and capability readiness is not permission.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redjohn.assessment.registry import CapabilityRegistry
from redjohn.utils.resource_paths import get_redjohn_resource_path


if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class SkillDefinition:
    id: str
    description: str
    path: str
    capabilities: tuple[str, ...]
    optional_capabilities: tuple[str, ...]
    internal_modules: tuple[str, ...]
    unimplemented_requirements: tuple[str, ...]
    domains: tuple[str, ...]
    profiles: tuple[str, ...]
    supported_content_types: tuple[str, ...]
    unsupported_content_types: tuple[str, ...]
    input_mode: str
    requires_actor: bool
    requires_fixture: bool
    status: str
    control_test_refs: tuple[str, ...]
    provenance: dict[str, Any]


@dataclass(frozen=True)
class SkillEligibility:
    skill_id: str
    status: str
    eligible: bool
    missing_capabilities: tuple[str, ...]
    reasons: tuple[str, ...]


class AssessmentSkillRegistry:
    def __init__(
        self,
        manifest_path: Path | None = None,
        capability_registry: CapabilityRegistry | None = None,
    ) -> None:
        self.path = (
            manifest_path or get_redjohn_resource_path("skills") / "assessment" / "manifest.json"
        )
        self.capabilities = capability_registry or CapabilityRegistry()
        if self.path.stat().st_size > 1024 * 1024:
            raise ValueError("assessment_skill_manifest_too_large")
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1 or not isinstance(payload.get("skills"), list):
            raise ValueError("invalid_assessment_skill_manifest")
        if len(payload["skills"]) > 256:
            raise ValueError("assessment_skill_registry_capacity_exceeded")
        self._definitions: dict[str, SkillDefinition] = {}
        sequence_fields = (
            "capabilities",
            "optional_capabilities",
            "internal_modules",
            "unimplemented_requirements",
            "domains",
            "profiles",
            "supported_content_types",
            "unsupported_content_types",
            "control_test_refs",
        )
        for raw in payload["skills"]:
            if not isinstance(raw, dict):
                raise TypeError("invalid_assessment_skill_definition")
            item = dict(raw)
            for name in sequence_fields:
                if (
                    not isinstance(item.get(name), list)
                    or len(item[name]) > 32
                    or any(not isinstance(x, str) or len(x) > 512 for x in item[name])
                ):
                    raise ValueError("invalid_assessment_skill_metadata_list")
                item[name] = tuple(item[name])
            definition = SkillDefinition(**item)
            if (
                not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", definition.id)
                or definition.path != f"{definition.id}/SKILL.md"
                or definition.id in self._definitions
                or not isinstance(definition.description, str)
                or len(definition.description) > 1024
                or type(definition.requires_actor) is not bool
                or type(definition.requires_fixture) is not bool
                or definition.status
                not in {
                    "implemented_fixture_tested",
                    "adapter_not_implemented",
                    "deferred_not_required",
                }
                or definition.input_mode
                not in {"metadata", "recorded_request", "local_fixture", "source_artifact"}
            ):
                raise ValueError("invalid_assessment_skill_identity_or_status")
            for capability in (*definition.capabilities, *definition.optional_capabilities):
                if self.capabilities.get(capability) is None:
                    raise ValueError(f"unknown_assessment_skill_capability:{capability}")
            if (
                not definition.domains
                or not definition.profiles
                or not definition.control_test_refs
            ):
                raise ValueError("skill_activation_and_control_contract_required")
            self._definitions[definition.id] = definition

    def get(self, skill_id: str) -> SkillDefinition | None:
        return self._definitions.get(skill_id.removeprefix("assessment/"))

    def definitions(self) -> tuple[SkillDefinition, ...]:
        return tuple(self._definitions.values())

    def readiness(self, skill_id: str) -> SkillEligibility:
        """Dependency/mapping status only; it cannot authorize an engagement."""
        definition = self.get(skill_id)
        if definition is None:
            return SkillEligibility(
                skill_id=skill_id,
                status="adapter_not_implemented",
                eligible=False,
                missing_capabilities=(),
                reasons=("unknown_skill",),
            )
        health = {item["id"]: item for item in self.capabilities.health()}
        missing = list(definition.unimplemented_requirements)
        missing_dependency, unimplemented = False, bool(missing)
        blocked_configuration = False
        deferred = definition.status == "deferred_not_required"
        for module in definition.internal_modules:
            if not re.fullmatch(r"redjohn(?:\.[a-z][a-z0-9_]*)+", module):
                raise ValueError("invalid_internal_module_reference")
            module_path = module.removeprefix("redjohn.").replace(".", "/")
            if not get_redjohn_resource_path(f"{module_path}.py").is_file():
                missing.append(module)
                unimplemented = True
        for capability in definition.capabilities:
            registered = self.capabilities.get(capability)
            if registered is None or not registered.adapter_implemented:
                missing.append(capability)
                unimplemented = True
                deferred |= registered is not None and registered.status == "deferred_not_required"
            elif health[capability]["status"] == "blocked_missing_dependency":
                missing.append(capability)
                missing_dependency = True
            elif health[capability]["status"] == "blocked_configuration":
                missing.append(capability)
                blocked_configuration = True
        status = definition.status
        if deferred:
            status = "deferred_not_required"
        elif unimplemented:
            status = "adapter_not_implemented"
        elif missing_dependency:
            status = "blocked_missing_dependency"
        elif blocked_configuration:
            status = "blocked_configuration"
        return SkillEligibility(
            skill_id=definition.id,
            status=status,
            eligible=not missing and not deferred,
            missing_capabilities=tuple(missing),
            reasons=("required_capability_unavailable",) if missing else (),
        )

    def eligibility(
        self,
        skill_id: str,
        *,
        domain: str = "web",
        profile: str = "safe-production",
        content_type: str = "",
        actor_ref: str = "anonymous",
        has_fixture: bool = False,
    ) -> SkillEligibility:
        definition = self.get(skill_id)
        if definition is None:
            return SkillEligibility(
                skill_id=skill_id,
                status="adapter_not_implemented",
                eligible=False,
                missing_capabilities=(),
                reasons=("unknown_skill",),
            )
        readiness = self.readiness(skill_id)
        missing, reasons = list(readiness.missing_capabilities), list(readiness.reasons)
        if domain not in definition.domains:
            reasons.append("target_domain_not_applicable")
        if profile not in definition.profiles:
            reasons.append("impact_profile_not_permitted")
        if definition.requires_actor and actor_ref in {"", "anonymous"}:
            reasons.append("explicit_actor_required")
        if definition.requires_fixture and not has_fixture:
            reasons.append("controlled_fixture_required")
        body_type = content_type.partition(";")[0].strip().lower()
        unsupported = (
            definition.input_mode == "recorded_request"
            and body_type not in definition.supported_content_types
        )
        if unsupported:
            reasons.append("unsupported_body_format")
        status = readiness.status
        if not missing and status != "deferred_not_required" and unsupported:
            status = "unsupported_input"
        elif not missing and status != "deferred_not_required" and reasons:
            status = "blocked_by_policy"
        return SkillEligibility(
            skill_id=definition.id,
            status=status,
            eligible=readiness.eligible and not reasons,
            missing_capabilities=tuple(missing),
            reasons=tuple(reasons),
        )
