"""Optional cloud/node preparation, never a live cloud or cluster assessment.

The immutable source artifact is a reviewed preparation INPUT manifest. It is
not the account/cluster target and cannot grant target execution. Only native
kube-bench's fixed version command can run, inside the existing deny-all source
namespace; no benchmark YAML, credential chain or provider command is executed.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import EgressUnavailable
from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record, stable_key
from redjohn.assessment.pinned_tools import BinaryPin
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.source_tools import OfflineSourceRunner, SourceToolConfig, read_source_file
from redjohn.assessment.workflow_models import bounded_name


if TYPE_CHECKING:
    from redjohn.assessment.store import AssessmentStore


VERSIONS = {"prowler": "5.45.0", "kube-bench": "0.16.0"}
CAPABILITIES = {"prowler": "cloud_prepare", "kube-bench": "kubernetes_prepare"}


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("preparation_duplicate_json_key")
        value[key] = item
    return value


def bounded_document(raw: bytes) -> Any:
    if len(raw) > 512 * 1024:
        raise ValueError("preparation_document_byte_limit")
    try:
        result = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, RecursionError, UnicodeError):
        raise ValueError("preparation_invalid_json_document") from None
    pending, nodes = [(result, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 8192 or depth > 16:
            raise ValueError("preparation_document_structure_limit")
        if isinstance(item, dict):
            pending.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            pending.extend((value, depth + 1) for value in item)
        elif item is not None and type(item) not in {str, int, bool}:
            raise ValueError("preparation_invalid_json_scalar")
    return result


@dataclass(frozen=True)
class PreparationConfig:
    tool: str
    manifest_file: Path
    manifest_sha256: str
    binary: BinaryPin | None = None

    @classmethod
    def from_mapping(cls, tool: str, raw: dict[str, Any]) -> PreparationConfig:
        if (
            tool not in VERSIONS
            or not isinstance(raw, dict)
            or set(raw) - {"manifest_file", "manifest_sha256", "binary"}
            or not isinstance(raw.get("manifest_file"), str)
            or not Path(raw["manifest_file"]).is_absolute()
            or not isinstance(raw.get("manifest_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}", raw["manifest_sha256"]) is None
        ):
            raise ValueError("invalid_preparation_config")
        binary = None
        if "binary" in raw:
            pin = raw["binary"]
            if (
                not isinstance(pin, dict)
                or set(pin) != {"path", "sha256", "version"}
                or not all(isinstance(value, str) for value in pin.values())
                or not Path(pin["path"]).is_absolute()
                or re.fullmatch(r"[a-f0-9]{64}", pin["sha256"]) is None
                or pin["version"] != VERSIONS[tool]
            ):
                raise ValueError("invalid_preparation_binary_pin")
            binary = BinaryPin(Path(pin["path"]), pin["sha256"], pin["version"])
        config = cls(tool, Path(raw["manifest_file"]), raw["manifest_sha256"], binary)
        config.manifest()
        return config

    @property
    def capability(self) -> str:
        return CAPABILITIES[self.tool]

    @property
    def version(self) -> str:
        return VERSIONS[self.tool]

    @property
    def artifact_sha256(self) -> str:
        return self.manifest_sha256

    @property
    def revision(self) -> str:
        return stable_key(
            [self.tool, self.manifest_sha256, self.binary.sha256 if self.binary else ""]
        )

    def manifest(self) -> dict[str, Any]:
        raw = read_source_file(
            self.manifest_file.parent, self.manifest_file.name, self.manifest_sha256, 16384
        )
        value = bounded_document(raw)
        common = {"version", "tool", "operation", "checks", "live_authorization"}
        expected = common | (
            {"provider", "account_id", "profile", "regions"}
            if self.tool == "prowler"
            else {"cluster_id", "node_id", "benchmark"}
        )
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or type(value["version"]) is not int
            or value["version"] != 1
            or value["tool"] != self.tool
            or value["operation"] not in {"manifest_validate", "version_only"}
            or value["live_authorization"] != "deferred"
            or not isinstance(value["checks"], list)
            or not 1 <= len(value["checks"]) <= 32
            or any(not isinstance(check, str) for check in value["checks"])
            or len(set(value["checks"])) != len(value["checks"])
        ):
            raise ValueError("invalid_reviewed_preparation_manifest")
        if self.tool == "prowler":
            if (
                value["provider"] != "aws"
                or not isinstance(value["account_id"], str)
                or re.fullmatch(r"[0-9]{12}", value["account_id"]) is None
            ):
                raise ValueError("preparation_only_explicit_aws_account_supported")
            bounded_name(value["profile"])
            if (
                not isinstance(value["regions"], list)
                or not 1 <= len(value["regions"]) <= 16
                or any(
                    not isinstance(region, str)
                    or re.fullmatch(r"[a-z]{2}(?:-[a-z]+){1,3}-[0-9]", region) is None
                    for region in value["regions"]
                )
                or len(set(value["regions"])) != len(value["regions"])
            ):
                raise ValueError("explicit_preparation_regions_required")
            if any(
                re.fullmatch(r"[a-z][a-z0-9_]{1,127}", check) is None for check in value["checks"]
            ):
                raise ValueError("invalid_preparation_cloud_check")
        else:
            for field in ("cluster_id", "node_id", "benchmark"):
                bounded_name(value[field])
            if any(
                re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,4}", check) is None for check in value["checks"]
            ):
                raise ValueError("invalid_preparation_node_check")
        return value


class PreparationVersionRunner(OfflineSourceRunner):
    """Reuse the attested deny-all source snapshot, with one fixed subcommand."""

    async def version_only(self) -> dict[str, Any]:
        if self.boundary is None or not self.snapshot_readonly_attested:
            raise EgressUnavailable("preparation_attested_source_namespace_required")
        result = await self.execute([str(self.binary.path), "version"], 5)
        text = result.get("stdout", "").strip()
        if (
            result.get("error")
            or result.get("exit_code") != 0
            or result.get("truncated")
            or re.fullmatch(r"v?" + re.escape(self.binary.version), text) is None
            or self.denied_connections
        ):
            raise ValueError("preparation_version_or_offline_boundary_failed")
        return {
            "tool_version": self.binary.version,
            "binary_sha256": self.binary.sha256,
            "deny_all_namespace_attested": True,
            "snapshot_readonly_attested": self.snapshot_readonly_attested,
            "denied_connections": self.denied_connections,
        }


def preparation_job(
    config: PreparationConfig,
    policy: EngagementPolicy,
    store: AssessmentStore,
    *,
    timeout_seconds: float = 20,
    retest_revision: str = "",
) -> JobSpec:
    """Register the exact approved INPUT, without inventing a target URL."""
    manifest = config.manifest()
    with store._lock:
        store.inventory._fence(store.db, policy)
    if config.artifact_sha256 not in policy.allowed_source_artifacts:
        raise PolicyDenied("preparation_input_artifact_not_approved")
    ref = store.evidence_put(
        policy.engagement_id,
        {
            "format": "redjohn-preparation-input-v1",
            "tool": config.tool,
            "artifact_sha256": config.artifact_sha256,
            "operation": manifest["operation"],
            "audit_executed": False,
            "target_authorization": "deferred",
        },
        kind="approved_preparation_input",
        deduplicate=True,
    )
    asset = store.inventory.record_asset(
        policy,
        kind="source_artifact",
        locator=config.artifact_sha256,
        source="imported",
        evidence_refs=(ref,),
    )
    surface = Surface(
        "",
        resource_kind="source_artifact",
        asset_ref=asset,
        artifact_sha256=config.artifact_sha256,
        input_location="source_artifact",
        input_name=config.revision,
        source="imported",
        workflow_state="approved_seed",
    )
    policy.check_surface(surface)
    sid = store.upsert_surface(policy.engagement_id, surface)
    return JobSpec(
        sid,
        "tool_preparation",
        config.capability,
        tool_version=config.version,
        template_version=config.revision,
        policy_revision=policy.revision,
        options={"operation": manifest["operation"]},
        timeout_seconds=timeout_seconds,
        retest_revision=retest_revision,
    )


class PreparationAdapter:
    resource_class = "worker"
    owner_process_only = True

    def __init__(
        self, config: PreparationConfig, policy: EngagementPolicy, store: AssessmentStore
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        config.manifest()
        self.runner: PreparationVersionRunner | None = None

    def _job_fence(self, job: dict[str, Any], spec: JobSpec) -> None:
        with self.store._lock:
            self.store.inventory._fence(self.store.db, self.policy)
            current = self.store.db.execute(
                "SELECT spec FROM rj_job WHERE id=? AND engagement=? AND owner=? "
                "AND attempt=? AND execution_status='running' AND cancel_requested=0 "
                "AND lease_until>? AND capability=?",
                (
                    job["id"],
                    self.policy.engagement_id,
                    job["owner"],
                    job["attempt"],
                    time.time(),
                    self.config.capability,
                ),
            ).fetchone()
            if current is None or JobSpec(**json.loads(current[0])).key != spec.key:
                raise PolicyDenied("preparation_job_lease_not_current")
            self.store.inventory.require_surface_active(self.store.db, self.policy, spec.surface_id)

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:
        started = time.monotonic()
        try:
            self._job_fence(job, spec)
            manifest = self.config.manifest()
            if (
                spec.capability != self.config.capability
                or spec.options != {"operation": manifest["operation"]}
                or surface.resource_kind != "source_artifact"
                or surface.artifact_sha256 != self.config.manifest_sha256
                or surface.input_location != "source_artifact"
                or surface.input_name != self.config.revision
                or spec.tool_version != self.config.version
                or spec.template_version != self.config.revision
                or spec.policy_revision != self.policy.revision
            ):
                raise PolicyDenied("preparation_exact_manifest_job_required")
            self.policy.check_surface(surface)
            self.store.inventory.require_source_asset(
                self.policy, surface.asset_ref, self.config.manifest_sha256
            )
            health: dict[str, Any] = {}
            if manifest["operation"] == "version_only":
                if self.config.tool == "prowler":
                    return self._blocked("prowler_pinned_python_dependency_snapshot_unavailable")
                if self.config.binary is None:
                    return self._blocked("preparation_pinned_engine_missing")
                source = SourceToolConfig(
                    self.config.tool,
                    self.config.binary,
                    self.config.manifest_file.parent,
                    ((self.config.manifest_file.name, self.config.manifest_sha256),),
                )
                self.runner = PreparationVersionRunner(
                    source, self.store.path.parent / (self.config.tool + "-preparation")
                )
                await self.runner.prepare_offline()
                self._job_fence(job, spec)
                health = await self.runner.version_only()
            self._job_fence(job, spec)
            proof = self.store.evidence_put(
                self.policy.engagement_id,
                {
                    "tool": self.config.tool,
                    "operation": manifest["operation"],
                    "input_manifest_sha256": self.config.manifest_sha256,
                    "engine": health,
                    "audit_executed": False,
                    "audit_coverage_status": "blocked",
                    "target_authorization": "deferred",
                },
                job_id=job["id"],
                kind="tool_preparation_outcome",
            )
            return AdapterResult(
                "succeeded",
                "completed",
                summary={
                    "preparation_completed": True,
                    "operation": manifest["operation"],
                    "tool": self.config.tool,
                    "engine": health,
                    "audit_executed": False,
                    "audit_coverage_status": "blocked",
                    "target_authorization": "deferred",
                    "evidence_refs": [proof],
                    "duration_seconds": time.monotonic() - started,
                },
            )
        except EgressUnavailable:
            return self._blocked("preparation_kernel_deny_all_unavailable")
        except (ValueError, OSError, RuntimeError):
            return self._blocked("preparation_manifest_engine_or_provenance_denied")
        finally:
            await asyncio.shield(self.cleanup())

    @staticmethod
    def _blocked(code: str) -> AdapterResult:
        return AdapterResult(
            "failed",
            "blocked",
            summary={
                "audit_executed": False,
                "audit_coverage_status": "blocked",
                "target_authorization": "deferred",
            },
            error=error_record(code, coverage_effect="blocked"),
        )

    async def cancel(self) -> None:
        if self.runner is not None:
            await self.runner.cancel()

    async def cleanup(self) -> None:
        if self.runner is not None:
            await self.runner.cleanup()
            self.runner = None
