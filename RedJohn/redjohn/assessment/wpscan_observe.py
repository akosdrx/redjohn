"""Explicit offline HTML observations using one reviewed external WPScan method.

This optional adapter is deliberately not registered by the default runtime.
Only a host-approved immutable HTML source artifact grants execution. A page URL
is provenance metadata and never supplies HTTP authority or causes a request.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import EgressUnavailable
from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record, stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.wpscan_component import (
    BOOTSTRAP_SHA256,
    COMPONENT_SHA256,
    LICENSE_SHA256,
    UPSTREAM_VERSION,
    WPScanComponentSource,
    WPScanHTMLArtifact,
    normalize_observation,
)
from redjohn.assessment.wpscan_runtime import (
    WPScanObservationRunner,
    WPScanRuntime,
    runtime_document,
)


if TYPE_CHECKING:
    from redjohn.assessment.store import AssessmentStore


CAPABILITY = "wordpress_observe"


@dataclass(frozen=True)
class WPScanObserveConfig:
    component: WPScanComponentSource
    artifact: WPScanHTMLArtifact
    runtime: WPScanRuntime

    @classmethod
    def from_mapping(cls, value: object) -> WPScanObserveConfig:
        if not isinstance(value, dict) or set(value) != {"component", "artifact", "runtime"}:
            raise ValueError("wpscan_explicit_component_artifact_runtime_required")
        config = cls(
            WPScanComponentSource.from_mapping(value["component"]),
            WPScanHTMLArtifact.from_mapping(value["artifact"]),
            WPScanRuntime.from_mapping(value["runtime"]),
        )
        config.validate_structure()
        return config

    def validate_structure(self) -> None:
        # No operator IO: availability/content/license is checked only in the
        # selected, owned deadline helper under the shared scanner lease.
        if (
            not isinstance(self.component, WPScanComponentSource)
            or not isinstance(self.artifact, WPScanHTMLArtifact)
            or not isinstance(self.runtime, WPScanRuntime)
        ):
            raise TypeError("wpscan_typed_configuration_required")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "component": {
                "source_file": str(self.component.source_file),
                "license_file": str(self.component.license_file),
                "external_operator_component": True,
                "operator_use": self.component.operator_use,
            },
            "artifact": {
                "html_file": str(self.artifact.html_file),
                "html_sha256": self.artifact.html_sha256,
                "page_url": self.artifact.page_url,
                "producer": "operator",
            },
            "runtime": {
                "root": str(self.runtime.root),
                "manifest_file": str(self.runtime.manifest_file),
                "manifest_sha256": self.runtime.manifest_sha256,
            },
        }

    @property
    def capability(self) -> str:
        return CAPABILITY

    @property
    def version(self) -> str:
        return UPSTREAM_VERSION

    @property
    def artifact_sha256(self) -> str:
        return self.artifact.html_sha256

    @property
    def revision(self) -> str:
        return stable_key(
            [
                CAPABILITY,
                self.artifact.revision,
                self.runtime.manifest_sha256,
                COMPONENT_SHA256,
                BOOTSTRAP_SHA256,
                LICENSE_SHA256,
                self.component.operator_use,
            ]
        )


def wordpress_observe_job(
    config: WPScanObserveConfig,
    policy: EngagementPolicy,
    store: AssessmentStore,
    *,
    timeout_seconds: float = 30,
    retest_revision: str = "",
) -> JobSpec:
    """Create one deduplicated INPUT job; inventory discovery grants nothing."""
    if type(timeout_seconds) not in {int, float} or not 1 <= timeout_seconds <= 30:
        raise ValueError("wpscan_observation_timeout_out_of_bounds")
    with store._lock:
        store.inventory._fence(store.db, policy)
    if config.artifact.html_sha256 not in policy.allowed_source_artifacts:
        raise PolicyDenied("wpscan_html_artifact_not_approved")
    config.validate_structure()
    ref = store.evidence_put(
        policy.engagement_id,
        {
            "format": "redjohn-wordpress-observation-input-v1",
            "html_sha256": config.artifact.html_sha256,
            "artifact_revision": config.artifact.revision,
            "configuration_revision": config.revision,
            "runtime_manifest_sha256": config.runtime.manifest_sha256,
            "component_sha256": COMPONENT_SHA256,
            "producer": "operator",
            "coverage_status": "partial",
        },
        kind="approved_wordpress_observation_input",
        deduplicate=True,
    )
    asset = store.inventory.record_asset(
        policy,
        kind="source_artifact",
        locator=config.artifact.html_sha256,
        source="imported",
        evidence_refs=(ref,),
    )
    surface = Surface(
        "",
        resource_kind="source_artifact",
        asset_ref=asset,
        artifact_sha256=config.artifact.html_sha256,
        input_location="source_artifact",
        input_name=config.revision,
        source="imported",
        workflow_state="approved_seed",
    )
    policy.check_surface(surface)
    sid = store.upsert_surface(policy.engagement_id, surface)
    return JobSpec(
        sid,
        "cms_observation",
        CAPABILITY,
        tool_version=UPSTREAM_VERSION,
        template_version=config.revision,
        policy_revision=policy.revision,
        timeout_seconds=timeout_seconds,
        retest_revision=retest_revision,
    )


class WPScanObserveAdapter:
    """One selected worker, shared scheduler admission, mandatory offline kernel boundary."""

    resource_class = "scanner"

    def __init__(
        self, config: WPScanObserveConfig, policy: EngagementPolicy, store: AssessmentStore
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        self.runner: WPScanObservationRunner | None = None

    def _job_fence(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> None:
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
                    CAPABILITY,
                ),
            ).fetchone()
            if current is None or JobSpec(**json.loads(current[0])) != spec:
                raise PolicyDenied("wpscan_observation_job_lease_not_current")
            actual = self.store.surface(self.policy.engagement_id, spec.surface_id)
            if actual != surface:
                raise PolicyDenied("wpscan_observation_surface_changed")
            self.store.inventory.require_surface_active(self.store.db, self.policy, spec.surface_id)
        if (
            spec.capability != CAPABILITY
            or spec.family != "cms_observation"
            or spec.options
            or not spec.idempotent
            or spec.tool_version != UPSTREAM_VERSION
            or spec.template_version != self.config.revision
            or spec.policy_revision != self.policy.revision
            or not 1 <= spec.timeout_seconds <= 30
            or surface.resource_kind != "source_artifact"
            or surface.artifact_sha256 != self.config.artifact.html_sha256
            or surface.input_name != self.config.revision
            or surface.input_location != "source_artifact"
            or surface.url
            or surface.actor_id != "anonymous"
            or surface.method != "GET"
        ):
            raise PolicyDenied("wpscan_exact_offline_html_job_required")
        self.policy.check_surface(surface)
        self.store.inventory.require_source_asset(
            self.policy, surface.asset_ref, self.config.artifact.html_sha256
        )

    async def run(  # noqa: PLR0911 - separate blocked/native/timeout outcomes
        self, job: dict[str, Any], surface: Surface, spec: JobSpec
    ) -> AdapterResult:
        started, stage = time.monotonic(), "prepare"
        try:
            self._job_fence(job, surface, spec)
            self.config.validate_structure()
            # The durable scheduler owns the shared worker/context/cgroup claim.
            # No private pool or independent subprocess bypass is introduced.
            self.runner = WPScanObservationRunner(
                self.config.runtime,
                self.config.component,
                self.config.artifact,
                self.store.path.parent / "wordpress-observation-workers",
                lambda: self._job_fence(job, surface, spec),
            )
            await self.runner.prepare_offline()
            stage = "health"
            health = await self.runner.healthcheck()
            self._job_fence(job, surface, spec)
            stage = "observe"
            remaining = spec.timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                return self._timeout()
            raw = await self.runner.execute(self.runner.argv(), remaining)
            self._job_fence(job, surface, spec)
            if raw.get("timed_out"):
                return self._timeout()
            if raw.get("error") or raw.get("truncated") or raw.get("exit_code") != 0:
                return self._failed("wpscan_observation_failed_or_output_limited", "inconclusive")
            if (
                self.runner.denied_connections
                or not self.runner.snapshot_readonly_attested
                or self.runner.boundary is None
            ):
                return self._failed("wpscan_observation_offline_boundary_failed", "blocked")
            document = runtime_document(raw.get("stdout", "").encode())
            self.runner.validate_runtime_files(document)
            observation = normalize_observation(document, self.config.artifact, COMPONENT_SHA256)
            self._job_fence(job, surface, spec)
            ref = self.store.evidence_put(
                self.policy.engagement_id,
                {
                    **observation,
                    "health": health,
                    "configuration_revision": self.config.revision,
                    "deny_all_namespace_attested": True,
                    "snapshot_readonly_attested": True,
                    "denied_network_connections": 0,
                    "duration_seconds": time.monotonic() - started,
                },
                job_id=job["id"],
                kind="wordpress_observation_outcome",
            )
            return AdapterResult(
                "succeeded",
                "partial",
                summary={**observation, "health": health, "evidence_refs": [ref]},
            )
        except PolicyDenied:
            raise
        except EgressUnavailable:
            return self._failed("wpscan_observation_kernel_deny_all_unavailable", "blocked")
        except (ValueError, TypeError, OSError, RuntimeError):
            return self._failed(
                "wpscan_observation_output_or_native_closure_invalid"
                if stage == "observe"
                else "wpscan_observation_component_runtime_or_license_unavailable",
                "inconclusive" if stage == "observe" else "blocked",
            )
        finally:
            await asyncio.shield(self.cleanup())

    @staticmethod
    def _timeout() -> AdapterResult:
        return AdapterResult(
            "timed_out", "inconclusive", error=error_record("wpscan_observation_timeout")
        )

    @staticmethod
    def _failed(code: str, coverage: str) -> AdapterResult:
        # Two fixed literal branches keep status values typed and unambiguous.
        if coverage == "blocked":
            return AdapterResult(
                "failed", "blocked", error=error_record(code, coverage_effect="blocked")
            )
        return AdapterResult(
            "failed", "inconclusive", error=error_record(code, coverage_effect="inconclusive")
        )

    async def cancel(self) -> None:
        if self.runner is not None:
            await self.runner.cancel()

    def resource_cleanup_verified(self) -> bool:
        return self.runner is None or self.runner.resource_cleanup_verified()

    async def cleanup(self) -> None:
        if self.runner is not None:
            await self.runner.cleanup()
            if self.runner.resource_cleanup_verified():
                self.runner = None
