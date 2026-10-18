"""Shared configured runtime composition for CLI and host-bound agent sessions.

The same durable store and reviewed adapter instances serve both entry points.
No optional worker starts during composition.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import JobSpec, Surface, error_record
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore


if TYPE_CHECKING:
    from redjohn.assessment.native_session import NativeFixtureSession
    from redjohn.assessment.os_memory import LinuxMemoryBoundary


def load_configuration(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 65536:
        raise ValueError("configuration_too_large")
    value = json.loads(path.read_text())
    return validate_configuration(value)


def validate_configuration(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - {
        "policy",
        "resources",
        "os_memory",
        "browser",
        "seeds",
        "nuclei_lock",
        "tls",
        "auth_vault_file",
        "refresh_provider_file",
        "browser_capture_file",
        "continuous_replay",
        "ffuf",
        "httpx",
        "katana",
        "vulnx",
        "arjun",
        "sqlmap",
        "dalfox",
        "tinja",
        "schemathesis",
        "interactsh",
        "jobs",
    }:
        raise ValueError("invalid_configuration_fields")
    if not isinstance(value.get("seeds", []), list) or len(value.get("seeds", [])) > 64:
        raise ValueError("invalid_seed_list")
    return value


def enqueue_configured_jobs(
    runtime: AssessmentRuntime,
    store: AssessmentStore,
    policy: EngagementPolicy,
    config: dict[str, Any],
) -> None:
    specs = []
    for seed in config.get("seeds", []):
        if not isinstance(seed, dict) or set(seed) - {
            "url",
            "actor_id",
            "session_revision",
            "tenant_id",
            "capabilities",
            "retest_revision",
        }:
            raise ValueError("invalid_seed_schema")
        capabilities = seed.get(
            "capabilities", ["browser_discover", "headers_audit", "nuclei_scan"]
        )
        if not isinstance(capabilities, list) or set(capabilities) - {
            "browser_discover",
            "http_observe",
            "headers_audit",
            "nuclei_scan",
            "session_refresh",
            "browser_post_capture",
            "ffuf_discover",
            "httpx_probe",
            "katana_discover",
            "vulnx_intelligence",
        }:
            raise ValueError("invalid_seed_capabilities")
        # A metadata-only import must not resolve DNS or require an egress
        # grant. Actual submissions and workers still enforce check_scope_url.
        if capabilities:
            policy.check_scope_url(seed["url"])
        else:
            policy.check_inventory_url(seed["url"])
        actor = seed.get("actor_id", "anonymous")
        policy.check_actor(actor)
        surface_id = store.upsert_surface(
            policy.engagement_id,
            Surface(
                seed["url"],
                actor_id=actor,
                session_revision=str(seed.get("session_revision", "1")),
                tenant_id=seed.get("tenant_id", ""),
                source="imported",
                workflow_state="approved_seed",
            ),
        )
        for capability in capabilities:
            family = {
                "browser_discover": "discovery",
                "http_observe": "traffic",
                "headers_audit": "configuration",
                "nuclei_scan": "known_vulnerability",
                "session_refresh": "authentication",
                "browser_post_capture": "discovery",
                "ffuf_discover": "content_discovery",
                "httpx_probe": "service_observation",
                "katana_discover": "endpoint_discovery",
                "vulnx_intelligence": "intelligence",
            }[capability]
            specs.append(
                JobSpec(
                    surface_id,
                    family,
                    capability,
                    policy_revision=policy.revision,
                    retest_revision=str(seed.get("retest_revision", "")),
                    idempotent=capability not in {"session_refresh", "browser_post_capture"},
                    **runtime.registry.execution_versions(capability),
                )
            )
    selected_jobs = config.get("jobs", [])
    if not isinstance(selected_jobs, list) or len(selected_jobs) > 64:
        raise ValueError("invalid_selected_specialist_jobs")
    for selected in selected_jobs:
        if (
            not isinstance(selected, dict)
            or set(selected)
            - {"surface_id", "capability", "hint_ref", "timeout_seconds", "retest_revision"}
            or selected.get("capability")
            not in {
                "arjun_parameters",
                "sqlmap_validate",
                "dalfox_validate",
                "tinja_validate",
                "schemathesis_validate",
                "oast_correlate",
            }
        ):
            raise ValueError("invalid_selected_specialist_job")
        capability = selected["capability"]
        family = {
            "arjun_parameters": "parameter_discovery",
            "sqlmap_validate": "sqli",
            "dalfox_validate": "xss",
            "tinja_validate": "ssti",
            "schemathesis_validate": "api_schema",
            "oast_correlate": "oast",
        }[capability]
        specs.append(
            JobSpec(
                selected["surface_id"],
                family,
                capability,
                policy_revision=policy.revision,
                idempotent=store.surface(policy.engagement_id, selected["surface_id"]).method
                != "POST",
                options={"hint_ref": selected["hint_ref"]} if "hint_ref" in selected else {},
                timeout_seconds=selected.get("timeout_seconds", 60),
                retest_revision=selected.get("retest_revision", ""),
                **runtime.registry.execution_versions(capability),
            )
        )
    store.submit(policy, specs)


class ConfiguredAssessment:
    """Own a configured store, runtime and optional existing Nuclei session."""

    def __init__(self, config: dict[str, Any], output: Path, *, caller: str) -> None:
        self.config, self.output, self.caller = config, Path(output), caller
        self.policy = EngagementPolicy.from_mapping(config["policy"])
        self.policy.authorize(caller)
        self.envelope = ResourceEnvelope(**config.get("resources", {}))
        self._store: AssessmentStore | None = None
        self._runtime: AssessmentRuntime | None = None
        self._native_session: NativeFixtureSession | None = None

    @property
    def store(self) -> AssessmentStore:
        if self._store is None:
            raise RuntimeError("configured_assessment_not_open")
        return self._store

    @property
    def runtime(self) -> AssessmentRuntime:
        if self._runtime is None:
            raise RuntimeError("configured_assessment_not_open")
        return self._runtime

    def metrics(self, *, os_boundary: LinuxMemoryBoundary | None = None) -> dict[str, Any]:
        """The same observed metrics for dedicated CLI and bound host reports."""
        runtime = self.runtime
        metrics: dict[str, Any] = dict(runtime.scheduler.metrics)
        metrics["automatic_browser_capture_jobs"] = list(runtime.capture_job_ids)
        current = self.store.policy(self.policy.engagement_id, self.caller)
        if current != self.policy:
            # Reporting must not adopt permissions changed by another owner
            # process, or ask the new revision for the old workflow's state.
            workflow = {
                "enabled": runtime.continuous_workflow is not None,
                "coverage_status": "blocked",
                "error": error_record(
                    "assessment_reapproval_required", category="policy", coverage_effect="blocked"
                ),
            }
        else:
            workflow = runtime.workflow_status()
        workflow["reconciliation_errors"] = runtime.scheduler.metrics["followup_errors"]
        metrics["continuous_replay"] = workflow
        metrics["approved_policy_revision"] = self.policy.revision
        metrics["current_policy_revision"] = current.revision
        metrics["performance"] = runtime.scheduler.monitor.snapshot()
        metrics["resources"] = runtime.governor.snapshot()
        metrics["resources"]["os_memory"] = (
            os_boundary.snapshot() if os_boundary is not None else {"enforced": False}
        )
        return metrics

    async def __aenter__(self) -> Self:
        if self._store is not None:
            raise RuntimeError("configured_assessment_already_open")
        config, policy, envelope = self.config, self.policy, self.envelope
        store = self._store = AssessmentStore(
            self.output / ".state" / "agents.db",
            queue_max_items=envelope.queue_max_items,
            artifact_max_bytes=envelope.artifact_max_bytes,
        )
        native_session = None
        try:
            # Resolve the persisted default deadline before composing any
            # native/browser/HTTP component, including the Nuclei session.
            policy = self.policy = store.register(policy)
            lock_config = config.get("nuclei_lock")
            if lock_config is not None:
                from redjohn.assessment.native_session import NativeFixtureSession  # noqa: PLC0415
                from redjohn.tools.hunt.nuclei import NucleiLock  # noqa: PLC0415

                native_session = NativeFixtureSession(
                    policy,
                    self.output / ".state" / "nuclei-worker",
                    NucleiLock.from_mapping(lock_config),
                )
                self._native_session = native_session
            self._runtime = AssessmentRuntime(
                store,
                policy,
                caller=self.caller,
                envelope=envelope,
                browser_limits=BrowserLimits(**config.get("browser", {})),
                browser_tls=BrowserTLSConfig(**config.get("tls", {})),
                nuclei_lock=lock_config,
                session=native_session,
                auth_vault_file=config.get("auth_vault_file"),
                refresh_provider_file=config.get("refresh_provider_file"),
                browser_capture_file=config.get("browser_capture_file"),
                continuous_replay=config.get("continuous_replay"),
                ffuf_config=config.get("ffuf"),
                httpx_config=config.get("httpx"),
                katana_config=config.get("katana"),
                vulnx_config=config.get("vulnx"),
                arjun_config=config.get("arjun"),
                sqlmap_config=config.get("sqlmap"),
                dalfox_config=config.get("dalfox"),
                tinja_config=config.get("tinja"),
                schemathesis_config=config.get("schemathesis"),
                interactsh_config=config.get("interactsh"),
            )
            self.policy = self._runtime.policy
            enqueue_configured_jobs(self.runtime, store, policy, config)
        except BaseException:
            await self.close()
            raise
        return self

    async def close(self) -> None:
        try:
            if self._runtime is not None:
                await self._runtime.close()
        finally:
            self._runtime = None
            try:
                if self._native_session is not None:
                    await self._native_session.aclose()
            finally:
                self._native_session = None
                if self._store is not None:
                    self._store.close()
                    self._store = None

    async def __aexit__(self, *_args: object) -> None:
        await self.close()
