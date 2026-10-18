"""Compose actual adapters without eager optional-tool startup."""

from __future__ import annotations

from contextlib import AsyncExitStack
from typing import TYPE_CHECKING, Any, Self

from redjohn.assessment.adapters import (
    BrowserInventoryAdapter,
    HTTPObservationAdapter,
    NucleiPipelineAdapter,
)
from redjohn.assessment.browser import BrowserDiscoveryService, BrowserLimits
from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.host_resources import HostResourcePool, default_pool_path
from redjohn.assessment.intelligence import TechnologyDetector
from redjohn.assessment.persistent_rate_limit import PersistentRateLimitDetector
from redjohn.assessment.policy import origin_for
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.resources import ResourceEnvelope, ResourceGovernor
from redjohn.assessment.scheduler import Scheduler
from redjohn.assessment.store import AssessmentStore, CapacityExceeded


if TYPE_CHECKING:
    from pathlib import Path

    from redjohn.assessment.adapters import WorkerAdapter
    from redjohn.assessment.auth_replay import AuthReplayVault
    from redjohn.assessment.browser_capture import BrowserPostCaptureService
    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.browser_workflow import ContinuousBrowserWorkflow
    from redjohn.assessment.contracts import ScannerSession
    from redjohn.assessment.oast import OASTAdapter
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.session_refresh import SessionRefreshService


class AssessmentRuntime:
    def __init__(  # noqa: PLR0912, PLR0915 - explicit lazy adapter composition
        self,
        store: AssessmentStore,
        policy: EngagementPolicy,
        *,
        caller: str,
        envelope: ResourceEnvelope | None = None,
        host_pool_path: str | Path | None = None,
        browser_limits: BrowserLimits | None = None,
        browser_tls: BrowserTLSConfig | None = None,
        actor_states: dict[str, Any] | None = None,
        nuclei_lock: dict[str, Any] | None = None,
        session: ScannerSession | None = None,
        auth_vault: AuthReplayVault | None = None,
        auth_vault_file: str | Path | None = None,
        refresh_provider_file: str | Path | None = None,
        browser_capture_file: str | Path | None = None,
        continuous_replay: dict[str, Any] | None = None,
        ffuf_config: dict[str, Any] | None = None,
        httpx_config: dict[str, Any] | None = None,
        katana_config: dict[str, Any] | None = None,
        vulnx_config: dict[str, Any] | None = None,
        arjun_config: dict[str, Any] | None = None,
        sqlmap_config: dict[str, Any] | None = None,
        dalfox_config: dict[str, Any] | None = None,
        tinja_config: dict[str, Any] | None = None,
        schemathesis_config: dict[str, Any] | None = None,
        interactsh_config: dict[str, Any] | None = None,
    ) -> None:
        policy.authorize(caller)
        if continuous_replay is not None and not isinstance(continuous_replay, dict):
            raise ValueError("continuous_replay_invalid_configuration")
        if continuous_replay is not None and (
            auth_vault_file is None
            or browser_capture_file is None
            or (nuclei_lock is None and not continuous_replay.get("adapter_rules"))
        ):
            raise ValueError("continuous_replay_configuration_missing")
        session_recovery_enabled = (
            isinstance(continuous_replay, dict) and "session_recovery" in continuous_replay
        )
        if session_recovery_enabled and refresh_provider_file is None:
            raise ValueError("session_recovery_provider_configuration_missing")
        policy = store.register(policy)
        self.store, self.policy = store, policy
        self.governor = ResourceGovernor(
            envelope, host_pool=HostResourcePool(host_pool_path or default_pool_path())
        )
        self.rate_limits = PersistentRateLimitDetector(
            store, policy.engagement_id, requests_per_window=min(60, policy.request_budget)
        )
        self.registry = CapabilityRegistry(
            nuclei_lock=nuclei_lock,
            session_refresh_configured=bool(auth_vault_file and refresh_provider_file),
            browser_post_capture_configured=bool(auth_vault_file and browser_capture_file),
            ffuf_config=ffuf_config,
            httpx_config=httpx_config,
            katana_config=katana_config,
            vulnx_config=vulnx_config,
            arjun_config=arjun_config,
            sqlmap_config=sqlmap_config,
            dalfox_config=dalfox_config,
            tinja_config=tinja_config,
            schemathesis_config=schemathesis_config,
            interactsh_config=interactsh_config,
        )
        self.technology = TechnologyDetector(store.path)

        def admit(url: str) -> None:
            policy.check_scope_url(url)
            if not self.rate_limits.admit(origin_for(url)):
                raise CapacityExceeded("shared_origin_cooldown")
            store.consume_requests(policy)

        def observe(url: str, status: int, headers: dict[str, str]) -> None:
            self.rate_limits.observe(origin_for(url), status, headers)

        self.post_capture: BrowserPostCaptureService | None = None
        if auth_vault_file is not None and browser_capture_file is not None:
            from redjohn.assessment.browser_capture import BrowserPostCaptureService  # noqa: PLC0415

            self.post_capture = BrowserPostCaptureService(
                policy, store, auth_vault_file, browser_capture_file, rate_limits=self.rate_limits
            )
        self.browser = BrowserDiscoveryService(
            policy,
            self.governor,
            browser_limits,
            request_admission=admit,
            on_response=observe,
            tls_config=browser_tls,
            egress_workspace=store.path.parent / "browser-egress",
            post_capture=self.post_capture,
        )
        adapters: dict[str, WorkerAdapter] = {
            "browser_discover": BrowserInventoryAdapter(self.browser, policy, store, actor_states),
            "http_observe": HTTPObservationAdapter(
                policy,
                store,
                self.rate_limits,
                technology_detector=self.technology,
                tls_config=browser_tls,
            ),
            "headers_audit": HTTPObservationAdapter(
                policy,
                store,
                self.rate_limits,
                header_audit=True,
                technology_detector=self.technology,
                tls_config=browser_tls,
            ),
            "nuclei_scan": NucleiPipelineAdapter(
                policy,
                store,
                session=session,
                lock=nuclei_lock,
                tls_config=browser_tls,
                rate_limits=self.rate_limits,
                auth_vault=auth_vault,
                auth_vault_file=auth_vault_file,
                session_recovery_enabled=session_recovery_enabled,
            ),
        }
        if self.post_capture is not None:
            adapters["browser_post_capture"] = BrowserInventoryAdapter(
                self.browser,
                policy,
                store,
                actor_states,
                capture_post=True,
                session_recovery_enabled=session_recovery_enabled,
            )
        refresh_adapter: SessionRefreshService | None = None
        if any(value is not None for value in (arjun_config, sqlmap_config, dalfox_config)):
            from redjohn.assessment.specialists import CAPABILITIES as SPECIALISTS  # noqa: PLC0415
            from redjohn.assessment.specialists import SpecialistAdapter, SpecialistConfig  # noqa: PLC0415 - selected adapters only

            for name, document in (
                ("arjun", arjun_config),
                ("sqlmap", sqlmap_config),
                ("dalfox", dalfox_config),
            ):
                if document is not None:
                    adapters[SPECIALISTS[name]] = SpecialistAdapter(
                        SpecialistConfig.from_mapping(name, document),
                        policy,
                        store,
                        self.rate_limits,
                        tls_config=browser_tls,
                        auth_vault_file=auth_vault_file,
                    )
        self.oast: OASTAdapter | None = None
        if tinja_config is not None or schemathesis_config is not None:
            from redjohn.assessment.schema_tools import CAPABILITIES as SCHEMA_TOOLS  # noqa: PLC0415
            from redjohn.assessment.schema_tools import SchemaToolAdapter, SchemaToolConfig  # noqa: PLC0415

            for name, document in (("tinja", tinja_config), ("schemathesis", schemathesis_config)):
                if document is not None:
                    adapters[SCHEMA_TOOLS[name]] = SchemaToolAdapter(
                        SchemaToolConfig.from_mapping(name, document),
                        policy,
                        store,
                        self.rate_limits,
                        tls_config=browser_tls,
                        auth_vault_file=auth_vault_file,
                        session_recovery_enabled=session_recovery_enabled,
                    )
        if interactsh_config is not None:
            from redjohn.assessment.oast import OASTAdapter, OASTConfig  # noqa: PLC0415

            self.oast = OASTAdapter(
                OASTConfig.from_mapping(interactsh_config),
                policy,
                store,
                self.rate_limits,
                tls_config=browser_tls,
                auth_vault_file=auth_vault_file,
                session_recovery_enabled=session_recovery_enabled,
            )
            adapters["oast_correlate"] = adapters["oast_poll"] = self.oast
        if dalfox_config is not None:
            from redjohn.assessment.xss_confirmation import BrowserXSSConfirmationAdapter  # noqa: PLC0415

            adapters["browser_xss_confirmation"] = BrowserXSSConfirmationAdapter(
                self.browser, policy, store
            )
        if httpx_config is not None or katana_config is not None:
            from redjohn.assessment.discovery_tools import (  # noqa: PLC0415
                DiscoveryToolConfig,
                HTTPXProbeAdapter,
                KatanaDiscoveryAdapter,
            )

            for tool, document, adapter_class, capability in (
                ("httpx", httpx_config, HTTPXProbeAdapter, "httpx_probe"),
                ("katana", katana_config, KatanaDiscoveryAdapter, "katana_discover"),
            ):
                if document is not None:
                    adapters[capability] = adapter_class(
                        DiscoveryToolConfig.from_mapping(tool, document),
                        policy,
                        store,
                        self.rate_limits,
                        tls_config=browser_tls,
                        technology=self.technology,
                    )
        if vulnx_config is not None:
            from redjohn.assessment.vulnx import VulnXConfig, VulnXIntelligenceAdapter  # noqa: PLC0415

            adapters["vulnx_intelligence"] = VulnXIntelligenceAdapter(
                VulnXConfig.from_mapping(vulnx_config),
                policy,
                store,
                self.rate_limits,
                tls_config=browser_tls,
            )
        if ffuf_config is not None:
            from redjohn.assessment.ffuf import FFUFConfig, FFUFDiscoveryAdapter  # noqa: PLC0415

            adapters["ffuf_discover"] = FFUFDiscoveryAdapter(
                FFUFConfig.from_mapping(ffuf_config),
                policy,
                store,
                self.rate_limits,
                tls_config=browser_tls,
            )
        if auth_vault_file is not None and refresh_provider_file is not None:
            from redjohn.assessment.session_refresh import SessionRefreshService  # noqa: PLC0415

            refresh_adapter = SessionRefreshService(
                policy,
                store,
                auth_vault_file,
                refresh_provider_file,
                tls_config=browser_tls,
                rate_limits=self.rate_limits,
            )
            adapters["session_refresh"] = refresh_adapter
        self.scheduler = Scheduler(store, policy, self.governor, self.registry, adapters)
        self.control = AssessmentControl(
            store,
            policy,
            caller=caller,
            governor=self.governor,
            registry=self.registry,
            scheduler=self.scheduler,
        )
        if refresh_adapter is not None:
            refresh_adapter.cache = self.control.cache
        self.capture_job_ids: tuple[str, ...] = ()
        self.continuous_workflow: ContinuousBrowserWorkflow | None = None
        if self.post_capture is not None:
            from redjohn.assessment.browser_workflow import (  # noqa: PLC0415
                ContinuousBrowserWorkflow,
                enqueue_browser_capture_contexts,
            )

            try:
                if continuous_replay is not None:
                    # The prerequisites were checked before opening handles.
                    assert auth_vault_file is not None
                    self.continuous_workflow = ContinuousBrowserWorkflow(
                        self.post_capture,
                        store,
                        policy,
                        continuous_replay,
                        nuclei_lock,
                        auth_vault_file,
                        refresh_provider_file=refresh_provider_file,
                        adapter_versions={
                            capability: self.registry.execution_versions(capability)
                            for capability in (
                                "tinja_validate",
                                "schemathesis_validate",
                                "oast_correlate",
                            )
                            if capability in adapters
                        },
                    )
                    self.scheduler.reconcile = self.continuous_workflow.reconcile
                self.capture_job_ids = enqueue_browser_capture_contexts(
                    self.post_capture, store, policy
                )
            except BaseException:
                # No worker has started during reconciliation, but the two
                # controller-owned database handles already need releasing.
                self.control.close()
                self.technology.close()
                raise

        if dalfox_config is not None:
            from redjohn.assessment.specialists import reconcile_confirmations  # noqa: PLC0415

            previous_reconcile = self.scheduler.reconcile

            def reconcile_all() -> None:
                if previous_reconcile is not None:
                    previous_reconcile()
                reconcile_confirmations(store, policy)

            self.scheduler.reconcile = reconcile_all

        if self.oast is not None:
            from redjohn.assessment.oast import reconcile_oast  # noqa: PLC0415

            oast_previous = self.scheduler.reconcile
            oast_config = self.oast.config

            def reconcile_with_oast() -> None:
                if oast_previous is not None:
                    oast_previous()
                reconcile_oast(store, policy, oast_config)

            self.scheduler.reconcile = reconcile_with_oast

    def workflow_status(self) -> dict[str, Any]:
        if self.continuous_workflow is not None:
            status = self.continuous_workflow.status()
            status["capture_job_ids"] = list(
                dict.fromkeys((*self.capture_job_ids, *status["capture_job_ids"]))
            )[-64:]
            return status
        return {
            "enabled": False,
            "capture_job_ids": list(self.capture_job_ids),
            "replay_job_ids": [],
            **self.store.followup_status(self.policy),
        }

    async def close(self) -> None:
        # A failing optional component cannot skip the other owners' cleanup.
        # Keep the existing close order and preserve chained cleanup failures.
        async with AsyncExitStack() as cleanup:
            cleanup.callback(self.governor.close)
            cleanup.callback(self.technology.close)
            cleanup.callback(self.control.close)
            cleanup.push_async_callback(self.browser.close)
            if self.oast is not None:
                cleanup.push_async_callback(self.oast.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.close()
