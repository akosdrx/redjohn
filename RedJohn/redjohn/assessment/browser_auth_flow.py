"""Scheduled reviewed login/MFA/logout with private checkpointed input state."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.browser_action_models import BrowserAuthPlan
from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied, origin_for
from redjohn.assessment.workflow_inputs import PrivateWorkflowState, WorkflowInputVault


if TYPE_CHECKING:
    from collections.abc import Callable

    from redjohn.assessment.browser import BrowserDiscoveryService
    from redjohn.assessment.persistent_rate_limit import PersistentRateLimitDetector
    from redjohn.assessment.store import AssessmentStore


@dataclass(frozen=True)
class BrowserAuthFlowConfig:
    private_inputs_file: Path
    private_state_file: Path
    plans: tuple[BrowserAuthPlan, ...]

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> BrowserAuthFlowConfig:
        if (
            not isinstance(raw, dict)
            or set(raw) != {"private_inputs_file", "private_state_file", "plans"}
            or not isinstance(raw["plans"], list)
            or not 1 <= len(raw["plans"]) <= 16
            or any(
                not isinstance(raw[key], str) or not Path(raw[key]).is_absolute()
                for key in ("private_inputs_file", "private_state_file")
            )
        ):
            raise ValueError("invalid_browser_auth_flow_config")
        return cls(
            Path(raw["private_inputs_file"]),
            Path(raw["private_state_file"]),
            tuple(BrowserAuthPlan.from_mapping(plan) for plan in raw["plans"]),
        )

    def validate(self, policy: EngagementPolicy) -> None:
        WorkflowInputVault(self.private_inputs_file, policy)
        PrivateWorkflowState(self.private_state_file, policy)
        for plan in self.plans:
            plan.authorize(policy)


class BrowserAuthFlowAdapter:
    resource_class = "browser"

    def __init__(
        self,
        config: BrowserAuthFlowConfig,
        policy: EngagementPolicy,
        store: AssessmentStore,
        browser: BrowserDiscoveryService,
        *,
        on_session_state: Callable[[str, dict[str, Any] | None], None] | None = None,
        rate_limits: PersistentRateLimitDetector | None = None,
    ) -> None:
        config.validate(policy)
        self.config, self.policy, self.store, self.service = config, policy, store, browser
        self.on_session_state = on_session_state
        self.rate_limits = rate_limits
        self.plan_ids = tuple(store.auth_flows.register(policy, plan) for plan in config.plans)
        self._active_task: asyncio.Task[Any] | None = None
        private = PrivateWorkflowState(config.private_state_file, policy)
        store.auth_flows.reconcile_expired(policy, private.data["flows"])
        self._restore_ready_sessions()

    def _restore_ready_sessions(self) -> None:
        if self.on_session_state is None:
            return
        state = PrivateWorkflowState(self.config.private_state_file, self.policy)
        for checkpoint in state.data["flows"].values():
            if not isinstance(checkpoint, dict) or checkpoint.get("outcome") != "authenticated":
                continue
            actor, tenant, revision = (
                checkpoint.get("actor_id"),
                checkpoint.get("tenant_id"),
                checkpoint.get("session_revision"),
            )
            if (
                not isinstance(actor, str)
                or not isinstance(tenant, str)
                or not isinstance(revision, str)
            ):
                raise TypeError("invalid_private_auth_identity_checkpoint")
            current = self.store.session_state(
                self.policy,
                Surface(self.policy.allowed_origins[0], actor_id=actor, tenant_id=tenant),
            )
            if current and current["status"] == "ready" and current["revision"] == revision:
                ref = checkpoint.get("auth_evidence_ref", "")
                with self.store._lock:
                    evidence = self.store.db.execute(
                        "SELECT payload FROM rj_evidence WHERE engagement=? AND id=? "
                        "AND kind='auth_flow_outcome'",
                        (self.policy.engagement_id, ref),
                    ).fetchone()
                proof = json.loads(evidence[0]) if evidence else {}
                if (
                    not isinstance(proof, dict)
                    or proof.get("outcome") != "authenticated"
                    or (
                        proof.get("actor_id"),
                        proof.get("tenant_id"),
                        proof.get("session_revision"),
                        proof.get("policy_revision"),
                    )
                    != (actor, tenant, revision, self.policy.revision)
                    or type(proof.get("expires_at")) not in {float, int}
                    or proof["expires_at"] <= time.time()
                ):
                    continue
                try:
                    self.on_session_state(
                        actor,
                        {
                            "storage_state": checkpoint["storage_state"],
                            "tenant_id": tenant,
                            "session_revision": revision,
                            "auth_evidence_ref": checkpoint.get("auth_evidence_ref", ""),
                        },
                    )

                except (PolicyDenied, OSError, ValueError):
                    with self.store.transaction() as db:
                        self.store._audit(
                            db,
                            self.policy.engagement_id,
                            "auth_restore_blocked",
                            {
                                "actor_id": actor,
                                "tenant_id": tenant,
                                "session_revision": revision,
                                "reason": "auth_checkpoint_not_current_or_bootstrap_denied",
                            },
                            "auth_restore:block:" + str(ref),
                        )

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:  # noqa: PLR0912, PLR0915 - one admitted auth lifecycle
        if (
            spec.capability != "browser_auth_flow"
            or spec.idempotent
            or set(spec.options) != {"flow_id", "expected_revision"}
            or not isinstance(spec.options["flow_id"], str)
            or type(spec.options["expected_revision"]) is not int
            or spec.options["expected_revision"] < 1
        ):
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record("invalid_auth_flow_job", coverage_effect="blocked"),
            )
        flow_id = spec.options["flow_id"]
        selected_flow = self.store.auth_flows.get(self.policy, flow_id)
        if selected_flow["plan_id"] not in self.plan_ids:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    "auth_plan_not_currently_configured",
                    category="policy",
                    coverage_effect="blocked",
                ),
            )
        claimed = False
        flow = None
        try:
            flow = self.store.auth_flows.claim(self.policy, job, flow_id)
            claimed = True
            plan = self.store.auth_flows.plan(self.policy, flow["plan_id"])
            if (surface.url, surface.actor_id, surface.tenant_id, surface.session_revision) != (
                plan.actions[0].url,
                plan.actor_id,
                plan.tenant_id,
                flow["from_revision"],
            ):
                raise PolicyDenied("auth_flow_surface_identity_denied")
            inputs = WorkflowInputVault(self.config.private_inputs_file, self.policy)
            private = PrivateWorkflowState(self.config.private_state_file, self.policy)
            checkpoint = private.get(flow_id)
            if checkpoint and checkpoint.get("next_action") != flow["next_action"]:
                raise PolicyDenied("auth_private_checkpoint_not_committed")
            if not checkpoint:
                sessions = [
                    item
                    for item in private.data["flows"].values()
                    if isinstance(item, dict)
                    and item.get("actor_id") == plan.actor_id
                    and item.get("tenant_id") == plan.tenant_id
                    and item.get("session_revision") == flow["from_revision"]
                    and item.get("outcome") == "authenticated"
                ]
                if len(sessions) > 1:
                    raise PolicyDenied("auth_private_session_ambiguous")
                checkpoint = {"next_action": 0}
                if sessions:
                    checkpoint["storage_state"] = sessions[0]["storage_state"]

            def fence_read(_url: str) -> None:
                if self.rate_limits is not None and not self.rate_limits.admit(origin_for(_url)):
                    raise PolicyDenied("auth_rate_limited")
                with self.store._lock:
                    self.store.auth_flows._fence(self.store.db, self.policy, job, flow_id)
                self.store.consume_requests(self.policy)

            def admit(refs: tuple[str, ...]) -> None:
                if self.rate_limits is not None and not self.rate_limits.admit(
                    origin_for(plan.identity_url)
                ):
                    raise PolicyDenied("auth_rate_limited")
                self.store.auth_flows.admit(self.policy, job, flow_id, refs)

            def save(index: int, storage: dict[str, Any], url: str) -> None:
                private.put(
                    flow_id,
                    {
                        "next_action": index,
                        "storage_state": storage,
                        "url": url,
                        "actor_id": plan.actor_id,
                        "tenant_id": plan.tenant_id,
                    },
                )
                self.store.auth_flows.checkpoint(self.policy, job, flow_id, index)

            self._active_task = asyncio.current_task()
            result = await self.service.run_reviewed_actions(
                plan, inputs, checkpoint, on_read=fence_read, on_admit=admit, on_checkpoint=save
            )
            if result.outcome == "awaiting_input":
                private.put(
                    flow_id,
                    {
                        "next_action": result.next_action,
                        "storage_state": result.storage_state,
                        "url": result.url,
                        "actor_id": plan.actor_id,
                        "tenant_id": plan.tenant_id,
                    },
                )
                self.store.auth_flows.checkpoint(
                    self.policy, job, flow_id, result.next_action, awaiting=True
                )
                claimed = False
                await self.service.close()
                return AdapterResult(
                    "failed",
                    "blocked",
                    summary={
                        "flow_id": flow_id,
                        "state": "awaiting_input",
                        "requests": result.requests,
                        "automatic_replay": False,
                    },
                    error=error_record(
                        "workflow_private_input_required",
                        category="input",
                        coverage_effect="blocked",
                        recovery_action="supply_private_input_then_resume",
                    ),
                )
            revision = str(int(flow["from_revision"]) + 1)
            ref = self.store.evidence_put(
                self.policy.engagement_id,
                {
                    "engagement_id": self.policy.engagement_id,
                    "owner_id": self.policy.owner_id,
                    "policy_revision": self.policy.revision,
                    "flow_id": flow_id,
                    "actor_id": plan.actor_id,
                    "tenant_id": plan.tenant_id,
                    "session_revision": revision,
                    "outcome": result.outcome,
                    "identity_verified": True,
                    "identity_url": plan.identity_url,
                    "identity_status": result.identity_status,
                    "origin": origin_for(plan.identity_url),
                    "expires_at": time.time() + 300,
                    "requests": result.requests,
                },
                job_id=job["id"],
                kind="auth_flow_outcome",
            )
            private.put(
                flow_id,
                {
                    "next_action": result.next_action,
                    "storage_state": result.storage_state,
                    "url": result.url,
                    "actor_id": plan.actor_id,
                    "tenant_id": plan.tenant_id,
                    "session_revision": revision,
                    "outcome": result.outcome,
                    "auth_evidence_ref": ref,
                },
            )
            revision = self.store.auth_flows.finish(self.policy, job, flow_id, result.outcome)
            if self.on_session_state is not None:
                self.on_session_state(
                    plan.actor_id,
                    {
                        "storage_state": result.storage_state,
                        "tenant_id": plan.tenant_id,
                        "session_revision": revision,
                        "auth_evidence_ref": ref,
                    }
                    if result.outcome == "authenticated"
                    else None,
                )
            claimed = False
            return AdapterResult(
                "succeeded",
                "completed",
                summary={
                    "flow_id": flow_id,
                    "session_revision": revision,
                    "outcome": result.outcome,
                    "requests": result.requests,
                    "chromium_version": self.service.healthcheck()["chromium_version"],
                    "playwright_version": self.service.healthcheck()["playwright_version"],
                    "evidence_refs": [ref],
                },
            )
        except asyncio.CancelledError:
            raise
        except (ValueError, RuntimeError, OSError):
            return AdapterResult(
                "failed",
                "inconclusive" if claimed else "blocked",
                error=error_record(
                    "auth_flow_blocked_or_uncertain",
                    coverage_effect="inconclusive" if claimed else "blocked",
                    recovery_action="reconcile_auth_flow",
                ),
            )
        finally:
            self._active_task = None
            if claimed:
                with contextlib.suppress(RuntimeError, OSError):
                    self.store.auth_flows.uncertain(self.policy, job, flow_id)

    async def close_idle(self) -> None:
        await self.service.close()

    async def cancel(self) -> None:
        await self.service.close()

    async def cleanup(self) -> None:
        pass  # Each run closes its context; the shared admitted browser is reusable.
