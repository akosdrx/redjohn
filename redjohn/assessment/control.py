"""Caller-bound, size-bounded control API; no server, arbitrary shell or URL fetch."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, overload

from redjohn.assessment.cache import SmartCache
from redjohn.assessment.inventory import INVENTORY_OPERATIONS, InventoryConflictError
from redjohn.assessment.models import JobSpec, Surface, error_record, stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.resources import ResourceAdmissionError, ResourceGovernor
from redjohn.assessment.scheduler import IntelligentDecisionEngine, Scheduler
from redjohn.assessment.store import AssessmentStore, CapacityExceeded, redact
from redjohn.assessment.workflow_execution import reviewed_step


if TYPE_CHECKING:
    from collections.abc import Callable


@overload
def public_view(value: dict[str, Any]) -> dict[str, Any]: ...


@overload
def public_view(value: object) -> object: ...


def public_view(value: object) -> object:
    return redact(value)


class AssessmentControl:
    """The host binds caller identity. Client engagement IDs never grant access."""

    def __init__(
        self,
        store: AssessmentStore,
        policy: EngagementPolicy,
        *,
        caller: str,
        governor: ResourceGovernor | None = None,
        registry: CapabilityRegistry | None = None,
        scheduler: Scheduler | None = None,
    ) -> None:
        self.store, self.policy, self.caller = store, policy, caller
        self.governor = governor or ResourceGovernor()
        self.registry = registry or CapabilityRegistry()
        self.scheduler = scheduler
        self.engine = IntelligentDecisionEngine(self.registry)
        self.cache = SmartCache(self.governor.envelope.cache_max_bytes, max_items=64)
        self.runtime_status: Callable[[], dict[str, Any]] | None = None
        self.submission_admission: Callable[[], None] | None = None
        self.policy_admission: Callable[[EngagementPolicy], None] | None = None
        self.auth_plan_ids: tuple[str, ...] = ()
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.cache.close()

    def _submitted_job(self, policy: EngagementPolicy, submitted: dict[str, Any]) -> JobSpec:
        value = dict(submitted)
        surface = self.store.surface(policy.engagement_id, value.get("surface_id", ""))
        if surface.method not in {"GET", "HEAD", "OPTIONS"} or value.get("capability") in {
            "session_refresh",
            "browser_post_capture",
        }:
            if value.get("idempotent") is True:
                raise PolicyDenied("mutating_job_requires_nonidempotent_execution")
            value.setdefault("idempotent", False)
        for key, version in self.registry.execution_versions(value.get("capability", "")).items():
            if value.get(key, "") in {"", "1"}:
                value[key] = version
        return JobSpec(**value)

    def _auth_call(
        self, policy: EngagementPolicy, operation: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        required = {
            "auth_plan_search": set(),
            "auth_flow_start": {"plan_id", "run_key"},
            "auth_flow_get": {"flow_id"},
            "auth_flow_submit": {"flow_id", "expected_revision"},
        }[operation]
        if set(args) != required or any(
            (type(value) is not int or value < 1)
            if key == "expected_revision"
            else (not isinstance(value, str) or not 1 <= len(value) <= 128)
            for key, value in args.items()
        ):
            raise ValueError("invalid_auth_control_fields")
        if operation == "auth_plan_search":
            with self.store._lock:
                rows = self.store.db.execute(
                    "SELECT id,payload FROM rj_auth_plan WHERE engagement=? AND "
                    "policy_revision=? ORDER BY id LIMIT 64",
                    (policy.engagement_id, policy.revision),
                ).fetchall()
            return {
                "items": [
                    {"plan_id": row["id"], **json.loads(row["payload"])}
                    for row in rows
                    if row["id"] in self.auth_plan_ids
                ]
            }
        if operation == "auth_flow_start":
            if args["plan_id"] not in self.auth_plan_ids:
                raise PolicyDenied("auth_plan_not_currently_configured")
            return {
                "flow_id": self.store.auth_flows.start(policy, args["plan_id"], args["run_key"])
            }
        flow = self.store.auth_flows.get(policy, args["flow_id"])
        if operation == "auth_flow_get":
            return flow
        if flow["plan_id"] not in self.auth_plan_ids:
            raise PolicyDenied("auth_plan_not_currently_configured")
        if self.submission_admission is not None:
            self.submission_admission()
        if flow["revision"] != args["expected_revision"] or flow["status"] not in {
            "prepared",
            "awaiting_input",
        }:
            raise InventoryConflictError("auth_flow_requires_reconciliation")
        plan = self.store.auth_flows.plan(policy, flow["plan_id"])
        sid = self.store.upsert_surface(
            policy.engagement_id,
            Surface(
                plan.actions[0].url,
                actor_id=plan.actor_id,
                tenant_id=plan.tenant_id,
                session_revision=flow["from_revision"],
                source="imported",
                workflow_state="approved_seed",
            ),
        )
        spec = JobSpec(
            sid,
            "auth",
            "browser_auth_flow",
            policy_revision=policy.revision,
            idempotent=False,
            options={"flow_id": args["flow_id"], "expected_revision": args["expected_revision"]},
            **self.registry.execution_versions("browser_auth_flow"),
        )
        return {"job_ids": self.store.submit(policy, [spec])}

    async def call(  # noqa: PLR0912, PLR0915 - explicit bounded API dispatch
        self, operation: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        arguments = {} if arguments is None else arguments
        result: dict[str, Any]
        if self._closed:
            return {
                "ok": False,
                "error": error_record(
                    "engagement_runtime_closed", category="resource", coverage_effect="blocked"
                ),
            }
        try:
            if not isinstance(arguments, dict) or len(json.dumps(arguments).encode()) > 65536:
                raise ValueError("invalid_api_input_size")  # noqa: TRY301 - normalize at this API boundary
            current = self.store.policy(self.policy.engagement_id, self.caller)
            current.authorize(self.caller)
            if self.policy_admission is not None:
                self.policy_admission(current)
            if (
                "policy_revision" not in arguments
                or arguments["policy_revision"] != current.revision
            ):
                raise PolicyDenied("stale_policy_revision")  # noqa: TRY301 - normalize at this API boundary
            args = {k: v for k, v in arguments.items() if k != "policy_revision"}
            if operation == "surface_search":
                if set(args) - {
                    "limit",
                    "after",
                    "actor_id",
                    "tenant_id",
                    "session_revision",
                    "method",
                    "source",
                    "workflow_state",
                    "asset_id",
                }:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                result = {"items": self.store.surfaces(current.engagement_id, **args)}
            elif operation == "surface_get":
                if set(args) != {"surface_id"}:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                result = asdict(self.store.surface(current.engagement_id, args["surface_id"]))
            elif operation in {
                "auth_plan_search",
                "auth_flow_start",
                "auth_flow_get",
                "auth_flow_submit",
            }:
                result = self._auth_call(current, operation, args)
            elif operation == "workflow_submit_step":
                if self.submission_admission is not None:
                    self.submission_admission()
                if set(args) != {"instance_id", "step_name", "surface_id", "expected_revision"}:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - bounded dispatch
                reviewed_step(
                    self.store,
                    current,
                    args["instance_id"],
                    args["step_name"],
                    args["surface_id"],
                    args["expected_revision"],
                )
                spec = JobSpec(
                    args["surface_id"],
                    "workflow",
                    "workflow_execute",
                    policy_revision=current.revision,
                    idempotent=False,
                    options={
                        name: args[name]
                        for name in ("instance_id", "step_name", "expected_revision")
                    },
                    **self.registry.execution_versions("workflow_execute"),
                )
                result = {"job_ids": self.store.submit(current, [spec])}
            elif operation in INVENTORY_OPERATIONS:
                result = self.store.inventory.control_call(
                    current, operation, args, owner=stable_key([self.caller, current.engagement_id])
                )
            elif operation == "plan_next_batch":
                if set(args) - {"limit"}:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                result = self.engine.plan(self.store, current, **args)
            elif operation == "jobs_submit_batch":
                if self.submission_admission is not None:
                    self.submission_admission()
                if (
                    set(args) != {"jobs"}
                    or not isinstance(args["jobs"], list)
                    or len(args["jobs"]) > 64
                ):
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                specs = [self._submitted_job(current, value) for value in args["jobs"]]
                for spec in specs:
                    entry = self.registry.get(spec.capability)
                    if entry is None or not entry.adapter_implemented:
                        raise ValueError("adapter_not_implemented")  # noqa: TRY301 - normalize at this API boundary
                    current.check_capability(domains=entry.domains, profiles=entry.profiles)
                result = {"job_ids": self.store.submit(current, specs)}
            elif operation == "jobs_get_status":
                if set(args) - {"limit", "after"}:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                result = {"items": self.store.jobs(current.engagement_id, **args)}
            elif operation == "jobs_cancel":
                if set(args) - {"job_id"}:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                count = (
                    await self.scheduler.cancel(**args)
                    if self.scheduler
                    else self.store.cancel(current.engagement_id, **args)
                )
                result = {"cancel_requested": count}
            elif operation == "evidence_get":
                if set(args) - {"ref", "max_bytes"} or "ref" not in args:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                result = self.store.evidence_get(current.engagement_id, **args)
            elif operation == "coverage_get":
                if args:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                result = {
                    "items": self.store.coverage(current.engagement_id),
                    "source": "machine_observed",
                }
            elif operation == "findings_get":
                if set(args) - {"limit", "after"}:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                result = {"items": self.store.findings(current.engagement_id, **args)}
            elif operation == "system_health":
                if args:
                    raise ValueError("invalid_api_fields")  # noqa: TRY301 - normalize at this API boundary
                self.governor.sample()
                result = {
                    "capabilities": self.registry.health(),
                    "resources": self.governor.snapshot(),
                    "cache": self.cache.stats(),
                    "egress_mode": current.egress_mode,
                    "remote_egress": "requires_attested_linux_workers",
                }
                if self.runtime_status is not None:
                    result["controller"] = self.runtime_status()
            else:
                raise ValueError("unsupported_api_operation")  # noqa: TRY301 - normalize at this API boundary
            result = {"ok": True, "operation": operation, "result": public_view(result)}
            if len(json.dumps(result).encode()) > 65536:
                result = {
                    "ok": False,
                    "error": error_record(
                        "response_size_exceeded", recovery_action="reduce_page_limit"
                    ),
                }
        except PolicyDenied:
            result = {
                "ok": False,
                "error": error_record(
                    "policy_denied", category="policy", coverage_effect="blocked"
                ),
            }
        except InventoryConflictError:
            result = {
                "ok": False,
                "error": error_record(
                    "inventory_state_conflict",
                    category="state",
                    coverage_effect="blocked",
                    recovery_action="reconcile_or_reload_current_revision",
                ),
            }
        except ResourceAdmissionError:
            result = {
                "ok": False,
                "error": error_record(
                    "host_controller_unavailable", category="resource", coverage_effect="blocked"
                ),
            }
        except (ValueError, TypeError, KeyError, CapacityExceeded) as exc:
            code = (
                "queue_capacity_exhausted"
                if isinstance(exc, CapacityExceeded)
                else "invalid_api_input"
            )
            result = {
                "ok": False,
                "error": error_record(code, category="input", coverage_effect="unsupported"),
            }
        # Denied cross-engagement calls are also auditable, without client text.
        with self.store.transaction() as db:
            self.store._audit(
                db,
                self.policy.engagement_id,
                "control_call",
                {
                    "operation": operation
                    if operation
                    in INVENTORY_OPERATIONS
                    | {
                        "auth_plan_search",
                        "auth_flow_start",
                        "auth_flow_get",
                        "auth_flow_submit",
                        "workflow_submit_step",
                        "surface_search",
                        "surface_get",
                        "plan_next_batch",
                        "jobs_submit_batch",
                        "jobs_get_status",
                        "jobs_cancel",
                        "evidence_get",
                        "coverage_get",
                        "findings_get",
                        "system_health",
                    }
                    else "unknown",
                    "ok": result["ok"],
                },
            )
        return result
