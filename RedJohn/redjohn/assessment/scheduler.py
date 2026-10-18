"""Persistent fair job selection, fenced leases, bounded retries and cancellation."""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import math
import os
import sqlite3
import time
import uuid
from collections import Counter
from dataclasses import asdict, replace
from typing import TYPE_CHECKING, Any, TypedDict
from urllib.parse import urlsplit

from redjohn.assessment.egress import EgressUnavailable
from redjohn.assessment.intelligence import PerformanceMonitor
from redjohn.assessment.models import AdapterResult, JobSpec, error_record, stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.recovery import CircuitBreaker, FailureRecoverySystem, error_from_code
from redjohn.assessment.resources import ResourceAdmissionError, ResourceGovernor
from redjohn.assessment.store import AssessmentStore, CapacityExceeded, EvidenceWriteError


if TYPE_CHECKING:
    from collections.abc import Callable

    from redjohn.assessment.adapters import WorkerAdapter
    from redjohn.assessment.models import Surface
    from redjohn.assessment.registry import Capability, CapabilityRegistry


_TRANSIENT_HOST_CAPACITY = frozenset(
    {
        "host_browser_capacity_exhausted",
        "host_worker_capacity_exhausted",
        "host_page_capacity_exhausted",
        "host_context_capacity_exhausted",
        "host_memory_reservation_exhausted",
    }
)


class _PlannedJob(TypedDict):
    spec: dict[str, Any]
    score: float
    reasons: list[str]


class IntelligentDecisionEngine:
    """Deterministic permission/capability/input filters then explainable ranking."""

    def __init__(
        self, registry: CapabilityRegistry, *, weights: dict[str, float] | None = None
    ) -> None:
        self.registry = registry
        self.weights = weights or {"new_coverage": 4.0, "evidence": 2.0, "cost": 1.0}
        if set(self.weights) != {"new_coverage", "evidence", "cost"} or any(
            not isinstance(value, (float, int)) or not 0 <= value <= 10
            for value in self.weights.values()
        ):
            raise ValueError("invalid_decision_weights")

    def plan(  # noqa: PLR0912, PLR0915 - bounded deterministic routing
        self, store: AssessmentStore, policy: EngagementPolicy, *, limit: int = 16
    ) -> dict[str, Any]:
        if not 1 <= limit <= 64:
            raise ValueError("invalid_plan_limit")
        selected: list[_PlannedJob] = []
        rejected: list[dict[str, str]] = []
        health = {row["id"]: row for row in self.registry.health()}
        # Scan indexed pages rather than repeatedly planning the first surface.
        # The bounded cursor is engine state, independent of scheduler job state.
        cursor, inspected, scanned_end = store.planner_cursor(policy.engagement_id), 0, False
        surfaces: list[dict[str, Any]] = []
        while inspected < 512 and len(surfaces) < 512:
            page = store.surfaces(policy.engagement_id, limit=64, after=cursor)
            if not page:
                scanned_end = True
                break
            surfaces.extend(page)
            inspected += len(page)
            cursor = page[-1]["id"]
            if len(page) < 64:
                scanned_end = True
                break
        for surface in surfaces:
            for capability, family in (
                ("browser_discover", "discovery"),
                ("headers_audit", "configuration"),
                ("nuclei_scan", "known_vulnerability"),
                ("ffuf_discover", "content_discovery"),
                ("httpx_probe", "service_observation"),
                ("katana_discover", "endpoint_discovery"),
            ):
                entry = self.registry.get(capability)
                if entry is None:
                    raise RuntimeError("planner_capability_missing")
                reason = None
                try:
                    policy.check_scope_url(surface["url"])
                    policy.check_actor(surface["actor_id"])
                    policy.check_capability(domains=entry.domains, profiles=entry.profiles)
                except PolicyDenied as exc:
                    reason = str(exc)
                if surface["source"] != "observed":
                    reason = "requires_observed_input"
                elif surface["method"] != "GET":
                    if (
                        capability == "nuclei_scan"
                        and surface["method"] == "POST"
                        and surface.get("body_sha256")
                    ):
                        try:
                            policy.check_replay_request(surface["url"], surface["method"])
                            store.assert_session_revision(
                                policy, store.surface(policy.engagement_id, surface["id"])
                            )
                        except PolicyDenied as exc:
                            reason = str(exc)
                    else:
                        reason = "unsupported_input"
                elif health[capability]["status"].startswith("blocked_"):
                    reason = health[capability]["status"]
                elif (
                    capability not in {"browser_discover", "nuclei_scan"}
                    and surface["actor_id"] != "anonymous"
                ):
                    reason = "authenticated_replay_not_implemented"
                elif capability == "ffuf_discover" and (
                    not urlsplit(surface["url"]).path.endswith("/")
                    or urlsplit(surface["url"]).query
                    or urlsplit(surface["url"]).fragment
                    or surface["content_type"]
                ):
                    reason = "unsupported_input"
                if reason:
                    rejected.append(
                        {
                            "surface_id": surface["id"],
                            "capability": capability,
                            "reason": reason,
                            "coverage_status": "unsupported"
                            if "unsupported" in reason
                            else "blocked",
                        }
                    )
                    continue
                score = (
                    self.weights["new_coverage"]
                    + bool(surface["request_ref"]) * self.weights["evidence"]
                )
                score -= self.weights["cost"] * (2 if capability == "browser_discover" else 1)
                spec = JobSpec(
                    surface["id"],
                    family,
                    capability,
                    priority=max(score, 0),
                    idempotent=surface["method"] != "POST",
                    policy_revision=policy.revision,
                    **self.registry.execution_versions(capability),
                )
                if store.job_exists(policy.engagement_id, spec.key):
                    continue
                selected.append(
                    {
                        "spec": asdict(spec),
                        "score": score,
                        "reasons": ["new_family_coverage", "observed_input", "policy_allowed"],
                    }
                )
        # Start with least-served families, even across single-job plan calls.
        store.set_planner_cursor(policy.engagement_id, "" if scanned_end else cursor)
        served = store.family_order(policy.engagement_id)
        # Round robin across families before spending extra budget within a family.
        groups: dict[str, list[_PlannedJob]] = {}
        for item in sorted(
            selected, key=lambda item: (served.get(item["spec"]["family"], 0), -item["score"])
        ):
            groups.setdefault(item["spec"]["family"], []).append(item)
        ordered: list[_PlannedJob] = []
        while groups and len(ordered) < limit:
            for family in list(groups):
                ordered.append(groups[family].pop(0))
                if not groups[family]:
                    del groups[family]
                if len(ordered) == limit:
                    break
        return {
            "plan_ref": stable_key([policy.revision, ordered, rejected]),
            "jobs": ordered,
            "rejected": rejected[:64],
            "rejected_counts": dict(Counter(item["reason"] for item in rejected)),
            "next_surface_cursor": "" if scanned_end else cursor,
            "inventory_scan_partial": not scanned_end,
            "estimated_budget": {"jobs": len(ordered), "model_calls": 0},
            "prerequisites": ["current_policy", "egress_boundary", "actor_session"],
            "coverage_delta": sorted({x["spec"]["family"] for x in ordered}),
        }


class Scheduler:
    def __init__(
        self,
        store: AssessmentStore,
        policy: EngagementPolicy,
        governor: ResourceGovernor,
        registry: CapabilityRegistry,
        adapters: dict[str, WorkerAdapter],
        *,
        lease_seconds: float = 15,
        reconcile: Callable[[], None] | None = None,
    ) -> None:
        self.store, self.policy, self.governor = store, policy, governor
        self.registry, self.adapters = registry, adapters
        self.owner = uuid.uuid4().hex
        self.lease_seconds = lease_seconds
        self.reconcile = reconcile
        self._active: dict[str, tuple[asyncio.Task[AdapterResult], WorkerAdapter]] = {}
        self.metrics = Counter(model_calls=0, input_tokens=0, output_tokens=0, retries=0, jobs=0)
        self.recovery = FailureRecoverySystem(
            max_attempts=policy.max_attempts, retry_budget=policy.retry_budget
        )
        self.circuits = CircuitBreaker()
        self.monitor = PerformanceMonitor(entry.id for entry in registry._capabilities.values())

    async def run_until_idle(self, *, max_jobs: int = 16, wait_seconds: float = 0) -> list[str]:
        """Bounded draining, including durable jobs that become ready later.

        No worker/resource lease is held while waiting. The existing coordinator
        lock still serializes each batch across processes. Zero wait preserves
        the one-batch API; sleeping never authorizes additional jobs or retries.
        """
        if (
            type(max_jobs) is not int
            or not 1 <= max_jobs <= self.store.queue_max_items
            or isinstance(wait_seconds, bool)
            or not isinstance(wait_seconds, (float, int))
            or not math.isfinite(wait_seconds)
            or not 0 <= wait_seconds <= 120
        ):
            raise ValueError("invalid_scheduler_drain_budget")
        deadline = time.monotonic() + wait_seconds
        if self.policy.deadline:
            deadline = min(deadline, time.monotonic() + max(0, self.policy.deadline - time.time()))
        finished: list[str] = []
        while len(finished) < max_jobs:
            finished.extend(await self.run_batch(max_jobs=max_jobs - len(finished)))
            remaining = deadline - time.monotonic()
            if len(finished) >= max_jobs or remaining <= 0:
                break
            row = self.store.db.execute(
                "SELECT MIN(j.ready_at) FROM rj_job j JOIN rj_engagement e ON e.id=j.engagement "
                "WHERE j.engagement=? AND e.stopped=0 "
                "AND j.execution_status IN ('queued','retry_wait')",
                (self.policy.engagement_id,),
            ).fetchone()
            if row is None or row[0] is None:
                break
            await asyncio.sleep(min(remaining, 0.5, max(0.05, row[0] - time.time())))
        return finished

    def _reconcile_followups(self) -> None:
        if self.reconcile is None:
            return
        try:
            self.reconcile()
        except Exception:  # noqa: BLE001 - continuation failure cannot retry a mutating parent
            self.metrics["followup_errors"] += 1
            try:
                self.store.record_followup_error(self.policy, None, "workflow_reconciliation_error")
            except Exception:  # noqa: BLE001 - unavailable audit storage cannot change parent outcome
                self.metrics["followup_audit_errors"] += 1

    async def _close_idle_browsers(self) -> None:
        """Release retained browser workers before admitting another tool class."""
        closed: set[int] = set()
        for capability, adapter in self.adapters.items():
            entry = self.registry.get(capability)
            if entry is None or entry.resource_class != "browser" or id(adapter) in closed:
                continue
            closed.add(id(adapter))
            close_idle = getattr(adapter, "close_idle", None)
            if close_idle is not None:
                await asyncio.wait_for(close_idle(), timeout=15)

    async def _heartbeat(self, job: dict[str, Any], task: asyncio.Task[Any]) -> None:
        while not task.done():
            await asyncio.sleep(max(0.02, self.lease_seconds / 3))
            if not self.store.heartbeat(job["id"], self.owner, job["attempt"], self.lease_seconds):
                task.cancel()
                return
            self.governor.sample()
            if self.governor.snapshot()["pressure"] == "high":
                task.cancel()
                return

    async def _execute(self, job: dict[str, Any]) -> AdapterResult:  # noqa: PLR0911, PLR0912, PLR0915 - explicit state boundaries
        execution_started = time.monotonic()
        spec = JobSpec(**json.loads(job["spec"]))
        surface = self.store.surface(self.policy.engagement_id, spec.surface_id)
        entry = self.registry.get(spec.capability)
        adapter = self.adapters.get(spec.capability)
        if (
            spec.capability
            in {
                "session_refresh",
                "browser_post_capture",
                "ffuf_discover",
                "httpx_probe",
                "katana_discover",
                "vulnx_intelligence",
                "arjun_parameters",
                "sqlmap_validate",
                "dalfox_validate",
                "browser_xss_confirmation",
                "tinja_validate",
                "schemathesis_validate",
                "oast_correlate",
                "oast_poll",
            }
            and adapter is None
        ):
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    f"{spec.capability}_configuration_missing",
                    category="capability",
                    coverage_effect="blocked",
                ),
            )
        if entry is None or not entry.adapter_implemented or adapter is None:
            return AdapterResult(
                "failed",
                "unsupported",
                error=error_record(
                    "adapter_not_implemented", category="capability", coverage_effect="unsupported"
                ),
            )
        if spec.policy_revision != self.policy.revision:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    "stale_policy_revision", category="policy", coverage_effect="blocked"
                ),
            )
        self._authorize_surface(entry, surface)
        with self.store._lock:
            self.store.inventory.require_surface_active(self.store.db, self.policy, spec.surface_id)
        if (
            surface.method not in {"GET", "HEAD", "OPTIONS"}
            or spec.capability in {"browser_post_capture", "session_refresh"}
        ) and spec.idempotent:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    spec.capability + "_requires_nonidempotent_job"
                    if spec.capability in {"browser_post_capture", "session_refresh"}
                    else "post_replay_requires_nonidempotent_job",
                    coverage_effect="blocked",
                ),
            )
        circuit_key = stable_key([spec.capability, self.policy.resource_identity(surface)])
        if not self.circuits.allow(circuit_key):
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    "circuit_open", category="availability", coverage_effect="blocked"
                ),
            )
        lease = None
        has_prepare = False
        # BrowserService owns its process/page/context leases; no double charge.
        if entry.resource_class != "browser":
            try:
                # This coordinator executes jobs sequentially. A completed
                # browser job may retain Chromium and its worker lease, which
                # would otherwise block the next scanner with max_workers=1.
                await self._close_idle_browsers()
            except Exception:  # noqa: BLE001 - cleanup failure must prevent another process launch
                return AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record(
                        "browser_idle_cleanup_failed",
                        category="resource",
                        coverage_effect="blocked",
                    ),
                )
            prepare = getattr(adapter, "prepare", None)
            if callable(prepare):
                has_prepare = True
                prepare_task = asyncio.create_task(prepare(job, surface, spec))
                prepare_heartbeat = asyncio.create_task(self._heartbeat(job, prepare_task))
                try:
                    prepare_timeout = min(
                        spec.timeout_seconds - (time.monotonic() - execution_started), 15.0
                    )
                    if self.policy.deadline:
                        prepare_timeout = min(prepare_timeout, self.policy.deadline - time.time())
                    await asyncio.wait_for(prepare_task, timeout=max(0.0, prepare_timeout))
                except (PolicyDenied, EgressUnavailable, ResourceAdmissionError, CapacityExceeded):
                    raise
                except TimeoutError:
                    return AdapterResult(
                        "timed_out",
                        "inconclusive",
                        error=error_record(
                            "adapter_prepare_timeout",
                            category="timeout",
                            coverage_effect="inconclusive",
                        ),
                    )
                except Exception as exc:  # noqa: BLE001 - unknown admission failure blocks dispatch
                    return AdapterResult(
                        "failed",
                        "blocked",
                        error=error_record(
                            "adapter_prepare_failed",
                            category="capability",
                            cause_ref=type(exc).__name__,
                            coverage_effect="blocked",
                        ),
                    )
                finally:
                    prepare_heartbeat.cancel()
                    await asyncio.gather(prepare_heartbeat, return_exceptions=True)
            owner_only = (
                entry.owner_process_only and getattr(adapter, "owner_process_only", False) is True
            )
            memory = self.governor.envelope.worker_memory_budget
            dispatch_memory = getattr(adapter, "dispatch_memory_bytes", None)
            if owner_only and type(dispatch_memory) is int and 0 <= dispatch_memory <= memory:
                # Trusted adapter's child already holds its full context lease;
                # this dispatch accounts only for host parser/frame overhead.
                memory = dispatch_memory
            lease = self.governor.acquire(
                kind=entry.resource_class,
                estimated_bytes=memory,
                owner_process_only=owner_only,
                cleanup_guard=getattr(adapter, "resource_cleanup_verified", None),
            )
        try:
            # Preserve established dispatch timing for adapters without a
            # preparation phase. The new prepare+dispatch path shares one clock.
            if not has_prepare:
                execution_started = time.monotonic()
            timeout = spec.timeout_seconds - (time.monotonic() - execution_started)
            if self.policy.deadline:
                timeout = min(timeout, self.policy.deadline - time.time())
            if timeout <= 0:
                await adapter.cancel()
                await adapter.cleanup()
                return AdapterResult(
                    "timed_out",
                    "inconclusive",
                    error=error_record(
                        "adapter_prepare_timeout" if has_prepare else "timeout", category="timeout"
                    ),
                )
            task = asyncio.create_task(adapter.run(job, surface, spec))
            self._active[job["id"]] = (task, adapter)
            heartbeat = asyncio.create_task(self._heartbeat(job, task))
            try:
                return await asyncio.wait_for(task, timeout=timeout)
            except asyncio.CancelledError:
                await adapter.cancel()
                partial_refs = list(getattr(adapter, "partial_evidence_refs", ()))
                current_task = asyncio.current_task()
                if current_task is not None and current_task.cancelling():
                    self.store.cancel(self.policy.engagement_id)
                if self.governor.snapshot()["pressure"] == "high":
                    return AdapterResult(
                        "resource_exhausted",
                        "partial",
                        summary={"evidence_refs": partial_refs},
                        error={
                            **error_record(
                                "resource_exhausted", category="resource", coverage_effect="partial"
                            ),
                            "partial_evidence_refs": partial_refs,
                        },
                    )
                return AdapterResult(
                    "cancelled",
                    "partial",
                    summary={"evidence_refs": partial_refs},
                    error={
                        **error_record("cancelled", coverage_effect="partial"),
                        "partial_evidence_refs": partial_refs,
                    },
                )
            except TimeoutError:
                await adapter.cancel()
                partial_refs = list(getattr(adapter, "partial_evidence_refs", ()))
                return AdapterResult(
                    "timed_out",
                    "inconclusive",
                    summary={"evidence_refs": partial_refs},
                    error={
                        **error_record(
                            "timeout",
                            category="timeout",
                            retryable=spec.idempotent,
                            terminal=not spec.idempotent,
                            recovery_action="retry_safe" if spec.idempotent else "reconcile",
                        ),
                        "partial_evidence_refs": partial_refs,
                    },
                )
            finally:
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)
                self._active.pop(job["id"], None)
                await adapter.cleanup()
        finally:
            if lease is not None:
                lease.release()

    async def run_batch(self, *, max_jobs: int | None = None) -> list[str]:
        # Cross-process exclusion: two CLI/coordinator instances cannot bypass a
        # shared worker budget by each constructing a separate local governor.
        path = self.store.path.with_name(self.store.path.name + ".assessment.lock")
        descriptor = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        acquired = False
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CapacityExceeded("coordinator_already_running") from exc
            acquired = True
            return await self._run_batch_locked(max_jobs=max_jobs)
        finally:
            try:
                if acquired:
                    for adapter in self.adapters.values():
                        close_idle = getattr(adapter, "close_idle", None)
                        if close_idle is not None:
                            await asyncio.wait_for(close_idle(), timeout=15)
            finally:
                os.close(descriptor)

    def _authorize_surface(self, entry: Capability, surface: Surface) -> None:
        self.policy.check_capability(domains=entry.domains, profiles=entry.profiles)
        self.policy.check_actor(surface.actor_id)
        self.policy.check_surface(surface)
        if surface.resource_kind == "source_artifact":
            if "source" not in entry.domains:
                raise PolicyDenied("source_artifact_capability_mismatch")
            self.store.inventory.require_source_asset(
                self.policy, surface.asset_ref, surface.artifact_sha256
            )
        elif surface.resource_kind in {"network_endpoint", "dns_name"}:
            if "network" not in entry.domains:
                raise PolicyDenied("network_capability_mismatch")
            if surface.resource_kind == "network_endpoint":
                self.store.inventory.require_network_asset(
                    self.policy, surface.asset_ref, surface.network_address
                )
            else:
                self.store.inventory.require_dns_asset(
                    self.policy, surface.asset_ref, surface.dns_name
                )
        elif entry.domains in {("source",), ("network",)}:
            raise PolicyDenied("source_artifact_resource_required")

    def _resource_denial(
        self,
        error: ResourceAdmissionError | CapacityExceeded,
        requests_before: int | None,
    ) -> AdapterResult:
        before_send = False
        if isinstance(error, ResourceAdmissionError) and str(error) in _TRANSIENT_HOST_CAPACITY:
            # Unverified delivery cannot authorize a retry.
            with contextlib.suppress(CapacityExceeded, PolicyDenied, sqlite3.Error):
                before_send = requests_before == self.store.request_usage(self.policy)
        return AdapterResult(
            "resource_exhausted",
            "blocked",
            error=error_record(
                "host_resource_busy" if before_send else "resource_exhausted",
                category="resource",
                coverage_effect="blocked",
                retryable=before_send,
                terminal=not before_send,
                retry_after=2.0 if before_send else None,
            ),
        )

    def _retry_delay(
        self,
        job: dict[str, Any],
        result: AdapterResult,
        spec: JobSpec,
    ) -> float | None:
        if (
            result.error
            and result.error.get("code") in {"rate_limited", "host_resource_busy"}
            and not result.summary.get("requests")
            and spec.idempotent
            and job["attempt"] < self.policy.max_attempts
        ):
            decision = self.recovery.plan(
                error_from_code(result.error["code"], retry_after=result.error.get("retry_after")),
                attempt=job["attempt"],
                idempotent=True,
                deadline=time.monotonic() + max(0, self.policy.deadline - time.time())
                if self.policy.deadline
                else time.monotonic() + 600,
            )
            if decision.retry and self.store.retry_charge(self.policy):
                self.metrics["retries"] += 1
                return decision.delay
        return None

    async def _run_batch_locked(self, *, max_jobs: int | None = None) -> list[str]:
        max_jobs = min(16, self.store.queue_max_items) if max_jobs is None else max_jobs
        if not 1 <= max_jobs <= self.store.queue_max_items:
            raise ValueError("invalid_batch_limit")
        self.store.recover_expired(self.policy)
        finished = []
        self._reconcile_followups()
        for _ in range(max_jobs):
            job = self.store.claim(self.policy, self.owner, lease_seconds=self.lease_seconds)
            if job is None:
                break
            started = time.monotonic()
            requests_before = None
            try:
                requests_before = self.store.request_usage(self.policy)
                result = await self._execute(job)
            except PolicyDenied as exc:
                result = AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record(str(exc), category="policy", coverage_effect="blocked"),
                )
            except (ResourceAdmissionError, CapacityExceeded) as exc:
                result = self._resource_denial(exc, requests_before)
            except EvidenceWriteError:
                result = AdapterResult(
                    "failed",
                    "inconclusive",
                    error=error_record(
                        "evidence_write_failed",
                        category="storage",
                        recovery_action="stop_evidence_work",
                    ),
                )
                self.store.cancel(self.policy.engagement_id)
            except EgressUnavailable as exc:
                result = AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record(
                        str(exc).partition(":")[0], category="capability", coverage_effect="blocked"
                    ),
                )
            except asyncio.CancelledError:
                self.store.cancel(self.policy.engagement_id)
                result = AdapterResult(
                    "cancelled",
                    "partial",
                    error=error_record("cancelled", coverage_effect="partial"),
                )
            except Exception as exc:  # noqa: BLE001 - worker bulkhead normalizes unknown failures
                # Stable safe code; no raw target content/credentials/stack in API.
                result = AdapterResult(
                    "failed",
                    "inconclusive",
                    error=error_record(
                        "adapter_execution_error",
                        category="execution",
                        cause_ref=type(exc).__name__,
                    ),
                )
            elapsed = time.monotonic() - started
            surface = self.store.surface(self.policy.engagement_id, job["surface_id"])
            if not result.error or (
                result.error.get("code") != "circuit_open"
                and result.error.get("category") != "resource"
            ):
                self.circuits.record(
                    stable_key([job["capability"], self.policy.resource_identity(surface)]),
                    success=result.execution_status == "succeeded"
                    or (result.error or {}).get("category")
                    in {"policy", "capability", "input", "permission", "auth", "rate_limit"},
                )
            result = AdapterResult(
                result.execution_status,
                result.coverage_status,
                {
                    **result.summary,
                    "duration_seconds": elapsed,
                    "queue_wait_seconds": max(0, job["started_at"] or time.time())
                    - job["created_at"],
                },
                result.findings,
                result.error,
            )
            spec = JobSpec(**json.loads(job["spec"]))
            # Only proven pre-send admission failures may enter bounded retry.
            retry_after = self._retry_delay(job, result, spec)
            if (
                result.error
                and result.error.get("code") == "host_resource_busy"
                and retry_after is None
            ):
                result = replace(
                    result,
                    error={
                        **result.error,
                        "retryable": False,
                        "terminal": True,
                        "retry_after": None,
                        "recovery_action": "stop",
                    },
                )
            try:
                self.store.finish(job, result, retry_after=retry_after)
            except EvidenceWriteError:
                # Large adapter responses must not leave a successful coverage row.
                result = AdapterResult(
                    "failed",
                    "inconclusive",
                    error=error_record("evidence_write_failed", category="storage"),
                )
                self.store.finish(job, result)
                self.store.cancel(self.policy.engagement_id)
            self.monitor.record(
                job["capability"],
                "execution",
                duration=elapsed,
                queue_wait=max(0, job["started_at"] - job["created_at"]),
                requests=int(result.summary.get("requests") or 0),
                errors=int(result.execution_status != "succeeded"),
                retries=int(retry_after is not None),
                new_inputs=len(result.summary.get("surface_ids", ())),
                candidate_findings=len(result.findings),
                peak_memory_bytes=self.governor.peak_rss_bytes,
            )
            self.metrics["jobs"] += 1
            finished.append(job["id"])
            # Also publish children after the final execution slot. Their
            # durable queue entries survive the bounded batch without launching
            # extra optional tools or exceeding max_jobs.
            self._reconcile_followups()
        return finished

    async def cancel(self, job_id: str | None = None) -> int:
        count = self.store.cancel(self.policy.engagement_id, job_id)
        for active_id, (task, adapter) in tuple(self._active.items()):
            if job_id is None or job_id == active_id:
                task.cancel()
                await adapter.cancel()
        return count
