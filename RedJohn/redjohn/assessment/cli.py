"""Reproducible RedJohn assessment CLI, independent of model/provider startup."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import statistics
import time
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.configuration import ConfiguredAssessment, load_configuration
from redjohn.assessment.fixture import FixtureServer
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.os_memory import MemoryLimitExceededError
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.report import build_report, write_report
from redjohn.assessment.resources import (
    ResourceAdmissionError,
    ResourceEnvelope,
    process_tree_memory,
)
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore


if TYPE_CHECKING:
    from redjohn.assessment.os_memory import LinuxMemoryBoundary


_PUBLIC_POLICY_REASONS = frozenset(
    {
        "campaign_deadline_exceeded",
        "policy_change_requires_new_revision",
        "policy_revision_reuse_denied",
        "stale_policy_revision",
        "engagement_access_denied",
        "engagement_stopped",
        "native_session_proxy_binding_busy",
        "remote_egress_boundary_required",
        "blocked_egress_enforcement_unavailable",
        "origin_denied",
        "surface_access_denied",
    }
)

_PUBLIC_RESOURCE_REASONS = frozenset(
    {
        "linux_cgroup_v2_required",
        "memory_and_pids_controllers_not_delegated",
        "os_memory_delegation_unavailable",
        "os_memory_cleanup_not_verified",
        "os_memory_limit_readback_mismatch",
        "os_memory_membership_not_enforced",
        "host_owner_lost_requires_recovery",
        "host_memory_reservation_exhausted",
        "host_memory_measurement_unavailable",
        "host_resource_store_unavailable",
        "host_resource_directory_not_private",
        "host_resource_store_not_private",
        "host_owner_identity_unavailable",
        "resource_leases_still_active",
        "os_memory_limit_exceeded",
        "contained_controller_failed",
        "host_resource_policy_busy",
        "host_resource_policy_invalid",
    }
)


def load_config(path: Path) -> dict[str, Any]:
    return load_configuration(path)


def _validate_scheduler_budget(
    envelope: ResourceEnvelope,
    max_jobs: int,
    wait_ready_seconds: float,
) -> None:
    if (
        type(max_jobs) is not int
        or not 1 <= max_jobs <= envelope.queue_max_items
        or isinstance(wait_ready_seconds, bool)
        or not isinstance(wait_ready_seconds, (int, float))
        or not math.isfinite(wait_ready_seconds)
        or not 0 <= wait_ready_seconds <= 120
    ):
        raise ValueError("invalid_scheduler_drain_budget")


async def configured_run(
    config: dict[str, Any], output: Path, *, max_jobs: int = 16, wait_ready_seconds: float = 0
) -> dict[str, Any]:
    if "os_memory" not in config:
        return await _configured_run(
            config, output, max_jobs=max_jobs, wait_ready_seconds=wait_ready_seconds
        )
    from redjohn.assessment.os_memory import LinuxMemoryBoundary  # noqa: PLC0415 - explicit opt-in

    envelope = ResourceEnvelope(**config.get("resources", {}))
    _validate_scheduler_budget(envelope, max_jobs, wait_ready_seconds)
    current = LinuxMemoryBoundary.current(config["os_memory"], envelope.total_memory_budget)
    if current is not None:
        with current:
            return await _configured_run(
                config,
                output,
                max_jobs=max_jobs,
                wait_ready_seconds=wait_ready_seconds,
                os_boundary=current,
            )
    from redjohn.assessment.contained_controller import (  # noqa: PLC0415
        contained_run,
        record_resource_failure,
    )

    try:
        with LinuxMemoryBoundary(config["os_memory"], envelope.total_memory_budget) as boundary:
            return await contained_run(
                config,
                output,
                boundary,
                max_jobs=max_jobs,
                wait_ready_seconds=wait_ready_seconds,
            )
    except MemoryLimitExceededError as exc:
        record_resource_failure(config, output, exc)
        raise


async def _configured_run(
    config: dict[str, Any],
    output: Path,
    *,
    max_jobs: int = 16,
    wait_ready_seconds: float = 0,
    os_boundary: LinuxMemoryBoundary | None = None,
) -> dict[str, Any]:
    policy = EngagementPolicy.from_mapping(config["policy"])
    envelope = ResourceEnvelope(**config.get("resources", {}))
    _validate_scheduler_budget(envelope, max_jobs, wait_ready_seconds)
    async with ConfiguredAssessment(config, output, caller=policy.owner_id) as configured:
        runtime, store = configured.runtime, configured.store
        await runtime.scheduler.run_until_idle(max_jobs=max_jobs, wait_seconds=wait_ready_seconds)
        metrics = configured.metrics(os_boundary=os_boundary)
        report = build_report(
            store, policy.engagement_id, metrics=metrics, registry=runtime.registry
        )
        write_report(output, report)
        return report


async def demo(output: Path, *, cycles: int = 5) -> dict[str, Any]:
    if not 1 <= cycles <= 1000:
        raise ValueError("cycles_must_be_1_to_1000")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    started = time.monotonic()
    before = process_tree_memory()
    with FixtureServer() as fixture:
        policy = EngagementPolicy(
            engagement_id=f"local-demo-{time.time_ns()}",
            owner_id="local-operator",
            allowed_origins=(fixture.origin,),
            allowed_ips=("127.0.0.1/32",),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice", "bob"),
            request_budget=max(128, cycles * 12),
            deadline=time.time() + 600,
        )
        envelope = ResourceEnvelope(queue_max_items=max(128, min(3000, cycles * 3)))
        store = AssessmentStore(
            output / ".state" / "agents.db", queue_max_items=envelope.queue_max_items
        )
        try:
            async with AssessmentRuntime(
                store,
                policy,
                caller=policy.owner_id,
                envelope=envelope,
                actor_states={actor: fixture.actor_state(actor) for actor in ("alice", "bob")},
            ) as runtime:
                durations, memory, finished = [], [], []
                for index in range(cycles):
                    actor = "alice" if index % 2 == 0 else "bob"
                    surface_id = store.upsert_surface(
                        policy.engagement_id,
                        Surface(
                            fixture.origin + "/",
                            actor_id=actor,
                            session_revision="1",
                            source="imported",
                            workflow_state="approved_seed",
                        ),
                    )
                    spec = JobSpec(
                        surface_id,
                        "discovery",
                        "browser_discover",
                        retest_revision=str(index),
                        policy_revision=policy.revision,
                    )
                    store.submit(policy, [spec])
                    tick = time.monotonic()
                    finished.extend(await runtime.scheduler.run_batch(max_jobs=1))
                    durations.append(time.monotonic() - tick)
                    memory.append(asdict(process_tree_memory()))
                anon_surface = store.upsert_surface(
                    policy.engagement_id,
                    Surface(
                        fixture.origin + "/api/items",
                        source="imported",
                        workflow_state="approved_seed",
                    ),
                )
                initial = JobSpec(anon_surface, "configuration", "headers_audit")
                nuclei = JobSpec(anon_surface, "known_vulnerability", "nuclei_scan")
                ids = store.submit(policy, [initial, nuclei])
                finished.extend(await runtime.scheduler.run_batch(max_jobs=2))
                duplicate_ids = store.submit(policy, [initial, nuclei])
                assert ids == duplicate_ids
                fixture.fixed = True
                retest = JobSpec(
                    anon_surface, "configuration", "headers_audit", retest_revision="fixed-deploy-2"
                )
                store.submit(policy, [retest])
                finished.extend(await runtime.scheduler.run_batch(max_jobs=1))
                health_before = runtime.browser.healthcheck()
                report = build_report(
                    store, policy.engagement_id, metrics=dict(runtime.scheduler.metrics)
                )
                await runtime.browser.close()
                after = asdict(process_tree_memory())
                metrics = {
                    "measurement": "actual_local_chromium_and_http; nuclei_missing_is_blocked",
                    "cycles": cycles,
                    "elapsed_seconds": time.monotonic() - started,
                    "cycle_seconds": durations,
                    "p50_seconds": statistics.median(durations),
                    "p95_seconds": sorted(durations)[max(0, math.ceil(len(durations) * 0.95) - 1)],
                    "http_requests": sum(fixture.counts.values()),
                    "fixture_request_counts": dict(fixture.counts),
                    "process_memory_before": asdict(before),
                    "process_memory_samples": memory,
                    "process_memory_after": after,
                    "peak_memory_bytes": max(
                        runtime.governor.peak_rss_bytes, *(x["rss_bytes"] for x in memory)
                    ),
                    "resource_snapshot": runtime.governor.snapshot(),
                    "browser_health_before_close": health_before,
                    "performance": runtime.scheduler.monitor.snapshot(),
                    "browser_health_after_close": runtime.browser.healthcheck(),
                    "model_calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "model_cost": 0,
                    "cache": runtime.control.cache.stats(),
                    "deduplicated_jobs": 2,
                    "repeated_jobs_without_explicit_retest": 0,
                    "explicit_retests": sum(
                        bool(job["spec"]["retest_revision"]) for job in report["jobs_page"]
                    ),
                    "coverage": report["coverage"],
                    "new_inputs": store.db.execute(
                        "SELECT count(*) FROM rj_surface WHERE engagement=?",
                        (policy.engagement_id,),
                    ).fetchone()[0],
                    "candidate_findings": len(store.findings(policy.engagement_id, limit=100)),
                    "confirmed_findings": 0,
                    "false_positive_count": None,
                    "known_fixture_false_negative_count": None,
                    "accuracy_measurement": "not_measured_no_vulnerability_oracle_fixture",
                    "rce_regression": "not_reproduced_missing_fixture",
                    "baseline": "baseline_unavailable",
                    "long_soak": False,
                    "memory_method": (
                        "process_tree_summed_rss_shared_pages_may_be_counted_multiple_times"
                    ),
                    "capabilities": runtime.registry.health(),
                }
                report["metrics"] = metrics
                write_report(output, report)
                measurement_path = output / "benchmark.json"
                measurement_path.write_text(json.dumps(metrics, indent=2) + "\n")
                measurement_path.chmod(0o600)
                return metrics
        finally:
            store.close()


def resource_status(
    path: Path | None,
    policy_path: Path | None,
    *,
    recover: bool,
) -> dict[str, Any]:
    from redjohn.assessment.host_resources import (  # noqa: PLC0415 - explicit resource operation
        HostResourceLimits,
        HostResourcePool,
        default_pool_path,
    )

    pool = HostResourcePool(path or default_pool_path())
    recovered = pool.recover() if recover else 0
    if policy_path is not None:
        with policy_path.open("rb") as handle:
            payload = handle.read(4097)
        if len(payload) > 4096:
            raise ValueError("host_policy_byte_limit")
        pool.configure(HostResourceLimits(**json.loads(payload)))
    return {"product": "RedJohn", "recovered_leases": recovered, "resources": pool.snapshot()}


def _public_error(exc: Exception) -> dict[str, Any]:
    error = {
        "ok": False,
        "error": getattr(exc, "code", "assessment_configuration_error"),
        "category": type(exc).__name__,
    }
    if isinstance(exc, PolicyDenied):
        # Policy messages can contain private context. Only known constant
        # reasons are public; absolute deadline failures stay exit code 2.
        error["reason"] = str(exc) if str(exc) in _PUBLIC_POLICY_REASONS else exc.code
    elif isinstance(exc, ResourceAdmissionError):
        error["reason"] = str(exc) if str(exc) in _PUBLIC_RESOURCE_REASONS else exc.code
    else:
        reason = getattr(exc, "public_reason", None)
        if isinstance(reason, str) and reason in _PUBLIC_RESOURCE_REASONS | _PUBLIC_POLICY_REASONS:
            error["reason"] = reason
    if isinstance(exc, MemoryLimitExceededError):
        error["resources"] = exc.measurement
        error["evidence_ref"] = exc.evidence_ref
        error["evidence_error"] = exc.evidence_error
    return error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="redjohn assess", description="RedJohn persistent bounded assessments"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    local = subparsers.add_parser(
        "demo", help="Actual local Chromium/HTTP pipeline and measurement"
    )
    local.add_argument("--output", type=Path, default=Path("redjohn_runs/local-assessment"))
    local.add_argument("--cycles", type=int, default=5)
    run = subparsers.add_parser("run", help="Run/resume a configured engagement")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--max-jobs", type=int, default=16)
    run.add_argument(
        "--wait-ready-seconds",
        type=float,
        default=0,
        help="Wait up to 120 seconds for queued jobs to become ready; max-jobs still applies",
    )
    https = subparsers.add_parser(
        "https-demo", help="Real HTTPS Chromium/inventory/Nuclei across durable CLI restarts"
    )
    https.add_argument("--output", type=Path, default=Path("redjohn_runs/https-e2e"))
    https.add_argument(
        "--nuclei-lock",
        type=Path,
        default=Path(__file__).resolve().parents[2] / ".tools/nuclei/3.11.1/fixture-lock.json",
    )
    subparsers.add_parser("health", help="Inspect capabilities; does not launch optional tools")
    resources = subparsers.add_parser("resources", help="Inspect/configure shared host admission")
    resources.add_argument("--pool", type=Path)
    resources.add_argument(
        "--policy", type=Path, help="Apply this bounded JSON host policy while idle"
    )
    resources.add_argument(
        "--recover",
        action="store_true",
        help="Reclaim verified dead controller-only owners or fully terminated OS-fenced workers",
    )
    args = parser.parse_args(argv)
    if args.command == "demo":
        metrics = asyncio.run(demo(args.output, cycles=args.cycles))
        print(  # noqa: T201 - CLI emits structured JSON
            json.dumps(
                {
                    k: metrics[k]
                    for k in (
                        "cycles",
                        "elapsed_seconds",
                        "p50_seconds",
                        "p95_seconds",
                        "http_requests",
                        "peak_memory_bytes",
                        "model_calls",
                    )
                },
                indent=2,
            )
        )
        return 0
    if args.command == "health":
        print(json.dumps(CapabilityRegistry().health(), indent=2))  # noqa: T201 - CLI JSON
        return 0
    try:
        if args.command == "resources":
            print(  # noqa: T201 - CLI JSON
                json.dumps(
                    resource_status(args.pool, args.policy, recover=args.recover),
                    indent=2,
                )
            )
            return 0
        if args.command == "https-demo":
            from redjohn.assessment.https_verification import https_demo  # noqa: PLC0415

            metrics = asyncio.run(https_demo(args.output, args.nuclei_lock))
            print(json.dumps(metrics, indent=2))  # noqa: T201 - verification CLI JSON
            return 0
        run_options: dict[str, Any] = {"max_jobs": args.max_jobs}
        if args.wait_ready_seconds != 0:
            run_options["wait_ready_seconds"] = args.wait_ready_seconds
        report = asyncio.run(configured_run(load_config(args.config), args.output, **run_options))
        print(  # noqa: T201 - CLI emits structured JSON
            json.dumps(
                {
                    "product": "RedJohn",
                    "coverage": report["coverage"],
                    "continuous_replay": report["metrics"].get("continuous_replay", {}),
                    "report": str(args.output / "assessment-report.html"),
                },
                indent=2,
            )
        )
        return int(
            bool(report["metrics"].get("continuous_replay", {}).get("errors"))
            or bool(report["metrics"].get("continuous_replay", {}).get("reconciliation_errors"))
            or any(
                row["coverage_status"] in {"blocked", "unsupported", "inconclusive"}
                for row in report["coverage"]
            )
        )
    except (ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
        print(  # noqa: T201 - CLI emits structured JSON
            json.dumps(_public_error(exc))
        )
        return 2
