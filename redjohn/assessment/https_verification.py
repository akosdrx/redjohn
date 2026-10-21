"""Real Chromium -> inventory -> pinned Nuclei verification across CLI processes.

Only the project's harmless, ephemeral HTTPS loopback fixture is contacted.
The engine must already be installed and explicitly locked; this never downloads.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, TypedDict

from redjohn.assessment.models import JobSpec
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import process_tree_memory
from redjohn.assessment.store import AssessmentStore


class _ProcessMeasurement(TypedDict):
    pid: int
    exit_code: int | None
    duration_seconds: float
    stderr_bytes: int
    sampled_peak_rss_bytes: int
    sampled_peak_process_count: int
    memory_samples: int


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


async def https_demo(  # noqa: PLR0915 - explicit E2E verification stages
    output: Path,
    lock_path: Path,
    *,
    os_memory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from redjohn.assessment.tls_fixture import TLSFixtureServer  # noqa: PLC0415
    from redjohn.tools.hunt.nuclei import NucleiLock  # noqa: PLC0415

    lock_mapping = json.loads(lock_path.read_text())
    lock = NucleiLock.from_mapping(lock_mapping)
    require(Path(lock.binary_path).is_file(), "blocked_missing_nuclei_binary")
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_path = output / "fixture-config.json"
    database = output / ".state/agents.db"
    started = time.monotonic()
    processes: list[_ProcessMeasurement] = []

    async def run_cli(config: dict[str, Any]) -> dict[str, Any]:
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        config_path.chmod(0o600)
        tick = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "redjohn.assessment",
            "run",
            "--config",
            str(config_path),
            "--output",
            str(output),
            "--max-jobs",
            "8",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        peak_rss, peak_processes, samples = 0, 0, 0

        async def sample_memory() -> None:
            nonlocal peak_rss, peak_processes, samples
            while process.returncode is None:
                memory = await asyncio.to_thread(process_tree_memory, process.pid)
                if memory.available:
                    samples += 1
                    peak_rss = max(peak_rss, memory.rss_bytes)
                    peak_processes = max(peak_processes, memory.process_count)
                await asyncio.sleep(0.05)

        sampler = asyncio.create_task(sample_memory())
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=90)
        except BaseException:
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
        finally:
            sampler.cancel()
            await asyncio.gather(sampler, return_exceptions=True)
        processes.append(
            {
                "pid": process.pid,
                "exit_code": process.returncode,
                "duration_seconds": round(time.monotonic() - tick, 6),
                "stderr_bytes": len(stderr),
                "sampled_peak_rss_bytes": peak_rss,
                "sampled_peak_process_count": peak_processes,
                "memory_samples": samples,
            }
        )
        require(process.returncode == 0, f"https_demo_cli_failed_{process.returncode}")
        require(len(stdout) < 65536 and len(stderr) < 65536, "https_demo_output_limit")
        json.loads(stdout)
        report = json.loads((output / "assessment-report.json").read_text())
        if not isinstance(report, dict):
            raise TypeError("invalid_https_demo_report")
        return report

    with TLSFixtureServer() as fixture:
        policy = EngagementPolicy(
            f"https-e2e-{time.time_ns()}",
            "local-operator",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            request_budget=40,
            deadline=time.time() + 600,
        )
        config = {
            "policy": policy.to_dict(),
            "resources": {"total_memory_budget": 2 * 1024**3},
            "browser": {"readiness_selector": "body[data-actor]"},
            "tls": {"upstream_ca_file": str(fixture.ca_file)},
            "nuclei_lock": lock_mapping,
            "seeds": [{"url": fixture.origin + "/", "capabilities": ["browser_discover"]}],
        }
        if os_memory is not None:
            config["os_memory"] = os_memory
        browser_report = await run_cli(config)
        require(browser_report["jobs_page"][0]["execution_status"] == "succeeded", "browser_failed")
        store = AssessmentStore(database)
        try:
            observed = next(
                row
                for row in store.surfaces(policy.engagement_id, limit=100)
                if row["url"] == fixture.origin + "/api/items" and row["source"] == "observed"
            )
            require(observed["request_ref"], "browser_request_evidence_missing")
            scanner = JobSpec(
                observed["id"],
                "known_vulnerability",
                "nuclei_scan",
                policy_revision=policy.revision,
                tool_version=lock.binary_version,
                template_version=lock.bundle_sha256,
            )
            scanner_id = store.submit(policy, [scanner])[0]
        finally:
            store.close()
        # Pending job survives the first process's exit; the next CLI process
        # receives no seed and reads the observed surface and queue from SQLite.
        config["seeds"] = []
        initial = await run_cli(config)
        row = next(row for row in initial["jobs_page"] if row["id"] == scanner_id)
        require(row["coverage_status"] == "completed", "scanner_initial_incomplete")
        require(len(row["result"]["findings"]) == 1, "scanner_marker_not_detected")
        require(
            row["result"]["findings"][0]["finding_status"] == "candidate", "invalid_proof_level"
        )
        require(
            row["result"]["summary"]["network"]["complete_response_statuses"] == [200],
            "missing_actual_response",
        )

        counts_before_resume = dict(fixture.counts)
        store = AssessmentStore(database)
        try:
            require(store.submit(policy, [scanner]) == [scanner_id], "deduplication_failed")
        finally:
            store.close()
        resumed = await run_cli(config)
        require(dict(fixture.counts) == counts_before_resume, "resume_duplicated_network_request")
        require(resumed["metrics"]["jobs"] == 0, "resume_duplicated_job")

        fixture.fixed = True
        store = AssessmentStore(database)
        try:
            fixed_spec = JobSpec(**{**asdict(scanner), "retest_revision": "fixture-fixed-1"})
            fixed_id = store.submit(policy, [fixed_spec])[0]
        finally:
            store.close()
        final = await run_cli(config)
        fixed = next(row for row in final["jobs_page"] if row["id"] == fixed_id)
        require(fixed["coverage_status"] == "completed", "fixed_control_incomplete")
        require(fixed["result"]["summary"]["no_finding_observed"] is True, "negative_not_observed")
        require(not fixed["result"]["findings"], "fixed_control_false_positive")
        require(
            fixed["result"]["summary"]["network"]["complete_response_statuses"] == [200],
            "negative_without_actual_response",
        )
        require(fixture.counts["/api/items"] == 3, "unexpected_scanner_request_count")
        require(
            not fixture.counts["unexpected_post"] and not fixture.counts["/logout"],
            "unsafe_request_reached_fixture",
        )
        store = AssessmentStore(database)
        try:
            used = store.db.execute(
                "SELECT requests_used FROM rj_engagement WHERE id=?", (policy.engagement_id,)
            ).fetchone()[0]
            candidates = len(store.findings(policy.engagement_id))
        finally:
            store.close()
        measurements = {
            "product": "RedJohn",
            "measurement": "actual_https_chromium_inventory_nuclei_cli_processes",
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "processes": processes,
            "nuclei_version": lock.binary_version,
            "nuclei_binary_sha256": lock.binary_sha256,
            "template_bundle_sha256": lock.bundle_sha256,
            "inventory_surface_id": observed["id"],
            "inventory_source": observed["source"],
            "inventory_request_ref": observed["request_ref"],
            "scanner_job_id": scanner_id,
            "fixed_retest_job_id": fixed_id,
            "fixture_request_counts": dict(fixture.counts),
            "http_requests": sum(fixture.counts.values()),
            "persisted_requests_used": used,
            "restart_duplicate_requests": 0,
            "initial_candidates": 1,
            "fixed_control_new_findings": 0,
            "historical_candidates_retained": candidates,
            "confirmed_vulnerabilities": 0,
            "model_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "resource_state_after_final_job": final["metrics"].get("resources"),
            "sampled_peak_rss_bytes": max(row["sampled_peak_rss_bytes"] for row in processes),
            "memory_method": (
                "sampled_50ms_process_tree_summed_rss_shared_pages_may_be_counted_multiple_times"
            ),
            "negative_control": "complete_200_response_and_reviewed_marker_absent",
            "scope": "isolated_loopback_fixture_only",
            "parent_pid": os.getpid(),
        }
    path = output / "https-e2e-measurements.json"
    path.write_text(json.dumps(measurements, indent=2) + "\n")
    path.chmod(0o600)
    return measurements
