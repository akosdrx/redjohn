"""Bounded CLI child lifecycle under the explicitly requested OS backstop."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from redjohn.assessment.models import error_record
from redjohn.assessment.os_memory import (
    LinuxMemoryBoundary,
    MemoryLimitExceededError,
    MemoryLimitUnavailableError,
)
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.report import write_report
from redjohn.assessment.store import AssessmentStore


class ContainedControllerError(RuntimeError):
    def __init__(self, code: str, public_reason: object = None) -> None:
        self.code = code
        self.public_reason = public_reason
        super().__init__(code)


def record_resource_failure(
    config: dict[str, Any],
    output: Path,
    error: MemoryLimitExceededError,
) -> None:
    """Persist kernel proof after containment cleanup, without retrying a job."""
    store = None
    try:
        policy = EngagementPolicy.from_mapping(config["policy"])
        store = AssessmentStore(output / ".state/agents.db")
        store.register(policy)
        error.evidence_ref = store.evidence_put(
            policy.engagement_id,
            {
                "execution_status": "resource_exhausted",
                "coverage_status": "inconclusive",
                "error": error_record("os_memory_limit_exceeded", category="resource"),
                "os_memory": error.measurement,
                "process_cleanup_verified": True,
                "job_effects": "require_existing_fenced_lease_reconciliation_no_automatic_resend",
            },
            kind="resource_failure",
        )
    except Exception:  # noqa: BLE001 - evidence failure must not hide the kernel OOM cause
        error.evidence_error = "resource_failure_evidence_unavailable"
    finally:
        if store is not None:
            store.close()


async def _collect(process: asyncio.subprocess.Process, timeout: float) -> bytes:
    async def drain(stream: asyncio.StreamReader) -> bytes:
        captured = bytearray()
        while chunk := await stream.read(8192):
            if len(captured) + len(chunk) > 65536:
                raise ValueError("controller_output_limit")
            captured.extend(chunk)
        return bytes(captured)

    assert process.stdout is not None and process.stderr is not None
    tasks = [asyncio.create_task(drain(stream)) for stream in (process.stdout, process.stderr)]
    try:
        async with asyncio.timeout(timeout):
            stdout, _stderr = await asyncio.gather(*tasks)
            await process.wait()
        return stdout
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def contained_run(
    config: dict[str, Any],
    output: Path,
    boundary: LinuxMemoryBoundary,
    *,
    max_jobs: int,
    wait_ready_seconds: float,
) -> dict[str, Any]:
    """A child runs the ordinary persistent scheduler; this is no second queue."""
    policy = EngagementPolicy.from_mapping(config["policy"])
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(config).encode()
    if len(payload) > 65536:
        raise ValueError("configuration_too_large")
    with tempfile.TemporaryDirectory(prefix=".controller-", dir=output) as temporary:
        path = Path(temporary) / "config.json"
        path.write_bytes(payload)
        path.chmod(0o600)
        argv = boundary.wrap_argv(
            [
                sys.executable,
                "-m",
                "redjohn.assessment",
                "run",
                "--config",
                str(path),
                "--output",
                str(output),
                "--max-jobs",
                str(max_jobs),
                "--wait-ready-seconds",
                str(wait_ready_seconds),
            ]
        )
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        )
        try:
            process = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            process = await spawn
            process.kill()
            await process.wait()
            raise

        # Every contained job is already bounded by its policy and scheduler.
        timeout = max_jobs * 600 + wait_ready_seconds + 30
        if policy.deadline:
            timeout = max(1, min(timeout, policy.deadline - time.time() + 30))
        stdout = await _collect(process, timeout)
        measurement = boundary.snapshot()
        if measurement["oom_kills"]:
            raise MemoryLimitExceededError(measurement)
        if process.returncode not in {0, 1}:
            # Child configuration errors are safe JSON; unexpected traceback or
            # tool output is never reflected into an agent/public response.
            try:
                error = json.loads(stdout)
            except (ValueError, UnicodeError):
                error = {}
            codes = {
                "assessment_configuration_error",
                "policy_denied",
                "resource_admission_denied",
                "resource_exhausted",
                "blocked_os_memory_limit_unavailable",
            }
            if isinstance(error, dict) and error.get("error") in codes:
                raise ContainedControllerError(error["error"], error.get("reason"))
            raise MemoryLimitUnavailableError("contained_controller_failed")
        report_path = output / "assessment-report.json"
        with report_path.open("rb") as handle:
            raw = handle.read(4 * 1024**2 + 1)
        if len(raw) > 4 * 1024**2:
            raise ValueError("contained_report_byte_limit")
        report = json.loads(raw)
        if not isinstance(report, dict) or report.get("product") != "RedJohn":
            raise ValueError("invalid_contained_report")
        report["metrics"]["resources"]["os_memory"] = measurement
        write_report(output, report)
        return report
