"""Actual Naabu -> fenced Nmap service profile -> durable SQLite E2E.

Only owned SSH/HTTP loopback fixtures are contacted. Missing engine/kernel
capabilities fail required CI mode; none are converted to negative findings.
"""

import asyncio
import hashlib
import json
import os
import platform
from pathlib import Path

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment, enqueue_configured_jobs
from redjohn.assessment.service_broker import HTTP_SERVICE_PROBE
from redjohn.assessment.service_tools import NMAP_LICENSE_SHA256, NMAP_VERSION, PROBE_SHA256
from tests.test_network_broker_contract import close_stream
from tests.test_network_tools_live import assessment_config, installed_pin


def installed_nmap():
    root = Path(__file__).resolve().parents[1] / ".tools" / "nmap" / NMAP_VERSION
    binary, receipt_file = root / "nmap", root / "receipt.json"
    if platform.system() != "Linux" or not binary.is_file() or not receipt_file.is_file():
        message = "blocked_missing_dependency: reviewed Linux no-NSE Nmap fixture build required"
        if os.environ.get("REDJOHN_REQUIRE_SERVICE_SCANNER_E2E") == "1":
            pytest.fail(message)
        pytest.skip(message)
    receipt = json.loads(receipt_file.read_text())
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert receipt["version"] == NMAP_VERSION and receipt["source_macro_version"] == NMAP_VERSION
    assert receipt["binary_sha256"] == digest
    assert receipt["probe_profile"]["sha256"] == PROBE_SHA256
    return {
        "binary": {"path": str(binary), "sha256": digest, "version": NMAP_VERSION},
        "external_operator_install": True,
        "license_sha256": NMAP_LICENSE_SHA256,
    }


async def initial_open_proof(config, output):
    async with ConfiguredAssessment(config, output, caller="owner") as assessment:
        enqueue_configured_jobs(assessment.runtime, assessment.store, assessment.policy, config)
        rows = assessment.store.jobs(assessment.policy.engagement_id)
        assert len(rows) == 1
        await assessment.runtime.scheduler.run_batch(max_jobs=1)
        row = assessment.store.jobs(assessment.policy.engagement_id)[0]
        assert row["execution_status"] == "succeeded", json.dumps(row["result"])
        assert row["result"]["summary"]["observation"]["state"] == "open"
        return row["result"]["summary"]["evidence_refs"][0]


def selected_nmap_row(assessment):
    return next(
        row
        for row in assessment.store.jobs(assessment.policy.engagement_id)
        if row["spec"]["capability"] == "nmap_services"
    )


def record_owned_native_diagnostics(assessment):
    """Actual engine calls on these public fixtures only; no proxy nonce in argv."""
    runner = assessment.runtime.scheduler.adapters["nmap_services"].runner
    execute, events = runner.execute, []

    async def recorded(argv, timeout):
        result = await execute(argv, timeout)
        events.append(
            {
                "stage": "health" if "--version" in argv else "scan",
                "exit_code": result.get("exit_code"),
                "error": result.get("error"),
                "timed_out": result.get("timed_out"),
                "truncated": result.get("truncated"),
                "stdout": result.get("stdout", "")[:4096],
                "stderr": result.get("stderr", "")[:8192],
            }
        )
        del events[:-4]
        return result

    runner.execute = recorded
    return events


def native_failure(row, events):
    return json.dumps(
        {"job_id": row["id"], "result": row["result"], "native_diagnostics": events},
        ensure_ascii=True,
    )


@pytest.mark.parametrize("kind", ["ssh", "http", "closed-after-open"])
async def test_real_naabu_observed_open_nmap_service_and_false_relay_open_control(  # noqa: PLR0915 - real two-engine lifecycle and restart
    tmp_path, kind
):
    nmap = installed_nmap()
    naabu = installed_pin("naabu")
    seen_probes = []

    async def target(reader, writer):
        try:
            if kind != "http":
                writer.write(b"SSH-2.0-RedJohn_owned_fixture\r\n")
                await writer.drain()
                await reader.read()
            else:
                probe = await reader.readexactly(len(HTTP_SERVICE_PROBE))
                assert probe == HTTP_SERVICE_PROBE
                seen_probes.append(probe)
                writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass  # Naabu and Nmap's initial CONNECT may close without a probe.
        finally:
            await close_stream(writer)

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    config = assessment_config("naabu", naabu, port)
    config["nmap"] = nmap
    output = tmp_path / "run"
    try:
        proof = await initial_open_proof(config, output)
        if kind == "closed-after-open":
            server.close()
            await server.wait_closed()
        config["service_jobs"] = [
            {"address": "127.0.0.1", "port": str(port), "open_evidence_ref": proof}
        ]
        async with ConfiguredAssessment(config, output, caller="owner") as assessment:
            native_diagnostics = record_owned_native_diagnostics(assessment)
            enqueue_configured_jobs(assessment.runtime, assessment.store, assessment.policy, config)
            queued = selected_nmap_row(assessment)
            assert await assessment.runtime.scheduler.run_batch(max_jobs=1) == [queued["id"]]
            row = selected_nmap_row(assessment)
            result = row["result"]
            if kind == "closed-after-open":
                assert row["execution_status"] == "failed", json.dumps(result)
                assert row["coverage_status"] == "inconclusive"
                assert result["error"]["code"] == "nmap_service_upstream_response_not_proven", (
                    native_failure(row, native_diagnostics)
                )
                ref = result["summary"]["evidence_refs"][0]
                proof = json.loads(
                    assessment.store.evidence_get(assessment.policy.engagement_id, ref)["excerpt"]
                )
                assert proof["refused"] >= 1 and proof["response_bytes"] == 0
                assert not result["findings"]
            else:
                if row["execution_status"] != "succeeded" or not result["summary"].get(
                    "service_observed"
                ):
                    pytest.fail(native_failure(row, native_diagnostics))
                assert row["coverage_status"] == "partial"
                assert result["summary"]["service_observed"] is True
                assert result["summary"]["service"]["name"] == kind
                assert (
                    result["summary"]["product_version_status"]
                    == "not_determined_by_narrow_profile"
                )
                assert not result["findings"]
                ref = result["summary"]["evidence_refs"][0]
                evidence = assessment.store.evidence_get(assessment.policy.engagement_id, ref)
                payload = json.loads(evidence["excerpt"])
                assert payload["response_bytes"] > 0 and payload["response_digests"]
                assert payload["admission_closed"] is True and payload["denied"] == 0
            assert assessment.store.request_usage(assessment.policy) == 0
            assert assessment.runtime.governor.snapshot()["active"] == {}
            worker_root = assessment.store.path.parent / "nmap-service-workers"
            assert not list(worker_root.glob("job-*")) and not list(worker_root.glob("payload-*"))
            job_id = row["id"]
        async with ConfiguredAssessment(config, output, caller="owner") as restarted:
            enqueue_configured_jobs(restarted.runtime, restarted.store, restarted.policy, config)
            assert await restarted.runtime.scheduler.run_batch(max_jobs=1) == []
            assert selected_nmap_row(restarted)["id"] == job_id
            assert selected_nmap_row(restarted)["attempt"] == 1
        if kind == "http":
            assert seen_probes
    finally:
        server.close()
        await server.wait_closed()


async def test_real_scheduled_nmap_cancel_closes_actual_upstream_and_worker(  # noqa: PLR0915 - actual native admission/cancellation/cleanup
    tmp_path,
):
    nmap, naabu = installed_nmap(), installed_pin("naabu")
    received, disconnected = asyncio.Event(), asyncio.Event()

    async def target(reader, writer):
        probed = False
        try:
            data = await reader.readexactly(len(HTTP_SERVICE_PROBE))
            assert data == HTTP_SERVICE_PROBE
            probed = True
            received.set()
            await reader.read()
        except asyncio.IncompleteReadError:
            pass
        finally:
            await close_stream(writer)
            if probed:
                disconnected.set()

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    config, output = assessment_config("naabu", naabu, port), tmp_path / "run"
    config["nmap"] = nmap
    try:
        proof = await initial_open_proof(config, output)
        config["service_jobs"] = [
            {"address": "127.0.0.1", "port": str(port), "open_evidence_ref": proof}
        ]
        async with ConfiguredAssessment(config, output, caller="owner") as assessment:
            native_diagnostics = record_owned_native_diagnostics(assessment)
            enqueue_configured_jobs(assessment.runtime, assessment.store, assessment.policy, config)
            assessment.runtime.scheduler.lease_seconds = 0.3
            row = selected_nmap_row(assessment)
            task = asyncio.create_task(assessment.runtime.scheduler.run_batch(max_jobs=1))
            try:
                try:
                    await asyncio.wait_for(received.wait(), 12)
                except TimeoutError:
                    pytest.fail(native_failure(selected_nmap_row(assessment), native_diagnostics))
                assessment.store.cancel(assessment.policy.engagement_id, row["id"])
                await asyncio.wait_for(task, 5)
                await asyncio.wait_for(disconnected.wait(), 2)
                assert selected_nmap_row(assessment)["execution_status"] == "cancelled"
                adapter = assessment.runtime.scheduler.adapters["nmap_services"]
                assert adapter.runner.process is None and adapter.runner.broker is None
                assert assessment.runtime.governor.snapshot()["active"] == {}
                assert adapter.partial_evidence_refs
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    finally:
        server.close()
        await server.wait_closed()
