"""Actual offline Ruby/Nokogiri/WPScan-component -> shared scheduler -> SQLite.

The actual public runtime/configuration selects the capability lazily. No live WordPress/version/vulnerability
assessment is claimed from an immutable owned HTML fixture.
"""

import asyncio
import hashlib
import json
import os
import platform
from pathlib import Path

import pytest

from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.configuration import enqueue_configured_jobs
from redjohn.assessment.runtime import AssessmentRuntime
from tests.owned_artifact_execution import supervise_owned_test
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.wpscan_observe import (
    CAPABILITY,
    WPScanObserveConfig,
    wordpress_observe_job,
)
from redjohn.assessment.wpscan_runtime import WPScanObservationRunner


def installed_config(page, body):
    root = Path(__file__).resolve().parents[1] / ".tools/wordpress-observe/4.1.0"
    manifest = root / "runtime-manifest.json"
    if (
        platform.system() != "Linux"
        or not manifest.is_file()
        or not (root / "receipt.json").is_file()
    ):
        message = "blocked_missing_dependency: pinned Linux Ruby/Nokogiri/Racc observation runtime"
        if os.environ.get("REDJOHN_REQUIRE_WORDPRESS_OBSERVE_E2E") == "1":
            pytest.fail(message)
        pytest.skip(message)
    receipt = json.loads((root / "receipt.json").read_text())
    assert receipt["runtime_manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert receipt["upstream_signature_verified"] is False
    page.write_bytes(body)
    return WPScanObserveConfig.from_mapping(
        {
            "component": {
                "source_file": str(root / "operator-component/wordpress.rb"),
                "license_file": str(root / "operator-component/LICENSE"),
                "external_operator_component": True,
                "operator_use": "own-systems",
            },
            "artifact": {
                "html_file": str(page),
                "html_sha256": hashlib.sha256(body).hexdigest(),
                "page_url": "https://metadata.invalid/owned/",
                "producer": "operator",
            },
            "runtime": {
                "root": str(root / "runtime"),
                "manifest_file": str(manifest),
                "manifest_sha256": receipt["runtime_manifest_sha256"],
            },
        }
    )


def bound_scheduler(store, policy, config):
    runtime = AssessmentRuntime(
        store,
        policy,
        caller="operator",
        envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3, max_workers=1),
        wordpress_observe_config=config.to_mapping(),
    )
    enqueue_configured_jobs(
        runtime,
        store,
        policy,
        {"wordpress_observe": config.to_mapping(), "source_jobs": [{"capability": CAPABILITY}]},
    )
    return runtime.scheduler, runtime.governor, runtime.scheduler.adapters[CAPABILITY], runtime


@pytest.mark.parametrize("kind", ["positive", "generic", "external-dtd"])
async def test_real_offline_component_observation_and_durable_restart(
    tmp_path, monkeypatch, kind, request
):
    if await supervise_owned_test(request, tmp_path):
        return
    body = (
        b'<html><meta name="generator" content="WordPress 6.4.3"></html>'
        if kind == "positive"
        else b"<html><p>Owned generic fixture</p></html>"
    )
    # Own control endpoint: XML/HTML system identifiers must never fetch it.
    requests = []

    async def forbidden_control(reader, writer):
        requests.append(await reader.read(1024))
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(forbidden_control, "127.0.0.1", 0)
    if kind == "external-dtd":
        port = server.sockets[0].getsockname()[1]
        body = (
            f'<!DOCTYPE html SYSTEM "http://127.0.0.1:{port}/must-not-fetch"><html></html>'.encode()
        )
    try:
        config = installed_config(tmp_path / "owned.html", body)
        store = AssessmentStore(tmp_path / "state.db")
        policy = store.register(
            EngagementPolicy(
                "owned-wordpress-" + kind,
                "operator",
                (),
                target_domains=("source",),
                allowed_source_artifacts=(config.artifact.html_sha256,),
                profile="isolated-lab",
                egress_mode="unavailable",
            )
        )
        spec = wordpress_observe_job(config, policy, store)
        job_id = store.submit(policy, [spec])[0]
        scheduler, governor, adapter, runtime = bound_scheduler(store, policy, config)
        actual_execute, events = WPScanObservationRunner.execute, []

        async def recorded(runner, argv, timeout):
            # The actual native call occurs under the same selected worker
            # lease; no second private pool or fixture bypass starts it.
            assert governor.snapshot()["active"] == {"scanner": 1}
            result = await actual_execute(runner, argv, timeout)
            events.append(
                {
                    "exit_code": result.get("exit_code"),
                    "error": result.get("error"),
                    "timed_out": result.get("timed_out"),
                    "truncated": result.get("truncated"),
                    "stderr": result.get("stderr", "")[:4096],
                }
            )
            return result

        monkeypatch.setattr(WPScanObservationRunner, "execute", recorded)
        assert await scheduler.run_batch(max_jobs=1) == [job_id]
        row = store.jobs(policy.engagement_id)[0]
        assert row["execution_status"] == "succeeded", json.dumps({"row": row, "native": events})
        assert row["coverage_status"] == "partial"
        summary = row["result"]["summary"]
        assert summary["wordpress_signature_observed"] == (kind == "positive")
        assert len(summary["generator_observations"]) == (1 if kind == "positive" else 0)
        assert summary["requests"] == 0 and summary["findings"] == []
        assert "version_not_verified_against_database" in summary["coverage_gaps"]
        assert summary["health"]["ruby_version"] == "3.3.12"
        assert not requests and store.request_usage(policy) == 0
        assert governor.snapshot()["active"] == {} and adapter.runner is None
        assert not list((tmp_path / "wordpress-observation-workers").glob("job-*"))
        assert not list((tmp_path / "wordpress-observation-workers").glob("snapshot-*"))
        await runtime.close()
        store.close()
        reopened = AssessmentStore(tmp_path / "state.db")
        assert reopened.submit(policy, [wordpress_observe_job(config, policy, reopened)]) == [
            job_id
        ]
        second, second_governor, _, second_runtime = bound_scheduler(reopened, policy, config)
        assert await second.run_batch(max_jobs=1) == []
        assert second_governor.snapshot()["active"] == {}
        assert reopened.jobs(policy.engagement_id)[0]["attempt"] == 1
        assert (
            reopened.db.execute(
                "SELECT count(*) FROM rj_evidence WHERE kind='approved_wordpress_observation_input'"
            ).fetchone()[0]
            == 1
        )
        await second_runtime.close()
        reopened.close()
    finally:
        server.close()
        await server.wait_closed()


async def test_real_native_health_then_durable_cancel_prevents_observation(
    tmp_path, monkeypatch, request
):
    if await supervise_owned_test(request, tmp_path):
        return
    config = installed_config(tmp_path / "owned.html", b"<html>owned</html>")
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(
        EngagementPolicy(
            "cancel-wordpress",
            "operator",
            (),
            target_domains=("source",),
            allowed_source_artifacts=(config.artifact.html_sha256,),
            profile="isolated-lab",
        )
    )
    spec = wordpress_observe_job(config, policy, store)
    job_id = store.submit(policy, [spec])[0]
    scheduler, governor, adapter, runtime = bound_scheduler(store, policy, config)
    actual_execute, native_health = WPScanObservationRunner.execute, []

    async def cancel_after_actual_health(runner, argv, timeout):
        result = await actual_execute(runner, argv, timeout)
        if "--health" in argv:
            assert result["exit_code"] == 0, result
            native_health.append(True)
            store.cancel(policy.engagement_id, job_id)
        return result

    monkeypatch.setattr(WPScanObservationRunner, "execute", cancel_after_actual_health)
    assert await scheduler.run_batch(max_jobs=1) == [job_id]
    assert native_health == [True]
    assert store.jobs(policy.engagement_id)[0]["execution_status"] == "cancelled"
    assert (
        store.db.execute(
            "SELECT count(*) FROM rj_evidence WHERE kind='wordpress_observation_outcome'"
        ).fetchone()[0]
        == 0
    )
    assert governor.snapshot()["active"] == {} and adapter.runner is None
    assert not list((tmp_path / "wordpress-observation-workers").glob("job-*"))
    assert not list((tmp_path / "wordpress-observation-workers").glob("snapshot-*"))
    await runtime.close()
    store.close()
