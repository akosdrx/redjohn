"""Actual SDK tool -> host pump -> HTTPS Chromium/Nuclei -> durable restart.

No model is called. HTTP, browser, Nuclei, SQLite and the tool SDK are real;
legacy CLI/TUI startup contracts are a separate verification layer.
"""

import asyncio
import json
import os
import time
from pathlib import Path

from agents.tool_context import ToolContext

from redjohn.assessment.host import HostAssessment, HostControllerLimits
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.tools.assessment.tool import assessment_control
from tests.test_nuclei_live import DEFAULT_LOCK, existing_live_lock


async def invoke(service, operation, **arguments):
    context = ToolContext(
        context={"assessment_service": service},
        tool_name="assessment_control",
        tool_call_id="host-" + operation,
        tool_arguments="{}",
    )
    return json.loads(
        await assessment_control.on_invoke_tool(
            context,
            json.dumps(
                {
                    "operation": operation,
                    "arguments_json": json.dumps(
                        {
                            "policy_revision": service.policy.revision,
                            **arguments,
                        }
                    ),
                }
            ),
        )
    )


async def wait_job(service, capability, *, expected_count=1):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        response = await invoke(service, "jobs_get_status", limit=64)
        assert response["ok"], response
        rows = [row for row in response["result"]["items"] if row["capability"] == capability]
        if len(rows) == expected_count and all(
            row["execution_status"] not in {"queued", "running", "retry_wait"} for row in rows
        ):
            return rows
        await asyncio.sleep(0.05)
    raise AssertionError("host scheduler did not complete the actual job")


def config_for(fixture, *, capability="browser_discover", nuclei=False):
    policy = EngagementPolicy(
        "host-real-engagement",
        "operator",
        (fixture.origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
        request_budget=64,
    )
    config = {
        "policy": policy.to_dict(),
        "resources": {"total_memory_budget": 2 * 1024**3, "max_workers": 1},
        "browser": {"readiness_selector": "body[data-actor]"},
        "tls": {"upstream_ca_file": str(fixture.ca_file)},
        "seeds": [{"url": fixture.origin + "/", "capabilities": [capability]}],
    }
    if nuclei:
        existing_live_lock()
        config["nuclei_lock"] = json.loads(
            Path(os.environ.get("REDJOHN_NUCLEI_LOCK", str(DEFAULT_LOCK))).read_text()
        )
    return config


async def test_actual_sdk_host_pump_browser_nuclei_restart_and_fixed_control(tmp_path, monkeypatch):
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "pool.sqlite3"))
    with TLSFixtureServer() as fixture:
        config = config_for(fixture, nuclei=True)
        limits = HostControllerLimits(max_jobs=8, max_seconds=30)
        async with HostAssessment(
            config, tmp_path / "run", caller="operator", limits=limits
        ) as host:
            service = host.control
            assert host.configured._native_session is not None
            assert host.configured._native_session.policy == host.configured.policy
            browser = await wait_job(service, "browser_discover")
            assert browser[0]["execution_status"] == "succeeded"
            surfaces = await invoke(service, "surface_search", limit=64)
            observed = next(
                row
                for row in surfaces["result"]["items"]
                if row["url"] == fixture.origin + "/api/items" and row["request_ref"]
            )
            job = {
                "surface_id": observed["id"],
                "family": "known_vulnerability",
                "capability": "nuclei_scan",
            }
            submitted = await invoke(service, "jobs_submit_batch", jobs=[job])
            assert submitted["ok"], submitted
            rows = await wait_job(service, "nuclei_scan")
            assert rows[0]["execution_status"] == "succeeded"
            assert len(rows[0]["result"]["findings"]) == 1
        closed = await invoke(service, "system_health")
        assert closed["error"]["code"] == "engagement_runtime_closed"
        requests = sum(fixture.counts.values())
        async with HostAssessment(
            config, tmp_path / "run", caller="operator", limits=limits
        ) as host:
            duplicate = await invoke(host.control, "jobs_submit_batch", jobs=[job])
            assert duplicate["result"]["job_ids"] == submitted["result"]["job_ids"]
            await asyncio.sleep(0.35)
            assert sum(fixture.counts.values()) == requests
            fixture.fixed = True
            fixed = await invoke(
                host.control,
                "jobs_submit_batch",
                jobs=[{**job, "retest_revision": "fixed-deployment"}],
            )
            assert fixed["ok"], fixed
            rows = await wait_job(host.control, "nuclei_scan", expected_count=2)
            fixed_row = next(row for row in rows if row["spec"]["retest_revision"])
            assert fixed_row["execution_status"] == "succeeded"
            assert fixed_row["result"]["findings"] == []
        report = json.loads((tmp_path / "run/assessment-report.json").read_text())
        assert report["metrics"]["resources"]["active"] == {}


async def test_actual_host_job_budget_blocks_new_submissions_without_new_requests(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "pool.sqlite3"))
    with TLSFixtureServer() as fixture:
        config = config_for(fixture, capability="http_observe")
        async with HostAssessment(
            config,
            tmp_path / "run",
            caller="operator",
            limits=HostControllerLimits(max_jobs=1, max_seconds=10),
        ) as host:
            rows = await wait_job(host.control, "http_observe")
            assert rows[0]["execution_status"] == "succeeded"
            count = sum(fixture.counts.values())
            denied = await invoke(
                host.control,
                "jobs_submit_batch",
                jobs=[
                    {
                        "surface_id": rows[0]["surface_id"],
                        "family": "traffic",
                        "capability": "http_observe",
                        "retest_revision": "not-admitted",
                    }
                ],
            )
            assert denied["error"]["code"] == "host_controller_unavailable"
            assert sum(fixture.counts.values()) == count
            assert host.status()["stop_reason"] == "job_budget_exhausted"
