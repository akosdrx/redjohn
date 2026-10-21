"""Host API lifecycle contracts; real SQLite, no browser/scanner or model call."""

import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.host import HostAssessment
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.store import AssessmentStore


async def test_closed_host_service_returns_a_stable_blocked_result(tmp_path):
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(
        EngagementPolicy("closed-host", "operator", ("https://example.invalid",))
    )
    service = AssessmentControl(store, policy, caller="operator")
    service.close()
    store.close()
    result = await service.call("system_health", {"policy_revision": policy.revision})
    assert result["ok"] is False
    assert result["error"]["code"] == "engagement_runtime_closed"
    assert result["error"]["category"] == "resource"
    assert result["error"]["coverage_effect"] == "blocked"


def host_for(tmp_path):
    policy = EngagementPolicy(
        "host-failure",
        "operator",
        ("https://127.0.0.1:8443",),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )
    return HostAssessment(
        {"policy": policy.to_dict(), "seeds": []}, tmp_path / "run", caller="operator"
    )


async def test_failed_host_start_can_be_closed_without_masking_the_error(tmp_path, monkeypatch):
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "pool.sqlite3"))
    host = host_for(tmp_path)
    services = []

    def fail_audit():
        services.append(host.control)
        raise RuntimeError("synthetic-startup-audit-failure")

    monkeypatch.setattr(host, "_audit", fail_audit)
    with pytest.raises(RuntimeError, match="synthetic-startup-audit-failure"):
        await host.__aenter__()
    await host.close()
    result = await services[0].call("system_health", {"policy_revision": "1"})
    assert result["error"]["code"] == "engagement_runtime_closed"


async def test_report_write_failure_still_closes_actual_service_and_resources(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "pool.sqlite3"))
    host = await host_for(tmp_path).__aenter__()
    service = host.control

    def fail_report(*_args, **_kwargs):
        raise OSError("synthetic-report-storage-failure")

    monkeypatch.setattr("redjohn.assessment.host.write_report", fail_report)
    with pytest.raises(OSError, match="synthetic-report-storage-failure"):
        await host.close()
    await host.close()
    result = await service.call("system_health", {"policy_revision": "1"})
    assert result["error"]["code"] == "engagement_runtime_closed"
    assert service.governor.snapshot()["active"] == {}


async def test_one_component_close_failure_does_not_leave_other_databases_open(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "pool.sqlite3"))
    host = await host_for(tmp_path).__aenter__()
    runtime = host.configured.runtime
    close_oast = AsyncMock(side_effect=RuntimeError("synthetic-oast-close-failure"))
    monkeypatch.setattr(runtime, "oast", SimpleNamespace(close=close_oast))
    with pytest.raises(RuntimeError, match="synthetic-oast-close-failure"):
        await host.close()
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        runtime.technology.db.execute("SELECT 1")
    assert runtime.governor._closed is True
