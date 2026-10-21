"""Real Chromium + local TLS upstream tests; no browser/proxy mocks."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace

import pytest

from redjohn.assessment.browser import BrowserDiscoveryService, BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope, ResourceGovernor, process_tree_memory
from redjohn.assessment.tls_fixture import TLSFixtureServer


def _policy(origin: str) -> EngagementPolicy:
    return EngagementPolicy(
        engagement_id="https-browser-fixture",
        owner_id="operator",
        allowed_origins=(origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("alice", "bob"),
        revision="tls-1",
    )


def _governor() -> ResourceGovernor:
    return ResourceGovernor(ResourceEnvelope(total_memory_budget=2 * 1024**3))


@pytest.mark.asyncio
async def test_real_https_chromium_discovery_identity_request_budget_and_cleanup():
    pytest.importorskip("playwright.async_api")
    with TLSFixtureServer() as fixture:
        resources = _governor()
        admitted: list[str] = []

        def admit(url: str) -> None:
            if len(admitted) >= 9:
                raise RuntimeError("campaign_request_budget_exhausted")
            admitted.append(url)

        service = BrowserDiscoveryService(
            _policy(fixture.origin),
            resources,
            BrowserLimits(observation_window_ms=100),
            tls_config=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            request_admission=admit,
        )
        baseline = process_tree_memory()
        durations = []
        async with service:
            assert service._proxy is not None and service._proxy._tls_identity is not None
            identity_directory = service._proxy._tls_identity.directory
            assert identity_directory.stat().st_mode & 0o777 == 0o700
            chromium = service.healthcheck()["chromium_version"]
            for index, actor in enumerate(("alice", "bob")):
                result = await service.discover(
                    [fixture.origin + "/"],
                    actor_id=actor,
                    session_revision=index + 1,
                    storage_state=fixture.actor_state(actor),
                )
                assert result.execution_status == "succeeded", result
                assert any(
                    observation.url.endswith("/api/me") and observation.status == 200
                    for observation in result.observations
                )
                assert all(observation.actor_id == actor for observation in result.observations)
                assert all(
                    observation.session_revision == str(index + 1)
                    for observation in result.observations
                )
                assert "browser_upstream_tls_denied" not in {f.code for f in result.failures}
                assert result.metrics["proxy_upstream_tls_failures"] == 0
                assert service.healthcheck()["active_contexts"] == 0
                assert service.healthcheck()["active_pages"] == 0
                durations.append(result.metrics["elapsed_seconds"])
            assert len(admitted) == sum(fixture.counts.values()) == 8
            assert [
                item["actor"] for item in fixture.observed_actors if item["path"] == "/api/me"
            ] == ["alice", "bob"]
            result = await service.discover(
                [fixture.origin + "/"], actor_id="alice", session_revision=3
            )
            assert len(admitted) == sum(fixture.counts.values()) == 9
            assert "browser_request_admission_denied" in {f.code for f in result.failures}
            assert fixture.counts["unexpected_post"] == fixture.counts["/logout"] == 0
            memory = process_tree_memory()
        assert not identity_directory.exists()
        assert resources.snapshot()["active"] == {}
        health = service.healthcheck()
        assert health["contexts_created"] == health["contexts_closed"] == 3
        assert health["pages_created"] == health["pages_closed"] == 3
        assert health["cleanup_errors"] == 0
        print(  # noqa: T201 - actual integration measurements
            "HTTPS_BROWSER_MEASUREMENTS="
            + json.dumps(
                {
                    "chromium_version": chromium,
                    "requests": sum(fixture.counts.values()),
                    "durations_seconds": durations,
                    "process_tree_rss_bytes": memory.rss_bytes,
                    "process_count_before": baseline.process_count,
                    "process_count_during": memory.process_count,
                    "process_count_after": process_tree_memory().process_count,
                    "model_calls": 0,
                },
                sort_keys=True,
            )
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("certificate_mode", ["self_signed", "hostname_mismatch", "wrong_ca"])
async def test_real_https_chromium_rejects_invalid_upstream_certificate(certificate_mode):
    pytest.importorskip("playwright.async_api")
    mode = "trusted" if certificate_mode == "wrong_ca" else certificate_mode
    with TLSFixtureServer(certificate_mode=mode) as fixture:
        resources = _governor()
        async with BrowserDiscoveryService(
            _policy(fixture.origin),
            resources,
            BrowserLimits(observation_window_ms=0),
            tls_config=BrowserTLSConfig(
                upstream_ca_file=(
                    fixture.wrong_ca_file if certificate_mode == "wrong_ca" else fixture.ca_file
                )
            ),
        ) as service:
            result = await service.discover(
                [fixture.origin + "/"], actor_id="alice", session_revision=1
            )
            assert result.execution_status == "failed"
            assert result.coverage_status == "inconclusive"
            assert result.metrics["proxy_upstream_tls_failures"] > 0
            assert "browser_upstream_tls_denied" in {failure.code for failure in result.failures}
            assert sum(fixture.counts.values()) == 0
        assert resources.snapshot()["active"] == {}


@pytest.mark.asyncio
async def test_real_https_chromium_redirect_denied_and_cancel_cleanup():
    pytest.importorskip("playwright.async_api")
    with TLSFixtureServer() as fixture:
        resources = _governor()
        service = BrowserDiscoveryService(
            _policy(fixture.origin),
            resources,
            BrowserLimits(observation_window_ms=0, readiness_timeout_ms=5000),
            tls_config=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
        )
        async with service:
            result = await service.discover(
                [fixture.origin + "/offscope"], actor_id="alice", session_revision=1
            )
            assert result.coverage_status == "inconclusive"
            assert "browser_scope_denied" in {failure.code for failure in result.failures}
            assert fixture.counts["/offscope"] == 1
            assert fixture.counts["/forbidden"] == 0
            service.limits = replace(service.limits, readiness_selector="#never-ready")
            task = asyncio.create_task(
                service.discover([fixture.origin + "/"], actor_id="bob", session_revision=2)
            )
            for _ in range(100):
                if fixture.counts["/"]:
                    break
                await asyncio.sleep(0.01)
            # Cancel the readiness wait after actual TLS navigation completes.
            await asyncio.sleep(0.1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert service.healthcheck()["active_pages"] == 0
            assert service.healthcheck()["active_contexts"] == 0
            assert service.healthcheck()["cleanup_errors"] == 0
        assert resources.snapshot()["active"] == {}
