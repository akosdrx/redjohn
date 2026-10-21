"""Real pinned Nuclei/TLS failures through the durable scheduler, no doubles.

The upstream is an owned TLS loopback fixture. Missing binaries/locks are an
explicit capability skip; failed scans never become negative scan evidence.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied, origin_for
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer
from tests.test_nuclei_live import DEFAULT_LOCK, existing_live_lock


@pytest.fixture
def live_lock_document():
    lock = existing_live_lock()
    path = Path(os.environ.get("REDJOHN_NUCLEI_LOCK", str(DEFAULT_LOCK)))
    return lock, json.loads(path.read_text())


def _policy(origin: str, *, request_budget: int = 16) -> EngagementPolicy:
    return EngagementPolicy(
        engagement_id="https-scheduler-failure",
        owner_id="operator",
        allowed_origins=(origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
        request_budget=request_budget,
    )


def _submit(store: AssessmentStore, policy: EngagementPolicy, url: str, lock: dict) -> str:
    surface_id = store.upsert_surface(policy.engagement_id, Surface(url))
    return store.submit(
        policy,
        [
            JobSpec(
                surface_id,
                "known_vulnerability",
                "nuclei_scan",
                timeout_seconds=30,
                tool_version=lock["binary"]["version"],
                template_version=lock["bundle"]["sha256"],
            )
        ],
    )[0]


def _row(store: AssessmentStore, policy: EngagementPolicy, job_id: str) -> dict:
    return next(row for row in store.jobs(policy.engagement_id) if row["id"] == job_id)


def _requests_used(store: AssessmentStore, policy: EngagementPolicy) -> int:
    return store.db.execute(
        "SELECT requests_used FROM rj_engagement WHERE id=?", (policy.engagement_id,)
    ).fetchone()[0]


def _assert_blocked_without_negative(row: dict) -> None:
    assert row["execution_status"] == "failed", row
    assert row["coverage_status"] == "blocked", row
    assert row["result"]["summary"]["no_finding_observed"] is False, row
    assert not row["result"]["findings"], row


@pytest.mark.parametrize("certificate_mode", ["self_signed", "hostname_mismatch", "wrong_ca"])
async def test_scheduler_real_nuclei_invalid_upstream_tls_is_blocked_without_negative(
    tmp_path: Path, live_lock_document, certificate_mode: str
) -> None:
    lock, document = live_lock_document
    mode = "trusted" if certificate_mode == "wrong_ca" else certificate_mode
    with TLSFixtureServer(certificate_mode=mode) as fixture:
        policy = _policy(fixture.origin)
        store = AssessmentStore(tmp_path / "state" / "agents.db")
        tls = BrowserTLSConfig(
            upstream_ca_file=(
                fixture.wrong_ca_file if certificate_mode == "wrong_ca" else fixture.ca_file
            )
        )
        try:
            async with (
                NativeFixtureSession(policy, tmp_path / "worker", lock) as session,
                AssessmentRuntime(
                    store,
                    policy,
                    caller="operator",
                    envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
                    browser_tls=tls,
                    nuclei_lock=document,
                    session=session,
                ) as runtime,
            ):
                job_id = _submit(store, policy, fixture.origin + "/api/me", document)
                assert await runtime.scheduler.run_batch(max_jobs=1) == [job_id]
                row = _row(store, policy, job_id)
                _assert_blocked_without_negative(row)
                assert row["result"]["error"]["code"] == "nuclei_upstream_tls_denied", row
                network = row["result"]["summary"]["network"]
                assert network["upstream_tls_failures"] > 0
                assert network["forwarded_requests"] == 0
                assert network["complete_response_statuses"] == []
                assert not fixture.counts
                assert _requests_used(store, policy) >= 1
                assert await runtime.scheduler.run_batch(max_jobs=1) == []
                assert not session._active and not session._reservations
                assert not runtime.browser.healthcheck()["ready"]
                assert runtime.governor.snapshot()["active"] == {}
        finally:
            store.close()


async def test_scheduler_real_nuclei_429_blocks_another_job_on_shared_origin_cooldown(  # noqa: PLR0915
    tmp_path: Path, live_lock_document
) -> None:
    lock, document = live_lock_document
    with TLSFixtureServer() as fixture:
        # A real Retry-After response long enough to outlive worker startup and
        # cleanup makes shared-origin throttling deterministic without fake time.
        original_handler = fixture.server.RequestHandlerClass

        class LongCooldownHandler(original_handler):
            def do_GET(self):  # noqa: N802 - stdlib HTTP handler contract
                if urlsplit(self.path).path != "/rate-limit":
                    super().do_GET()
                    return
                fixture.counts["/rate-limit"] += 1
                self.send_response(429)
                self.send_header("Retry-After", "60")
                self.send_header("Content-Length", "0")
                self.end_headers()

        fixture.server.RequestHandlerClass = LongCooldownHandler
        policy = _policy(fixture.origin)
        store = AssessmentStore(tmp_path / "state" / "agents.db")
        try:
            async with (
                NativeFixtureSession(policy, tmp_path / "worker", lock) as session,
                AssessmentRuntime(
                    store,
                    policy,
                    caller="operator",
                    envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
                    browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                    nuclei_lock=document,
                    session=session,
                ) as runtime,
            ):
                limited_id = _submit(store, policy, fixture.origin + "/rate-limit", document)
                assert await runtime.scheduler.run_batch(max_jobs=1) == [limited_id]
                limited = _row(store, policy, limited_id)
                _assert_blocked_without_negative(limited)
                assert limited["result"]["error"]["code"] == "rate_limited", limited
                assert limited["result"]["summary"]["network"]["complete_response_statuses"] == [
                    429
                ]
                assert fixture.counts == {"/rate-limit": 1}
                assert _requests_used(store, policy) == 1
                assert runtime.rate_limits.remaining(origin_for(fixture.origin)) > 50

                second_id = _submit(store, policy, fixture.origin + "/api/items", document)
                assert second_id != limited_id
                assert await runtime.scheduler.run_batch(max_jobs=1) == [second_id]
                second = _row(store, policy, second_id)
                _assert_blocked_without_negative(second)
                assert second["result"]["error"]["code"] == "nuclei_request_admission_denied", (
                    second
                )
                network = second["result"]["summary"]["network"]
                assert network["admission_denials"] > 0
                assert network["forwarded_requests"] == 0
                assert not network["complete_response_statuses"]
                assert fixture.counts == {"/rate-limit": 1}
                assert _requests_used(store, policy) == 1
                assert await runtime.scheduler.run_batch(max_jobs=2) == []
                assert not session._active and not session._reservations
                assert not runtime.browser.healthcheck()["ready"]
                assert runtime.governor.snapshot()["active"] == {}
        finally:
            store.close()

        reopened = AssessmentStore(tmp_path / "state" / "agents.db")
        try:
            async with (
                NativeFixtureSession(policy, tmp_path / "restarted-worker", lock) as session,
                AssessmentRuntime(
                    reopened,
                    policy,
                    caller="operator",
                    envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
                    browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                    nuclei_lock=document,
                    session=session,
                ) as restarted,
            ):
                assert restarted.rate_limits.remaining(origin_for(fixture.origin)) > 45
                third_id = _submit(reopened, policy, fixture.origin + "/api/me", document)
                assert third_id not in {limited_id, second_id}
                assert await restarted.scheduler.run_batch(max_jobs=1) == [third_id]
                third = _row(reopened, policy, third_id)
                _assert_blocked_without_negative(third)
                assert third["result"]["error"]["code"] == "nuclei_request_admission_denied"
                assert third["result"]["summary"]["network"]["forwarded_requests"] == 0
                assert fixture.counts == {"/rate-limit": 1}
                assert _requests_used(reopened, policy) == 1
                assert not session._active and not session._reservations
                assert restarted.governor.snapshot()["active"] == {}
        finally:
            reopened.close()


async def test_scheduler_real_nuclei_request_budget_is_exact_and_persists_across_restart(
    tmp_path: Path, live_lock_document
) -> None:
    lock, document = live_lock_document
    with TLSFixtureServer() as fixture:
        policy = _policy(fixture.origin, request_budget=1)
        database = tmp_path / "state" / "agents.db"
        store = AssessmentStore(database)
        tls = BrowserTLSConfig(upstream_ca_file=fixture.ca_file)
        try:
            async with (
                NativeFixtureSession(policy, tmp_path / "worker-one", lock) as session,
                AssessmentRuntime(
                    store,
                    policy,
                    caller="operator",
                    envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
                    browser_tls=tls,
                    nuclei_lock=document,
                    session=session,
                ) as runtime,
            ):
                first_id = _submit(store, policy, fixture.origin + "/api/me", document)
                assert await runtime.scheduler.run_batch(max_jobs=1) == [first_id]
                first = _row(store, policy, first_id)
                assert first["execution_status"] == "succeeded", first
                assert first["coverage_status"] == "completed", first
                assert first["result"]["summary"]["network"]["forwarded_requests"] == 1
                assert fixture.counts == {"/api/me": 1}
                assert _requests_used(store, policy) == 1
                assert not session._active and not session._reservations
        finally:
            store.close()

        # New runtime and native worker give the rate limiter a clean process
        # lifetime. The durable SQLite request budget must still deny sending.
        reopened = AssessmentStore(database)
        try:
            async with (
                NativeFixtureSession(policy, tmp_path / "worker-two", lock) as session,
                AssessmentRuntime(
                    reopened,
                    policy,
                    caller="operator",
                    envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
                    browser_tls=tls,
                    nuclei_lock=document,
                    session=session,
                ) as runtime,
            ):
                second_id = _submit(reopened, policy, fixture.origin + "/api/items", document)
                assert second_id != first_id
                assert await runtime.scheduler.run_batch(max_jobs=1) == [second_id]
                second = _row(reopened, policy, second_id)
                _assert_blocked_without_negative(second)
                assert second["result"]["error"]["code"] == "nuclei_request_admission_denied", (
                    second
                )
                network = second["result"]["summary"]["network"]
                assert network["admission_denials"] > 0
                assert network["forwarded_requests"] == 0
                assert not network["complete_response_statuses"]
                assert fixture.counts == {"/api/me": 1}
                assert _requests_used(reopened, policy) == 1
                assert await runtime.scheduler.run_batch(max_jobs=1) == []
                assert not session._active and not session._reservations
                assert not runtime.browser.healthcheck()["ready"]
                assert runtime.governor.snapshot()["active"] == {}
        finally:
            reopened.close()


@pytest.mark.parametrize(
    "path",
    [
        "/logout",
        "/sign-out",
        "/%6cogout",
        "/%256cogout",
        "/api/delete",
        "/api/%2564elete",
        "/api?action=delete",
        "/api?action=%64elete",
        "/api?action=%2564elete",
        "/api?%2561ction=delete",
        "/api?operation=logout",
        "/api?command=send-mail",
    ],
)
def test_shared_readonly_guard_rejects_encoded_stateful_routes_without_network(path: str) -> None:
    policy = _policy("https://127.0.0.1:443")
    with pytest.raises(PolicyDenied, match="state_changing_read_route_denied"):
        policy.check_readonly_request("https://127.0.0.1:443" + path, "GET")
