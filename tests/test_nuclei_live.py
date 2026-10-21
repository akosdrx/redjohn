"""Actual pinned Nuclei engine over NativeFixtureSession, separate from all doubles.

No install/download occurs in tests. Both the marker and fixed-control target are
owned literal-loopback fixtures; full upstream templates are never selected.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.tools.hunt.nuclei import NucleiAdapter, NucleiLock, NucleiOptions


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / ".tools/nuclei/3.11.1/fixture-lock.json"


def existing_live_lock() -> NucleiLock:
    path = Path(os.environ.get("REDJOHN_NUCLEI_LOCK", str(DEFAULT_LOCK)))
    if not path.is_file():
        pytest.skip(
            "blocked_missing_dependency: reviewed local Nuclei lock unavailable; "
            "no install attempted"
        )
    lock = NucleiLock.from_mapping(json.loads(path.read_text()))
    if not Path(lock.binary_path).is_file():
        pytest.skip("blocked_missing_dependency: reviewed Nuclei binary unavailable")
    return lock


@pytest.fixture
def live_nuclei_lock() -> NucleiLock:
    return existing_live_lock()


async def test_live_pinned_nuclei_native_marker_then_fixed_control(
    tmp_path: Path, live_nuclei_lock: NucleiLock
) -> None:
    requests: list[str] = []
    state = {"marker": True}

    class MarkerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = (
                b"redjohn-fixture-marker"
                if state["marker"] and self.path == "/marker"
                else b"fixed-control"
            )
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), MarkerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    policy = EngagementPolicy(
        "live-native-fixture",
        "owner",
        (origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )
    measurements = []
    try:
        async with NativeFixtureSession(policy, tmp_path / "worker", live_nuclei_lock) as session:
            for marker in (True, False):
                state["marker"] = marker
                responses: list[dict] = []
                raw_evidence = []
                proxy = BrowserEgressProxy(
                    policy,
                    on_response=lambda url, status, headers, responses=responses: responses.append(
                        {"url": url, "status": status, "headers": headers}
                    ),
                )
                await proxy.start()
                session.bind_proxy(proxy.url)
                before = len(requests)
                started = time.monotonic()
                try:
                    adapter = NucleiAdapter(
                        session,
                        live_nuclei_lock,
                        proxy_url=proxy.url,
                        response_observations=lambda responses=responses: tuple(responses),
                        evidence_sink=lambda raw, raw_evidence=raw_evidence: (
                            raw_evidence.append(raw) or "raw-evidence"
                        ),
                    )
                    result = await adapter.run(
                        origin + "/marker", options=NucleiOptions(timeout_seconds=30), policy=policy
                    )
                finally:
                    session.bind_proxy(None)
                    await proxy.close()
                measurements.append(
                    {
                        "marker_enabled": marker,
                        "duration_seconds": time.monotonic() - started,
                        "target_requests": requests[before:],
                        "response_statuses": [item["status"] for item in responses],
                        "execution_status": result["execution_status"],
                        "coverage_status": result["coverage_status"],
                        "finding_count": len(result["findings"]),
                        "no_finding_observed": result["no_finding_observed"],
                        "binary_version": live_nuclei_lock.binary_version,
                        "binary_sha256": live_nuclei_lock.binary_sha256,
                    }
                )
                assert result["execution_status"] == "succeeded", json.dumps(
                    {"result": result, "raw": raw_evidence}
                )
                assert result["coverage_status"] == "completed", json.dumps(
                    {"result": result, "raw": raw_evidence}
                )
                assert requests[before:] == ["/marker"]
                assert responses and [item["status"] for item in responses] == [200]
                if marker:
                    assert len(result["findings"]) == 1
                    assert result["findings"][0]["finding_status"] == "candidate"
                    assert result["no_finding_observed"] is False
                else:
                    assert result["findings"] == []
                    assert result["no_finding_observed"] is True
                assert not session._active and not session._reservations
                assert not list(session.workspace.glob(".redjohn-hunt/*"))
                assert not list(session.workspace.glob(".redjohn-nuclei-*"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    if output := os.environ.get("REDJOHN_NUCLEI_MEASUREMENTS"):
        Path(output).write_text(json.dumps(measurements, indent=2) + "\n")


@pytest.mark.parametrize("certificate_mode", ["trusted", "self_signed", "hostname_mismatch"])
async def test_live_pinned_nuclei_https_strict_upstream_tls(
    tmp_path: Path, live_nuclei_lock: NucleiLock, certificate_mode: str
) -> None:
    with TLSFixtureServer(certificate_mode=certificate_mode) as fixture:
        policy = EngagementPolicy(
            "live-native-https",
            "owner",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
        )
        responses = []
        proxy = BrowserEgressProxy(
            policy,
            tls_config=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            on_response=lambda url, status, headers: responses.append(
                {"url": url, "status": status, "headers": headers}
            ),
        )
        await proxy.start()
        try:
            async with NativeFixtureSession(
                policy, tmp_path / "native-https", live_nuclei_lock
            ) as session:
                session.bind_proxy(proxy.url)
                adapter = NucleiAdapter(
                    session,
                    live_nuclei_lock,
                    proxy_url=proxy.url,
                    response_observations=lambda: tuple(responses),
                )
                result = await adapter.run(
                    fixture.origin, options=NucleiOptions(timeout_seconds=30), policy=policy
                )
                if certificate_mode == "trusted":
                    assert result["execution_status"] == "succeeded", result
                    assert result["coverage_status"] == "completed", result
                    assert len(result["findings"]) == 1
                    assert result["findings"][0]["finding_status"] == "candidate"
                    assert responses and responses[0]["status"] == 200
                    fixture.fixed = True
                    responses.clear()
                    fixed = await adapter.run(
                        fixture.origin, options=NucleiOptions(timeout_seconds=30), policy=policy
                    )
                    assert fixed["execution_status"] == "succeeded", fixed
                    assert fixed["coverage_status"] == "completed", fixed
                    assert fixed["no_finding_observed"] is True
                    assert fixed["findings"] == []
                else:
                    assert result["coverage_status"] != "completed", result
                    assert result["no_finding_observed"] is False
                    assert result["findings"] == []
                    assert proxy.upstream_tls_failures > 0
                    assert not responses
                    assert not fixture.counts
                session.bind_proxy(None)
                assert not session._active and not session._reservations
        finally:
            await proxy.close()


@pytest.mark.parametrize(
    "path,expected_code",
    [
        ("/expired", "authentication_expired"),
        ("/denied", "permission_or_challenge"),
        ("/rate-limit", "rate_limited"),
    ],
)
async def test_live_pinned_nuclei_http_error_is_blocked_not_negative(
    tmp_path: Path, live_nuclei_lock: NucleiLock, path: str, expected_code: str
) -> None:
    with TLSFixtureServer() as fixture:
        policy = EngagementPolicy(
            "live-response-blocked",
            "owner",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
        )
        responses = []
        proxy = BrowserEgressProxy(
            policy,
            tls_config=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            on_response=lambda url, status, headers: responses.append(
                {"url": url, "status": status, "headers": headers}
            ),
        )
        await proxy.start()
        try:
            async with NativeFixtureSession(
                policy, tmp_path / "worker", live_nuclei_lock
            ) as session:
                session.bind_proxy(proxy.url)
                result = await NucleiAdapter(
                    session,
                    live_nuclei_lock,
                    proxy_url=proxy.url,
                    response_observations=lambda: tuple(responses),
                ).run(
                    fixture.origin + path, options=NucleiOptions(timeout_seconds=30), policy=policy
                )
                assert result["coverage_status"] == "blocked", result
                assert result["no_finding_observed"] is False
                assert result["findings"] == []
                assert result["error"]["code"] == expected_code, result
                assert len(responses) == 1
                session.bind_proxy(None)
        finally:
            await proxy.close()
