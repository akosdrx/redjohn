"""Real local HTTP + headless Chromium integration tests (no browser mocks)."""

from __future__ import annotations

import asyncio
import json
import os
import threading
from collections import Counter
from contextlib import contextmanager, suppress
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from redjohn.assessment.browser import (
    BrowserDiscoveryService,
    BrowserLimits,
)
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.resources import (
    ResourceAdmissionError,
    ResourceEnvelope,
    ResourceGovernor,
    process_tree_memory,
)


_SPA = b"""<!doctype html><html><body>
<form action='/never-submit' method='post' enctype='multipart/form-data'>
<input name='upload' type='file'><input name='csrf' type='hidden' value='fixture-secret'>
<button>Delete object</button></form>
<a href='/logout'>Logout</a><iframe src='/frame'></iframe>
<script>
fetch('/api/me').then(r => r.json()).then(data => {
 document.body.dataset.actor = data.actor;
 const a=document.createElement('a'); a.href='/page'; a.textContent='SPA page';
 document.body.appendChild(a); document.body.dataset.ready = 'true';
});
const xhr = new XMLHttpRequest(); xhr.open('GET','/api/items?name=one&name=two'); xhr.send();
fetch('/never-submit',{method:'POST',body:JSON.stringify({x:'unsafe'}),
 headers:{'content-type':'application/json'}}).catch(()=>{});
</script></body></html>"""


@contextmanager
def local_spa():
    requests = Counter()
    actors: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            requests[self.path] += 1
            if path == "/redirect":
                self.send_response(302)
                self.send_header(
                    "Location", f"http://localhost:{self.server.server_port}/outside-scope"
                )
                self.end_headers()
                return
            if path == "/rate":
                self.send_response(429)
                self.send_header("Content-Type", "text/html")
                self.send_header("Retry-After", "2")
                self.end_headers()
                self.wfile.write(b"<html><body>Rate limited</body></html>")
                return
            if path == "/api/me":
                actor = self.headers.get("Cookie", "actor=anonymous").partition("actor=")[2]
                actors.append(actor)
                data, content_type = json.dumps({"actor": actor}).encode(), "application/json"
            elif path == "/":
                data, content_type = _SPA, "text/html"
            elif path == "/api/items":
                data, content_type = b'{"items": []}', "application/json"
            elif path == "/never-ready":
                data = b"<html><body>Still loading</body></html>"
                content_type = "text/html"
            else:
                data, content_type = (
                    b"<html><body data-ready='true'>Fixture</body></html>",
                    "text/html",
                )
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            requests["UNSAFE_POST"] += 1
            self.send_response(500)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests, actors
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def policy_for(origin: str) -> EngagementPolicy:
    return EngagementPolicy(
        engagement_id="browser-fixture",
        owner_id="operator",
        allowed_origins=(origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("alice", "bob"),
        revision="2",
    )


def storage_for(actor: str) -> dict:
    return {
        "cookies": [
            {
                "name": "actor",
                "value": actor,
                "domain": "127.0.0.1",
                "path": "/",
                "expires": -1,
                "httpOnly": False,
                "secure": False,
                "sameSite": "Lax",
            }
        ],
        "origins": [],
    }


def governor() -> ResourceGovernor:
    # This is a test resource envelope, not a claimed universal production limit.
    return ResourceGovernor(
        ResourceEnvelope(
            total_memory_budget=2 * 1024**3,
            worker_memory_budget=256 * 1024**2,
        )
    )


def test_browser_limits_and_scope_are_real_validation():
    with pytest.raises(ValueError, match="max_frontier"):
        BrowserLimits(max_frontier=0)
    with local_spa() as (origin, _, _):
        service = BrowserDiscoveryService(policy_for(origin), governor())
        with pytest.raises(PolicyDenied, match="origin_denied"):
            service.validate_input(["http://127.0.0.1:9/"], "alice", "1")
        with pytest.raises(PolicyDenied, match="actor_denied"):
            service.validate_input([origin], "unknown", "1")
        with pytest.raises(PolicyDenied, match="origin_denied"):
            service.validate_input([origin.replace("http:", "https:")], "alice", "1")


@pytest.mark.asyncio
async def test_real_chromium_spa_traffic_identity_repetition_and_cleanup():
    pytest.importorskip("playwright.async_api")
    with local_spa() as (origin, requests, actors):
        resources = governor()
        service = BrowserDiscoveryService(
            policy_for(origin),
            resources,
            BrowserLimits(readiness_selector="[data-ready]", observation_window_ms=50),
        )
        baseline = process_tree_memory()
        samples, durations = [], []
        cycles = int(os.environ.get("REDJOHN_BROWSER_SOAK_CYCLES", "5"))
        assert 3 <= cycles <= 1000
        expected_actors = ["alice" if cycle % 2 == 0 else "bob" for cycle in range(cycles)]
        async with service:
            chromium_version = service.healthcheck()["chromium_version"]
            for cycle, actor in enumerate(expected_actors):
                result = await service.discover(
                    [origin + "/"],
                    actor_id=actor,
                    session_revision=cycle + 1,
                    storage_state=storage_for(actor),
                    navigation_urls=(origin + "/page",),
                )
                assert result.execution_status == "succeeded"
                assert result.coverage_status == "partial"  # Deliberately blocked JS POST.
                assert result.metrics["visited_pages"] == 2
                assert result.metrics["model_calls"] == 0
                assert any(
                    x.resource_type == "fetch" and x.url.endswith("/api/me") and x.status == 200
                    for x in result.observations
                )
                assert any(
                    x.resource_type == "xhr" and "name=one&name=two" in x.url
                    for x in result.observations
                )
                assert any(
                    x.method == "POST"
                    and x.request_content_type == "application/json"
                    and not x.sent
                    for x in result.observations
                )
                assert all(
                    x.actor_id == actor
                    and x.session_revision == str(cycle + 1)
                    and x.policy_revision == "2"
                    for x in result.observations
                )
                assert result.forms[0].method == "POST"
                assert result.forms[0].enctype == "multipart/form-data"
                assert result.forms[0].inputs[1] == {"name": "csrf", "type": "hidden"}
                assert "fixture-secret" not in repr(result)
                assert service.healthcheck()["active_contexts"] == 0
                assert service.healthcheck()["active_pages"] == 0
                assert resources.snapshot()["active"] == {"browser": 1}
                samples.append(process_tree_memory())
                durations.append(result.metrics["elapsed_seconds"])
            assert actors == expected_actors
            assert requests["UNSAFE_POST"] == 0
            assert requests["/never-submit"] == 0
            assert requests["/logout"] == 0
            assert requests["/frame"] == cycles
            assert len({sample.process_count for sample in samples}) <= 2
        after = process_tree_memory()
        health = service.healthcheck()
        assert health["contexts_created"] == health["contexts_closed"] == cycles
        assert health["pages_created"] == health["pages_closed"] == cycles
        assert health["cleanup_errors"] == 0
        assert resources.snapshot()["active"] == {}
        assert after.process_count <= baseline.process_count
        measurements = {
            "test": "real_chromium_local_spa_repeated_cycles",
            "cycles": cycles,
            "chromium_version": chromium_version,
            "durations_seconds": durations,
            "process_tree_rss_bytes": [sample.rss_bytes for sample in samples],
            "process_counts": [sample.process_count for sample in samples],
            "after_process_count": after.process_count,
            "before_process_count": baseline.process_count,
            "rss_method": baseline.method,
            "contexts_created_closed": [health["contexts_created"], health["contexts_closed"]],
            "pages_created_closed": [health["pages_created"], health["pages_closed"]],
            "http_requests": sum(requests.values()),
            "model_calls": 0,
        }
        print("BROWSER_MEASUREMENTS=" + json.dumps(measurements, sort_keys=True))  # noqa: T201


@pytest.mark.asyncio
async def test_real_chromium_readiness_redirect_limits_and_cancel_cleanup():
    pytest.importorskip("playwright.async_api")
    with local_spa() as (origin, requests, _):
        resources = governor()
        limits = BrowserLimits(
            readiness_selector="[data-ready]",
            readiness_timeout_ms=150,
            navigation_timeout_ms=500,
            observation_window_ms=0,
        )
        async with BrowserDiscoveryService(policy_for(origin), resources, limits) as service:
            result = await service.discover(
                [origin + "/never-ready"],
                actor_id="alice",
                session_revision=1,
            )
            assert result.execution_status == "failed"
            assert result.coverage_status == "inconclusive"
            assert "browser_readiness_timeout" in {failure.code for failure in result.failures}
            result = await service.discover(
                [origin + "/redirect"],
                actor_id="alice",
                session_revision=1,
            )
            assert result.coverage_status == "inconclusive"
            assert "browser_scope_denied" in {failure.code for failure in result.failures}
            assert len(result.observations) == 1
            assert requests["/outside-scope"] == 0
            service.limits = replace(limits, max_requests=1)
            result = await service.discover(
                [origin + "/"],
                actor_id="alice",
                session_revision=1,
            )
            assert len(result.observations) == 1
            assert result.metrics["request_limit_drops"] > 0
            service.limits = replace(limits, readiness_timeout_ms=5000)
            task = asyncio.create_task(
                service.discover(
                    [origin + "/never-ready"],
                    actor_id="alice",
                    session_revision=1,
                )
            )
            for _ in range(50):
                if service.healthcheck()["active_pages"]:
                    break
                await asyncio.sleep(0.01)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert service.healthcheck()["active_contexts"] == 0
            assert service.healthcheck()["active_pages"] == 0
            assert service.healthcheck()["cleanup_errors"] == 0
            assert resources.snapshot()["active"] == {"browser": 1}
            assert requests["UNSAFE_POST"] == 0
        assert resources.snapshot()["active"] == {}


@pytest.mark.asyncio
async def test_real_chromium_request_admission_and_response_callbacks():
    pytest.importorskip("playwright.async_api")
    with local_spa() as (origin, requests, _):
        admitted: list[str] = []
        observed: list[tuple[str, int, dict[str, str]]] = []

        def admit(url: str) -> None:
            if len(admitted) >= 3:
                raise RuntimeError("campaign_request_budget_exhausted")
            admitted.append(url)

        def observe(url: str, status: int, headers: dict[str, str]) -> None:
            observed.append((url, status, headers))

        resources = governor()
        async with BrowserDiscoveryService(
            policy_for(origin),
            resources,
            BrowserLimits(readiness_selector="body", observation_window_ms=50),
            request_admission=admit,
            on_response=observe,
        ) as service:
            result = await service.discover(
                [origin + "/rate"],
                actor_id="alice",
                session_revision=1,
            )
            assert result.coverage_status == "partial"
            assert "browser_http_429" in {failure.code for failure in result.failures}
            assert observed == [
                (
                    origin + "/rate",
                    429,
                    {
                        "content-type": "text/html",
                        "retry-after": "2",
                    },
                )
            ]
            result = await service.discover(
                [origin + "/"],
                actor_id="alice",
                session_revision=1,
            )
            assert result.coverage_status == "partial"
            assert "browser_request_admission_denied" in {
                failure.code for failure in result.failures
            }
            assert len(admitted) == 3
            assert sum(requests.values()) <= 3
        assert resources.snapshot()["active"] == {}


@pytest.mark.asyncio
async def test_real_chromium_crash_reports_lost_coverage_and_releases_context():
    pytest.importorskip("playwright.async_api")
    with local_spa() as (origin, _, _):
        resources = governor()
        async with BrowserDiscoveryService(
            policy_for(origin),
            resources,
            BrowserLimits(readiness_selector="[data-ready]", readiness_timeout_ms=5000),
        ) as service:
            task = asyncio.create_task(
                service.discover(
                    [origin + "/never-ready"],
                    actor_id="alice",
                    session_revision=1,
                )
            )
            for _ in range(100):
                if service.healthcheck()["active_pages"]:
                    break
                await asyncio.sleep(0.01)
            assert service._browser is not None
            cdp = await service._browser.new_browser_cdp_session()
            # Chromium's actual browser process is terminated, rather than a mocked error.
            with suppress(Exception):  # Expected transport closure after actual process crash.
                await cdp.send("Browser.crash")
            result = await task
            assert result.execution_status == "failed"
            assert result.coverage_status == "inconclusive"
            assert any(
                f.code in {"browser_navigation_failed", "browser_page_crashed"}
                for f in result.failures
            )
            assert service.healthcheck()["active_contexts"] == 0
        assert resources.snapshot()["active"] == {}

@pytest.mark.asyncio
async def test_failed_chromium_close_quarantines_the_browser_lease():
    class FailingBrowser:
        contexts: list[object] = []
        version = "synthetic"

        def is_connected(self) -> bool:
            return True

        async def close(self) -> None:
            raise TimeoutError("synthetic browser close timeout")

    with local_spa() as (origin, _, _):
        resources = governor()
        service = BrowserDiscoveryService(policy_for(origin), resources)
        service._browser_lease = resources.acquire(
            "browser", 1, cleanup_guard=service._browser_cleanup_verified
        )
        service._browser = FailingBrowser()  # type: ignore[assignment]
        await service.close()
        snapshot = resources.snapshot()
        assert snapshot["active"] == {"browser": 1}
        assert snapshot["cleanup_quarantined"] == 1
        assert service.healthcheck()["cleanup_errors"] == 1
        with pytest.raises(ResourceAdmissionError, match="resource_cleanup_unverified"):
            resources.acquire("browser", 1)

        # A later close that observes no browser can prove cleanup and recover
        # the same reservation; no new admission is needed.
        service._browser_closed = True
        service._browser = None
        await service.close()
        assert resources.snapshot()["active"] == {}
