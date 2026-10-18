"""Real pinned binaries, Chromium and Nuclei against owned HTTPS fixtures.

The VulnX fixture speaks the real SDK protocol, but its synthetic advisory is
not live ProjectDiscovery data. The public-provider case is separate below.
"""

import asyncio
import gzip
import json
import os
import platform
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from contextlib import closing, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig, BrowserTLSIdentity
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.report import build_report
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from tests.remote_https_fixture import RemoteHTTPSFixture, fixture_host
from tests.test_nuclei_live import DEFAULT_LOCK, existing_live_lock


CVE = "CVE-2024-3094"
CAPABILITIES = {"httpx": "httpx_probe", "katana": "katana_discover", "vulnx": "vulnx_intelligence"}


def installed(tool):
    versions = {"httpx": "1.12.0", "katana": "1.8.0", "vulnx": "2.0.2"}
    directory = Path(__file__).resolve().parents[1] / ".tools" / tool / versions[tool]
    if not (directory / "receipt.json").is_file():
        message = f"blocked_missing_dependency: pinned {tool}; no implicit installation"
        if os.environ.get("REDJOHN_REQUIRE_PD_E2E") == "1":
            pytest.fail(message)
        pytest.skip(message)
    receipt = json.loads((directory / "receipt.json").read_text())
    return {
        "binary": {
            "path": str(directory / tool),
            "version": receipt["version"],
            "sha256": receipt["binary_sha256"],
        }
    }


def host_for(remote):
    if remote and platform.system() != "Linux":
        if os.environ.get("REDJOHN_REQUIRE_REMOTE_E2E") == "1":
            pytest.fail("blocked_linux_network_namespace_required")
        pytest.skip("blocked_linux_network_namespace_required")
    return fixture_host() if remote else "127.0.0.1"


def owned_fixture(host, path, *, port=0):
    fixture = RemoteHTTPSFixture(host, path)
    fixture.counts = Counter()
    fixture.requests = []
    fixture.fixed = False
    fixture.api_status = 200
    fixture.api_wrong_id = False
    fixture.api_delay = 0
    fixture.cookie = False

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: PLR0912 - owned HTTP fixture controls
            fixture.counts[self.path] += 1
            fixture.requests.append(
                {"path": self.path, "method": "GET", "api_key": self.headers.get("X-Api-Key")}
            )
            code, content, headers = 200, "text/plain", {}
            body = b"fixed-control"
            if self.path in {"/", "/guard", "/many"}:
                content = "text/html"
                links = b'<a href="/linked">linked</a><script src="/app.js"></script>'
                if self.path == "/guard":
                    links += b'<a href="/logout">unsafe read route</a>'
                if self.path == "/many":
                    links += b"".join(f'<a href="/extra-{i}">more</a>'.encode() for i in range(10))
                body = (
                    b"<html><head><title>RedJohn owned fixture</title></head><body>"
                    + links
                    + b"<script>document.body.dataset.ready='yes'</script></body></html>"
                )
            elif self.path == "/app.js":
                content = "application/javascript"
                body = (
                    b'window.unused = function(){ return fetch("/api/js-only"); };'
                    b'window.shortLeaf = function(){ return fetch("/js-only"); };'
                )
            elif self.path == "/linked":
                body = b"fixed-control" if fixture.fixed else b"redjohn-fixture-marker"
            elif self.path == "/rate":
                code, headers = 429, {"Retry-After": "30"}
            elif self.path == "/redirect":
                code, headers = 302, {"Location": "https://outside.invalid/trap"}
            elif self.path == "/huge":
                body = b"x" * (2 * 1024**2)
            elif self.path == "/encoded":
                body, headers = gzip.compress(b"x" * (4 * 1024**2)), {"Content-Encoding": "gzip"}
            elif self.path == "/slow":
                time.sleep(5)
            elif self.path.startswith("/v2/vulnerability/"):
                if fixture.api_delay:
                    time.sleep(fixture.api_delay)
                code, content = fixture.api_status, "application/json"
                cve = "CVE-2000-0000" if fixture.api_wrong_id else self.path.rsplit("/", 1)[1]
                body = json.dumps(
                    {
                        "data": {
                            "cve_id": cve,
                            "product": "xz",
                            "severity": "critical",
                            "is_kev": False,
                            "cve_updated_at": "2026-10-17T00:00:00Z",
                        }
                    }
                ).encode()
                if code == 429:
                    headers["Retry-After"] = "30"
            elif self.path not in {
                "/api/js-only",
                "/js-only",
                "/favicon.ico",
            } and not self.path.startswith("/extra-"):
                code = 404
            self.send_response(code)
            self.send_header("Content-Type", content)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Powered-By", "RedJohnFixture/1.2.3")
            if fixture.cookie:
                self.send_header(
                    "Set-Cookie", "owned-sensitive-cookie=private-value-123; Secure; HttpOnly"
                )
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                self.wfile.write(body)

        def log_message(self, *_args):
            pass

    fixture.server.RequestHandlerClass = Handler
    if port:
        fixture.server.server_close()
        fixture.server = ThreadingHTTPServer((host, port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(fixture.cert_file, fixture.key_file)
        fixture.server.socket = context.wrap_socket(fixture.server.socket, server_side=True)
        fixture.thread = threading.Thread(target=fixture.server.serve_forever, daemon=True)
    return fixture


def documents(fixture):
    return {
        "httpx_config": installed("httpx"),
        "katana_config": {**installed("katana"), "depth": 3},
        "vulnx_config": {
            **installed("vulnx"),
            "cve_ids": [CVE],
            "api_url": fixture.origin,
            "api_ips": [fixture.host],
        },
    }


def policy_for(fixture, remote, **changes):
    return EngagementPolicy(
        "pd-live",
        "operator",
        (fixture.origin,),
        profile="isolated-lab",
        egress_mode="enforced" if remote else "local-fixture",
        allowed_ips=(fixture.host + "/32",),
        request_budget=64,
        **changes,
    )


def evidence(store, policy, row):
    ref = row["result"]["summary"]["evidence_refs"][0]
    return json.loads(store.evidence_get(policy.engagement_id, ref)["excerpt"])


@pytest.mark.parametrize("remote", [False, True], ids=["loopback-https", "kernel-remote-https"])
async def test_actual_discovery_browser_intelligence_nuclei_durable_chain(tmp_path, remote):  # noqa: PLR0915 - six actual stages, reopen/resume and fixed control
    host, nuclei = host_for(remote), existing_live_lock()
    lock_document = json.loads(
        Path(os.environ.get("REDJOHN_NUCLEI_LOCK", DEFAULT_LOCK)).read_text()
    )
    started, stages, specs = time.monotonic(), [], []
    database = tmp_path / "state/agents.db"
    with owned_fixture(host, tmp_path / "tls") as fixture:
        configs, policy = documents(fixture), policy_for(fixture, remote)
        sequence = [
            "browser_discover",
            "httpx_probe",
            "katana_discover",
            "vulnx_intelligence",
            "nuclei_scan",
            "nuclei_scan",
        ]
        for index, capability in enumerate(sequence):
            with closing(AssessmentStore(database)) as store:
                async with (
                    NativeFixtureSession(policy, tmp_path / "nuclei-worker", nuclei) as session,
                    AssessmentRuntime(
                        store,
                        policy,
                        caller="operator",
                        **configs,
                        browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                        browser_limits=BrowserLimits(
                            max_pages=1, readiness_selector="body[data-ready='yes']"
                        ),
                        nuclei_lock=lock_document,
                        session=session,
                        envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
                    ) as runtime,
                ):
                    url = fixture.origin + ("/linked" if capability == "nuclei_scan" else "/")
                    if capability == "nuclei_scan":
                        observed = next(
                            row for row in store.surfaces(policy.engagement_id) if row["url"] == url
                        )
                        assert observed["source"] == "observed" and observed["request_ref"]
                        surface_id = observed["id"]
                    else:
                        surface_id = store.upsert_surface(policy.engagement_id, Surface(url))
                    spec = JobSpec(
                        surface_id,
                        {
                            "httpx_probe": "service_observation",
                            "katana_discover": "endpoint_discovery",
                            "vulnx_intelligence": "intelligence",
                        }.get(
                            capability,
                            "known_vulnerability" if capability == "nuclei_scan" else "discovery",
                        ),
                        capability,
                        policy_revision=policy.revision,
                        retest_revision="fixed" if index == 5 else "",
                        timeout_seconds=30,
                        **runtime.registry.execution_versions(capability),
                    )
                    specs.append(spec)
                    ids = store.submit(policy, [spec])
                    await runtime.scheduler.run_batch(max_jobs=1)
                    row = next(
                        row for row in store.jobs(policy.engagement_id) if row["id"] == ids[0]
                    )
                    if capability == "browser_discover" and row["coverage_status"] == "partial":
                        assert remote and {
                            item["code"] for item in row["result"]["summary"]["failures"]
                        } == {"browser_scope_denied"}
                    else:
                        assert row["coverage_status"] == "completed", row
                    if capability in {"httpx_probe", "katana_discover", "vulnx_intelligence"}:
                        detail = evidence(store, policy, row)
                        assert detail["tls_validation"] == "host_proxy_verified"
                        assert bool(detail["egress_attestations"]) is remote
                        assert not row["result"]["findings"]
                        if capability == "katana_discover":
                            urls = {item["url"] for item in store.surfaces(policy.engagement_id)}
                            assert fixture.origin + "/api/js-only" in urls
                            assert fixture.counts["/js-only"] == 0  # upstream regex limitation
                        if capability == "vulnx_intelligence":
                            advisory = row["result"]["summary"]["advisories"][0]
                            assert (
                                advisory["applicability"] == "unknown"
                                and not advisory["dynamic_finding"]
                            )
                            assert advisory["data_origin"] == "controlled_protocol_fixture"
                    if capability == "httpx_probe":
                        assert any(
                            item.product == "RedJohnFixture" and item.version == "1.2.3"
                            for item in runtime.technology.observations(
                                policy.engagement_id, fixture.origin + "/"
                            )
                        )
                    if capability == "nuclei_scan":
                        assert len(row["result"]["findings"]) == (0 if fixture.fixed else 1)
                        fixture.fixed = True
                    assert not runtime.governor.snapshot()["active"]
                    stages.append(
                        {
                            "capability": capability,
                            "coverage_status": row["coverage_status"],
                            "summary": row["result"]["summary"],
                            "resources": runtime.governor.snapshot(),
                        }
                    )
        before = dict(fixture.counts)
        with closing(AssessmentStore(database)) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                **configs,
                browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            ) as runtime:
                store.submit(policy, specs)
                await runtime.scheduler.run_batch(max_jobs=16)
                assert dict(fixture.counts) == before
                assert all(
                    not list((database.parent / (tool + "-workers")).glob("job-*"))
                    for tool in CAPABILITIES
                )
                assert not any(row["path"] == "/logout" for row in fixture.requests)
                assert not any(row["api_key"] for row in fixture.requests)
                report = build_report(store, policy.engagement_id, registry=runtime.registry)
                assert len(report["findings_page"]) == 1
        result = {
            "remote": remote,
            "duration_seconds": time.monotonic() - started,
            "actual_binaries": {key: value["binary"] for key, value in configs.items()},
            "stages": stages,
            "https_request_counts": before,
            "duplicate_requests_after_resume": 0,
            "model_calls": 0,
            "vulnx_data": "controlled_protocol_fixture_not_live_provider",
        }
        target = os.environ.get("REDJOHN_PD_E2E_MEASUREMENTS")
        if target:
            path = Path(target)
            path = path.with_name(path.stem + ("-remote" if remote else "-loopback") + path.suffix)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result, indent=2) + "\n")


@pytest.mark.parametrize("tool", ["httpx", "katana", "vulnx"])
async def test_actual_bad_binary_digest_is_blocked_before_target_request(tmp_path, tool):
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        configs, policy = documents(fixture), policy_for(fixture, remote=False)
        configs[tool + "_config"]["binary"]["sha256"] = "0" * 64
        with closing(AssessmentStore(tmp_path / "state.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                **configs,
                browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            ) as runtime:
                surface_id = store.upsert_surface(
                    policy.engagement_id, Surface(fixture.origin + "/")
                )
                capability = CAPABILITIES[tool]
                store.submit(
                    policy,
                    [
                        JobSpec(
                            surface_id,
                            "discovery",
                            capability,
                            **runtime.registry.execution_versions(capability),
                        )
                    ],
                )
                await runtime.scheduler.run_batch(max_jobs=1)
                row = store.jobs(policy.engagement_id)[0]
                assert row["coverage_status"] == "blocked"
                assert row["result"]["error"]["code"] == tool + "_binary_or_version_mismatch"
                assert not fixture.counts


@pytest.mark.parametrize("tool", ["httpx", "katana"])
@pytest.mark.parametrize("fault", ["tls", "budget", "rate", "huge", "encoded", "redirect"])
async def test_actual_discovery_faults_never_become_clean_negative(tmp_path, tool, fault):
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        configs, policy = documents(fixture), policy_for(fixture, remote=False)
        url = fixture.origin + ("/" if fault in {"tls", "budget"} else "/" + fault)
        tls = BrowserTLSConfig(upstream_ca_file=fixture.ca_file if fault != "tls" else None)
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                **configs,
                browser_tls=tls,
                envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
            ) as runtime:
                if fault == "budget":
                    store.consume_requests(policy, policy.request_budget)
                surface_id = store.upsert_surface(policy.engagement_id, Surface(url))
                capability = CAPABILITIES[tool]
                store.submit(
                    policy,
                    [
                        JobSpec(
                            surface_id,
                            "discovery",
                            capability,
                            **runtime.registry.execution_versions(capability),
                        )
                    ],
                )
                await runtime.scheduler.run_batch(max_jobs=1)
                row = store.jobs(policy.engagement_id)[0]
                if fault == "redirect":
                    assert row["coverage_status"] == "completed", row
                    assert fixture.counts["/redirect"] == 1 and sum(fixture.counts.values()) == 1
                else:
                    assert row["coverage_status"] in {"blocked", "inconclusive"}, row
                    assert row["result"]["error"] and not row["result"]["findings"]
                    if fault == "rate":
                        assert not runtime.rate_limits.admit(fixture.origin)
                assert runtime.governor.snapshot()["active"] == {}
                assert not list((tmp_path / ("state/" + tool + "-workers")).glob("job-*"))


@pytest.mark.parametrize("limit", ["unsafe-route", "page-limit"])
async def test_actual_katana_scope_and_page_budget_remain_enforced(tmp_path, limit):
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        configs, policy = documents(fixture), policy_for(fixture, remote=False)
        if limit == "page-limit":
            configs["katana_config"]["max_pages"] = 2
        path = "/guard" if limit == "unsafe-route" else "/many"
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                **configs,
                browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            ) as runtime:
                sid = store.upsert_surface(policy.engagement_id, Surface(fixture.origin + path))
                store.submit(
                    policy,
                    [
                        JobSpec(
                            sid,
                            "endpoint_discovery",
                            "katana_discover",
                            **runtime.registry.execution_versions("katana_discover"),
                        )
                    ],
                )
                await runtime.scheduler.run_batch(max_jobs=1)
                row = store.jobs(policy.engagement_id)[0]
                assert fixture.counts["/logout"] == 0
                if limit == "page-limit":
                    assert sum(fixture.counts.values()) <= 2
                    assert row["result"]["summary"]["complete_responses"] <= 2
                    assert row["coverage_status"] == "partial"
                else:
                    assert row["coverage_status"] == "inconclusive", row
                    assert row["result"]["error"]["code"] == "katana_proxy_incomplete_response"


@pytest.mark.parametrize("tool", ["httpx", "katana", "vulnx"])
@pytest.mark.parametrize("interrupt", ["cancel", "timeout"])
async def test_actual_discovery_interrupt_reaps_worker_and_preserves_evidence(
    tmp_path, tool, interrupt
):
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        configs, policy = documents(fixture), policy_for(fixture, remote=False)
        if tool == "vulnx":
            fixture.api_delay = 5
        expected_path = "/v2/vulnerability/" + CVE if tool == "vulnx" else "/slow"
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                **configs,
                browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
            ) as runtime:
                capability = CAPABILITIES[tool]
                sid = store.upsert_surface(policy.engagement_id, Surface(fixture.origin + "/slow"))
                job = store.submit(
                    policy,
                    [
                        JobSpec(
                            sid,
                            "discovery",
                            capability,
                            timeout_seconds=3 if interrupt == "timeout" else 15,
                            **runtime.registry.execution_versions(capability),
                        )
                    ],
                )[0]
                task = asyncio.create_task(runtime.scheduler.run_batch(max_jobs=1))
                async with asyncio.timeout(12):
                    while not fixture.counts[expected_path]:
                        if task.done():
                            await task
                            pytest.fail("worker stopped before the slow endpoint was reached")
                        await asyncio.sleep(0.02)
                    process = runtime.scheduler.adapters[capability].runner.process
                    assert process is not None
                    if interrupt == "cancel":
                        await runtime.scheduler.cancel(job_id=job)
                    await task
                row = store.jobs(policy.engagement_id)[0]
                assert row["execution_status"] == (
                    "cancelled" if interrupt == "cancel" else "timed_out"
                ), row
                assert row["result"]["error"]["partial_evidence_refs"]
                assert process.returncode is not None and fixture.counts[expected_path] == 1
                assert runtime.governor.snapshot()["active"] == {}
                assert not list((tmp_path / ("state/" + tool + "-workers")).glob("job-*"))


@pytest.mark.parametrize("tool", ["httpx", "katana"])
async def test_actual_discovery_does_not_persist_raw_cookie_headers(tmp_path, tool):
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        fixture.cookie = True
        configs, policy = documents(fixture), policy_for(fixture, remote=False)
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                **configs,
                browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            ) as runtime:
                sid = store.upsert_surface(policy.engagement_id, Surface(fixture.origin + "/"))
                capability = CAPABILITIES[tool]
                store.submit(
                    policy,
                    [
                        JobSpec(
                            sid,
                            "discovery",
                            capability,
                            **runtime.registry.execution_versions(capability),
                        )
                    ],
                )
                await runtime.scheduler.run_batch(max_jobs=1)
                row = store.jobs(policy.engagement_id)[0]
                assert row["coverage_status"] == "completed", row
                assert "private-value-123" not in json.dumps(row)
                assert "private-value-123" not in json.dumps(evidence(store, policy, row))


async def test_actual_vulnx_key_injection_persistent_cache_and_explicit_refresh(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("PDCP_API_KEY", "unrelated-host-credential-must-not-leak")
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        configs, policy = documents(fixture), policy_for(fixture, remote=False)
        key = "owned-fixture-api-key-12345"
        private = tmp_path / "api-key.json"
        private.write_text(json.dumps({"api_key": key}))
        private.chmod(0o600)
        configs["vulnx_config"]["api_key_file"] = str(private)
        database = tmp_path / "state/agents.db"
        for index in range(3):
            with closing(AssessmentStore(database)) as store:
                async with AssessmentRuntime(
                    store,
                    policy,
                    caller="operator",
                    **configs,
                    browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                ) as runtime:
                    sid = store.upsert_surface(
                        policy.engagement_id, Surface(fixture.origin + "/asset-" + str(index))
                    )
                    job = store.submit(
                        policy,
                        [
                            JobSpec(
                                sid,
                                "intelligence",
                                "vulnx_intelligence",
                                retest_revision="explicit-refresh" if index == 2 else "",
                                **runtime.registry.execution_versions("vulnx_intelligence"),
                            )
                        ],
                    )[0]
                    await runtime.scheduler.run_batch(max_jobs=1)
                    row = next(row for row in store.jobs(policy.engagement_id) if row["id"] == job)
                    assert row["coverage_status"] == "completed", row
                    assert row["result"]["summary"]["cache_hits"] == (1 if index == 1 else 0)
                    assert fixture.counts["/v2/vulnerability/" + CVE] == (2 if index == 2 else 1)
                    assert not store.findings(policy.engagement_id)
                    assert all(request["api_key"] == key for request in fixture.requests)
                    assert key not in json.dumps(row)
                    for ref in row["result"]["summary"]["evidence_refs"]:
                        assert key not in store.evidence_get(policy.engagement_id, ref)["excerpt"]
        assert all(
            request["path"].startswith("/v2/vulnerability/CVE-") for request in fixture.requests
        )


@pytest.mark.parametrize("problem", ["unauthorized", "rate", "wrong-id", "tls", "budget"])
async def test_actual_vulnx_provider_failure_is_not_absence_of_vulnerabilities(tmp_path, problem):
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        fixture.api_status = {"unauthorized": 401, "rate": 429}.get(problem, 200)
        fixture.api_wrong_id = problem == "wrong-id"
        configs, policy = documents(fixture), policy_for(fixture, remote=False)
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                **configs,
                browser_tls=BrowserTLSConfig(
                    upstream_ca_file=fixture.ca_file if problem != "tls" else None
                ),
            ) as runtime:
                if problem == "budget":
                    store.consume_requests(policy, policy.request_budget)
                sid = store.upsert_surface(policy.engagement_id, Surface(fixture.origin + "/"))
                store.submit(
                    policy,
                    [
                        JobSpec(
                            sid,
                            "intelligence",
                            "vulnx_intelligence",
                            **runtime.registry.execution_versions("vulnx_intelligence"),
                        )
                    ],
                )
                await runtime.scheduler.run_batch(max_jobs=1)
                row = store.jobs(policy.engagement_id)[0]
                assert row["coverage_status"] in {"blocked", "inconclusive"}, row
                assert not row["result"]["summary"]["advisories"] and not row["result"]["findings"]
                assert fixture.counts["/v2/vulnerability/" + CVE] == (
                    0 if problem in {"tls", "budget"} else 1
                )


async def test_actual_public_vulnx_provider_via_durable_scheduler(tmp_path):
    host = host_for(remote=True)
    with owned_fixture(host, tmp_path / "tls") as fixture:
        policy = policy_for(fixture, remote=True)
        ips = sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(
                    "api.projectdiscovery.io", 443, type=socket.SOCK_STREAM
                )
            }
        )
        config = {**installed("vulnx"), "api_ips": ips, "cve_ids": [CVE]}
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                vulnx_config=config,
                browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
            ) as runtime:
                sid = store.upsert_surface(
                    policy.engagement_id, Surface(fixture.origin + "/private-asset-never-uploaded")
                )
                spec = JobSpec(
                    sid,
                    "intelligence",
                    "vulnx_intelligence",
                    timeout_seconds=25,
                    **runtime.registry.execution_versions("vulnx_intelligence"),
                )
                job = store.submit(policy, [spec])[0]
                started = time.monotonic()
                await runtime.scheduler.run_batch(max_jobs=1)
                row = next(row for row in store.jobs(policy.engagement_id) if row["id"] == job)
                proof = {
                    "capability": "vulnx_intelligence",
                    "data_source": "actual_public_ProjectDiscovery_API",
                    "public_cve_ids": [CVE],
                    "api_ip_pins": ips,
                    "duration_seconds": time.monotonic() - started,
                    "coverage_status": row["coverage_status"],
                    "result": row["result"],
                }
                if row["result"]["summary"].get("evidence_refs"):
                    proof["worker_evidence"] = evidence(store, policy, row)
                target = os.environ.get("REDJOHN_PUBLIC_VULNX_MEASUREMENTS")
                if target:
                    Path(target).parent.mkdir(parents=True, exist_ok=True)
                    Path(target).write_text(json.dumps(proof, indent=2) + "\n")
                if row["coverage_status"] != "completed":
                    code = (row["result"]["error"] or {})["code"]
                    if code in {
                        "rate_limited",
                        "vulnx_provider_auth_or_service_unavailable",
                        "vulnx_provider_or_schema_error",
                        "vulnx_upstream_tls_verification_failed",
                        "vulnx_output_truncated",
                        "vulnx_provider_response_incomplete",
                        "vulnx_timeout",
                    }:
                        pytest.skip(
                            "blocked_public_provider: " + code + "; see actual execution evidence"
                        )
                    pytest.fail("public provider E2E implementation failure: " + code)
                advisory = row["result"]["summary"]["advisories"][0]
                assert (
                    advisory["advisory_id"] == CVE and advisory["data_origin"] == "public_provider"
                )
                assert advisory["applicability"] == "unknown" and not row["result"]["findings"]
                detail = evidence(store, policy, row)
                assert detail["provider_tls_roots"] == "system"
                assert (
                    detail["egress_attestations"]
                    and detail["tls_validation"] == "host_proxy_verified"
                )
                assert set(detail["responses"]) == {
                    "https://api.projectdiscovery.io/v2/vulnerability/" + CVE
                }
                store.submit(policy, [spec])
                assert await runtime.scheduler.run_batch(max_jobs=1) == []
                assert not fixture.requests


async def test_actual_cli_selects_optional_tools_lazily_and_resumes_without_traffic(tmp_path):
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        configs, policy = documents(fixture), policy_for(fixture, remote=False)
        config = {
            "policy": policy.to_dict(),
            "tls": {"upstream_ca_file": str(fixture.ca_file)},
            "httpx": configs["httpx_config"],
            "katana": configs["katana_config"],
            "vulnx": configs["vulnx_config"],
            "seeds": [{"url": fixture.origin + "/", "capabilities": list(CAPABILITIES.values())}],
        }
        path, output, before = tmp_path / "config.json", tmp_path / "output", None
        for attempt in range(2):
            if attempt:
                config["httpx"]["rate_limit"] = 1
                config["katana"]["rate_limit"] = 1
            path.write_text(json.dumps(config))
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "redjohn.assessment",
                "run",
                "--config",
                str(path),
                "--output",
                str(output),
                env={
                    **os.environ,
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                    "REDJOHN_TELEMETRY": "0",
                    "OPENAI_AGENTS_DISABLE_TRACING": "1",
                },
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 35)
            assert process.returncode == 0, (stdout, stderr)
            report = json.loads((output / "assessment-report.json").read_text())
            assert len(report["jobs_page"]) == 3
            assert all(row["coverage_status"] == "completed" for row in report["jobs_page"])
            assert report["metrics"]["model_calls"] == 0
            if before is not None:
                assert dict(fixture.counts) == before
            before = dict(fixture.counts)


async def test_actual_dns_https_origin_and_optional_default_port(tmp_path):
    host = host_for(remote=True)
    name = os.environ.get("REDJOHN_DNS_FIXTURE_NAME")
    if not name:
        pytest.skip("blocked_owned_dns_fixture_not_configured; no system files changed by tests")
    addresses = {item[4][0] for item in socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)}
    assert addresses == {host}, "DNS fixture must resolve only to the owned interface"
    port = int(os.environ.get("REDJOHN_DNS_FIXTURE_PORT", "0"))
    fixture = owned_fixture(host, tmp_path / "tls", port=port)
    with closing(BrowserTLSIdentity((host, name))) as identity:
        handler, actual_port = fixture.server.RequestHandlerClass, fixture.server.server_port
        fixture.server.server_close()
        fixture.server = ThreadingHTTPServer((host, actual_port), handler)
        fixture.server.socket = identity.server_context.wrap_socket(
            fixture.server.socket, server_side=True
        )
        fixture.thread = threading.Thread(target=fixture.server.serve_forever, daemon=True)
        fixture.ca_file = identity.directory / "chain.pem"
        authority = (
            name if fixture.server.server_port == 443 else f"{name}:{fixture.server.server_port}"
        )
        origin = "https://" + authority
        policy = EngagementPolicy(
            "pd-dns-live",
            "operator",
            (origin,),
            profile="isolated-lab",
            egress_mode="enforced",
            allowed_ips=(host + "/32",),
        )
        with fixture, closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                httpx_config=installed("httpx"),
                katana_config={**installed("katana"), "depth": 3},
                browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
            ) as runtime:
                sid = store.upsert_surface(policy.engagement_id, Surface(origin + "/"))
                for capability in ("httpx_probe", "katana_discover"):
                    store.submit(
                        policy,
                        [
                            JobSpec(
                                sid,
                                "discovery",
                                capability,
                                **runtime.registry.execution_versions(capability),
                            )
                        ],
                    )
                await runtime.scheduler.run_batch(max_jobs=2)
                assert all(
                    row["coverage_status"] == "completed"
                    for row in store.jobs(policy.engagement_id)
                ), store.jobs(policy.engagement_id)
                urls = {row["url"] for row in store.surfaces(policy.engagement_id)}
                assert origin + "/" in urls and origin + "/api/js-only" in urls
                assert fixture.counts["/api/js-only"] == 1
                measurement = os.environ.get("REDJOHN_DNS_E2E_MEASUREMENTS")
                if measurement:
                    Path(measurement).parent.mkdir(parents=True, exist_ok=True)
                    Path(measurement).write_text(
                        json.dumps(
                            {
                                "dns_name": name,
                                "actual_resolution": sorted(addresses),
                                "https_port": actual_port,
                                "jobs": [
                                    {
                                        "capability": row["capability"],
                                        "coverage_status": row["coverage_status"],
                                        "evidence": evidence(store, policy, row),
                                    }
                                    for row in store.jobs(policy.engagement_id)
                                ],
                                "resources": runtime.governor.snapshot(),
                            },
                            indent=2,
                        )
                        + "\n"
                    )


@pytest.mark.parametrize(
    "tool,path",
    [
        ("httpx", "/a%2fb?x=1&x=2&blank=&z=%2F"),
        ("katana", "/a%2fb?x=1&x=2&blank=&z=%2F"),
        ("httpx", "/echo?x=1&x=2&blank=&z=%2F"),
        ("katana", "/echo?x=1&x=2&blank=&z=%2F"),
        ("httpx", "/echo?"),
    ],
)
async def test_actual_discovery_preserves_encoded_path_and_query(tmp_path, tool, path):
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        configs, policy = documents(fixture), policy_for(fixture, remote=False)
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                **configs,
                browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            ) as runtime:
                capability = CAPABILITIES[tool]
                sid = store.upsert_surface(policy.engagement_id, Surface(fixture.origin + path))
                store.submit(
                    policy,
                    [
                        JobSpec(
                            sid,
                            "discovery",
                            capability,
                            **runtime.registry.execution_versions(capability),
                        )
                    ],
                )
                await runtime.scheduler.run_batch(max_jobs=1)
                row = store.jobs(policy.engagement_id)[0]
                if row["coverage_status"] == "unsupported":
                    assert row["result"]["error"]["code"] == tool + "_request_rewrite_unsupported"
                    assert not fixture.counts
                else:
                    assert row["coverage_status"] == "completed", row
                    assert fixture.counts[path] == 1 and sum(fixture.counts.values()) == 1
