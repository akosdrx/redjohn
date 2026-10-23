"""Real ffuf + Chromium + Nuclei, durable restart, HTTPS and adversarial responses.

All traffic goes to servers owned by this test. No fake executable or scanner
mock is used. Remote cases additionally require real Linux kernel namespaces.
"""

import asyncio
import gzip
import json
import os
import platform
import time
from collections import Counter
from contextlib import closing, suppress
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.ffuf import FFUFConfig
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.report import build_report, write_report
from redjohn.assessment.resources import ResourceEnvelope, process_tree_memory
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from tests.remote_https_fixture import RemoteHTTPSFixture, fixture_host
from tests.test_nuclei_live import DEFAULT_LOCK, existing_live_lock


def installed():
    directory = Path(__file__).resolve().parents[1] / ".tools/ffuf/2.1.0"
    receipt = directory / "receipt.json"
    if not receipt.is_file():
        if os.environ.get("REDJOHN_REQUIRE_FFUF_E2E") == "1":
            pytest.fail("blocked_missing_dependency: pinned ffuf is required")
        pytest.skip("blocked_missing_dependency: ffuf not installed; no install attempted")
    record = json.loads(receipt.read_text())
    return {
        "binary": {
            "path": str(directory / "ffuf"),
            "sha256": record["binary_sha256"],
            "version": record["version"],
        },
        "paths": ["hidden", "absent", "redirect"],
    }


def owned_fixture(host, tmp_path):
    fixture = RemoteHTTPSFixture(host, tmp_path)
    fixture.request_counts = Counter()
    fixture.fixed = False

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            fixture.request_counts[self.path] += 1
            status, body, headers = 200, b"fixed-control", {}
            if self.path == "/":
                body = (
                    b"<html><body><script>document.body.dataset.ready='yes'</script>"
                    b"RedJohn fixture</body></html>"
                )
            elif self.path == "/hidden":
                body = b"fixed-control" if fixture.fixed else b"redjohn-fixture-marker"
            elif self.path == "/redirect":
                status, headers = 302, {"Location": "https://outside.invalid/credential-trap"}
            elif self.path == "/rate":
                status, headers = 429, {"Retry-After": "5"}
            elif self.path == "/encoded":
                body, headers = gzip.compress(b"x" * (4 * 1024**2)), {"Content-Encoding": "gzip"}
            elif self.path == "/slow":
                time.sleep(2)
            else:
                status = 404
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/html" if self.path == "/" else "text/plain")
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

        def log_message(self, *_args):
            pass

    fixture.server.RequestHandlerClass = Handler
    return fixture


def environment(remote):
    if remote and platform.system() != "Linux":
        if os.environ.get("REDJOHN_REQUIRE_REMOTE_E2E") == "1":
            pytest.fail("blocked_linux_network_namespace_required")
        pytest.skip("blocked_linux_network_namespace_required")
    return fixture_host() if remote else "127.0.0.1"


@pytest.mark.parametrize("remote", [False, True], ids=["loopback-https", "kernel-remote-https"])
async def test_actual_ffuf_browser_nuclei_durable_chain_and_retest(tmp_path, remote):  # noqa: PLR0915 - real durable chain plus controls
    host, document, nuclei = environment(remote), installed(), existing_live_lock()
    nuclei_document = json.loads(
        Path(os.environ.get("REDJOHN_NUCLEI_LOCK", DEFAULT_LOCK)).read_text()
    )
    database = tmp_path / "state/agents.db"
    started, metrics = time.monotonic(), []
    with owned_fixture(host, tmp_path / "tls") as fixture:
        policy = EngagementPolicy(
            "ffuf-live",
            "operator",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="enforced" if remote else "local-fixture",
            allowed_ips=(host + "/32",),
            request_budget=32,
        )
        config = FFUFConfig.from_mapping(document)
        specs = []
        # Reopen both store and coordinator between every stage. No network work
        # repeats when the same durable spec is submitted again.
        for stage in ["browser_discover", "ffuf_discover", "nuclei_scan", "nuclei_scan"]:
            with closing(AssessmentStore(database)) as store:
                policy = store.register(policy)
                async with (
                    NativeFixtureSession(policy, tmp_path / "nuclei-worker", nuclei) as session,
                    AssessmentRuntime(
                        store,
                        policy,
                        caller="operator",
                        ffuf_config=document,
                        browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                        browser_limits=BrowserLimits(
                            max_pages=1, readiness_selector="body[data-ready='yes']"
                        ),
                        nuclei_lock=nuclei_document,
                        session=session,
                        envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
                    ) as runtime,
                ):
                    url = fixture.origin + ("/hidden" if stage == "nuclei_scan" else "/")
                    if stage == "nuclei_scan":
                        discovered = next(
                            row for row in store.surfaces(policy.engagement_id) if row["url"] == url
                        )
                        assert discovered["source"] == "observed" and discovered["request_ref"]
                        surface_id = discovered["id"]
                    else:
                        surface_id = store.upsert_surface(policy.engagement_id, Surface(url))
                    spec = JobSpec(
                        surface_id,
                        {
                            "browser_discover": "discovery",
                            "ffuf_discover": "content_discovery",
                            "nuclei_scan": "known_vulnerability",
                        }[stage],
                        stage,
                        retest_revision="fixed-control" if fixture.fixed else "",
                        **runtime.registry.execution_versions(stage),
                    )
                    store.submit(policy, [spec])
                    completed = await runtime.scheduler.run_batch(max_jobs=2)
                    assert len(completed) == 1
                    current = next(
                        row
                        for row in store.jobs(policy.engagement_id)
                        if row["spec"]["retest_revision"] == spec.retest_revision
                        and row["spec"]["capability"] == stage
                    )
                    assert current["execution_status"] == "succeeded", current
                    if stage == "browser_discover" and current["coverage_status"] == "partial":
                        failures = current["result"]["summary"]["failures"]
                        assert failures and {item["code"] for item in failures} == {
                            "browser_scope_denied"
                        }
                        assert current["result"]["summary"]["metrics"]["visited_pages"] == 1
                    else:
                        assert current["coverage_status"] == "completed", current
                    result = current["result"]
                    if stage == "ffuf_discover":
                        observed = store.surfaces(policy.engagement_id)
                        assert any(
                            row["url"] == fixture.origin + "/hidden"
                            and row["source"] == "observed"
                            and row["request_ref"]
                            for row in observed
                        )
                        assert not any(row["url"].endswith("/absent") for row in observed)
                        assert result["summary"]["discovered_endpoints"] == 2
                        evidence = store.evidence_get(
                            policy.engagement_id,
                            result["summary"]["evidence_refs"][0],
                            max_bytes=65536,
                        )
                        if remote:
                            assert json.loads(evidence["excerpt"])["egress_attestations"]
                    if stage == "nuclei_scan":
                        assert len(result["findings"]) == (0 if fixture.fixed else 1)
                        fixture.fixed = True
                    specs.append(spec)
                    before = sum(fixture.request_counts.values())
                    store.submit(policy, specs)
                    assert await runtime.scheduler.run_batch(max_jobs=4) == []
                    assert sum(fixture.request_counts.values()) == before
                    assert runtime.governor.snapshot()["active"] == {}
                    metrics.append(
                        {
                            "capability": stage,
                            "result": result,
                            "scheduler": dict(runtime.scheduler.metrics),
                            "resources": runtime.governor.snapshot(),
                        }
                    )
                    report = build_report(
                        store,
                        policy.engagement_id,
                        metrics={"model_calls": 0},
                        registry=runtime.registry,
                    )
                    write_report(tmp_path / "report", report)
        assert fixture.request_counts["/hidden"] == 3  # ffuf + marker + fixed control
        assert fixture.request_counts["/absent"] == 1
        assert fixture.request_counts["/redirect"] == 1
        measurement = {
            "remote": remote,
            "duration_seconds": time.monotonic() - started,
            "requests": dict(fixture.request_counts),
            "stages": metrics,
            "model_calls": 0,
            "memory_after": asdict(process_tree_memory()),
            "config_revision": config.revision,
        }
        if output := os.environ.get("REDJOHN_FFUF_E2E_MEASUREMENTS"):
            path = Path(output).with_name(
                Path(output).stem + ("-remote.json" if remote else "-loopback.json")
            )
            path.write_text(json.dumps(measurement, indent=2) + "\n")


@pytest.mark.parametrize(
    "case,paths,budget",
    [
        ("encoded", ["encoded"], 4),
        ("rate", ["rate", "hidden"], 4),
        ("budget", ["hidden", "absent"], 1),
        ("tls", ["hidden"], 4),
        ("digest", ["hidden"], 4),
    ],
)
async def test_actual_ffuf_failure_is_not_negative(tmp_path, case, paths, budget):
    document = installed()
    document["paths"] = paths
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        policy = EngagementPolicy(
            "ffuf-fault",
            "operator",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            request_budget=budget,
        )
        if case == "digest":
            document["binary"]["sha256"] = "0" * 64
        config = FFUFConfig.from_mapping(document)
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                ffuf_config=document,
                browser_tls=None
                if case == "tls"
                else BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
            ) as runtime:
                sid = store.upsert_surface(policy.engagement_id, Surface(fixture.origin + "/"))
                store.submit(
                    policy,
                    [
                        JobSpec(
                            sid,
                            "content_discovery",
                            "ffuf_discover",
                            tool_version=config.version,
                            template_version=config.revision,
                        )
                    ],
                )
                await runtime.scheduler.run_batch()
                row = store.jobs(policy.engagement_id)[0]
                assert row["execution_status"] == "failed"
                assert row["coverage_status"] in {"blocked", "inconclusive"}
                if case == "digest":
                    assert row["result"]["error"]["code"] == "ffuf_binary_or_version_mismatch"
                    assert not fixture.request_counts
                else:
                    assert row["result"]["summary"]["evidence_refs"]
                assert not store.findings(policy.engagement_id)
                assert runtime.governor.snapshot()["active"] == {}
                assert sum(fixture.request_counts.values()) <= budget
                if case in {"rate", "tls"}:
                    assert fixture.request_counts["/hidden"] == 0


@pytest.mark.parametrize("interrupt", ["cancel", "timeout"])
async def test_actual_ffuf_interruption_preserves_evidence_and_reaps_process(tmp_path, interrupt):
    document = installed()
    document["paths"] = ["slow"]
    document["request_timeout"] = 5
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        policy = EngagementPolicy(
            "ffuf-interruption",
            "operator",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            max_attempts=1,
            retry_budget=0,
        )
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(
                store,
                policy,
                caller="operator",
                ffuf_config=document,
                browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
            ) as runtime:
                sid = store.upsert_surface(policy.engagement_id, Surface(fixture.origin + "/"))
                job = store.submit(
                    policy,
                    [
                        JobSpec(
                            sid,
                            "content_discovery",
                            "ffuf_discover",
                            timeout_seconds=1.5 if interrupt == "timeout" else 15,
                            **runtime.registry.execution_versions("ffuf_discover"),
                        )
                    ],
                )[0]
                task = asyncio.create_task(runtime.scheduler.run_batch())
                async with asyncio.timeout(10):
                    while not fixture.request_counts["/slow"]:
                        await asyncio.sleep(0.02)
                    adapter = runtime.scheduler.adapters["ffuf_discover"]
                    process = adapter._process
                    assert process is not None
                    if interrupt == "cancel":
                        await runtime.scheduler.cancel(job_id=job)
                    await task
                assert process.returncode is not None
                row = store.jobs(policy.engagement_id)[0]
                assert row["execution_status"] == (
                    "cancelled" if interrupt == "cancel" else "timed_out"
                )
                assert row["coverage_status"] in {"partial", "inconclusive"}
                assert row["result"]["error"]["partial_evidence_refs"]
                assert fixture.request_counts["/slow"] == 1
                assert runtime.governor.snapshot()["active"] == {}
                assert not list((tmp_path / "state/ffuf-workers").iterdir())
                assert await runtime.scheduler.run_batch() == []
