"""Actual Linux namespace + Chromium + authenticated Nuclei durable pipeline.

The target is a server owned by this test, bound to a real local interface.
No external website is contacted. CI can require every capability explicitly.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import os
import platform
import shutil
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope, process_tree_memory
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from tests.remote_https_fixture import RemoteHTTPSFixture, fixture_host
from tests.test_nuclei_live import DEFAULT_LOCK, existing_live_lock


def _unavailable(code: str) -> None:
    if os.environ.get("REDJOHN_REQUIRE_REMOTE_E2E") == "1":
        pytest.fail(code)
    pytest.skip("blocked_missing_capability: " + code)


def _dependencies():
    if platform.system() != "Linux":
        _unavailable("Linux network namespaces required")
    if not shutil.which("bwrap"):
        _unavailable("bubblewrap required")
    try:
        host = fixture_host()
        lock = existing_live_lock()
        from playwright.async_api import async_playwright  # noqa: PLC0415 - explicit optional dependency
    except pytest.skip.Exception as exc:
        _unavailable(str(exc))
    except (ImportError, RuntimeError, OSError) as exc:
        _unavailable(str(exc))
    path = Path(os.environ.get("REDJOHN_NUCLEI_LOCK", str(DEFAULT_LOCK)))
    return host, lock, json.loads(path.read_text()), async_playwright


def _row(store: AssessmentStore, policy: EngagementPolicy, job_id: str) -> dict:
    return next(row for row in store.jobs(policy.engagement_id, limit=100) if row["id"] == job_id)


def _assert_attested(values: list[dict]) -> None:
    assert values, "No actual worker kernel namespace attestation captured"
    for value in values:
        assert value["interfaces"] == ["lo"]
        assert value["effective_capabilities"] == "0"
        assert value["no_new_privileges"] is True
        assert set(value["namespaces"]) == {"net", "mnt", "pid", "user"}
        for name, namespace in value["namespaces"].items():
            assert namespace != str((Path("/proc/self/ns") / name).readlink())


async def test_actual_remote_authenticated_browser_inventory_nuclei_restart(  # noqa: PLR0912, PLR0915 - real lifecycle and failure matrix
    tmp_path: Path,
) -> None:
    host, lock, lock_document, async_playwright = _dependencies()
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            _unavailable("actual Playwright Chromium executable missing")
    database = tmp_path / ".state" / "agents.db"
    metrics: dict = {
        "platform": platform.platform(),
        "pid": os.getpid(),
        "binary_version": lock.binary_version,
        "binary_sha256": lock.binary_sha256,
        "stages": [],
        "model_calls": 0,
        "memory_before": asdict(process_tree_memory()),
    }
    started = time.monotonic()
    with RemoteHTTPSFixture(host, tmp_path / "upstream-tls") as fixture:
        policy = EngagementPolicy(
            "remote-authenticated-e2e",
            "operator",
            (fixture.origin,),
            allowed_ips=(host + "/32",),
            profile="isolated-lab",
            egress_mode="enforced",
            actor_ids=("anonymous", "alice", "bob"),
            request_budget=32,
        )
        assert not ipaddress.ip_address(host).is_loopback
        tls = BrowserTLSConfig(upstream_ca_file=fixture.ca_file)

        def enqueue(surface: Surface, capability: str, *, retest: str = "") -> tuple[str, str]:
            store = AssessmentStore(database)
            try:
                actual_policy = store.register(policy)
                surface_id = store.upsert_surface(policy.engagement_id, surface)
                spec = JobSpec(
                    surface_id,
                    "discovery" if capability == "browser_discover" else "known_vulnerability",
                    capability,
                    retest_revision=retest,
                    timeout_seconds=40,
                    tool_version=lock.binary_version if capability == "nuclei_scan" else "1",
                    template_version=lock.bundle_sha256 if capability == "nuclei_scan" else "",
                )
                return store.submit(actual_policy, [spec])[0], surface_id
            finally:
                store.close()

        run_number = 0

        async def run_queued(label: str, job_id: str | None, vault=None) -> dict | None:
            nonlocal run_number
            run_number += 1
            store = AssessmentStore(database)
            before = len(fixture.observed)
            stage_start = time.monotonic()
            try:
                async with (
                    NativeFixtureSession(
                        policy, tmp_path / f"worker-{run_number}", lock
                    ) as session,
                    AssessmentRuntime(
                        store,
                        policy,
                        caller="operator",
                        nuclei_lock=lock_document,
                        session=session,
                        browser_tls=tls,
                        auth_vault=vault,
                        actor_states={"alice": fixture.actor_state()},
                        envelope=ResourceEnvelope(total_memory_budget=3 * 1024**3),
                        browser_limits=BrowserLimits(
                            max_pages=1,
                            max_requests=8,
                            readiness_selector="body[data-ready='yes']",
                            readiness_timeout_ms=5000,
                            observation_window_ms=200,
                            total_timeout_seconds=30,
                        ),
                    ) as runtime,
                ):
                    executed = await runtime.scheduler.run_batch(max_jobs=1)
                    assert executed == ([job_id] if job_id else []), executed
                    result = _row(store, policy, job_id) if job_id else None
                    assert runtime.governor.snapshot()["active"] == {}
                    assert not runtime.browser.healthcheck()["ready"]
                    assert not session._active and not session._reservations
                    metrics["model_calls"] += runtime.scheduler.metrics["model_calls"]
                    resources = runtime.governor.snapshot()
                requests_used = store.db.execute(
                    "SELECT requests_used FROM rj_engagement WHERE id=?", (policy.engagement_id,)
                ).fetchone()[0]
                metrics["stages"].append(
                    {
                        "case": label,
                        "duration_seconds": time.monotonic() - stage_start,
                        "target_requests": fixture.observed[before:],
                        "requests_used": requests_used,
                        "execution_status": result["execution_status"] if result else None,
                        "coverage_status": result["coverage_status"] if result else None,
                        "result": result["result"] if result else None,
                        "resources": resources,
                    }
                )
                return result
            finally:
                store.close()

        seed = Surface(
            fixture.origin + "/",
            actor_id="alice",
            tenant_id="tenant-a",
            session_revision="7",
            source="imported",
            workflow_state="approved_seed",
        )
        browser_id, _ = enqueue(seed, "browser_discover")
        browser = await run_queued("authenticated_browser_inventory", browser_id)
        assert browser["execution_status"] == "succeeded", browser
        assert browser["coverage_status"] in {"completed", "partial"}, browser
        # Full Chromium may attempt its own Google startup traffic even with
        # background networking disabled. The proxy must deny those requests;
        # retain partial coverage rather than disguising the denied egress.
        browser_summary = browser["result"]["summary"]
        assert {failure["code"] for failure in browser_summary["failures"]} <= {
            "browser_scope_denied"
        }
        assert browser_summary["metrics"]["proxy_upstream_tls_failures"] == 0
        assert browser_summary["metrics"]["proxy_limit_drops"] == 0
        _assert_attested(browser["result"]["summary"]["tool"]["egress_attestations"])
        metrics["chromium_version"] = browser["result"]["summary"]["tool"]["chromium_version"]
        metrics["playwright_version"] = browser["result"]["summary"]["tool"]["playwright_version"]
        store = AssessmentStore(database)
        try:
            private_record = next(
                row
                for row in store.surfaces(policy.engagement_id, limit=100)
                if row["url"] == fixture.origin + "/private" and row["actor_id"] == "alice"
            )
            private = store.surface(policy.engagement_id, private_record["id"])
            assert private.source == "observed" and private.request_ref
            captured = json.loads(
                store.evidence_get(policy.engagement_id, private.request_ref)["excerpt"]
            )
            assert captured["status"] == 200 and captured["sent"] is True
            assert (captured["actor_id"], captured["tenant_id"], captured["session_revision"]) == (
                "alice",
                "tenant-a",
                "7",
            )
        finally:
            store.close()
        metrics["inventory_source"] = private.source
        metrics["captured_request_ref"] = private.request_ref
        data = {
            "version": 1,
            "entries": [
                {
                    "engagement_id": policy.engagement_id,
                    "owner_id": policy.owner_id,
                    "actor_id": "alice",
                    "tenant_id": "tenant-a",
                    "session_revision": "7",
                    "policy_revision": policy.revision,
                    "expires_at": time.time() + 600,
                    "origin": fixture.origin,
                    "allowed_requests": [
                        {
                            "url": private.url,
                            "method": private.method,
                            "request_ref": private.request_ref,
                        }
                    ],
                    "headers": {},
                    "cookies": [{"name": "fixture_session", "value": fixture.credential}],
                }
            ],
        }
        vault = AuthReplayVault.from_mapping(data, policy)
        named_id, named_surface_id = enqueue(private, "nuclei_scan")
        host_secrets = tmp_path / "host-secrets"
        host_secrets.mkdir(mode=0o700)
        vault_path = host_secrets / "replay.json"
        descriptor = os.open(vault_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(data, stream)
        config_path = tmp_path / "configured-remote.json"
        config_path.write_text(
            json.dumps(
                {
                    "policy": policy.to_dict(),
                    "nuclei_lock": lock_document,
                    "tls": {"upstream_ca_file": str(fixture.ca_file)},
                    "auth_vault_file": str(vault_path),
                    "seeds": [],
                    "resources": {"total_memory_budget": 3 * 1024**3},
                }
            )
        )
        environment = dict(os.environ)
        package_root = str(Path(__file__).resolve().parents[1])
        environment["PYTHONPATH"] = package_root + (
            os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""
        )
        before = len(fixture.observed)
        cli_started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "redjohn.assessment",
            "run",
            "--config",
            str(config_path),
            "--output",
            str(tmp_path),
            "--max-jobs",
            "1",
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 60)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        assert fixture.credential.encode() not in stdout + stderr
        assert len(stdout) <= 65536 and len(stderr) <= 65536
        assert process.returncode == 0, (stdout.decode()[-8192:], stderr.decode()[-8192:])
        assert process.pid != os.getpid()
        metrics["independent_cli_pids"] = [process.pid]
        report = json.loads((tmp_path / "assessment-report.json").read_text())
        assert report["metrics"]["model_calls"] == 0
        assert report["metrics"]["jobs"] == 1
        store = AssessmentStore(database)
        try:
            named = _row(store, policy, named_id)
        finally:
            store.close()
        metrics["stages"].append(
            {
                "case": "named_actor_candidate_cli_process",
                "pid": process.pid,
                "exit_code": process.returncode,
                "duration_seconds": time.monotonic() - cli_started,
                "target_requests": fixture.observed[before:],
                "result": named["result"],
                "execution_status": named["execution_status"],
                "coverage_status": named["coverage_status"],
                "resources": report["metrics"]["resources"],
            }
        )
        assert named["execution_status"] == "succeeded", named
        assert named["coverage_status"] == "completed", named
        assert len(named["result"]["findings"]) == 1
        assert named["result"]["findings"][0]["finding_status"] == "candidate"
        _assert_attested(named["result"]["summary"]["network"]["egress_attestations"])
        anonymous_id, _ = enqueue(Surface(private.url), "nuclei_scan")
        anonymous = await run_queued("anonymous_denied", anonymous_id)
        assert anonymous["coverage_status"] == "blocked", anonymous
        assert anonymous["result"]["error"]["code"] == "authentication_expired", anonymous
        assert anonymous["result"]["summary"]["no_finding_observed"] is False
        before = len(fixture.observed)
        duplicate_id, _ = enqueue(private, "nuclei_scan")
        assert duplicate_id == named_id
        assert await run_queued("restart_duplicate_no_request", None, vault) is None
        assert len(fixture.observed) == before

        fixture.mode = "fixed"
        fixed_id, _ = enqueue(private, "nuclei_scan", retest="fixed-deployment-2")
        fixed = await run_queued("authenticated_fixed_control", fixed_id, vault)
        assert fixed["coverage_status"] == "completed", fixed
        assert fixed["result"]["summary"]["no_finding_observed"] is True
        assert not fixed["result"]["findings"]

        before = len(fixture.observed)
        for label, changes in (
            ("wrong_session_revision_no_request", {"session_revision": "8"}),
            ("wrong_tenant_no_request", {"tenant_id": "tenant-b"}),
            ("wrong_actor_no_request", {"actor_id": "bob"}),
        ):
            wrong_id, _ = enqueue(replace(private, **changes), "nuclei_scan")
            wrong = await run_queued(label, wrong_id, vault)
            assert wrong["coverage_status"] == "blocked", wrong
            assert wrong["result"]["error"]["code"] == "auth_replay_identity_or_request_mismatch"
        expiring = copy.deepcopy(data)
        expiring["entries"][0]["expires_at"] = time.time() + 0.01
        expired_vault = AuthReplayVault.from_mapping(expiring, policy)
        await asyncio.sleep(0.02)
        expired_id, _ = enqueue(private, "nuclei_scan", retest="expired-session")
        expired = await run_queued("expired_credentials_no_request", expired_id, expired_vault)
        assert expired["coverage_status"] == "blocked", expired
        assert expired["result"]["error"]["code"] == "auth_replay_expired"
        assert len(fixture.observed) == before

        for label, changes in (
            ("capture_identity_tamper_no_request", {"actor_id": "bob"}),
            ("capture_sent_false_no_request", {"sent": False}),
            ("capture_sent_missing_no_request", {}),
            ("capture_policy_tamper_no_request", {"policy_revision": "other-policy"}),
        ):
            altered_capture = {**captured, **changes}
            if label == "capture_sent_missing_no_request":
                altered_capture.pop("sent")
            store = AssessmentStore(database)
            try:
                bad_ref = store.evidence_put(
                    policy.engagement_id, altered_capture, kind="browser_request_metadata"
                )
            finally:
                store.close()
            tampered_surface = replace(private, workflow_state=label, request_ref=bad_ref)
            tampered_data = copy.deepcopy(data)
            tampered_data["entries"][0]["allowed_requests"][0]["request_ref"] = bad_ref
            tampered_vault = AuthReplayVault.from_mapping(tampered_data, policy)
            tampered_id, _ = enqueue(tampered_surface, "nuclei_scan")
            tampered = await run_queued(label, tampered_id, tampered_vault)
            assert tampered["coverage_status"] == "blocked", tampered
            assert tampered["result"]["error"]["code"] == "auth_replay_capture_identity_mismatch"
            assert len(fixture.observed) == before

        fixture.mode = "redirect"
        redirect_id, _ = enqueue(private, "nuclei_scan", retest="redirect-control")
        redirect = await run_queued("redirect_no_credential_replay", redirect_id, vault)
        assert redirect["coverage_status"] == "inconclusive", redirect
        assert redirect["result"]["summary"]["no_finding_observed"] is False
        assert fixture.counts["/credential-trap"] == 0
        assert len(fixture.observed) == before + 1
        store = AssessmentStore(database)
        try:
            assert len(store.findings(policy.engagement_id)) == 1
            assert (
                store.surface(policy.engagement_id, named_surface_id).request_ref
                == private.request_ref
            )
            requests_used = store.db.execute(
                "SELECT requests_used FROM rj_engagement WHERE id=?", (policy.engagement_id,)
            ).fetchone()[0]
            assert requests_used == len(fixture.observed)
        finally:
            store.close()
        assert fixture.credential.encode() not in database.read_bytes()
        worker_files = list(tmp_path.glob("worker-*/**/*"))
        worker_files.extend((tmp_path / ".state" / "nuclei-worker").rglob("*"))
        for path in worker_files:
            if path.is_file():
                assert fixture.credential.encode() not in path.read_bytes()
        metrics.update(
            {
                "http_requests": len(fixture.observed),
                "persisted_requests_used": requests_used,
                "restart_duplicate_requests": 0,
                "duration_seconds": time.monotonic() - started,
                "target_origin": fixture.origin,
                "target_ip": host,
                "initial_candidates": 1,
                "fixed_control_new_findings": 0,
            }
        )
        metrics["memory_after"] = asdict(process_tree_memory())
        metrics["sampled_tree_peak_rss_bytes"] = max(
            stage["resources"]["peak_rss_bytes"] for stage in metrics["stages"]
        )
        metrics["memory_measurement"] = (
            "maximum observed process-tree summed RSS across individual controller/CLI stages; "
            "shared pages may be counted more than once"
        )
        assert fixture.credential not in json.dumps(metrics)
        vault_path.unlink()
    if output := os.environ.get("REDJOHN_REMOTE_E2E_MEASUREMENTS"):
        Path(output).write_text(json.dumps(metrics, indent=2) + "\n")
