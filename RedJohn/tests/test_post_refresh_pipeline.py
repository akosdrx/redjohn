"""Real Linux HTTPS POST replay, independent CLI restart and session rotation.

Every destination is an owned non-loopback HTTPS fixture. Actual pinned Nuclei
workers run in attested kernel namespaces; private bodies and credentials stay
in the controller. Missing capabilities can be required failures in CI.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import platform
import secrets
import shutil
import sys
import time
from base64 import b64encode
from dataclasses import replace
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import process_tree_memory
from redjohn.assessment.store import AssessmentStore
from tests.remote_https_fixture import RemoteHTTPSFixture, fixture_host
from tests.test_nuclei_live import existing_live_lock
from tests.test_nuclei_post_live import post_fixture_lock, replay_body_cases
from tests.test_remote_authenticated_pipeline import _assert_attested


if TYPE_CHECKING:
    from redjohn.tools.hunt.nuclei import NucleiLock


def _unavailable(code: str) -> None:
    if os.environ.get("REDJOHN_REQUIRE_REMOTE_E2E") == "1":
        pytest.fail(code)
    pytest.skip("blocked_missing_capability: " + code)


def _dependencies() -> tuple[str, NucleiLock]:
    if platform.system() != "Linux":
        _unavailable("Linux network namespaces required")
    if not shutil.which("bwrap"):
        _unavailable("bubblewrap required")
    try:
        return fixture_host(), existing_live_lock()
    except pytest.skip.Exception as exc:
        _unavailable(str(exc))
    except (RuntimeError, OSError) as exc:
        _unavailable(str(exc))
    raise AssertionError("dependency check must return, skip or fail")


def _lock_document(lock: NucleiLock) -> dict:
    return {
        "binary": {
            "path": lock.binary_path,
            "version": lock.binary_version,
            "sha256": lock.binary_sha256,
            "source": lock.binary_source,
            "license": lock.binary_license,
        },
        "bundle": {
            "root": lock.bundle_root,
            "version": lock.bundle_version,
            "sha256": lock.bundle_sha256,
            "source": lock.bundle_source,
            "license": lock.bundle_license,
            "files": lock.files,
            "templates": [
                {
                    "path": item.path,
                    "id": item.template_id,
                    "profiles": list(item.profiles),
                    "effect": item.effect,
                    "protocol": item.protocol,
                }
                for item in lock.templates
            ],
        },
    }


def _private_json(path: Path, value: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream)
    assert path.stat().st_mode & 0o777 == 0o600


class PostRefreshHTTPSFixture(RemoteHTTPSFixture):
    """Harmless POST oracle with a single explicit credential rotation endpoint."""

    def __init__(self, host: str, directory: Path) -> None:
        super().__init__(host, directory)
        self.credential7 = secrets.token_urlsafe(32)
        self.credential8 = secrets.token_urlsafe(32)
        self.csrf7 = secrets.token_urlsafe(32)
        self.csrf8 = secrets.token_urlsafe(32)
        self.refresh_secret = secrets.token_urlsafe(32)
        self.body_secret = secrets.token_urlsafe(32)
        self.refresh_body = json.dumps({"refresh_token": self.refresh_secret}).encode()
        self.revision = "7"
        self.expected = {
            "/replay/" + kind: (content_type, body)
            for kind, content_type, body in replay_body_cases(self.body_secret)
        }
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                content_type = self.headers.get("Content-Type", "")
                if self.path == "/refresh":
                    authorized = (
                        self.headers.get("Authorization") == "Bearer " + fixture.refresh_secret
                        and body == fixture.refresh_body
                        and content_type == "application/json"
                    )
                    status = 200 if authorized else 401
                    if authorized:
                        fixture.revision = "8"
                        payload = {
                            "headers": {
                                "Authorization": "Bearer " + fixture.credential8,
                                "X-CSRF-Token": fixture.csrf8,
                            },
                            "cookies": [],
                            "expires_at": time.time() + 600,
                        }
                        response = json.dumps(payload).encode()
                    else:
                        response = b'{"error":"refresh denied"}'
                    response_type, matched = "application/json", body == fixture.refresh_body
                else:
                    credential = (
                        fixture.credential7 if fixture.revision == "7" else fixture.credential8
                    )
                    csrf = fixture.csrf7 if fixture.revision == "7" else fixture.csrf8
                    authorized = (
                        self.headers.get("Authorization") == "Bearer " + credential
                        and self.headers.get("X-CSRF-Token") == csrf
                    )
                    matched = fixture.expected.get(self.path) == (content_type, body)
                    if not authorized or not matched:
                        status, response = 401, b"authentication or captured bytes mismatch"
                    elif fixture.mode == "redirect":
                        status, response = 302, b""
                    else:
                        status = 200
                        response = (
                            b"redjohn-fixture-marker"
                            if fixture.mode == "marker"
                            else b"fixed-control"
                        )
                    response_type = "text/plain"
                with fixture._lock:
                    fixture.counts[self.path] += 1
                    fixture.observed.append(
                        {
                            "path": self.path,
                            "method": "POST",
                            "authorized": authorized,
                            "body_matches": matched,
                            "body_sha256": hashlib.sha256(body).hexdigest(),
                            "status": status,
                            "session_revision": fixture.revision,
                        }
                    )
                self.send_response(status)
                self.send_header("Content-Type", response_type)
                self.send_header("Content-Length", str(len(response)))
                if status == 302:
                    self.send_header("Location", fixture.origin + "/credential-trap")
                self.end_headers()
                self.wfile.write(response)

            def do_GET(self):
                with fixture._lock:
                    fixture.counts[self.path] += 1
                self.send_response(405)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.server.RequestHandlerClass = Handler

    def credentials(self, revision: str) -> dict[str, str]:
        return {
            "Authorization": "Bearer "
            + (self.credential7 if revision == "7" else self.credential8),
            "X-CSRF-Token": self.csrf7 if revision == "7" else self.csrf8,
        }


async def test_actual_persistent_post_types_session_refresh_and_revision_fencing(  # noqa: PLR0915 - real multi-process lifecycle matrix
    tmp_path: Path,
) -> None:
    from redjohn.assessment.capture import capture_authenticated_request  # noqa: PLC0415

    host, binary_lock = _dependencies()
    database = tmp_path / ".state" / "agents.db"
    private = tmp_path / "host-secrets"
    private.mkdir(mode=0o700)
    vault_path, providers_path = private / "replay.json", private / "providers.json"
    config_path = tmp_path / "configured-post-refresh.json"
    metrics: dict = {
        "platform": platform.platform(),
        "controller_pid": os.getpid(),
        "binary_version": binary_lock.binary_version,
        "binary_sha256": binary_lock.binary_sha256,
        "stages": [],
        "independent_cli_pids": [],
        "model_calls": 0,
    }
    started = time.monotonic()
    with PostRefreshHTTPSFixture(host, tmp_path / "upstream-tls") as fixture:
        urls = tuple(fixture.origin + path for path in fixture.expected)
        policy = EngagementPolicy(
            "post-refresh-e2e",
            "operator",
            (fixture.origin,),
            allowed_ips=(host + "/32",),
            profile="isolated-lab",
            egress_mode="enforced",
            actor_ids=("anonymous", "alice", "bob"),
            allowed_replay_urls=urls,
            allowed_refresh_urls=(fixture.origin + "/refresh",),
            request_budget=64,
            deadline=time.time() + 300,
        )
        tls = BrowserTLSConfig(upstream_ca_file=fixture.ca_file)
        locks = {
            path.rsplit("/", 1)[-1]: post_fixture_lock(
                tmp_path / ("templates-" + path.rsplit("/", 1)[-1]),
                content_type,
                path,
                binary_lock=binary_lock,
            )
            for path, (content_type, _body) in fixture.expected.items()
        }

        def enqueue(surface: Surface, kind: str, *, retest: str = "", refresh: bool = False) -> str:
            store = AssessmentStore(database)
            try:
                actual_policy = store.register(policy)
                surface_id = store.upsert_surface(policy.engagement_id, surface)
                spec = JobSpec(
                    surface_id,
                    "authentication" if refresh else "known_vulnerability",
                    "session_refresh" if refresh else "nuclei_scan",
                    policy_revision=policy.revision,
                    retest_revision=retest,
                    idempotent=False,
                    timeout_seconds=40,
                    tool_version="1" if refresh else binary_lock.binary_version,
                    template_version="" if refresh else locks[kind].bundle_sha256,
                )
                return store.submit(actual_policy, [spec])[0]
            finally:
                store.close()

        async def capture(kind: str, revision: str) -> Surface:
            path = "/replay/" + kind
            content_type, body = fixture.expected[path]
            before = len(fixture.observed)
            store = AssessmentStore(database)
            try:
                store.register(policy)
                observed = await capture_authenticated_request(
                    policy,
                    store,
                    Surface(
                        fixture.origin + path,
                        method="POST",
                        content_type=content_type,
                        body_sha256=hashlib.sha256(body).hexdigest(),
                        actor_id="alice",
                        tenant_id="tenant-a",
                        session_revision=revision,
                        source="imported",
                        workflow_state="approved_seed",
                    ),
                    body=body,
                    headers=fixture.credentials(revision),
                    tls_config=tls,
                )
                assert observed.source == "observed" and observed.request_ref
                captured = json.loads(
                    store.evidence_get(policy.engagement_id, observed.request_ref)["excerpt"]
                )
                assert captured["sent"] is True and captured["status"] == 200
                assert captured["body_sha256"] == hashlib.sha256(body).hexdigest()
            finally:
                store.close()
            assert len(fixture.observed) == before + 1
            metrics["stages"].append(
                {
                    "case": "actual_capture_" + kind + "_revision_" + revision,
                    "target_requests": fixture.observed[before:],
                    "body_sha256": observed.body_sha256,
                    "request_ref": observed.request_ref,
                }
            )
            return observed

        async def run_cli(  # noqa: PLR0915 - tracked subprocess, sampler and persisted result verification
            label: str, kind: str, job_id: str | None
        ) -> dict | None:
            _private_json(
                config_path,
                {
                    "policy": policy.to_dict(),
                    "nuclei_lock": _lock_document(locks[kind]),
                    "tls": {"upstream_ca_file": str(fixture.ca_file)},
                    "auth_vault_file": str(vault_path),
                    "refresh_provider_file": str(providers_path),
                    "seeds": [],
                    "resources": {"total_memory_budget": 3 * 1024**3},
                },
            )
            environment = dict(os.environ)
            package_root = str(Path(__file__).resolve().parents[1])
            environment["PYTHONPATH"] = package_root + (
                os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""
            )
            before = len(fixture.observed)
            tick = time.monotonic()
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
            sample_interval = 0.025
            memory_samples = {
                "target_interval_seconds": sample_interval,
                "sample_count": 0,
                "available_sample_count": 0,
                "peak_rss_bytes": 0,
                "peak_process_count": 0,
                "max_observed_interval_seconds": 0.0,
                "scope": "tracked CLI PID and its current kernel-reported descendants",
                "method": "process_tree_summed_rss_shared_pages_may_be_counted_multiple_times",
            }

            async def sample_cli_memory() -> None:
                previous = None
                next_sample = time.monotonic()
                while process.returncode is None:
                    sampled_at = time.monotonic()
                    if previous is not None:
                        memory_samples["max_observed_interval_seconds"] = max(
                            memory_samples["max_observed_interval_seconds"], sampled_at - previous
                        )
                    previous = sampled_at
                    memory = await asyncio.to_thread(process_tree_memory, process.pid)
                    memory_samples["sample_count"] += 1
                    if memory.available:
                        memory_samples["available_sample_count"] += 1
                        memory_samples["peak_rss_bytes"] = max(
                            memory_samples["peak_rss_bytes"], memory.rss_bytes
                        )
                        memory_samples["peak_process_count"] = max(
                            memory_samples["peak_process_count"], memory.process_count
                        )
                    next_sample += sample_interval
                    await asyncio.sleep(max(0.0, next_sample - time.monotonic()))

            sampler = asyncio.create_task(sample_cli_memory())
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), 65)
            finally:
                try:
                    if process.returncode is None:
                        process.kill()
                        await process.wait()
                finally:
                    sampler.cancel()
                    sample_results = await asyncio.gather(sampler, return_exceptions=True)
                    assert not any(isinstance(value, Exception) for value in sample_results)
            assert process.pid != os.getpid()
            assert memory_samples["available_sample_count"] > 0, memory_samples
            assert len(stdout) <= 65536 and len(stderr) <= 65536
            for secret in (
                fixture.credential7,
                fixture.credential8,
                fixture.csrf7,
                fixture.csrf8,
                fixture.refresh_secret,
                fixture.body_secret,
            ):
                assert secret.encode() not in stdout + stderr
            report_path = tmp_path / "assessment-report.json"
            assert report_path.is_file(), {
                "case": label,
                "exit_code": process.returncode,
                "stdout": stdout.decode()[-8192:],
                "stderr": stderr.decode()[-8192:],
            }
            report = json.loads(report_path.read_text())
            assert report["metrics"]["jobs"] == int(job_id is not None)
            assert report["metrics"]["model_calls"] == 0
            metrics["independent_cli_pids"].append(process.pid)
            metrics["model_calls"] += report["metrics"]["model_calls"]
            store = AssessmentStore(database)
            try:
                row = next(
                    (
                        row
                        for row in store.jobs(policy.engagement_id, limit=100)
                        if row["id"] == job_id
                    ),
                    None,
                )
            finally:
                store.close()
            # CLI status reflects the engagement's aggregate persisted coverage.
            # An expected blocked control keeps later successful runs at exit 1.
            expected_exit = int(
                any(
                    entry["coverage_status"] in {"blocked", "unsupported", "inconclusive"}
                    for entry in report["coverage"]
                )
            )
            assert process.returncode == expected_exit, {
                "case": label,
                "expected_exit_code": expected_exit,
                "actual_exit_code": process.returncode,
                "persisted_job": row,
                "aggregate_coverage": report["coverage"],
                "stdout": stdout.decode()[-8192:],
                "stderr": stderr.decode()[-8192:],
            }
            metrics["stages"].append(
                {
                    "case": label,
                    "pid": process.pid,
                    "exit_code": process.returncode,
                    "expected_exit_code": expected_exit,
                    "aggregate_coverage": report["coverage"],
                    "duration_seconds": time.monotonic() - tick,
                    "target_requests": fixture.observed[before:],
                    "execution_status": row["execution_status"] if row else None,
                    "coverage_status": row["coverage_status"] if row else None,
                    "result": row["result"] if row else None,
                    "governor_snapshot": report["metrics"]["resources"],
                    "governor_snapshot_measurement": (
                        "admission and cooperative heartbeat samples; not a continuous peak"
                    ),
                    "process_tree_memory_sampling": memory_samples,
                }
            )
            return row

        surfaces = {kind: await capture(kind, "7") for kind in locks}
        data = {
            "version": 2,
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
                    "headers": fixture.credentials("7"),
                    "cookies": [],
                    "allowed_requests": [
                        {
                            "url": surface.url,
                            "method": "POST",
                            "request_ref": surface.request_ref,
                            "content_type": surface.content_type,
                            "body_base64": b64encode(
                                fixture.expected["/replay/" + kind][1]
                            ).decode(),
                            "body_sha256": surface.body_sha256,
                            "replay_safety": "operator-approved",
                        }
                        for kind, surface in surfaces.items()
                    ],
                }
            ],
        }
        _private_json(vault_path, data)
        _private_json(
            providers_path,
            {
                "version": 1,
                "providers": [
                    {
                        "engagement_id": policy.engagement_id,
                        "owner_id": policy.owner_id,
                        "actor_id": "alice",
                        "tenant_id": "tenant-a",
                        "policy_revision": policy.revision,
                        "refresh_url": fixture.origin + "/refresh",
                        "headers": {"Authorization": "Bearer " + fixture.refresh_secret},
                        "body_base64": b64encode(fixture.refresh_body).decode(),
                        "content_type": "application/json",
                    }
                ],
            },
        )
        original_ids = {}
        for kind, surface in surfaces.items():
            job_id = enqueue(surface, kind)
            original_ids[kind] = job_id
            row = await run_cli("authenticated_" + kind + "_independent_cli", kind, job_id)
            assert row["execution_status"] == "succeeded", row
            assert row["coverage_status"] == "completed", row
            assert len(row["result"]["findings"]) == 1, row
            assert row["result"]["findings"][0]["finding_status"] == "candidate"
            _assert_attested(row["result"]["summary"]["network"]["egress_attestations"])
            assert len(metrics["stages"][-1]["target_requests"]) == 1

        before = len(fixture.observed)
        assert enqueue(surfaces["json"], "json") == original_ids["json"]
        assert await run_cli("restart_duplicate_no_request", "json", None) is None
        assert len(fixture.observed) == before
        expired_data = copy.deepcopy(data)
        expired_data["entries"][0]["expires_at"] = time.time() - 1
        _private_json(vault_path, expired_data)
        expired_id = enqueue(surfaces["json"], "json", retest="expired-session")
        expired = await run_cli("expired_revision7_no_request", "json", expired_id)
        assert expired["coverage_status"] == "blocked", expired
        assert expired["result"]["error"]["code"] == "auth_replay_expired", expired
        assert len(fixture.observed) == before

        refresh_id = enqueue(surfaces["json"], "json", refresh=True)
        refreshed = await run_cli("explicit_session_refresh_revision7_to8", "json", refresh_id)
        assert refreshed["execution_status"] == "succeeded", refreshed
        assert refreshed["coverage_status"] == "completed", refreshed
        assert refreshed["result"]["summary"]["session_revision"] == "8", refreshed
        assert fixture.counts["/refresh"] == 1 and fixture.revision == "8"
        assert len(fixture.observed) == before + 1
        rotated = json.loads(vault_path.read_text())
        assert rotated["entries"][0]["session_revision"] == "8"
        assert rotated["entries"][0]["headers"] == fixture.credentials("8")
        assert vault_path.stat().st_mode & 0o777 == 0o600
        before = len(fixture.observed)
        assert enqueue(surfaces["json"], "json", refresh=True) == refresh_id
        assert await run_cli("completed_refresh_is_not_repeated", "json", None) is None
        assert fixture.counts["/refresh"] == 1 and len(fixture.observed) == before
        stale_id = enqueue(surfaces["json"], "json", retest="old-revision-after-refresh")
        stale = await run_cli("old_revision_remains_blocked", "json", stale_id)
        assert stale["coverage_status"] == "blocked", stale
        assert len(fixture.observed) == before
        relabelled = replace(
            surfaces["json"], session_revision="8", workflow_state="old-capture-relabelled"
        )
        relabelled_id = enqueue(relabelled, "json")
        relabelled_row = await run_cli("old_capture_cannot_be_relabelled", "json", relabelled_id)
        assert relabelled_row["coverage_status"] == "blocked", relabelled_row
        assert (
            relabelled_row["result"]["error"]["code"] == "auth_replay_capture_identity_mismatch"
        ), relabelled_row
        assert len(fixture.observed) == before

        fresh = await capture("json", "8")
        before = len(fixture.observed)
        # Updating an observed reference is an explicit host/provider action.
        # Credential rotation cannot silently relabel the revision-7 capture.
        for request in rotated["entries"][0]["allowed_requests"]:
            if request["url"] == fresh.url:
                request["request_ref"] = fresh.request_ref
        _private_json(vault_path, rotated)
        fresh_id = enqueue(fresh, "json")
        fresh_row = await run_cli("new_capture_revision8_replay", "json", fresh_id)
        assert fresh_row["coverage_status"] == "completed", fresh_row
        assert len(fresh_row["result"]["findings"]) == 1
        assert len(fixture.observed) == before + 1
        assert metrics["stages"][-1]["target_requests"][0]["session_revision"] == "8"
        _assert_attested(fresh_row["result"]["summary"]["network"]["egress_attestations"])

        fixture.mode = "fixed"
        fixed_id = enqueue(fresh, "json", retest="fixed-control")
        fixed = await run_cli("authenticated_fixed_control", "json", fixed_id)
        assert fixed["coverage_status"] == "completed", fixed
        assert fixed["result"]["summary"]["no_finding_observed"] is True
        assert not fixed["result"]["findings"]
        fixture.mode = "marker"
        before = len(fixture.observed)
        tampered = replace(fresh, body_sha256="0" * 64, workflow_state="body-digest-tampered")
        tampered_id = enqueue(tampered, "json")
        rejected = await run_cli("body_digest_tamper_no_request", "json", tampered_id)
        assert rejected["coverage_status"] == "blocked", rejected
        assert len(fixture.observed) == before
        fixture.mode = "redirect"
        redirect_id = enqueue(fresh, "json", retest="redirect-control")
        redirect = await run_cli("redirect_no_credential_follow", "json", redirect_id)
        assert redirect["coverage_status"] == "inconclusive", redirect
        assert redirect["result"]["summary"]["no_finding_observed"] is False
        assert fixture.counts["/credential-trap"] == 0
        assert len(fixture.observed) == before + 1
        store = AssessmentStore(database)
        try:
            requests_used = store.db.execute(
                "SELECT requests_used FROM rj_engagement WHERE id=?", (policy.engagement_id,)
            ).fetchone()[0]
            state = store.session_state(policy, fresh)
            assert state["revision"] == "8" and state["status"] == "ready"
        finally:
            store.close()
        assert requests_used == len(fixture.observed)
        assert all(row["authorized"] and row["body_matches"] for row in fixture.observed)
        secrets_to_check = (
            fixture.credential7,
            fixture.credential8,
            fixture.csrf7,
            fixture.csrf8,
            fixture.refresh_secret,
            fixture.body_secret,
        )
        public_files = [
            path for path in tmp_path.rglob("*") if path.is_file() and private not in path.parents
        ]
        for path in public_files:
            contents = path.read_bytes()
            for secret in secrets_to_check:
                assert secret.encode() not in contents, path
        metrics.update(
            {
                "duration_seconds": time.monotonic() - started,
                "target_origin": fixture.origin,
                "target_ip": host,
                "http_requests": len(fixture.observed),
                "persisted_requests_used": requests_used,
                "refresh_requests": fixture.counts["/refresh"],
                "credential_trap_requests": fixture.counts["/credential-trap"],
                "positive_candidates": 4,
                "fixed_control_new_findings": 0,
                "restart_duplicate_requests": 0,
                "session_revision": "8",
                "csrf_rotation_verified": True,
                "sampled_tree_peak_rss_bytes": max(
                    stage["process_tree_memory_sampling"]["peak_rss_bytes"]
                    for stage in metrics["stages"]
                    if "process_tree_memory_sampling" in stage
                ),
                "memory_sample_target_interval_seconds": 0.025,
                "memory_sample_count": sum(
                    stage["process_tree_memory_sampling"]["sample_count"]
                    for stage in metrics["stages"]
                    if "process_tree_memory_sampling" in stage
                ),
                "memory_measurement": (
                    "maximum from a dedicated 25 ms target interval sampler of each live CLI "
                    "and its descendants, including live namespace workers; shared pages may "
                    "be counted more than once; sampling does not prove an absolute peak"
                ),
            }
        )
        for secret in secrets_to_check:
            assert secret not in json.dumps(metrics)
        vault_path.unlink()
        providers_path.unlink()
    if output := os.environ.get("REDJOHN_POST_REFRESH_MEASUREMENTS"):
        Path(output).write_text(json.dumps(metrics, indent=2) + "\n")
