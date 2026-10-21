"""Actual bounded authentication recovery without a controller restart.

Every case uses an owned remote-interface HTTPS oracle, headless Chromium and
the pinned Nuclei executable behind attested Linux egress boundaries. Setup can
expire the oracle or its private vault; no test submits a refresh job or a
refreshed browser/scanner child. Contract doubles are tested separately.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import time
from base64 import b64decode, b64encode
from pathlib import Path

import pytest

from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope, process_tree_memory
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from tests.test_browser_token_pipeline import BrowserTokenHTTPSFixture, _token_binding
from tests.test_continuous_refresh_pipeline import _MEDIA, _reviewed_chain_lock
from tests.test_post_refresh_pipeline import _dependencies, _lock_document, _private_json
from tests.test_remote_authenticated_pipeline import _assert_attested


class _AutomaticRecoveryHTTPSFixture(BrowserTokenHTTPSFixture):
    """Keep actual credential-presence proof, including rejected requests."""

    def __init__(self, host: str, directory: Path) -> None:
        super().__init__(host, directory)
        self.reject_current_get = False
        self.reject_post_revision7 = False
        self.truncate_post_response = False
        fixture, original = self, self.server.RequestHandlerClass

        class Handler(original):
            def _record(self, status: int, *, body: bytes = b"", valid: bool = True) -> None:
                authorization, cookies = (
                    self.headers.get("Authorization", ""),
                    self.headers.get("Cookie", ""),
                )
                known = [
                    revision
                    for revision in ("7", "8")
                    if authorization == "Bearer " + fixture.sessions[revision]
                    or "fixture_session=" + fixture.sessions[revision] in cookies
                ]
                with fixture._lock:
                    fixture.counts[self.path] += 1
                    fixture.observed.append(
                        {
                            "path": self.path,
                            "method": self.command,
                            "status": status,
                            "session_revision": fixture.revision,
                            "body_bytes": len(body),
                            "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
                            "private_values_valid": valid,
                            "authorization_present": bool(authorization),
                            "session_cookie_present": "fixture_session=" in cookies,
                            "credential_revisions": known,
                        }
                    )

            def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler dispatch name
                if self.path == "/start":
                    valid = "fixture_session=" + fixture.sessions[
                        fixture.revision
                    ] in self.headers.get("Cookie", "")
                    if fixture.reject_current_get or not valid:
                        self._record(401, valid=valid)
                        self._reply(
                            401,
                            b'<!doctype html><html><head><link rel="icon" href="data:,"></head>'
                            b"<body>Owned oracle revoked session</body></html>",
                            "text/html",
                        )
                        return
                super().do_GET()

            def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler dispatch name
                if (
                    fixture.reject_post_revision7
                    and fixture.revision == "7"
                    and self.path.startswith("/replay/")
                ):
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    valid = (
                        self.headers.get("Authorization") == "Bearer " + fixture.sessions["7"]
                        and self.headers.get("X-CSRF-Token") == fixture.tokens["7"]
                        and "fixture_session=" + fixture.sessions["7"]
                        in self.headers.get("Cookie", "")
                        and fixture.body_matches(
                            self.path, self.headers.get("Content-Type", ""), body
                        )
                    )
                    self._record(401, body=body, valid=valid)
                    if fixture.truncate_post_response:
                        self.send_response(401)
                        self.send_header("Content-Type", "text/plain")
                        self.send_header("Content-Length", "128")
                        self.end_headers()
                        self.wfile.write(b"incomplete")
                        self.wfile.flush()
                        self.close_connection = True
                        return
                    self._reply(401, b"owned oracle deliberately rejected captured POST")
                    return
                super().do_POST()

        self.server.RequestHandlerClass = Handler


@pytest.mark.parametrize(
    "scenario",
    (
        "browser_401",
        "browser_post_401",
        "scanner_401",
        "expired_scanner_binding",
        "expired_vault",
        "repeated_401",
        "truncated_401",
    ),
)
async def test_actual_automatic_bounded_session_recovery(  # noqa: PLR0912, PLR0915 - real recovery and persistence matrix
    tmp_path: Path,
    scenario: str,
) -> None:
    host, binary = _dependencies()
    expected_refreshes = int(scenario != "truncated_401")
    no_replay = scenario in {"repeated_401", "truncated_401"}
    private = tmp_path / "host-secrets"
    private.mkdir(mode=0o700)
    vault, provider, capture = (
        private / name for name in ("vault.json", "provider.json", "capture.json")
    )
    lock = _reviewed_chain_lock(tmp_path / "reviewed-templates", binary)
    database = tmp_path / ".state" / "agents.db"
    pid, started = os.getpid(), time.monotonic()
    metrics = {
        "case": scenario,
        "platform": platform.platform(),
        "controller_pid": pid,
        "binary_version": binary.binary_version,
        "binary_sha256": binary.binary_sha256,
        "bundle_sha256": lock.bundle_sha256,
        "model_calls": 0,
        "stages": [],
    }
    memory = {
        "target_interval_seconds": 0.025,
        "sample_count": 0,
        "available_sample_count": 0,
        "peak_rss_bytes": 0,
        "peak_process_count": 0,
        "max_observed_interval_seconds": 0.0,
    }
    resources = {
        "peak_active_workers": 0,
        "active_browser_samples": 0,
        "active_scanner_samples": 0,
        "overlapping_browser_scanner_samples": 0,
        "browser_samples_before_first_refresh": 0,
    }
    observed_runtime: AssessmentRuntime | None = None

    async def sample_memory() -> None:
        previous, next_tick = None, time.monotonic()
        while True:
            now = time.monotonic()
            if previous is not None:
                memory["max_observed_interval_seconds"] = max(
                    memory["max_observed_interval_seconds"], now - previous
                )
            previous = now
            sample = await asyncio.to_thread(process_tree_memory, pid)
            memory["sample_count"] += 1
            if sample.available:
                memory["available_sample_count"] += 1
                memory["peak_rss_bytes"] = max(memory["peak_rss_bytes"], sample.rss_bytes)
                memory["peak_process_count"] = max(
                    memory["peak_process_count"], sample.process_count
                )
            if observed_runtime is not None:
                active = observed_runtime.governor.snapshot()["active"]
                resources["peak_active_workers"] = max(
                    resources["peak_active_workers"],
                    sum(active.get(kind, 0) for kind in ("browser", "scanner", "worker")),
                )
                resources["active_browser_samples"] += bool(active.get("browser"))
                resources["active_scanner_samples"] += bool(active.get("scanner"))
                resources["overlapping_browser_scanner_samples"] += bool(
                    active.get("browser") and active.get("scanner")
                )
                resources["browser_samples_before_first_refresh"] += bool(
                    active.get("browser") and not fixture.counts["/refresh"]
                )
            next_tick += 0.025
            await asyncio.sleep(max(0.0, next_tick - time.monotonic()))

    with _AutomaticRecoveryHTTPSFixture(host, tmp_path / "upstream-tls") as fixture:
        policy = EngagementPolicy(
            "automatic-session-" + scenario,
            "operator",
            (fixture.origin,),
            allowed_ips=(host + "/32",),
            profile="isolated-lab",
            egress_mode="enforced",
            actor_ids=("anonymous", "alice"),
            allowed_replay_urls=tuple(fixture.origin + "/replay/" + kind for kind in _MEDIA),
            allowed_refresh_urls=(fixture.origin + "/refresh",),
            request_budget=64,
            deadline=time.time() + 300,
        )
        identity = {
            "engagement_id": policy.engagement_id,
            "owner_id": policy.owner_id,
            "actor_id": "alice",
            "tenant_id": "tenant-a",
            "policy_revision": policy.revision,
        }
        _private_json(
            vault,
            {
                "version": 2,
                "entries": [
                    {
                        **identity,
                        "session_revision": "7",
                        "origin": fixture.origin,
                        "expires_at": time.time() + (-1 if scenario == "expired_vault" else 600),
                        "headers": fixture.auth_headers("7"),
                        "cookies": [{"name": "fixture_session", "value": fixture.sessions["7"]}],
                        "allowed_requests": [
                            {
                                "url": fixture.origin + "/start",
                                "method": "GET",
                                "request_ref": "approved-start-anchor",
                            }
                        ],
                    }
                ],
            },
        )
        _private_json(
            provider,
            {
                "version": 1,
                "providers": [
                    {
                        **identity,
                        "refresh_url": fixture.origin + "/refresh",
                        "headers": {"Authorization": "Bearer " + fixture.refresh_secret},
                        "body_base64": b64encode(fixture.refresh_body).decode(),
                        "content_type": "application/json",
                    }
                ],
            },
        )
        _private_json(
            capture,
            {
                "version": 1,
                "rules": [
                    {
                        **identity,
                        "session_revision": "current",
                        "url": fixture.origin + "/replay/" + kind,
                        "content_type": content_type,
                        "expires_at": time.time() + 600,
                        "automatic_approval": True,
                        "start_url": fixture.origin + "/start",
                        "body_tokens": _token_binding(kind),
                    }
                    for kind, content_type in _MEDIA.items()
                ],
            },
        )
        if scenario in {"browser_401", "repeated_401"}:
            fixture.revision = "8"
        fixture.reject_current_get = scenario == "repeated_401"
        fixture.reject_post_revision7 = scenario in {"browser_post_401", "truncated_401"}
        fixture.truncate_post_response = scenario == "truncated_401"
        session = NativeFixtureSession(policy, tmp_path / "nuclei-worker", lock)
        configuration = {
            "caller": "operator",
            "session": session,
            "envelope": ResourceEnvelope(total_memory_budget=3 * 1024**3, max_workers=1),
            "browser_limits": BrowserLimits(
                max_pages=1,
                max_requests=12,
                readiness_selector="body[data-ready='yes']",
                readiness_timeout_ms=2000,
                observation_window_ms=200,
                total_timeout_seconds=35,
            ),
            "browser_tls": BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            "nuclei_lock": _lock_document(lock),
            "auth_vault_file": vault,
            "refresh_provider_file": provider,
            "browser_capture_file": capture,
            "continuous_replay": {
                "version": 1,
                "rules": [
                    {
                        "actor_id": "alice",
                        "tenant_id": "tenant-a",
                        "url": fixture.origin + "/replay/" + kind,
                        "content_type": content_type,
                        "template_id": "redjohn-fixture-post-" + kind,
                    }
                    for kind, content_type in _MEDIA.items()
                ],
                "session_recovery": {"max_refreshes": 1, "cooldown_seconds": 0},
            },
        }
        store = AssessmentStore(database)

        def rows() -> list[dict]:
            return store.jobs(policy.engagement_id, limit=100)

        async def run_batch(runtime: AssessmentRuntime, label: str, maximum: int) -> list[dict]:
            before, tick = len(fixture.observed), time.monotonic()
            completed = set(await runtime.scheduler.run_batch(max_jobs=maximum))
            actual = [row for row in rows() if row["id"] in completed]
            assert len(actual) == len(completed)
            metrics["stages"].append(
                {
                    "case": label,
                    "controller_pid": os.getpid(),
                    "duration_seconds": time.monotonic() - tick,
                    "completed_jobs": actual,
                    "target_requests": fixture.observed[before:],
                    "workflow_status": runtime.workflow_status(),
                    "governor_snapshot": runtime.governor.snapshot(),
                }
            )
            assert os.getpid() == pid
            return actual

        def capture_proofs(revision: str) -> dict:
            captures = {}
            for record in store.surfaces(policy.engagement_id, limit=100):
                if record["method"] != "POST" or record["session_revision"] != revision:
                    continue
                assert record["source"] == "observed", record
                surface = store.surface(policy.engagement_id, record["id"])
                proof = json.loads(
                    store.evidence_get(policy.engagement_id, surface.request_ref)["excerpt"]
                )
                assert proof["sent"] and proof["response_complete"] and proof["status"] == 200
                assert proof["engagement_id"] == policy.engagement_id
                assert proof["policy_revision"] == policy.revision
                assert proof["body_sha256"] == surface.body_sha256
                assert proof["request_content_type"] == surface.content_type
                assert all(
                    proof[key] == getattr(surface, key)
                    for key in ("url", "method", "actor_id", "tenant_id", "session_revision")
                )
                kind = surface.url.rsplit("/", 1)[-1]
                assert kind in _MEDIA and kind not in captures
                captures[kind] = surface
            assert set(captures) == set(_MEDIA), captures
            return captures

        sampler = asyncio.create_task(sample_memory())
        try:
            async with AssessmentRuntime(store, policy, **configuration) as runtime:
                observed_runtime = runtime
                browser_identity = id(runtime.browser)
                if scenario in {"scanner_401", "expired_scanner_binding"}:
                    initial = await run_batch(runtime, "capture_before_server_expiry", 1)
                    assert len(initial) == 1 and initial[0]["execution_status"] == "succeeded"
                    assert initial[0]["capability"] == "browser_post_capture"
                    old_captures = capture_proofs("7")
                    assert len([row for row in rows() if row["execution_status"] == "queued"]) == 3
                    if scenario == "scanner_401":
                        fixture.revision = "8"
                    else:
                        mapping = json.loads(vault.read_text())
                        for entry in mapping["entries"]:
                            entry["expires_at"] = time.time() - 1
                        _private_json(vault, mapping)
                        before_scanner_expiry = len(fixture.observed)
                # Authentication failure/expiry, the single admitted refresh,
                # fresh Chromium capture and all reviewed scanner children must
                # advance in this already-running controller without submission.
                recovered = await run_batch(runtime, "automatic_recovery_without_restart", 32)
                assert recovered
                assert id(runtime.browser) == browser_identity
                refreshes = [row for row in rows() if row["capability"] == "session_refresh"]
                assert len(refreshes) == expected_refreshes, rows()
                if refreshes:
                    assert refreshes[0]["coverage_status"] == "completed", refreshes
                assert fixture.counts["/refresh"] == expected_refreshes
                assert fixture.revision == ("7" if scenario == "truncated_401" else "8")
                if scenario == "truncated_401":
                    # A 401 header with a missing response body is uncertain
                    # delivery, so it cannot authorize credential recovery.
                    assert len(fixture.observed) == 2, fixture.observed
                    assert len(rows()) == 1 and rows()[0]["coverage_status"] == "inconclusive"
                    assert not [row for row in rows() if row["capability"] == "nuclei_scan"]
                    assert not runtime.workflow_status()["refresh_job_ids"]
                elif scenario == "repeated_401":
                    assert len(fixture.observed) == 3, fixture.observed
                    assert fixture.counts["/start"] == 2
                    assert not [row for row in rows() if row["capability"] == "nuclei_scan"]
                    assert not any(
                        row["method"] == "POST"
                        for row in store.surfaces(policy.engagement_id, limit=100)
                    )
                    errors = runtime.workflow_status()["errors"]
                    assert any(
                        error["code"] == "auth_recovery_budget_exhausted" for error in errors
                    ), errors
                    assert all(not row["result"]["findings"] for row in rows())
                else:
                    refreshed = capture_proofs("8")
                    scan_rows = [
                        row
                        for row in rows()
                        if row["capability"] == "nuclei_scan"
                        and store.surface(policy.engagement_id, row["surface_id"]).session_revision
                        == "8"
                    ]
                    assert len(scan_rows) == 3, rows()
                    for row in scan_rows:
                        assert row["execution_status"] == "succeeded", row
                        assert row["coverage_status"] == "completed", row
                        assert len(row["result"]["findings"]) == 1, row
                        _assert_attested(row["result"]["summary"]["network"]["egress_attestations"])
                    capture_rows = [
                        row
                        for row in rows()
                        if row["capability"] == "browser_post_capture"
                        and store.surface(policy.engagement_id, row["surface_id"]).session_revision
                        == "8"
                    ]
                    assert len(capture_rows) == 1, rows()
                    summary = capture_rows[0]["result"]["summary"]
                    assert summary["metrics"]["captured_post_requests"] == 3
                    assert all(
                        failure["code"] == "browser_scope_denied" for failure in summary["failures"]
                    ), summary
                    _assert_attested(summary["tool"]["egress_attestations"])
                    metrics["chromium_version"] = summary["tool"]["chromium_version"]
                    metrics["playwright_version"] = summary["tool"]["playwright_version"]
                    mapping = json.loads(vault.read_text())
                    requests = [
                        request
                        for entry in mapping["entries"]
                        for request in entry["allowed_requests"]
                        if request["method"] == "POST"
                    ]
                    assert len(requests) == 3
                    assert all(entry["session_revision"] == "8" for entry in mapping["entries"])
                    for request in requests:
                        kind = request["url"].rsplit("/", 1)[-1]
                        assert request["request_ref"] == refreshed[kind].request_ref
                        assert request["body_tokens"] == _token_binding(kind)
                        assert request["replay_safety"] == "operator-approved"
                        assert fixture.body_matches(
                            "/replay/" + kind,
                            request["content_type"],
                            b64decode(request["body_base64"]),
                        )
                        if scenario in {"scanner_401", "expired_scanner_binding"}:
                            assert refreshed[kind].body_sha256 != old_captures[kind].body_sha256
                failures = [row for row in rows() if row["execution_status"] == "failed"]
                assert failures, rows()
                for row in failures:
                    assert row["coverage_status"] in {"blocked", "inconclusive"}, row
                    assert not row["result"]["findings"], row
                    assert row["result"]["summary"].get("no_finding_observed") is not True
                if scenario == "truncated_401":
                    assert not any(
                        row["result"]["summary"].get("auth_recovery", {}).get("admitted")
                        for row in failures
                    ), failures
                else:
                    expected_code = {
                        "expired_vault": "browser_capture_credentials_expired",
                        "expired_scanner_binding": "auth_replay_expired",
                    }.get(scenario, "authentication_expired")
                    auth_failures = [
                        row
                        for row in failures
                        if (row["result"]["error"] or {}).get("code") == expected_code
                    ]
                    assert auth_failures, failures
                    assert all(
                        row["result"]["summary"]["auth_recovery"]["admitted"] is True
                        for row in auth_failures
                    )
                if scenario == "expired_vault":
                    assert not [
                        row for row in fixture.observed if "7" in row["credential_revisions"]
                    ], fixture.observed
                    assert fixture.observed[0]["path"] == "/refresh"
                elif scenario == "expired_scanner_binding":
                    assert before_scanner_expiry == 4
                    assert fixture.observed[before_scanner_expiry]["path"] == "/refresh"
                    assert not [row for row in fixture.observed if row["status"] == 401]
                    assert (
                        len([row for row in fixture.observed if "7" in row["credential_revisions"]])
                        == before_scanner_expiry
                    )
                else:
                    unauthorized = [row for row in fixture.observed if row["status"] == 401]
                    assert unauthorized, fixture.observed
                    assert all(row["credential_revisions"] for row in unauthorized)
                    if scenario == "scanner_401":
                        assert all(row["method"] == "POST" for row in unauthorized)
                        assert 1 <= len(unauthorized) <= 3
                    elif scenario in {"browser_post_401", "truncated_401"}:
                        assert len(unauthorized) == 1
                        assert unauthorized[0]["method"] == "POST"
                        assert unauthorized[0]["path"] == "/replay/json"
                        assert unauthorized[0]["private_values_valid"]
                        old_captures = store.db.execute(
                            "SELECT state FROM rj_request_capture WHERE engagement=? "
                            "AND session_revision='7'",
                            (policy.engagement_id,),
                        ).fetchall()
                        assert len(old_captures) == 1 and old_captures[0]["state"] == "uncertain"
                        assert not [
                            row
                            for row in store.surfaces(policy.engagement_id, limit=100)
                            if row["method"] == "POST" and row["session_revision"] == "7"
                        ]
                    else:
                        assert all(row["path"] == "/start" for row in unauthorized)
                        assert len(unauthorized) == (2 if scenario == "repeated_401" else 1)
                before = len(fixture.observed)
                assert await run_batch(runtime, "same_runtime_reconciliation_no_resend", 32) == []
                assert len(fixture.observed) == before
                final_status = runtime.workflow_status()
                assert final_status["session_recovery"]["refreshes_used"] == expected_refreshes
                identities = final_status["session_recovery"]["identities"]
                assert len(identities) == expected_refreshes
                if identities:
                    assert identities[0]["actor_id"] == "alice"
                    assert identities[0]["tenant_id"] == "tenant-a"
                    assert identities[0]["refreshes_used"] == 1
                if scenario != "repeated_401":
                    assert not final_status["errors"], final_status
                assert runtime.scheduler.metrics["model_calls"] == 0
            # A new controller must see the persisted reservation and limit;
            # neither the failed parent nor completed refresh may be resent.
            async with AssessmentRuntime(store, policy, **configuration) as reopened:
                observed_runtime = reopened
                assert await run_batch(reopened, "persistent_limit_after_restart", 32) == []
                restarted_status = reopened.workflow_status()
                assert restarted_status["session_recovery"]["refreshes_used"] == expected_refreshes
                assert restarted_status["session_recovery"]["identities"] == identities
            assert len(fixture.observed) == before
            assert fixture.counts["/refresh"] == expected_refreshes
            assert fixture.counts["/credential-trap"] == 0
            for request in fixture.observed:
                assert request["authorization_present"], request
                if request["path"] != "/refresh":
                    assert request["session_cookie_present"] and request["credential_revisions"]
                if request["status"] == 200:
                    assert request["private_values_valid"], request
            used = store.db.execute(
                "SELECT requests_used FROM rj_engagement WHERE id=?", (policy.engagement_id,)
            ).fetchone()[0]
            assert used == len(fixture.observed), (used, fixture.observed)
            metrics.update(
                scheduler_jobs=len(rows()),
                http_requests=len(fixture.observed),
                persisted_requests_used=used,
                refresh_requests=fixture.counts["/refresh"],
                actual_401_responses=sum(row["status"] == 401 for row in fixture.observed),
                positive_candidates=sum(len(row["result"]["findings"]) for row in rows()),
                workflow_status=final_status,
                restarted_workflow_status=restarted_status,
                target_requests=fixture.observed,
                runtime_restart_required=False,
                controller_pid_changed=False,
                restart_duplicate_requests=0,
                no_anonymous_fallback=True,
            )
        finally:
            sampler.cancel()
            await asyncio.gather(sampler, return_exceptions=True)
            await session.aclose()
            store.close()
        assert memory["available_sample_count"] > 0
        assert resources["active_browser_samples"] > 0
        if scenario == "expired_vault":
            assert resources["browser_samples_before_first_refresh"] == 0
        if not no_replay:
            assert resources["active_scanner_samples"] > 0
        assert resources["peak_active_workers"] == 1
        assert resources["overlapping_browser_scanner_samples"] == 0
        assert metrics["positive_candidates"] == (0 if no_replay else 3)
        secrets = (
            *fixture.tokens.values(),
            *fixture.sessions.values(),
            fixture.refresh_secret,
            fixture.private_value,
        )
        for path in tmp_path.rglob("*"):
            if path.is_file() and private not in path.parents:
                contents = path.read_bytes()
                assert all(secret.encode() not in contents for secret in secrets), path
        metrics.update(
            duration_seconds=time.monotonic() - started,
            target_origin=fixture.origin,
            target_ip=host,
            body_formats=[] if no_replay else list(_MEDIA),
            configured_body_formats=list(_MEDIA),
            actual_nuclei_replay=not no_replay,
            configured_max_workers=1,
            configured_max_refreshes=1,
            process_tree_memory_sampling=memory,
            resource_lease_sampling=resources,
            measurement=(
                "25 ms target interval test controller and descendant summed RSS; "
                "shared pages may be counted repeatedly; sampled peak; lease counts "
                "separately attest scheduler resource admission"
            ),
        )
        assert all(secret not in json.dumps(metrics) for secret in secrets)
        for path in (vault, provider, capture):
            path.unlink()
    if output := os.environ.get("REDJOHN_AUTOMATIC_SESSION_MEASUREMENTS"):
        path = Path(output)
        document = json.loads(path.read_text()) if path.exists() else {"version": 1, "cases": []}
        assert document["version"] == 1 and isinstance(document["cases"], list)
        document["cases"] = [case for case in document["cases"] if case["case"] != scenario]
        document["cases"].append(metrics)
        path.write_text(json.dumps(document, indent=2) + "\n")
