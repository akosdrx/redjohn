"""Actual Chromium POST capture, explicit body-token rotation and Nuclei replay.

The Linux-only target is an owned HTTPS service on a real local interface.
Every scheduler stage runs in a separate CLI process against the same SQLite
database. Browser JavaScript supplies the three POST formats without SDK capture.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import secrets
import sys
import time
from base64 import b64decode, b64encode
from dataclasses import replace
from email import policy as email_policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl

from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.request_body import HOST_REPLAY_MULTIPART_CONTENT_TYPE
from redjohn.assessment.resources import process_tree_memory
from redjohn.assessment.store import AssessmentStore
from tests.remote_https_fixture import RemoteHTTPSFixture
from tests.test_nuclei_post_live import post_fixture_lock
from tests.test_post_refresh_pipeline import _dependencies, _lock_document, _private_json
from tests.test_remote_authenticated_pipeline import _assert_attested


if TYPE_CHECKING:
    from redjohn.tools.hunt.nuclei import NucleiLock


_UPLOAD = b"redjohn-binary\x00\x01\xff"
_KINDS = ("json", "form", "multipart")


def _token_binding(kind: str) -> list[dict]:
    return [
        {
            "location": "json" if kind == "json" else kind,
            "selector": "/csrf" if kind == "json" else "csrf",
            "occurrence": 0,
            "source": {"kind": "header", "name": "X-CSRF-Token"},
        }
    ]


class BrowserTokenHTTPSFixture(RemoteHTTPSFixture):
    def __init__(self, host: str, directory: Path) -> None:
        super().__init__(host, directory)
        self.tokens = {revision: secrets.token_urlsafe(32) for revision in ("7", "8")}
        self.sessions = {revision: secrets.token_urlsafe(32) for revision in ("7", "8")}
        self.refresh_secret = secrets.token_urlsafe(32)
        self.refresh_body = json.dumps({"refresh_token": self.refresh_secret}).encode()
        self.private_value = secrets.token_urlsafe(32)
        self.revision = "7"
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                if status == 302:
                    self.send_header("Location", fixture.origin + "/credential-trap")
                self.end_headers()
                self.wfile.write(body)

            def _record(self, status: int, *, body: bytes = b"", valid: bool = True) -> None:
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
                        }
                    )

            def do_GET(self):
                if self.path == "/favicon.ico":
                    self._record(204)
                    self._reply(204, b"")
                    return
                if self.path != "/start":
                    self._record(404)
                    self._reply(404, b"unexpected endpoint")
                    return
                if "fixture_session=" + fixture.sessions[fixture.revision] not in self.headers.get(
                    "Cookie", ""
                ):
                    self._record(401, valid=False)
                    self._reply(401, b"session required")
                    return
                payload = json.dumps(
                    {
                        "fixture_value": fixture.private_value,
                        "csrf": fixture.tokens[fixture.revision],
                    },
                    separators=(",", ":"),
                )
                body = (
                    """<!doctype html><html><head><link rel="icon" href="data:,"></head>
<body><div>Owned RedJohn browser token fixture</div><script>
const fields = """
                    + payload
                    + """;
const headers = {'X-CSRF-Token': fields.csrf};
async function post(path, body, extra={}) {
  const response = await fetch(path, {method:'POST', credentials:'same-origin',
    headers:{...headers,...extra}, body});
  if (response.status !== 200) throw new Error('fixture POST rejected');
  await response.text();
}
(async()=>{
  await post('/replay/json', JSON.stringify(fields), {'Content-Type':'application/json'});
  await post('/replay/form', new URLSearchParams(fields).toString(),
    {'Content-Type':'application/x-www-form-urlencoded'});
  const multipart = new FormData();
  multipart.append('fixture_value', fields.fixture_value);
  multipart.append('csrf', fields.csrf);
  multipart.append('upload', new Blob([new Uint8Array("""
                    + json.dumps(list(_UPLOAD))
                    + """)],
    {type:'application/octet-stream'}), 'fixture.bin');
  await post('/replay/multipart', multipart);
  document.body.dataset.ready='yes';
})().catch(()=>document.body.dataset.failed='yes');
</script></body></html>"""
                ).encode()
                self._record(200)
                self._reply(200, body, "text/html; charset=utf-8")

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path == "/refresh":
                    valid = (
                        self.headers.get("Authorization") == "Bearer " + fixture.refresh_secret
                        and body == fixture.refresh_body
                    )
                    status = 200 if valid else 401
                    if valid:
                        fixture.revision = "8"
                        response = json.dumps(
                            {
                                "headers": fixture.auth_headers("8"),
                                "cookies": [
                                    {"name": "fixture_session", "value": fixture.sessions["8"]}
                                ],
                                "expires_at": time.time() + 600,
                            }
                        ).encode()
                    else:
                        response = b'{"error":"refresh denied"}'
                    content_type = "application/json"
                else:
                    valid = (
                        self.headers.get("Authorization")
                        == "Bearer " + fixture.sessions[fixture.revision]
                        and self.headers.get("X-CSRF-Token") == fixture.tokens[fixture.revision]
                        and "fixture_session=" + fixture.sessions[fixture.revision]
                        in self.headers.get("Cookie", "")
                        and fixture.body_matches(
                            self.path, self.headers.get("Content-Type", ""), body
                        )
                    )
                    status = 401 if not valid else 302 if fixture.mode == "redirect" else 200
                    response = (
                        b"redjohn-fixture-marker"
                        if valid and fixture.mode == "marker"
                        else b"fixed-control"
                    )
                    content_type = "text/plain"
                self._record(status, body=body, valid=valid)
                self._reply(status, response, content_type)

            def log_message(self, *_args):
                pass

        self.server.RequestHandlerClass = Handler

    def auth_headers(self, revision: str) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + self.sessions[revision],
            "X-CSRF-Token": self.tokens[revision],
        }

    def body_matches(self, path: str, content_type: str, body: bytes) -> bool:
        expected = {"fixture_value": self.private_value, "csrf": self.tokens[self.revision]}
        try:
            if path == "/replay/json":
                return content_type == "application/json" and json.loads(body) == expected
            if path == "/replay/form":
                return content_type == "application/x-www-form-urlencoded" and parse_qsl(
                    body.decode()
                ) == list(expected.items())
            if path != "/replay/multipart" or not content_type.startswith("multipart/form-data;"):
                return False
            parsed = BytesParser(policy=email_policy.default).parsebytes(
                ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + body
            )
            parts = list(parsed.iter_parts())
            return (
                len(parts) == 3
                and [part.get_param("name", header="content-disposition") for part in parts]
                == ["fixture_value", "csrf", "upload"]
                and [part.get_payload(decode=True) for part in parts]
                == [self.private_value.encode(), self.tokens[self.revision].encode(), _UPLOAD]
                and parts[2].get_filename() == "fixture.bin"
                and parts[2].get_content_type() == "application/octet-stream"
            )
        except (ValueError, UnicodeDecodeError):
            return False


async def test_actual_chromium_post_capture_body_token_refresh_and_nuclei_restart(  # noqa: PLR0915 - real multi-process lifecycle
    tmp_path: Path,
) -> None:
    host, base_lock = _dependencies()
    database = tmp_path / ".state" / "agents.db"
    private = tmp_path / "host-secrets"
    private.mkdir(mode=0o700)
    vault_path, provider_path, capture_path = (
        private / name for name in ("vault.json", "provider.json", "browser.json")
    )
    config_path = tmp_path / "configured-browser-token.json"
    metrics = {
        "platform": platform.platform(),
        "controller_pid": os.getpid(),
        "binary_version": base_lock.binary_version,
        "binary_sha256": base_lock.binary_sha256,
        "stages": [],
        "model_calls": 0,
        "pipeline_complete": False,
    }
    started = time.monotonic()
    with BrowserTokenHTTPSFixture(host, tmp_path / "upstream-tls") as fixture:
        policy = EngagementPolicy(
            "browser-token-e2e",
            "operator",
            (fixture.origin,),
            allowed_ips=(host + "/32",),
            profile="isolated-lab",
            egress_mode="enforced",
            actor_ids=("anonymous", "alice"),
            allowed_replay_urls=tuple(fixture.origin + "/replay/" + kind for kind in _KINDS),
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
            vault_path,
            {
                "version": 2,
                "entries": [
                    {
                        **identity,
                        "session_revision": "7",
                        "origin": fixture.origin,
                        "expires_at": time.time() + 600,
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
            provider_path,
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
            capture_path,
            {
                "version": 1,
                "rules": [
                    {
                        **identity,
                        "session_revision": "current",
                        "url": fixture.origin + "/replay/" + kind,
                        "content_type": {
                            "json": "application/json",
                            "form": "application/x-www-form-urlencoded",
                            "multipart": "multipart/form-data",
                        }[kind],
                        "expires_at": time.time() + 600,
                        "automatic_approval": True,
                        "start_url": fixture.origin + "/start",
                        "body_tokens": _token_binding(kind),
                    }
                    for kind in _KINDS
                ],
            },
        )

        def enqueue(
            surface: Surface, lock: NucleiLock, *, retest: str = "", refresh: bool = False
        ) -> str:
            store = AssessmentStore(database)
            try:
                actual_policy = store.register(policy)
                surface_id = store.upsert_surface(policy.engagement_id, surface)
                return store.submit(
                    actual_policy,
                    [
                        JobSpec(
                            surface_id,
                            "authentication" if refresh else "known_vulnerability",
                            "session_refresh" if refresh else "nuclei_scan",
                            policy_revision=policy.revision,
                            retest_revision=retest,
                            idempotent=False,
                            timeout_seconds=45,
                            tool_version="1" if refresh else lock.binary_version,
                            template_version="" if refresh else lock.bundle_sha256,
                        )
                    ],
                )[0]
            finally:
                store.close()

        async def run_cli(  # noqa: PLR0915 - tracked CLI, sampler and persisted outcome
            label: str,
            lock: NucleiLock,
            *,
            job_id: str | None = None,
            expect_jobs: int = 1,
            auto_capture: bool = True,
        ) -> dict | None:
            configuration = {
                "policy": policy.to_dict(),
                "nuclei_lock": _lock_document(lock),
                "tls": {"upstream_ca_file": str(fixture.ca_file)},
                "auth_vault_file": str(vault_path),
                "refresh_provider_file": str(provider_path),
                "seeds": [],
                "resources": {"total_memory_budget": 3 * 1024**3},
                "browser": {
                    "max_pages": 1,
                    "max_requests": 12,
                    "readiness_selector": "body[data-ready='yes']",
                    "readiness_timeout_ms": 8000,
                    "observation_window_ms": 200,
                    "total_timeout_seconds": 35,
                },
            }
            if auto_capture:
                configuration["browser_capture_file"] = str(capture_path)
            _private_json(config_path, configuration)
            store = AssessmentStore(database)
            try:
                previous = {row["id"] for row in store.jobs(policy.engagement_id, limit=100)}
            finally:
                store.close()
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
            before, tick = len(fixture.observed), time.monotonic()
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
            memory = {
                "target_interval_seconds": 0.025,
                "sample_count": 0,
                "available_sample_count": 0,
                "peak_rss_bytes": 0,
                "peak_process_count": 0,
                "max_observed_interval_seconds": 0.0,
            }

            async def sample() -> None:
                previous_tick = None
                next_tick = time.monotonic()
                while process.returncode is None:
                    now = time.monotonic()
                    if previous_tick is not None:
                        memory["max_observed_interval_seconds"] = max(
                            memory["max_observed_interval_seconds"], now - previous_tick
                        )
                    previous_tick = now
                    item = await asyncio.to_thread(process_tree_memory, process.pid)
                    memory["sample_count"] += 1
                    if item.available:
                        memory["available_sample_count"] += 1
                        memory["peak_rss_bytes"] = max(memory["peak_rss_bytes"], item.rss_bytes)
                        memory["peak_process_count"] = max(
                            memory["peak_process_count"], item.process_count
                        )
                    next_tick += 0.025
                    await asyncio.sleep(max(0.0, next_tick - time.monotonic()))

            sampler = asyncio.create_task(sample())
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), 70)
            finally:
                try:
                    if process.returncode is None:
                        process.kill()
                        await process.wait()
                finally:
                    sampler.cancel()
                    results = await asyncio.gather(sampler, return_exceptions=True)
                    assert not any(isinstance(result, Exception) for result in results)
            assert memory["available_sample_count"] > 0
            assert len(stdout) <= 65536 and len(stderr) <= 65536
            for secret in (
                *fixture.tokens.values(),
                *fixture.sessions.values(),
                fixture.refresh_secret,
                fixture.private_value,
            ):
                assert secret.encode() not in stdout + stderr
            report_path = tmp_path / "assessment-report.json"
            assert report_path.is_file(), (
                label,
                process.returncode,
                stdout.decode()[-4096:],
                stderr.decode()[-4096:],
            )
            report = json.loads(report_path.read_text())
            expected_exit = int(
                any(
                    row["coverage_status"] in {"blocked", "unsupported", "inconclusive"}
                    for row in report["coverage"]
                )
            )
            store = AssessmentStore(database)
            try:
                rows = store.jobs(policy.engagement_id, limit=100)
            finally:
                store.close()
            if job_id is not None:
                row = next(row for row in rows if row["id"] == job_id)
            elif expect_jobs:
                new = [row for row in rows if row["id"] not in previous]
                assert len(new) == 1, (label, new)
                row = new[0]
            else:
                row = None
            assert process.returncode == expected_exit, (
                label,
                row,
                stdout.decode()[-4096:],
                stderr.decode()[-4096:],
            )
            assert report["metrics"]["jobs"] == expect_jobs, (label, rows)
            assert report["metrics"]["model_calls"] == 0
            metrics["stages"].append(
                {
                    "case": label,
                    "pid": process.pid,
                    "exit_code": process.returncode,
                    "expected_exit_code": expected_exit,
                    "duration_seconds": time.monotonic() - tick,
                    "target_requests": fixture.observed[before:],
                    "result": row["result"] if row else None,
                    "execution_status": row["execution_status"] if row else None,
                    "coverage_status": row["coverage_status"] if row else None,
                    "process_tree_memory_sampling": memory,
                    "governor_snapshot": report["metrics"]["resources"],
                }
            )
            if progress_output := os.environ.get("REDJOHN_BROWSER_TOKEN_MEASUREMENTS"):
                progress = json.dumps(metrics, indent=2)
                for secret in (
                    *fixture.tokens.values(),
                    *fixture.sessions.values(),
                    fixture.refresh_secret,
                    fixture.private_value,
                ):
                    assert secret not in progress
                Path(progress_output).write_text(progress + "\n")
            return row

        def captured(revision: str) -> tuple[dict[str, Surface], dict[str, NucleiLock]]:
            store = AssessmentStore(database)
            try:
                candidates = [
                    row
                    for row in store.surfaces(policy.engagement_id, limit=100)
                    if row["method"] == "POST"
                    and row["session_revision"] == revision
                    and row["source"] == "observed"
                ]
                records = []
                relabelled_controls = 0
                for record in candidates:
                    surface = store.surface(policy.engagement_id, record["id"])
                    metadata = json.loads(
                        store.evidence_get(policy.engagement_id, surface.request_ref)["excerpt"]
                    )
                    if surface.workflow_state == "relabelled-old-capture":
                        # This deliberately forged inventory row is a negative
                        # control, whose referenced evidence still proves r7.
                        assert revision == "8" and metadata["session_revision"] == "7"
                        assert surface.url == fixture.origin + "/replay/json"
                        relabelled_controls += 1
                        continue
                    assert all(
                        metadata[key] == getattr(surface, key)
                        for key in ("url", "method", "actor_id", "tenant_id", "session_revision")
                    ), (record, metadata)
                    assert metadata["engagement_id"] == policy.engagement_id
                    assert metadata["policy_revision"] == policy.revision
                    assert metadata["sent"] is True and metadata["response_complete"] is True
                    assert metadata["status"] == 200
                    assert metadata["body_sha256"] == surface.body_sha256
                    assert metadata["request_content_type"] == surface.content_type
                    records.append(record)
                assert relabelled_controls == int(revision == "8")
                assert len(records) == 3, records
                surfaces = {
                    row["url"].rsplit("/", 1)[-1]: store.surface(policy.engagement_id, row["id"])
                    for row in records
                }
                assert set(surfaces) == set(_KINDS)
            finally:
                store.close()
            locks = {
                kind: post_fixture_lock(
                    tmp_path / f"templates-r{revision}-{kind}",
                    HOST_REPLAY_MULTIPART_CONTENT_TYPE
                    if kind == "multipart"
                    else surface.content_type,
                    "/replay/" + kind,
                    binary_lock=base_lock,
                )
                for kind, surface in surfaces.items()
            }
            mapping = json.loads(vault_path.read_text())
            requests = [
                request
                for entry in mapping["entries"]
                for request in entry["allowed_requests"]
                if request["method"] == "POST" and entry["session_revision"] == revision
            ]
            assert len(requests) == 3
            for request in requests:
                kind = request["url"].rsplit("/", 1)[-1]
                assert request["replay_safety"] == "operator-approved"
                assert request["request_ref"] == surfaces[kind].request_ref
                assert request["body_tokens"] == _token_binding(kind)
                assert fixture.body_matches(
                    "/replay/" + kind, request["content_type"], b64decode(request["body_base64"])
                )
            return surfaces, locks

        initial = await run_cli("automatic_chromium_capture_revision7", base_lock)
        assert initial["capability"] == "browser_post_capture", initial
        assert initial["execution_status"] == "succeeded" and initial["coverage_status"] in {
            "completed",
            "partial",
        }, initial
        initial_summary = initial["result"]["summary"]
        assert initial_summary["metrics"]["captured_post_requests"] == 3
        _assert_attested(initial_summary["tool"]["egress_attestations"])
        metrics["chromium_version"] = initial_summary["tool"]["chromium_version"]
        metrics["playwright_version"] = initial_summary["tool"]["playwright_version"]
        first_surfaces, first_locks = captured("7")
        initial_ids = {}
        for kind in _KINDS:
            job_id = enqueue(first_surfaces[kind], first_locks[kind])
            initial_ids[kind] = job_id
            row = await run_cli("nuclei_revision7_" + kind, first_locks[kind], job_id=job_id)
            assert row["coverage_status"] == "completed" and len(row["result"]["findings"]) == 1, (
                row
            )
            _assert_attested(row["result"]["summary"]["network"]["egress_attestations"])
        before = len(fixture.observed)
        assert enqueue(first_surfaces["json"], first_locks["json"]) == initial_ids["json"]
        await run_cli("unchanged_restart_no_browser_or_post", first_locks["json"], expect_jobs=0)
        assert len(fixture.observed) == before
        refresh_id = enqueue(first_surfaces["json"], first_locks["json"], refresh=True)
        refresh = await run_cli(
            "explicit_refresh_body_tokens_to8", first_locks["json"], job_id=refresh_id
        )
        assert refresh["coverage_status"] == "completed", refresh
        assert fixture.revision == "8" and fixture.counts["/refresh"] == 1
        rotated = json.loads(vault_path.read_text())
        pending = [
            request
            for entry in rotated["entries"]
            for request in entry["allowed_requests"]
            if request["method"] == "POST"
        ]
        assert len(pending) == 3 and all(
            request["replay_safety"] == "fresh-capture-required" for request in pending
        )
        assert all(request["request_ref"].startswith("pending-capture:") for request in pending)
        for request in pending:
            assert fixture.body_matches(
                request["url"].removeprefix(fixture.origin),
                request["content_type"],
                b64decode(request["body_base64"]),
            )
        before = len(fixture.observed)
        for label, surface in (
            ("old_revision_no_request", first_surfaces["json"]),
            (
                "old_capture_cannot_be_relabelled",
                replace(
                    first_surfaces["json"],
                    session_revision="8",
                    workflow_state="relabelled-old-capture",
                ),
            ),
        ):
            job_id = enqueue(surface, first_locks["json"], retest=label)
            row = await run_cli(label, first_locks["json"], job_id=job_id, auto_capture=False)
            assert row["coverage_status"] == "blocked", row
            assert len(fixture.observed) == before
        second = await run_cli("automatic_fresh_chromium_capture_revision8", base_lock)
        assert (
            second["capability"] == "browser_post_capture"
            and second["execution_status"] == "succeeded"
        ), second
        assert second["result"]["summary"]["metrics"]["captured_post_requests"] == 3
        _assert_attested(second["result"]["summary"]["tool"]["egress_attestations"])
        second_surfaces, second_locks = captured("8")
        assert second_surfaces["multipart"].content_type != first_surfaces["multipart"].content_type
        assert second_locks["multipart"].bundle_sha256 == first_locks["multipart"].bundle_sha256
        for kind in _KINDS:
            assert second_surfaces[kind].body_sha256 != first_surfaces[kind].body_sha256
            job_id = enqueue(second_surfaces[kind], second_locks[kind])
            row = await run_cli(
                "nuclei_refreshed_body_token_" + kind, second_locks[kind], job_id=job_id
            )
            assert row["coverage_status"] == "completed" and len(row["result"]["findings"]) == 1, (
                row
            )
            _assert_attested(row["result"]["summary"]["network"]["egress_attestations"])
        fixture.mode = "fixed"
        for kind in _KINDS:
            job_id = enqueue(second_surfaces[kind], second_locks[kind], retest="fixed-control")
            row = await run_cli("fixed_control_" + kind, second_locks[kind], job_id=job_id)
            assert row["coverage_status"] == "completed" and not row["result"]["findings"], row
            assert row["result"]["summary"]["no_finding_observed"] is True
        before = len(fixture.observed)
        assert enqueue(first_surfaces["json"], first_locks["json"], refresh=True) == refresh_id
        await run_cli("completed_refresh_not_repeated", second_locks["json"], expect_jobs=0)
        assert len(fixture.observed) == before and fixture.counts["/refresh"] == 1
        fixture.mode = "redirect"
        job_id = enqueue(second_surfaces["json"], second_locks["json"], retest="redirect-control")
        redirect = await run_cli(
            "redirect_no_credential_follow", second_locks["json"], job_id=job_id
        )
        assert (
            redirect["coverage_status"] == "inconclusive"
            and not redirect["result"]["summary"]["no_finding_observed"]
        ), redirect
        assert fixture.counts["/credential-trap"] == 0
        store = AssessmentStore(database)
        try:
            used = store.db.execute(
                "SELECT requests_used FROM rj_engagement WHERE id=?", (policy.engagement_id,)
            ).fetchone()[0]
            state = store.session_state(policy, second_surfaces["json"])
            assert state["revision"] == "8" and state["status"] == "ready"
        finally:
            store.close()
        assert used == len(fixture.observed), (used, fixture.observed)
        assert all(row["private_values_valid"] for row in fixture.observed)
        for path in tmp_path.rglob("*"):
            if path.is_file() and private not in path.parents:
                contents = path.read_bytes()
                for secret in (
                    *fixture.tokens.values(),
                    *fixture.sessions.values(),
                    fixture.refresh_secret,
                    fixture.private_value,
                ):
                    assert secret.encode() not in contents, path
        metrics.update(
            duration_seconds=time.monotonic() - started,
            target_origin=fixture.origin,
            target_ip=host,
            http_requests=len(fixture.observed),
            persisted_requests_used=used,
            refresh_requests=fixture.counts["/refresh"],
            browser_capture_revisions=["7", "8"],
            body_formats=list(_KINDS),
            positive_candidates=6,
            fixed_control_new_findings=0,
            restart_duplicate_requests=0,
            credential_trap_requests=fixture.counts["/credential-trap"],
            body_tokens_rotated=True,
            capture_source="actual_headless_chromium_post_via_host_proxy_no_sdk_capture",
            sampled_tree_peak_rss_bytes=max(
                stage["process_tree_memory_sampling"]["peak_rss_bytes"]
                for stage in metrics["stages"]
            ),
            memory_sample_count=sum(
                stage["process_tree_memory_sampling"]["sample_count"] for stage in metrics["stages"]
            ),
            memory_measurement=(
                "25 ms target interval CLI and descendant summed RSS; "
                "shared pages may be counted more than once; sampled peak"
            ),
        )
        for secret in (
            *fixture.tokens.values(),
            *fixture.sessions.values(),
            fixture.refresh_secret,
            fixture.private_value,
        ):
            assert secret not in json.dumps(metrics)
        for path in (vault_path, provider_path, capture_path):
            path.unlink()
    metrics["pipeline_complete"] = True
    if output := os.environ.get("REDJOHN_BROWSER_TOKEN_MEASUREMENTS"):
        Path(output).write_text(json.dumps(metrics, indent=2) + "\n")
