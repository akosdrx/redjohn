"""Actual pinned specialist CLIs and Chromium on disposable HTTPS/SQLite.

No mock scanner or canned SQL response: SQLite executes either the vulnerable
read-only SELECT or its parameterized control. XSS is target-delivered HTML;
Chromium must observe the per-job alert nonce, without page.evaluate/init JS.
"""

import asyncio
import hashlib
import html
import json
import os
import platform
import sqlite3
import ssl
import sys
import time
from contextlib import closing, suppress
from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.specialists import CAPABILITIES
from redjohn.assessment.store import AssessmentStore
from tests.remote_https_fixture import RemoteHTTPSFixture, fixture_host


def installed(tool):
    versions = {"arjun": "2.2.7", "sqlmap": "1.10.10", "dalfox": "3.2.4"}
    receipt = Path(__file__).parents[1] / ".tools" / tool / versions[tool] / "install-receipt.json"
    if not receipt.exists():
        if os.environ.get("REDJOHN_REQUIRE_SPECIALIST_E2E") == "1":
            pytest.fail(f"required pinned {tool} installation missing")
        pytest.skip(f"blocked_missing_dependency: pinned {tool}; tests never install tools")
    data = json.loads(receipt.read_text())
    assert hashlib.sha256(Path(data["path"]).read_bytes()).hexdigest() == data["sha256"]
    return {"binary": {key: data[key] for key in ("path", "sha256", "version")}}


def owned_fixture(host, path, *, fixed=False):
    fixture = RemoteHTTPSFixture(host, path)
    fixture.wire = []
    fixture.slow = False

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            parsed = urlsplit(self.path)
            fixture.wire.append(
                {"path": parsed.path, "query": parsed.query, "authorized": False, "method": "HEAD"}
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):  # noqa: PLR0912 - controlled endpoint/fault fixture
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query, keep_blank_values=True)
            authorized = self.headers.get("Cookie") == "fixture_session=" + fixture.credential
            fixture.wire.append(
                {"path": parsed.path, "query": parsed.query, "authorized": authorized}
            )
            content, code = "text/html", 200
            if parsed.path == "/params":
                body = "<html><body>fixture parameter control</body></html>"
                if not fixed and "hidden" in query:
                    body = (
                        "<html><body>discovered hidden parameter changes "
                        "the owned fixture response</body></html>"
                    )
            elif parsed.path in {"/sql", "/private-sql"}:
                value = query.get("id", ["1"])[0]
                if parsed.path == "/private-sql" and not authorized:
                    code, body = 401, "test actor required"
                else:
                    with closing(sqlite3.connect(":memory:")) as db:
                        db.execute("CREATE TABLE items(id INTEGER, label TEXT)")
                        db.execute("INSERT INTO items VALUES(1,'RedJohn harmless fixture row')")
                        try:
                            rows = (
                                db.execute(
                                    "SELECT label FROM items WHERE id=?", (value,)
                                ).fetchall()
                                if fixed
                                else db.execute(
                                    "SELECT label FROM items WHERE id=" + value  # noqa: S608 - intentionally vulnerable owned SQLite control
                                ).fetchall()
                            )
                            body = (
                                "<html><body>" + ";".join(row[0] for row in rows) + "</body></html>"
                            )
                        except sqlite3.Error:
                            code, body = 500, "<html><body></body></html>"
            elif parsed.path == "/xss":
                value = query.get("q", ["benign"])[0]
                body = (
                    "<!doctype html><html><body>"
                    + (html.escape(value) if fixed else value)
                    + "</body></html>"
                )
            elif parsed.path == "/slow":
                if fixture.slow:
                    time.sleep(5)
                body = "<html><body>bounded slow fixture</body></html>"
            elif parsed.path == "/limited":
                code, body = 429, "fixture cooldown"
            elif parsed.path == "/redirect":
                code, body = 302, "redirect blocked"
            else:
                body = "<!doctype html><body>RedJohn owned fixture</body>"
            raw = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", content)
            self.send_header("Content-Length", str(len(raw)))
            if code == 302:
                self.send_header("Location", "https://outside.invalid/never")
            if code == 429:
                self.send_header("Retry-After", "30")
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    fixture.server.RequestHandlerClass = Handler
    return fixture


def host_for(remote):
    if remote and platform.system() != "Linux":
        if os.environ.get("REDJOHN_REQUIRE_REMOTE_E2E") == "1":
            pytest.fail("Linux namespace E2E required")
        pytest.skip("blocked_kernel_egress_unavailable_on_macos")
    return fixture_host() if remote else "127.0.0.1"


def policy_for(fixture, remote, **changes):
    return EngagementPolicy(
        "specialist-live",
        "operator",
        (fixture.origin,),
        profile="isolated-lab",
        egress_mode="enforced" if remote else "local-fixture",
        allowed_ips=(fixture.host + "/32",),
        request_budget=512,
        **changes,
    )


def runtime(store, policy, fixture, **configs):
    return AssessmentRuntime(
        store,
        policy,
        caller="operator",
        browser_tls=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
        browser_limits=BrowserLimits(max_pages=1, max_frontier=8, observation_window_ms=150),
        envelope=ResourceEnvelope(total_memory_budget=1536 * 1024**2, max_workers=1),
        **configs,
    )


async def capture(store, policy, fixture, url, parameter="", actor="anonymous", state=None):
    store.register(policy)
    seed = Surface(url, source="imported", workflow_state="approved_seed", actor_id=actor)
    surface_id = store.upsert_surface(policy.engagement_id, seed)
    async with runtime(store, policy, fixture, actor_states=state) as app:
        spec = JobSpec(surface_id, "discovery", "browser_discover", timeout_seconds=15)
        store.submit(policy, [spec])
        await app.scheduler.run_batch(max_jobs=1)
        rows = store.surfaces(policy.engagement_id, limit=64)
        found = next(row for row in rows if row["url"] == url and row["request_ref"])
        actual = store.surface(policy.engagement_id, found["id"])
        if parameter:
            actual = replace(actual, input_location="query", input_name=parameter)
            surface_id = store.upsert_surface(policy.engagement_id, actual)
        else:
            surface_id = found["id"]
        return surface_id, actual


def spec_for(app, store, policy, surface_id, surface, tool, **changes):
    options = {}
    if tool != "arjun":
        hint = store.evidence_put(
            policy.engagement_id,
            {
                "signal": "sqli" if tool == "sqlmap" else "xss",
                "request_ref": surface.request_ref,
                "input_name": surface.input_name,
                "source": "operator_selected_owned_fixture_validation",
            },
            kind="reviewed_specialist_hint",
        )
        options = {"hint_ref": hint}
    return JobSpec(
        surface_id,
        "parameter_discovery" if tool == "arjun" else "sqli" if tool == "sqlmap" else "xss",
        CAPABILITIES[tool],
        options=options,
        timeout_seconds=45,
        **app.registry.execution_versions(CAPABILITIES[tool]),
        **changes,
    )


@pytest.mark.parametrize("remote", [False, True], ids=["loopback-https", "kernel-remote-https"])
@pytest.mark.parametrize("fixed", [False, True], ids=["vulnerable-fixture", "fixed-control"])
async def test_actual_specialists_restart_browser_sqlite_and_xss_chain(tmp_path, remote, fixed):  # noqa: PLR0915
    host = host_for(remote)
    configs = {tool + "_config": installed(tool) for tool in CAPABILITIES}
    configs["arjun_config"]["parameters"] = ["hidden", "unused"]
    stages, specs, started = [], [], time.monotonic()
    database = tmp_path / "state/agents.db"
    with owned_fixture(host, tmp_path / "tls", fixed=fixed) as fixture:
        policy = policy_for(fixture, remote)
        for tool, endpoint, parameter in (
            ("arjun", "/params", ""),
            ("sqlmap", "/sql?id=1", "id"),
            ("dalfox", "/xss?q=benign", "q"),
        ):
            with closing(AssessmentStore(database)) as store:
                surface_id, surface = await capture(
                    store, policy, fixture, fixture.origin + endpoint, parameter
                )
            with closing(AssessmentStore(database)) as store:
                async with runtime(store, policy, fixture, **configs) as app:
                    spec = spec_for(app, store, policy, surface_id, surface, tool)
                    specs.append(spec)
                    store.submit(policy, [spec])
                    await app.scheduler.run_batch(max_jobs=1)
                    row = next(
                        row
                        for row in store.jobs(policy.engagement_id, limit=64)
                        if row["job_key"] == spec.key
                    )
                    stages.append(
                        {
                            "tool": tool,
                            "execution": row["execution_status"],
                            "coverage": row["coverage_status"],
                            "result": row["result"],
                            "peak_rss_bytes": app.governor.peak_rss_bytes,
                        }
                    )
                    assert row["execution_status"] == "succeeded", row
                    assert row["coverage_status"] == "completed", row
                    summary = row["result"]["summary"]
                    if remote:
                        assert summary["egress_attestations"]
                    assert summary["upstream_tls"] == "host_proxy_verified"
                    if tool == "arjun":
                        assert summary["parameters"] == ([] if fixed else ["hidden"])
                    else:
                        assert summary["outcome"] == (
                            "no_finding_observed" if fixed else "candidate"
                        ), row
                    assert app.governor.snapshot()["reserved_bytes"] == 0
                    replanned = spec_for(app, store, policy, surface_id, surface, tool)
                    assert replanned.key == spec.key
                    assert store.submit(policy, [replanned]) == [row["id"]]
        # The Dalfox process and runtime are gone. The outbox/queue must retain
        # the follow-up, then an independent runtime runs actual Chromium.
        with closing(AssessmentStore(database)) as store:
            async with runtime(store, policy, fixture, **configs) as app:
                await app.scheduler.run_batch(max_jobs=4)
                confirmations = [
                    r
                    for r in store.jobs(policy.engagement_id, limit=64)
                    if r["capability"] == "browser_xss_confirmation"
                ]
                assert len(confirmations) == (0 if fixed else 1)
                if confirmations:
                    row = confirmations[0]
                    assert row["execution_status"] == "succeeded", row
                    assert row["result"]["summary"]["outcome"] == "confirmed_weakness", row
                    assert row["result"]["findings"][0]["finding_status"] == "confirmed_weakness"
                    confirmed = [
                        r
                        for r in store.findings(policy.engagement_id)
                        if r["payload"].get("cwe") == "CWE-79"
                    ]
                    assert len(confirmed) == 1 and confirmed[0]["status"] == "confirmed_weakness"
                    stages.append(
                        {
                            "tool": "chromium_confirmation",
                            "result": row["result"],
                            "peak_rss_bytes": app.governor.peak_rss_bytes,
                        }
                    )
                before = len(fixture.wire)
                store.submit(policy, specs)
                assert await app.scheduler.run_batch(max_jobs=8) == []
                assert len(fixture.wire) == before
                assert app.governor.snapshot()["reserved_bytes"] == 0

                metrics = {
                    "platform": platform.system(),
                    "remote": remote,
                    "fixed": fixed,
                    "elapsed_seconds": time.monotonic() - started,
                    "requests": len(fixture.wire),
                    "duplicate_resume_requests": len(fixture.wire) - before,
                    "model_calls": 0,
                    "stages": stages,
                }
                measurement = os.environ.get("REDJOHN_SPECIALIST_MEASUREMENTS")
                if measurement:
                    path = Path(measurement)
                    path = path.with_name(
                        path.stem
                        + ("-remote" if remote else "-loopback")
                        + ("-fixed" if fixed else "-positive")
                        + path.suffix
                    )
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(metrics, indent=2) + "\n")
                print(  # noqa: T201 - measured E2E summary
                    "REDJOHN_SPECIALIST_E2E="
                    + json.dumps({key: value for key, value in metrics.items() if key != "stages"})
                )


@pytest.mark.parametrize("remote", [False, True], ids=["loopback-https", "kernel-remote-https"])
async def test_actual_sqlmap_host_only_authenticated_capture_and_expiry(tmp_path, remote):
    config = installed("sqlmap")
    with owned_fixture(host_for(remote), tmp_path / "tls") as fixture:
        policy = policy_for(fixture, remote, actor_ids=("anonymous", "alice"))
        with closing(AssessmentStore(tmp_path / "state/db")) as store:
            actor = {
                "alice": {
                    "cookies": [
                        {
                            "name": "fixture_session",
                            "value": fixture.credential,
                            "url": fixture.origin,
                        }
                    ],
                    "origins": [],
                }
            }
            sid, surface = await capture(
                store, policy, fixture, fixture.origin + "/private-sql?id=1", "id", "alice", actor
            )
            vault = tmp_path / "private-vault.json"
            data = {
                "version": 1,
                "entries": [
                    {
                        "engagement_id": policy.engagement_id,
                        "owner_id": policy.owner_id,
                        "actor_id": "alice",
                        "tenant_id": "",
                        "session_revision": "1",
                        "policy_revision": policy.revision,
                        "expires_at": time.time() + 120,
                        "origin": fixture.origin,
                        "headers": {},
                        "cookies": [{"name": "fixture_session", "value": fixture.credential}],
                        "allowed_requests": [
                            {
                                "url": surface.url,
                                "method": "GET",
                                "request_ref": surface.request_ref,
                            }
                        ],
                    }
                ],
            }
            vault.write_text(json.dumps(data))
            vault.chmod(0o600)
            async with runtime(
                store, policy, fixture, sqlmap_config=config, auth_vault_file=vault
            ) as app:
                spec = spec_for(app, store, policy, sid, surface, "sqlmap")
                before = len(fixture.wire)
                store.submit(policy, [spec])
                await app.scheduler.run_batch(max_jobs=1)
                row = next(r for r in store.jobs(policy.engagement_id) if r["job_key"] == spec.key)
                assert row["execution_status"] == "succeeded", row
                assert row["result"]["summary"]["outcome"] == "candidate"
                assert len(fixture.wire) > before and all(
                    r["authorized"] for r in fixture.wire[before:]
                )
                data["entries"][0]["expires_at"] = time.time() - 1
                vault.write_text(json.dumps(data))
                expired = replace(spec, retest_revision="expired-session-control")
                before = len(fixture.wire)
                store.submit(policy, [expired])
                await app.scheduler.run_batch(max_jobs=1)
                row = next(
                    r for r in store.jobs(policy.engagement_id) if r["job_key"] == expired.key
                )
                assert row["coverage_status"] == "blocked", row
                assert row["result"]["error"]["code"] == "auth_replay_expired"
                assert len(fixture.wire) == before and not row["result"]["findings"]
                assert fixture.credential.encode() not in store.path.read_bytes()
                assert (
                    fixture.credential.encode()
                    not in store.path.with_name(store.path.name + "-wal").read_bytes()
                )
                assert not list((store.path.parent / "sqlmap-workers").glob("job-*"))


@pytest.mark.parametrize("tool", list(CAPABILITIES))
async def test_actual_specialist_cancellation_reaps_process_tree(tmp_path, tool):
    config = installed(tool)
    if tool == "arjun":
        config["parameters"] = ["hidden", "unused"]
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        policy = policy_for(fixture, remote=False)
        with closing(AssessmentStore(tmp_path / "state/db")) as store:
            sid, surface = await capture(
                store,
                policy,
                fixture,
                fixture.origin + "/slow" + ("?id=1" if tool != "arjun" else ""),
                "id" if tool != "arjun" else "",
            )
            fixture.slow = True
            async with runtime(store, policy, fixture, **{tool + "_config": config}) as app:
                app.scheduler.lease_seconds = 0.15
                spec = spec_for(app, store, policy, sid, surface, tool)
                job_id = store.submit(policy, [spec])[0]
                task = asyncio.create_task(app.scheduler.run_batch(max_jobs=1))
                adapter = app.scheduler.adapters[CAPABILITIES[tool]]
                async with asyncio.timeout(10):
                    while adapter.runner.process is None or len(fixture.wire) < 2:
                        await asyncio.sleep(0.02)
                process = adapter.runner.process
                store.cancel(policy.engagement_id, job_id)
                await task
                row = next(r for r in store.jobs(policy.engagement_id) if r["id"] == job_id)
                assert row["execution_status"] == "cancelled", row
                assert row["result"]["error"]["partial_evidence_refs"]
                assert process.returncode is not None
                assert adapter.runner.process is None and adapter.runner.workspace is None
                assert app.governor.snapshot()["reserved_bytes"] == 0


@pytest.mark.parametrize("tool", list(CAPABILITIES))
async def test_actual_specialist_timeout_reaps_worker_and_keeps_partial_evidence(tmp_path, tool):
    config = installed(tool)
    if tool == "arjun":
        config["parameters"] = ["hidden", "unused"]
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        policy = policy_for(fixture, remote=False)
        with closing(AssessmentStore(tmp_path / "state/db")) as store:
            # Capture a completed benign endpoint, then use an exact observation
            # of the slow endpoint for this lifecycle fault injection.
            surface = Surface(
                fixture.origin + "/slow" + ("?id=1" if tool != "arjun" else ""),
                input_location="query" if tool != "arjun" else "",
                input_name="id" if tool != "arjun" else "",
            )
            # Real browser capture itself waits for the response; scanner timeout
            # begins only after this independent successful request has completed.
            sid, surface = await capture(store, policy, fixture, surface.url, surface.input_name)
            fixture.slow = True
            async with runtime(store, policy, fixture, **{tool + "_config": config}) as app:
                spec = spec_for(app, store, policy, sid, surface, tool)
                spec = replace(spec, timeout_seconds=2)
                store.submit(policy, [spec])
                await app.scheduler.run_batch(max_jobs=1)
                row = next(r for r in store.jobs(policy.engagement_id) if r["job_key"] == spec.key)
                assert row["execution_status"] == "timed_out", row
                assert row["result"]["error"]["partial_evidence_refs"]
                adapter = app.scheduler.adapters[CAPABILITIES[tool]]
                assert adapter.runner.process is None and adapter.runner.workspace is None
                assert app.governor.snapshot()["reserved_bytes"] == 0


@pytest.mark.parametrize("tool", list(CAPABILITIES))
@pytest.mark.parametrize("fault", ["redirect", "limited", "tls-trust", "bad-digest"])
async def test_actual_specialist_fault_is_not_a_clean_negative(tmp_path, tool, fault):
    config = installed(tool)
    if tool == "arjun":
        config["parameters"] = ["hidden", "unused"]
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        policy = policy_for(fixture, remote=False)
        endpoint = (
            "/" + fault
            if fault in {"redirect", "limited"}
            else "/params"
            if tool == "arjun"
            else "/sql"
        )
        url = fixture.origin + endpoint + ("?id=1" if tool != "arjun" else "")
        with closing(AssessmentStore(tmp_path / "state/db")) as store:
            sid, surface = await capture(
                store, policy, fixture, url, "id" if tool != "arjun" else ""
            )
            if fault == "bad-digest":
                config["binary"]["sha256"] = "0" * 64
            # Capturing used the real fixture CA. The following runtime really
            # lacks it: TLS must fail instead of adding ignore-certificate flags.
            app = (
                AssessmentRuntime(store, policy, caller="operator", **{tool + "_config": config})
                if fault == "tls-trust"
                else runtime(store, policy, fixture, **{tool + "_config": config})
            )
            async with app:
                before = len(fixture.wire)
                spec = replace(spec_for(app, store, policy, sid, surface, tool), timeout_seconds=6)
                store.submit(policy, [spec])
                await app.scheduler.run_batch(max_jobs=1)
                row = next(r for r in store.jobs(policy.engagement_id) if r["job_key"] == spec.key)
                assert row["execution_status"] in {"failed", "timed_out"}, row
                assert row["coverage_status"] in {"blocked", "inconclusive"}, row
                assert not row["result"]["findings"]
                assert row["result"]["summary"].get("outcome") != "no_finding_observed"
                if fault in {"tls-trust", "bad-digest"}:
                    assert len(fixture.wire) == before
                if fault == "tls-trust":
                    assert row["result"]["summary"]["upstream_tls_failures"] > 0
                adapter = app.scheduler.adapters[CAPABILITIES[tool]]
                assert adapter.runner.process is None and adapter.runner.workspace is None
                assert app.governor.snapshot()["reserved_bytes"] == 0


async def test_actual_cli_selected_jobs_survive_process_restart_without_rescan(tmp_path):
    config = {**installed("arjun"), "parameters": ["hidden", "unused"]}
    output = tmp_path / "assessment"
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        policy = policy_for(fixture, remote=False)
        with closing(AssessmentStore(output / ".state/agents.db")) as store:
            sid, _surface = await capture(store, policy, fixture, fixture.origin + "/params")
        document = {
            "policy": asdict(policy),
            "arjun": config,
            "tls": {"upstream_ca_file": str(fixture.ca_file)},
            "jobs": [{"surface_id": sid, "capability": "arjun_parameters"}],
        }
        path = tmp_path / "engagement.json"
        path.write_text(json.dumps(document))
        for index in range(2):
            before = len(fixture.wire)
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "redjohn.assessment",
                "run",
                "--config",
                str(path),
                "--output",
                str(output),
                "--max-jobs",
                "2",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode == 0, (stdout, stderr)
            with closing(AssessmentStore(output / ".state/agents.db")) as store:
                jobs = [
                    row
                    for row in store.jobs(policy.engagement_id)
                    if row["capability"] == "arjun_parameters"
                ]
                assert len(jobs) == 1 and jobs[0]["execution_status"] == "succeeded"
            if index:
                assert len(fixture.wire) == before
            else:
                assert len(fixture.wire) > before
                document["arjun"]["rate_limit"] = 1
                path.write_text(json.dumps(document))
