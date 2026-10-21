"""Actual TInjA / Schemathesis processes and official Interactsh receiver.

No fake engine output or mock OAST encryption. The fixtures render real Jinja,
return real JSON, and the pinned upstream server encrypts actual HTTP callbacks.
DNS delegation and public-internet reachability are separate, untested capabilities.
"""

import asyncio
import hashlib
import html
import http.client
import json
import os
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time
from contextlib import closing, nullcontext, suppress
from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from jinja2 import TemplateError
from jinja2.sandbox import SandboxedEnvironment

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import JobSpec
from redjohn.assessment.oast import OASTConfig
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.schema_tools import CAPABILITIES
from redjohn.assessment.store import AssessmentStore
from tests.remote_https_fixture import RemoteHTTPSFixture
from tests.test_specialists_live import capture, host_for, policy_for, runtime


def installed(tool):
    version = {"tinja": "1.2.0", "schemathesis": "4.31.1", "interactsh-server": "1.4.1"}[tool]
    file = Path(__file__).parents[1] / ".tools" / tool / version / "install-receipt.json"
    if not file.exists():
        if os.environ.get("REDJOHN_REQUIRE_SCHEMA_OAST_E2E") == "1":
            pytest.fail("required pinned " + tool + " installation missing")
        pytest.skip("blocked_missing_dependency: pinned " + tool)
    receipt = json.loads(file.read_text())
    assert hashlib.sha256(Path(receipt["path"]).read_bytes()).hexdigest() == receipt["sha256"]
    return {"binary": {k: receipt[k] for k in ("path", "sha256", "version")}}


def reviewed_schema(tmp_path, path="/api"):
    schema = {
        "openapi": "3.0.3",
        "info": {"title": "RedJohn reviewed API", "version": "1"},
        "paths": {
            path: {
                "get": {
                    "operationId": "reviewedRead",
                    "parameters": [
                        {
                            "in": "query",
                            "name": "id",
                            "required": True,
                            "schema": {"type": "integer", "minimum": 0, "maximum": 9},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Reviewed response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"id": {"type": "integer"}},
                                        "required": ["id"],
                                        "additionalProperties": False,
                                    }
                                }
                            },
                        },
                    },
                }
            }
        },
    }
    file = tmp_path / "schema.json"
    file.write_text(json.dumps(schema))
    return {
        "schema_file": str(file),
        "schema_sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
    }


def owned_fixture(host, directory, *, fixed=False, receiver=None, late=False):
    fixture = RemoteHTTPSFixture(host, directory)
    fixture.wire, fixture.callbacks, fixture.slow, fixture.fault = [], [], False, ""
    engine = SandboxedEnvironment()

    def callback(url):
        parsed = urlsplit(url)
        assert receiver is not None
        assert parsed.scheme == "http" and parsed.hostname.endswith(".redjohn-oast.test")
        assert parsed.port == receiver.ports["http"]
        conn = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=3)
        try:
            conn.request("GET", parsed.path, headers={"Host": parsed.netloc})
            response = conn.getresponse()
            assert response.status == 200
            response.read(65536)
        finally:
            conn.close()

    fixture.deliver_callback = callback

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: PLR0912 - controlled positive/fixed and fault endpoints
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query, keep_blank_values=True)
            fixture.wire.append((parsed.path, parsed.query))
            content, code = "text/html", 200
            if fixture.slow:
                time.sleep(5)
            if parsed.path == "/template":
                value = query.get("q", ["benign"])[0]
                try:
                    body = html.escape(value) if fixed else engine.from_string(value).render()
                except TemplateError:
                    code, body = 500, "template_error"
                body = "<!doctype html><body><pre>template:" + body + "</pre></body>"
            elif parsed.path == "/api":
                content = "application/json"
                value = int(query.get("id", ["1"])[0])
                body = json.dumps({"id": value if fixed else str(value)})
            elif parsed.path == "/callback":
                value = query.get("url", ["benign"])[0]
                if value.startswith("http://"):
                    fixture.callbacks.append(value)
                    if not fixed and not late:
                        callback(value)
                body = "<!doctype html><body>owned callback endpoint</body>"
            elif parsed.path == "/limited":
                code, body = 429, "cooldown"
            elif parsed.path == "/redirect":
                code, body = 302, "denied redirect"
            else:
                body = "<!doctype html><body>fixture</body>"
            if fixture.fault == "limited":
                code, body = 429, "cooldown"
            elif fixture.fault == "redirect":
                code, body = 302, "redirect"
            raw = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", content)
            self.send_header("Content-Length", str(len(raw)))
            if code == 429:
                self.send_header("Retry-After", "20")
            if code == 302:
                self.send_header("Location", "https://outside.invalid/never")
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    fixture.server.RequestHandlerClass = Handler
    return fixture


def make_spec(app, store, policy, surface_id, surface, tool, **changes):
    signal_name = {"tinja": "ssti", "schemathesis": "schema", "interactsh": "oast_http"}[tool]
    ref = store.evidence_put(
        policy.engagement_id,
        {
            "signal": signal_name,
            "request_ref": surface.request_ref,
            "input_name": surface.input_name,
        },
        kind="reviewed_tool_hint",
    )
    capability = "oast_correlate" if tool == "interactsh" else CAPABILITIES[tool]
    return JobSpec(
        surface_id,
        {"tinja": "ssti", "schemathesis": "api_schema", "interactsh": "oast"}[tool],
        capability,
        options={"hint_ref": ref},
        timeout_seconds=45,
        **app.registry.execution_versions(capability),
        **changes,
    )


def measure(name, value):
    output = os.environ.get("REDJOHN_SCHEMA_OAST_MEASUREMENTS")
    if output:
        path = Path(output).with_name(name + ".json")
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(json.dumps(value, indent=2) + "\n")


async def test_actual_alias_proxy_rejects_direct_https_tunnel_before_admission_or_credentials(
    tmp_path,
):
    import httpx  # noqa: PLC0415 - explicit real transport fixture

    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        policy = policy_for(fixture, remote=False)
        calls = []

        def connect_guard(origin):
            calls.append("connect_guard")
            assert origin == fixture.origin
            raise PolicyDenied("selected_http_alias_only")

        def admit(_url):
            calls.append("admission")

        def headers(_url, _method, fields):
            calls.append("credentials")
            return fields

        proxy = BrowserEgressProxy(
            policy,
            connect_policy=connect_guard,
            request_admission=admit,
            request_headers=headers,
            tls_config=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
        )
        try:
            await proxy.start()
            async with httpx.AsyncClient(
                proxy=proxy.url, verify=proxy.client_tls_context, trust_env=False
            ) as client:
                with pytest.raises(httpx.ProxyError):
                    await client.get(fixture.origin + "/api?id=1")
            assert calls == ["connect_guard"]
            assert not fixture.wire and proxy.forwarded_requests == 0
            assert proxy.denied_requests == 1
        finally:
            await proxy.close()


@pytest.mark.parametrize("tool", ["tinja", "schemathesis"])
@pytest.mark.parametrize("fixed", [False, True], ids=["positive", "fixed"])
@pytest.mark.parametrize("remote", [False, True], ids=["loopback", "remote"])
async def test_actual_schema_tools_browser_capture_restart_and_controls(
    tmp_path, tool, fixed, remote
):
    host = host_for(remote)
    config = installed(tool)
    if tool == "schemathesis":
        config.update(reviewed_schema(tmp_path))
    endpoint, parameter = ("/template?q=benign", "q") if tool == "tinja" else ("/api?id=1", "id")
    started = time.monotonic()
    database = tmp_path / "state/agents.db"
    with owned_fixture(host, tmp_path / "tls", fixed=fixed) as fixture:
        policy = policy_for(fixture, remote)
        with closing(AssessmentStore(database)) as store:
            surface_id, surface = await capture(
                store, policy, fixture, fixture.origin + endpoint, parameter
            )
        with closing(AssessmentStore(database)) as store:
            async with runtime(store, policy, fixture, **{tool + "_config": config}) as app:
                spec = make_spec(app, store, policy, surface_id, surface, tool)
                job_id = store.submit(policy, [spec])[0]
                await app.scheduler.run_batch(max_jobs=1)
                row = next(r for r in store.jobs(policy.engagement_id) if r["id"] == job_id)
                measure(
                    "-".join(
                        (tool, "remote" if remote else "loopback", "fixed" if fixed else "positive")
                    ),
                    {
                        "row": row,
                        "elapsed_seconds": time.monotonic() - started,
                        "requests": len(fixture.wire),
                        "peak_rss_bytes": app.governor.peak_rss_bytes,
                    },
                )
                assert row["execution_status"] == "succeeded", row
                assert row["coverage_status"] == "completed", row
                summary = row["result"]["summary"]
                assert summary["outcome"] == ("no_finding_observed" if fixed else "candidate"), row
                assert summary["upstream_tls"] == "host_proxy_verified"
                assert bool(summary["egress_attestations"]) is remote
                assert app.governor.snapshot()["reserved_bytes"] == 0
                replanned = make_spec(app, store, policy, surface_id, surface, tool)
                assert replanned.key == spec.key
                assert store.submit(policy, [replanned]) == [job_id]
        count = len(fixture.wire)
        with closing(AssessmentStore(database)) as store:
            async with runtime(store, policy, fixture, **{tool + "_config": config}) as app:
                assert store.submit(policy, [spec]) == [job_id]
                await app.scheduler.run_batch(max_jobs=4)
                assert len(fixture.wire) == count
                findings = store.findings(policy.engagement_id)
                assert len(findings) == (0 if fixed else 1)
                assert all(f["status"] == "candidate" for f in findings)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class OwnedInteractsh:
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(mode=0o700, parents=True)
        certs = RemoteHTTPSFixture("127.0.0.1", directory / "tls")
        certs.server.server_close()  # only the generated certs; no replacement protocol server
        self.ca_file = certs.ca_file
        self.ports = {}
        for name in ("http", "https", "dns", "smtp", "smtps", "smtp-autotls", "ldap"):
            port = free_port()
            while port in self.ports.values():
                port = free_port()
            self.ports[name] = port
        self.origin = "https://127.0.0.1:" + str(self.ports["https"])
        self.token = secrets.token_hex(24)
        self.token_file = directory / "token.json"
        self.token_file.write_text(json.dumps({"token": self.token}))
        self.token_file.chmod(0o600)
        self.binary = installed("interactsh-server")["binary"]
        self.argv = [
            self.binary["path"],
            "-duc",
            "-d",
            "redjohn-oast.test",
            "-ip",
            "127.0.0.1",
            "-listen-ip",
            "127.0.0.1",
            "-cert",
            str(certs.cert_file),
            "-privkey",
            str(certs.key_file),
            "-token",
            self.token,
            "-resolvers",
            "127.0.0.1:" + str(self.ports["dns"]),
        ]
        for name, port in self.ports.items():
            self.argv += ["-" + name + "-port", str(port)]

    def __enter__(self):
        self.log = (self.directory / "server.log").open("w")
        self.process = subprocess.Popen(  # noqa: S603 - verified pinned owned receiver
            self.argv,
            cwd=self.directory,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(self.directory),
                "GOMEMLIMIT": "128MiB",
                "GOMAXPROCS": "1",
            },
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert self.process.poll() is None, (self.directory / "server.log").read_text()
            try:
                with socket.create_connection(("127.0.0.1", self.ports["https"]), timeout=0.1):
                    return self
            except OSError:
                time.sleep(0.05)
        self.__exit__(None, None, None)
        raise RuntimeError("actual_interactsh_server_start_timeout")

    def config(self, **changes):
        return {
            "receiver_url": self.origin,
            "receiver_ips": ["127.0.0.1"],
            "callback_domain": "redjohn-oast.test",
            "callback_port": self.ports["http"],
            "token_file": str(self.token_file),
            "window_seconds": 3,
            "poll_interval": 1,
            "max_polls": 5,
            **changes,
        }

    def __exit__(self, *_args):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        self.log.close()


@pytest.mark.parametrize("mode", ["positive", "fixed", "late", "auto-late"])
async def test_actual_interactsh_encrypted_http_late_poll_restart_and_controls(tmp_path, mode):  # noqa: PLR0915 - complete lifecycle
    database = tmp_path / "state/agents.db"
    started = time.monotonic()
    with (
        OwnedInteractsh(tmp_path / "receiver") as receiver,
        owned_fixture(
            "127.0.0.1",
            tmp_path / "target",
            receiver=receiver,
            fixed=mode == "fixed",
            late=mode in {"late", "auto-late"},
        ) as fixture,
    ):
        # Distinct temporary authorities, explicitly trust both for this owned lab.
        bundle = tmp_path / "both-ca.pem"
        bundle.write_bytes(fixture.ca_file.read_bytes() + receiver.ca_file.read_bytes())
        fixture.ca_file = bundle
        policy = policy_for(fixture, remote=False)
        config = receiver.config(window_seconds=5, max_polls=7)
        OASTConfig.from_mapping(config)
        with closing(AssessmentStore(database)) as store:
            surface_id, surface = await capture(
                store, policy, fixture, fixture.origin + "/callback?url=benign", "url"
            )
        with closing(AssessmentStore(database)) as store:
            async with runtime(store, policy, fixture, interactsh_config=config) as app:
                spec = make_spec(app, store, policy, surface_id, surface, "interactsh")
                job_id = store.submit(policy, [spec])[0]
                await app.scheduler.run_batch(max_jobs=1)
                row = next(r for r in store.jobs(policy.engagement_id) if r["id"] == job_id)
                measure("interactsh-first-" + mode, row)
                assert row["execution_status"] == "succeeded", row
                assert row["result"]["summary"]["outcome"] in (
                    {"callback_observed", "waiting_for_callback"}
                    if mode == "positive"
                    else {"waiting_for_callback"}
                ), row
                assert len(fixture.callbacks) == 1
        count = len(fixture.wire)
        if mode == "late":
            # Both controller/runtime are closed. The official receiver retains
            # the real callback encrypted for the original private client key.
            fixture.deliver_callback(fixture.callbacks[0])
        with closing(AssessmentStore(database)) as store:
            async with runtime(store, policy, fixture, interactsh_config=config) as app:
                assert store.submit(policy, [spec]) == [job_id]

                async def deliver_later():
                    await asyncio.sleep(1.3)
                    await asyncio.to_thread(fixture.deliver_callback, fixture.callbacks[0])

                delayed = asyncio.create_task(deliver_later()) if mode == "auto-late" else None
                try:
                    await app.scheduler.run_until_idle(max_jobs=8, wait_seconds=8)
                finally:
                    if delayed is not None:
                        await delayed
                rows = store.jobs(policy.engagement_id)
                assert not any(
                    r["execution_status"] in {"queued", "running", "retry_wait"} for r in rows
                )
                assert len(fixture.wire) == count  # no repeated target delivery on resume
                assert all(r["execution_status"] == "succeeded" for r in rows), rows
                observations = [
                    r["result"]["summary"]
                    for r in rows
                    if r["capability"] in {"oast_correlate", "oast_poll"}
                ]
                assert any(
                    s["outcome"]
                    == (
                        "no_callback_observed_in_window" if mode == "fixed" else "callback_observed"
                    )
                    for s in observations
                )
                findings = store.findings(policy.engagement_id)
                assert len(findings) == (0 if mode == "fixed" else 1)
                assert all(f["status"] == "candidate" for f in findings)
                assert app.governor.snapshot()["reserved_bytes"] == 0
                measure(
                    "interactsh-" + mode,
                    {
                        "rows": rows,
                        "elapsed_seconds": time.monotonic() - started,
                        "target_requests": count,
                        "model_calls": 0,
                        "receiver_binary": receiver.binary,
                        "peak_rss_bytes": app.governor.peak_rss_bytes,
                    },
                )
        raw = database.read_bytes() + (
            Path(str(database) + "-wal").read_bytes()
            if Path(str(database) + "-wal").exists()
            else b""
        )
        assert receiver.token.encode() not in raw
        for file in (database.parent / "oast-private").glob("*.json"):
            assert file.stat().st_mode & 0o777 == 0o600
            state = json.loads(file.read_text())
            if state["secret"]:
                assert state["secret"].encode() not in raw
            assert not state["private"] and not state["secret"]
            assert b"PRIVATE KEY" not in raw


@pytest.mark.parametrize("tool", ["tinja", "schemathesis"])
@pytest.mark.parametrize("mode", ["cancel", "timeout"])
async def test_actual_schema_worker_stop_reaps_process_and_keeps_evidence(tmp_path, tool, mode):
    config = installed(tool)
    if tool == "schemathesis":
        config.update(reviewed_schema(tmp_path))
    endpoint, parameter = ("/template?q=benign", "q") if tool == "tinja" else ("/api?id=1", "id")
    with (
        owned_fixture("127.0.0.1", tmp_path / "tls") as fixture,
        closing(AssessmentStore(tmp_path / "state/db")) as store,
    ):
        policy = policy_for(fixture, remote=False)
        sid, surface = await capture(store, policy, fixture, fixture.origin + endpoint, parameter)
        before = len(fixture.wire)
        fixture.slow = True
        async with runtime(store, policy, fixture, **{tool + "_config": config}) as app:
            spec = make_spec(app, store, policy, sid, surface, tool)
            if mode == "timeout":
                spec = replace(spec, timeout_seconds=1.5)
            job_id = store.submit(policy, [spec])[0]
            adapter = app.scheduler.adapters[CAPABILITIES[tool]]
            task = asyncio.create_task(app.scheduler.run_batch(max_jobs=1))
            if mode == "cancel":
                async with asyncio.timeout(12):
                    while adapter.runner.process is None or len(fixture.wire) == before:
                        await asyncio.sleep(0.02)
                process = adapter.runner.process
                store.cancel(policy.engagement_id, job_id)
            await task
            row = next(r for r in store.jobs(policy.engagement_id) if r["id"] == job_id)
            assert row["execution_status"] == ("cancelled" if mode == "cancel" else "timed_out"), (
                row
            )
            assert row["result"]["error"]["partial_evidence_refs"]
            assert not row["result"].get("findings")
            assert adapter.runner.process is None and adapter.runner.workspace is None
            if mode == "cancel":
                assert process.returncode is not None
            assert app.governor.snapshot()["reserved_bytes"] == 0
            assert not store.db.execute("SELECT 1 FROM rj_job WHERE owner IS NOT NULL").fetchall()


@pytest.mark.parametrize("tool", ["tinja", "schemathesis"])
@pytest.mark.parametrize("fault", ["bad-digest", "tls-trust", "limited", "redirect"])
async def test_actual_schema_failure_cannot_be_a_clean_negative(tmp_path, tool, fault):
    config = installed(tool)
    if tool == "schemathesis":
        config.update(reviewed_schema(tmp_path))
    endpoint, parameter = ("/template?q=benign", "q") if tool == "tinja" else ("/api?id=1", "id")
    with (
        owned_fixture("127.0.0.1", tmp_path / "tls") as fixture,
        closing(AssessmentStore(tmp_path / "state/db")) as store,
    ):
        policy = policy_for(fixture, remote=False)
        sid, surface = await capture(store, policy, fixture, fixture.origin + endpoint, parameter)
        fixture.fault = fault
        if fault == "bad-digest":
            config["binary"]["sha256"] = "0" * 64
        app = (
            AssessmentRuntime(store, policy, caller="operator", **{tool + "_config": config})
            if fault == "tls-trust"
            else runtime(store, policy, fixture, **{tool + "_config": config})
        )
        async with app:
            before = len(fixture.wire)
            spec = make_spec(app, store, policy, sid, surface, tool)
            job_id = store.submit(policy, [spec])[0]
            await app.scheduler.run_batch(max_jobs=1)
            row = next(r for r in store.jobs(policy.engagement_id) if r["id"] == job_id)
            assert row["execution_status"] == "failed", row
            assert row["coverage_status"] in {"inconclusive", "blocked"}
            assert row["result"]["summary"].get("outcome") != "no_finding_observed"
            assert not store.findings(policy.engagement_id)
            if fault in {"bad-digest", "tls-trust"}:
                assert len(fixture.wire) == before
            assert app.governor.snapshot()["reserved_bytes"] == 0


@pytest.mark.parametrize("tool", ["tinja", "schemathesis", "interactsh"])
async def test_actual_selected_cli_process_restart_has_no_duplicate_delivery(tmp_path, tool):
    receiver_context = (
        OwnedInteractsh(tmp_path / "receiver") if tool == "interactsh" else nullcontext()
    )
    with (
        receiver_context as receiver,
        owned_fixture(
            "127.0.0.1", tmp_path / "tls", receiver=receiver, late=tool == "interactsh"
        ) as fixture,
    ):
        config = receiver.config(window_seconds=8, max_polls=10) if receiver else installed(tool)
        if tool == "schemathesis":
            config.update(reviewed_schema(tmp_path))
        if receiver:
            bundle = tmp_path / "combined-ca.pem"
            bundle.write_bytes(fixture.ca_file.read_bytes() + receiver.ca_file.read_bytes())
            fixture.ca_file = bundle
        endpoint, parameter = {
            "tinja": ("/template?q=benign", "q"),
            "schemathesis": ("/api?id=1", "id"),
            "interactsh": ("/callback?url=benign", "url"),
        }[tool]
        output = tmp_path / "cli"
        with closing(AssessmentStore(output / ".state/agents.db")) as store:
            policy = policy_for(fixture, remote=False)
            sid, surface = await capture(
                store, policy, fixture, fixture.origin + endpoint, parameter
            )
            async with runtime(store, policy, fixture, **{tool + "_config": config}) as app:
                spec = make_spec(app, store, policy, sid, surface, tool)
        file = tmp_path / "approved-cli.json"
        file.write_text(
            json.dumps(
                {
                    "policy": asdict(policy),
                    "tls": {"upstream_ca_file": str(fixture.ca_file)},
                    "resources": {"total_memory_budget": 1536 * 1024**2, "max_workers": 1},
                    tool: config,
                    "jobs": [
                        {
                            "surface_id": sid,
                            "capability": spec.capability,
                            "hint_ref": spec.options["hint_ref"],
                        }
                    ],
                }
            )
        )

        async def run_cli(max_jobs=1, wait=0):
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "redjohn.assessment",
                "run",
                "--config",
                str(file),
                "--output",
                str(output),
                "--max-jobs",
                str(max_jobs),
                "--wait-ready-seconds",
                str(wait),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=50)
            assert proc.returncode == 0, stderr.decode()
            assert len(stdout) < 65536 and len(stderr) < 65536
            json.loads(stdout)

        await run_cli()
        count = len(fixture.wire)
        if receiver:
            assert len(fixture.callbacks) == 1
            fixture.deliver_callback(fixture.callbacks[0])
            await asyncio.sleep(1.1)
        await run_cli(max_jobs=8 if receiver else 1, wait=8 if receiver else 0)
        assert len(fixture.wire) == count
        with closing(AssessmentStore(output / ".state/agents.db")) as store:
            rows = store.jobs(policy.engagement_id)
            assert all(r["execution_status"] == "succeeded" for r in rows), rows
            assert len(store.findings(policy.engagement_id)) == 1
            assert not any(r["owner"] for r in rows)


@pytest.mark.parametrize("fault", ["wrong-token", "bad-trust", "wrong-ip-pin"])
async def test_actual_oast_receiver_failure_blocks_before_target_delivery(tmp_path, fault):
    with (
        OwnedInteractsh(tmp_path / "receiver") as receiver,
        owned_fixture("127.0.0.1", tmp_path / "target", receiver=receiver) as fixture,
        closing(AssessmentStore(tmp_path / "state/db")) as store,
    ):
        original_ca = fixture.ca_file
        bundle = tmp_path / "both-ca.pem"
        bundle.write_bytes(fixture.ca_file.read_bytes() + receiver.ca_file.read_bytes())
        fixture.ca_file = bundle
        policy = policy_for(fixture, remote=False)
        sid, surface = await capture(
            store, policy, fixture, fixture.origin + "/callback?url=benign", "url"
        )
        config = receiver.config()
        if fault == "wrong-token":
            wrong = tmp_path / "wrong-token.json"
            wrong.write_text(json.dumps({"token": secrets.token_hex(24)}))
            wrong.chmod(0o600)
            config["token_file"] = str(wrong)
        elif fault == "bad-trust":
            fixture.ca_file = original_ca
        else:
            config["receiver_ips"] = ["127.0.0.2"]
        before = len(fixture.wire)
        async with runtime(store, policy, fixture, interactsh_config=config) as app:
            spec = make_spec(app, store, policy, sid, surface, "interactsh")
            job_id = store.submit(policy, [spec])[0]
            await app.scheduler.run_batch(max_jobs=1)
            row = next(r for r in store.jobs(policy.engagement_id) if r["id"] == job_id)
            assert row["execution_status"] == "failed", row
            assert row["coverage_status"] == "blocked", row
            assert len(fixture.wire) == before
            assert not fixture.callbacks and not store.findings(policy.engagement_id)
            assert app.governor.snapshot()["reserved_bytes"] == 0
            assert not any(r["owner"] for r in store.jobs(policy.engagement_id))


async def test_actual_interactsh_draining_poll_process_crash_is_not_a_negative(tmp_path):
    """Actual register, callback and draining poll precede immediate process exit.

    The lease really expires. A fresh CLI process must preserve the unknown
    outcome and checkpoint and never deliver the target URL a second time.
    No mocked receiver, output, SQLite status or clock is used.
    """
    with (
        OwnedInteractsh(tmp_path / "receiver") as receiver,
        owned_fixture("127.0.0.1", tmp_path / "tls", receiver=receiver) as fixture,
    ):
        bundle = tmp_path / "combined-ca.pem"
        bundle.write_bytes(fixture.ca_file.read_bytes() + receiver.ca_file.read_bytes())
        fixture.ca_file = bundle
        output = tmp_path / "cli"
        database = output / ".state/agents.db"
        config = receiver.config(window_seconds=20, max_polls=16, poll_interval=2)
        with closing(AssessmentStore(database)) as store:
            policy = policy_for(fixture, remote=False)
            sid, surface = await capture(
                store, policy, fixture, fixture.origin + "/callback?url=benign", "url"
            )
            async with runtime(store, policy, fixture, interactsh_config=config) as app:
                spec = make_spec(app, store, policy, sid, surface, "interactsh")
        file = tmp_path / "approved-config.json"
        file.write_text(
            json.dumps(
                {
                    "policy": asdict(policy),
                    "tls": {"upstream_ca_file": str(bundle)},
                    "resources": {"total_memory_budget": 1536 * 1024**2, "max_workers": 1},
                    "interactsh": config,
                    "jobs": [
                        {
                            "surface_id": sid,
                            "capability": "oast_correlate",
                            "hint_ref": spec.options["hint_ref"],
                        }
                    ],
                }
            )
        )
        hook = tmp_path / "kill-after-real-poll.py"
        hook.write_text("""import asyncio,os,sys
from pathlib import Path
from urllib.parse import urlsplit
from redjohn.assessment.cli import configured_run,load_config
from redjohn.assessment.oast import OASTAdapter
original=OASTAdapter._request
async def request(self,policy,url,*args,**kwargs):
 result=await original(self,policy,url,*args,**kwargs)
 if urlsplit(url).path=='/poll': os._exit(86)
 return result
OASTAdapter._request=request
asyncio.run(configured_run(load_config(Path(sys.argv[1])),Path(sys.argv[2]),max_jobs=1))
""")
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            str(hook),
            str(file),
            str(output),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)
        assert proc.returncode == 86, stderr.decode()
        assert not stdout
        count = len(fixture.wire)
        assert len(fixture.callbacks) == 1
        with closing(AssessmentStore(database)) as store:
            row = next(
                r for r in store.jobs(policy.engagement_id) if r["capability"] == "oast_correlate"
            )
            assert row["execution_status"] == "running" and row["owner"]
            remaining = row["lease_until"] - time.time()
            assert remaining <= 15
            private = next((database.parent / "oast-private").glob("*.json"))
            state = json.loads(private.read_text())
            assert state["poll_inflight"] is True
        await asyncio.sleep(max(0, remaining) + 0.1)
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "redjohn.assessment",
            "run",
            "--config",
            str(file),
            "--output",
            str(output),
            "--max-jobs",
            "1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)
        assert proc.returncode == 1, (stdout.decode(), stderr.decode())
        with closing(AssessmentStore(database)) as store:
            row = next(
                r for r in store.jobs(policy.engagement_id) if r["capability"] == "oast_correlate"
            )
            assert row["attempt"] == 1
            assert (
                row["execution_status"] == "failed" and row["coverage_status"] == "inconclusive"
            ), row
            assert row["result"]["error"]["code"] == "unknown_execution_outcome"
            assert row["result"]["error"]["partial_evidence_refs"]
            assert not store.findings(policy.engagement_id)
            assert len(fixture.wire) == count and len(fixture.callbacks) == 1
            assert not row["owner"]
            measure(
                "interactsh-real-process-crash",
                {
                    "exit_code": 86,
                    "row": row,
                    "duplicate_target_requests_after_restart": len(fixture.wire) - count,
                    "lease_wait_seconds": max(0, remaining) + 0.1,
                    "model_calls": 0,
                },
            )
