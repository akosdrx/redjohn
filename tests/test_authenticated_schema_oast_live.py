"""Real Chromium -> private POST -> pinned scanners/receiver -> refresh E2Es.

Only disposable owned HTTPS services are used. No fake scanner output, provider
reply, browser capture or callback encryption substitutes for an integration.
"""

import hashlib
import html
import http.client
import json
import os
import secrets
import ssl
import time
from base64 import b64encode
from contextlib import closing, nullcontext, suppress
from dataclasses import replace
from email import policy as email_policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest
from jinja2 import TemplateError
from jinja2.sandbox import SandboxedEnvironment

from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import JobSpec
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from tests.remote_https_fixture import RemoteHTTPSFixture
from tests.test_post_refresh_pipeline import _private_json
from tests.test_schema_oast_live import OwnedInteractsh, installed, reviewed_schema
from tests.test_specialists_live import host_for


MEDIA = {
    "json": "application/json",
    "form": "application/x-www-form-urlencoded",
    "multipart": "multipart/form-data",
}
CAPABILITIES = {
    "tinja": "tinja_validate",
    "schemathesis": "schemathesis_validate",
    "interactsh": "oast_correlate",
}
UPLOAD = b"RedJohn immutable upload\x00\xff\x01"


class OwnedReceiver(OwnedInteractsh):
    def __init__(self, directory, host):
        super().__init__(directory)
        self.host = host
        if host != "127.0.0.1":
            certs = RemoteHTTPSFixture(host, directory / "interface-tls")
            certs.server.server_close()
            self.ca_file = certs.ca_file
            for flag, value in [
                ("-listen-ip", "0.0.0.0"),
                ("-ip", host),
                ("-cert", str(certs.cert_file)),
                ("-privkey", str(certs.key_file)),
            ]:
                self.argv[self.argv.index(flag) + 1] = value
            self.origin = "https://" + host + ":" + str(self.ports["https"])

    def config(self, **changes):
        return {**super().config(**changes), "receiver_ips": [self.host]}


class AuthenticatedInputFixture(RemoteHTTPSFixture):
    def __init__(self, host, directory, tool, kind, *, fixed=False, receiver=None):
        super().__init__(host, directory)
        self.tool, self.kind, self.fixed, self.receiver = tool, kind, fixed, receiver
        self.sessions = {r: secrets.token_urlsafe(24) for r in ("7", "8")}
        self.csrf = {r: secrets.token_urlsafe(24) for r in ("7", "8")}
        self.refresh_secret, self.private_value = (
            secrets.token_urlsafe(24),
            secrets.token_urlsafe(24),
        )
        self.revision, self.fault = "7", ""
        self.late = False
        self.posts, self.callbacks = [], []
        fixture = self
        engine = SandboxedEnvironment()

        class Handler(BaseHTTPRequestHandler):
            def reply(self, code, data, content_type="text/plain"):
                raw = data.encode() if isinstance(data, str) else data
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header(
                    "Content-Length",
                    str(len(raw) + (50 if fixture.fault == "truncated401" and code == 401 else 0)),
                )
                if code == 429:
                    self.send_header("Retry-After", "30")
                self.end_headers()
                with suppress(BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                    self.wfile.write(raw)
                self.close_connection = True

            def authorized(self):
                r = fixture.revision
                return (
                    self.headers.get("Authorization") == "Bearer " + fixture.sessions[r]
                    and self.headers.get("Cookie") == "fixture_session=" + fixture.sessions[r]
                    and self.headers.get("X-CSRF-Token") == fixture.csrf[r]
                )

            def do_GET(self):
                if self.path != "/start" or not self.authorized():
                    self.reply(401, "owned actor required")
                    return
                fields = {
                    "value": 1 if tool == "schemathesis" else "benign",
                    "csrf": fixture.csrf[fixture.revision],
                    "private": fixture.private_value,
                }
                javascript = (
                    "const fields="
                    + json.dumps(fields)
                    + ";let body;const headers={'X-CSRF-Token':fields.csrf};"
                )
                if kind == "json":
                    javascript += (
                        "body=JSON.stringify(fields);headers['Content-Type']='application/json';"
                    )
                elif kind == "form":
                    javascript += (
                        "body=new URLSearchParams(fields).toString();"
                        "headers['Content-Type']='application/x-www-form-urlencoded';"
                    )
                else:
                    javascript += (
                        "body=new FormData();"
                        "for(const [k,v] of Object.entries(fields))body.append(k,v);"
                        "body.append('upload',new Blob([new Uint8Array("
                        + json.dumps(list(UPLOAD))
                        + ")],{type:'application/octet-stream'}),'fixture.bin');"
                    )
                javascript += (
                    "fetch('/input',{method:'POST',credentials:'same-origin',headers,body})"
                    ".then(r=>r.text()).then(()=>document.body.dataset.ready='yes');"
                )
                self.reply(
                    200,
                    '<!doctype html><html><head><link rel="icon" href="data:,"></head>'
                    "<body>Owned RedJohn input<script>" + javascript + "</script></body></html>",
                    "text/html",
                )

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path == "/refresh":
                    valid = (
                        self.headers.get("Authorization") == "Bearer " + fixture.refresh_secret
                        and body == b'{"refresh":true}'
                    )
                    fixture.posts.append(
                        {"path": self.path, "valid": valid, "revision": fixture.revision}
                    )
                    if not valid:
                        self.reply(401, "refresh denied")
                        return
                    fixture.revision, fixture.fault = "8", ""
                    self.reply(
                        200,
                        json.dumps(
                            {
                                "headers": fixture.auth_headers("8"),
                                "cookies": [
                                    {"name": "fixture_session", "value": fixture.sessions["8"]}
                                ],
                                "expires_at": time.time() + 600,
                            }
                        ),
                        "application/json",
                    )
                    return
                if self.path != "/input":
                    self.reply(404, "unselected route")
                    return
                content_type = self.headers.get("Content-Type", "")
                fields = fixture.fields(body, content_type)
                valid = (
                    self.authorized()
                    and content_type.partition(";")[0] == MEDIA[kind]
                    and fields.get("csrf") == fixture.csrf[fixture.revision]
                    and fields.get("private") == fixture.private_value
                )
                if kind == "multipart":
                    valid &= (
                        fields.get("upload") == UPLOAD and fields.get("filename") == "fixture.bin"
                    )
                fixture.posts.append(
                    {
                        "path": self.path,
                        "valid": valid,
                        "revision": fixture.revision,
                        "body": body,
                        "content_type": content_type,
                        "value": fields.get("value"),
                    }
                )
                if not valid or fixture.fault in {"401", "truncated401"}:
                    self.reply(401, "actor expired")
                    return
                if fixture.fault in {"403", "429"}:
                    self.reply(int(fixture.fault), "owned rejecting control")
                    return
                value = fields["value"]
                if tool == "schemathesis":
                    self.reply(
                        200,
                        json.dumps({"id": int(value) if fixed else str(value)}),
                        "application/json",
                    )
                elif tool == "tinja":
                    try:
                        rendered = (
                            html.escape(str(value))
                            if fixed
                            else engine.from_string(str(value)).render()
                        )
                        self.reply(
                            200,
                            "<html><body><pre>template:" + rendered + "</pre></body></html>",
                            "text/html",
                        )
                    except TemplateError:
                        self.reply(500, "owned template error")
                else:
                    if str(value).startswith("http://"):
                        fixture.callbacks.append(value)
                        if not fixed and not fixture.late:
                            fixture.deliver_callback(value)
                    self.reply(200, "owned callback control")

            def log_message(self, *_args):
                pass

        self.server.RequestHandlerClass = Handler

    def auth_headers(self, revision):
        return {
            "Authorization": "Bearer " + self.sessions[revision],
            "X-CSRF-Token": self.csrf[revision],
        }

    def fields(self, body, content_type):
        if self.kind == "json":
            return json.loads(body)
        if self.kind == "form":
            return dict(parse_qsl(body.decode(), keep_blank_values=True))
        message = BytesParser(policy=email_policy.default).parsebytes(
            ("Content-Type: " + content_type + "\r\n\r\n").encode() + body
        )
        parts = list(message.iter_parts())
        assert [p.get_param("name", header="content-disposition") for p in parts] == [
            "value",
            "csrf",
            "private",
            "upload",
        ]
        result = {
            p.get_param("name", header="content-disposition"): p.get_payload(decode=True).decode()
            for p in parts[:-1]
        }
        result.update(upload=parts[-1].get_payload(decode=True), filename=parts[-1].get_filename())
        return result

    def deliver_callback(self, url):
        parsed = urlsplit(url)
        assert self.receiver is not None and parsed.hostname.endswith(".redjohn-oast.test")
        assert parsed.scheme == "http" and parsed.port == self.receiver.ports["http"]
        connection = http.client.HTTPConnection(self.host, parsed.port, timeout=3)
        try:
            connection.request("GET", parsed.path, headers={"Host": parsed.netloc})
            reply = connection.getresponse()
            assert reply.status == 200
            reply.read(65536)
        finally:
            connection.close()


def configuration(tmp_path, fixture, remote, *, recovery=False):
    tool, kind = fixture.tool, fixture.kind
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    vault, provider, capture = (
        private / n for n in ("vault.json", "provider.json", "capture.json")
    )
    policy = EngagementPolicy(
        "authenticated-schema-oast",
        "operator",
        (fixture.origin,),
        allowed_ips=(fixture.host + "/32",),
        actor_ids=("anonymous", "alice", "bob"),
        profile="isolated-lab",
        egress_mode="enforced" if remote else "local-fixture",
        allowed_replay_urls=(fixture.origin + "/input",),
        allowed_refresh_urls=(fixture.origin + "/refresh",),
        request_budget=512,
        deadline=time.time() + 240,
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
                    "expires_at": time.time() + 600,
                    "headers": fixture.auth_headers("7"),
                    "cookies": [{"name": "fixture_session", "value": fixture.sessions["7"]}],
                    "allowed_requests": [
                        {
                            "url": fixture.origin + "/start",
                            "method": "GET",
                            "request_ref": "approved-start",
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
                    "body_base64": b64encode(b'{"refresh":true}').decode(),
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
                    "url": fixture.origin + "/input",
                    "content_type": MEDIA[kind],
                    "expires_at": time.time() + 600,
                    "automatic_approval": True,
                    "start_url": fixture.origin + "/start",
                    "body_tokens": [
                        {
                            "location": kind,
                            "selector": "/csrf" if kind == "json" else "csrf",
                            "occurrence": 0,
                            "source": {"kind": "header", "name": "X-CSRF-Token"},
                        }
                    ],
                }
            ],
        },
    )
    tls = tmp_path / "trust.pem"
    tls.write_bytes(
        fixture.ca_file.read_bytes()
        + (fixture.receiver.ca_file.read_bytes() if fixture.receiver else b"")
    )
    config = {
        "caller": "operator",
        "envelope": ResourceEnvelope(total_memory_budget=3 * 1024**3, max_workers=1),
        "browser_limits": BrowserLimits(
            max_pages=1,
            max_requests=8,
            readiness_selector="body[data-ready='yes']",
            readiness_timeout_ms=5000,
            observation_window_ms=100,
            total_timeout_seconds=20,
        ),
        "browser_tls": BrowserTLSConfig(upstream_ca_file=tls),
        "auth_vault_file": vault,
        "refresh_provider_file": provider,
        "browser_capture_file": capture,
        "continuous_replay": {
            "version": 1,
            "rules": [],
            "adapter_rules": [
                {
                    "actor_id": "alice",
                    "tenant_id": "tenant-a",
                    "url": fixture.origin + "/input",
                    "content_type": MEDIA[kind],
                    "capability": CAPABILITIES[tool],
                    "input_location": kind,
                    "input_name": "/value" if kind == "json" else "value",
                }
            ],
        },
    }
    if recovery:
        config["continuous_replay"]["session_recovery"] = {
            "max_refreshes": 1,
            "cooldown_seconds": 0,
        }
    if tool == "interactsh":
        config["interactsh_config"] = fixture.receiver.config()
    else:
        config[tool + "_config"] = installed(tool)
        if tool == "schemathesis":
            schema = reviewed_schema(tmp_path, "/input")
            path = Path(schema["schema_file"])
            data = json.loads(path.read_text())
            operation = data["paths"]["/input"].pop("get")
            domain = operation.pop("parameters")[0]["schema"]
            operation["requestBody"] = {
                "required": True,
                "content": {
                    MEDIA[kind]: {
                        "schema": {
                            "type": "object",
                            "properties": {"value": domain},
                            "required": ["value"],
                            "additionalProperties": False,
                        }
                    }
                },
            }
            data["paths"]["/input"]["post"] = operation
            path.write_text(json.dumps(data))
            schema["schema_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            config[tool + "_config"].update(schema)
    return policy, config


def publish_measurement(name, payload):
    value = os.environ.get("REDJOHN_AUTH_SCHEMA_MEASUREMENTS")
    if value:
        directory = Path(value).parent
        directory.mkdir(parents=True, exist_ok=True)
        (directory / (name + ".json")).write_text(json.dumps(payload, indent=2) + "\n")


def assert_private_and_clean(store, fixture, app):
    assert all(p["valid"] for p in fixture.posts)
    sensitive = [
        fixture.private_value,
        fixture.refresh_secret,
        *fixture.sessions.values(),
        *fixture.csrf.values(),
    ]
    payload = "\n".join(
        json.dumps(dict(r), default=str)
        for table in ["rj_evidence", "rj_surface", "rj_job"]
        for r in store.db.execute("SELECT * FROM " + table)  # noqa: S608 - closed table whitelist
    )
    assert all(s not in payload for s in sensitive)
    assert not app.scheduler._active
    assert app.browser.healthcheck()["active_contexts"] == 0
    assert (
        store.db.execute("SELECT count(*) FROM rj_job WHERE owner IS NOT NULL").fetchone()[0] == 0
    )


@pytest.mark.parametrize("remote", [False, True], ids=["loopback", "remote"])
@pytest.mark.parametrize("fixed", [False, True], ids=["positive", "fixed"])
@pytest.mark.parametrize("kind", list(MEDIA))
@pytest.mark.parametrize("tool", list(CAPABILITIES))
async def test_actual_authenticated_post_formats_and_durable_restart(
    tmp_path, tool, kind, fixed, remote
):
    host, started = host_for(remote), time.monotonic()
    with (
        (
            OwnedReceiver(tmp_path / "receiver", host)
            if tool == "interactsh"
            else nullcontext(None)
        ) as receiver,
        AuthenticatedInputFixture(
            host, tmp_path / "target", tool, kind, fixed=fixed, receiver=receiver
        ) as fixture,
    ):
        policy, config = configuration(tmp_path, fixture, remote)
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(store, policy, **config) as app:
                assert len(await app.scheduler.run_batch(max_jobs=1)) == 1
                rows = store.jobs(policy.engagement_id, limit=100)
                capture = next(r for r in rows if r["capability"] == "browser_post_capture")
                assert capture["execution_status"] == "succeeded", capture
                assert sum(r["capability"] == CAPABILITIES[tool] for r in rows) == 1, rows
            # Actual controller/runtime close; SQLite, private body and queued
            # selected job are reopened rather than reconstructed from a mock.
            async with AssessmentRuntime(store, policy, **config) as app:
                await app.scheduler.run_until_idle(max_jobs=12, wait_seconds=8)
                rows = store.jobs(policy.engagement_id, limit=100)
                jobs = [r for r in rows if r["capability"] in {CAPABILITIES[tool], "oast_poll"}]
                assert jobs and all(r["execution_status"] == "succeeded" for r in jobs), jobs
                outcomes = [r["result"]["summary"].get("outcome") for r in jobs]
                assert ("candidate" in outcomes or "callback_observed" in outcomes) is not fixed, (
                    jobs
                )
                if fixed:
                    assert (
                        "no_callback_observed_in_window"
                        if tool == "interactsh"
                        else "no_finding_observed"
                    ) in outcomes
                before = len(fixture.posts)
                await app.scheduler.run_until_idle(max_jobs=12, wait_seconds=0)
                assert len(fixture.posts) == before
                if tool == "interactsh":
                    assert len(fixture.callbacks) == 1
                elif remote:
                    assert jobs[0]["result"]["summary"]["egress_attestations"]
                assert_private_and_clean(store, fixture, app)
                publish_measurement(
                    f"auth-{tool}-{kind}-"
                    f"{'fixed' if fixed else 'positive'}-{'remote' if remote else 'loopback'}",
                    {
                        "elapsed_seconds": time.monotonic() - started,
                        "target_posts": len(fixture.posts),
                        "duplicate_resume_requests": 0,
                        "model_calls": 0,
                        "jobs": jobs,
                    },
                )


@pytest.mark.parametrize("tool", list(CAPABILITIES))
@pytest.mark.parametrize("kind", list(MEDIA))
async def test_actual_refresh_recapture_and_adapter_in_same_scheduler(tmp_path, tool, kind):
    started = time.monotonic()
    with (
        (
            OwnedReceiver(tmp_path / "receiver", "127.0.0.1")
            if tool == "interactsh"
            else nullcontext(None)
        ) as receiver,
        AuthenticatedInputFixture(
            "127.0.0.1", tmp_path / "target", tool, kind, receiver=receiver
        ) as fixture,
    ):
        policy, config = configuration(tmp_path, fixture, remote=False, recovery=True)
        with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
            async with AssessmentRuntime(store, policy, **config) as app:
                await app.scheduler.run_batch(max_jobs=1)
                old = next(
                    r
                    for r in store.jobs(policy.engagement_id, limit=100)
                    if r["capability"] == CAPABILITIES[tool]
                )
                old_spec = JobSpec(**old["spec"])
                if kind == "json":
                    fixture.fault = "401"
                elif kind == "form":
                    vault = Path(config["auth_vault_file"])
                    data = json.loads(vault.read_text())
                    for entry in data["entries"]:
                        entry["expires_at"] = time.time() - 1
                    _private_json(vault, data)
                else:
                    capture = next(
                        r
                        for r in store.jobs(policy.engagement_id, limit=100)
                        if r["capability"] == "browser_post_capture"
                    )
                    refresh = JobSpec(
                        capture["surface_id"],
                        "authentication",
                        "session_refresh",
                        idempotent=False,
                        timeout_seconds=30,
                    )
                    store.submit(policy, [refresh])
                pid = os.getpid()
                await app.scheduler.run_until_idle(max_jobs=20, wait_seconds=8)
                assert os.getpid() == pid
                rows = store.jobs(policy.engagement_id, limit=100)
                refreshes = [r for r in rows if r["capability"] == "session_refresh"]
                assert len(refreshes) == 1 and refreshes[0]["execution_status"] == "succeeded", rows
                fresh = [
                    r
                    for r in rows
                    if r["capability"] == CAPABILITIES[tool]
                    and store.surface(policy.engagement_id, r["surface_id"]).session_revision == "8"
                ]
                assert len(fresh) == 1 and fresh[0]["execution_status"] == "succeeded", rows
                if kind != "multipart":
                    original = next(r for r in rows if r["id"] == old["id"])
                    assert (
                        original["execution_status"] == "failed"
                        and original["coverage_status"] == "blocked"
                    )
                    assert original["attempt"] == 1
                count = len(fixture.posts)
                # Explicit stale-revision retest gets a separate blocked job;
                # neither old private bytes nor an old 401 POST are resent.
                stale = store.submit(
                    policy, [replace(old_spec, retest_revision="stale-session-control")]
                )[0]
                await app.scheduler.run_batch(max_jobs=1)
                stale_row = next(
                    r for r in store.jobs(policy.engagement_id, limit=100) if r["id"] == stale
                )
                assert stale_row["execution_status"] == "failed", stale_row
                assert len(fixture.posts) == count
                assert sum(p["path"] == "/refresh" for p in fixture.posts) == 1
                assert_private_and_clean(store, fixture, app)
                publish_measurement(
                    f"refresh-{tool}-{kind}",
                    {
                        "elapsed_seconds": time.monotonic() - started,
                        "target_posts": len(fixture.posts),
                        "refresh_count": 1,
                        "duplicate_stale_requests": 0,
                        "new_session_revision": "8",
                        "model_calls": 0,
                        "jobs": rows,
                    },
                )
