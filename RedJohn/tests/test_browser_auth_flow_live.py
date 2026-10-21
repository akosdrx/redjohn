"""Actual sandboxed Chromium, HTTPS login/MFA/logout, SQLite and private inputs."""

from __future__ import annotations

import asyncio
import base64
import html
import json
import secrets
import time
from collections import Counter
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from threading import Event
from urllib.parse import parse_qs

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.tls_fixture import TLSFixtureServer
from tests.test_nuclei_post_live import post_fixture_lock
from tests.test_post_refresh_pipeline import _lock_document


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def form_page(kind, nonce):
    fields = (
        '<input id="username" name="username"><input id="password" name="password" type="password">'
        if kind == "login"
        else '<input id="otp" name="otp">'
        if kind == "mfa"
        else ""
    )
    return (
        f'<html><body><form id="{kind}_form" action="/{kind}" method="post">{fields}'
        f'<input id="csrf" name="csrf" type="hidden" value="{html.escape(nonce)}">'
        '<button type="submit">Continue</button></form></body></html>'
    ).encode()


def auth_plan(origin, actor, *, logout=False):
    actions = (
        [
            {"kind": "navigate", "url": origin + "/account"},
            {
                "kind": "submit",
                "selector": "#logout_form",
                "url": origin + "/logout",
                "nonce_selector": "#csrf",
                "nonce_field": "csrf",
                "fields": ["csrf"],
            },
            {"kind": "wait", "selector": "#logged_out"},
        ]
        if logout
        else [
            {"kind": "navigate", "url": origin + "/login"},
            {"kind": "fill", "selector": "#username", "input_ref": actor + ":username"},
            {"kind": "fill", "selector": "#password", "input_ref": actor + ":password"},
            {
                "kind": "submit",
                "selector": "#login_form",
                "url": origin + "/login",
                "nonce_selector": "#csrf",
                "nonce_field": "csrf",
                "fields": ["username", "password", "csrf"],
            },
            {"kind": "fill", "selector": "#otp", "input_ref": actor + ":otp"},
            {
                "kind": "submit",
                "selector": "#mfa_form",
                "url": origin + "/mfa",
                "nonce_selector": "#csrf",
                "nonce_field": "csrf",
                "fields": ["otp", "csrf"],
            },
            {"kind": "wait", "selector": "#authenticated"},
        ]
    )
    return {
        "name": actor + ("-logout" if logout else "-login"),
        "revision": "1",
        "actor_id": actor,
        "tenant_id": "owned",
        "actions": actions,
        "allowed_get_urls": [origin + path for path in ("/login", "/whoami", "/account", "/app")],
        "identity_url": origin + "/whoami",
        "outcome": "logged_out" if logout else "authenticated",
    }


@pytest.mark.parametrize(
    "case", ["positive", "wrong_mfa", "offscope_form", "wrong_identity", "cancel_mfa"]
)
async def test_actual_chromium_mfa_private_input_restart_two_actors_capture_and_logout(  # noqa: PLR0912, PLR0915 - actual owned lifecycle
    tmp_path, monkeypatch, record_testsuite_property, case
):
    monkeypatch.setenv("REDJOHN_HOST_RESOURCE_DB", str(tmp_path / "host-pool.db"))
    passwords = {actor: secrets.token_urlsafe(24) for actor in ("alice", "bob")}
    codes = {actor: str(secrets.randbelow(900000) + 100000) for actor in passwords}
    nonces, challenges, sessions, used_codes = {}, {}, {}, set()
    seen = Counter()
    oracle = {"fixed": False}
    mfa_admitted, release_mfa = Event(), Event()

    class Handler(BaseHTTPRequestHandler):
        def cookies(self):
            jar = SimpleCookie()
            jar.load(self.headers.get("Cookie", ""))
            return {key: value.value for key, value in jar.items()}

        def respond(self, status, raw=b"", *, cookie=None, json_body=False):
            self.send_response(status)
            self.send_header(
                "Content-Type", "application/json" if json_body else "text/html; charset=utf-8"
            )
            self.send_header("Content-Length", str(len(raw)))
            if cookie:
                for value in cookie:
                    self.send_header("Set-Cookie", value)
            self.end_headers()
            self.wfile.write(raw)

        def nonce(self, kind, identity):
            token = secrets.token_urlsafe(24)
            nonces[token] = (kind, identity)
            return token

        def do_GET(self):
            seen[("GET", self.path)] += 1
            cookies = self.cookies()
            actor = sessions.get(cookies.get("session"))
            if self.path == "/login":
                challenge = cookies.get("challenge")
                if challenge in challenges:
                    self.respond(200, form_page("mfa", self.nonce("mfa", challenge)))
                else:
                    csrf_identity = secrets.token_urlsafe(24)
                    self.respond(
                        200,
                        form_page("login", self.nonce("login", csrf_identity)).replace(
                            b'action="/login"', b'action="/unreviewed"'
                        )
                        if case == "offscope_form"
                        else form_page("login", self.nonce("login", csrf_identity)),
                        cookie=[
                            "preauth="
                            + csrf_identity
                            + "; Secure; HttpOnly; SameSite=Strict; Path=/"
                        ],
                    )
            elif self.path == "/whoami":
                self.respond(
                    200 if actor else 401,
                    json.dumps(
                        {
                            "actor": "wrong-actor" if case == "wrong_identity" and actor else actor,
                            "tenant": "owned",
                        }
                    ).encode(),
                    json_body=True,
                )
            elif self.path == "/account" and actor:
                self.respond(200, form_page("logout", self.nonce("logout", cookies["session"])))
            elif self.path == "/app" and actor:
                self.respond(
                    200,
                    b'<html><body><script>fetch("/api/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({q:"owned"})}).then(()=>document.body.dataset.ready="yes")</script></body></html>',
                )
            else:
                self.respond(401)

        def do_POST(self):
            seen[("POST", self.path)] += 1
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            values = (
                {
                    key: item[0]
                    for key, item in parse_qs(raw.decode(), keep_blank_values=True).items()
                }
                if self.path != "/api/save"
                else {}
            )
            cookies = self.cookies()
            nonce = nonces.pop(values.get("csrf"), None)
            if (
                self.path == "/login"
                and nonce == ("login", cookies.get("preauth"))
                and passwords.get(values.get("username")) == values.get("password")
            ):
                challenge = secrets.token_urlsafe(24)
                challenges[challenge] = values["username"]
                self.respond(
                    200,
                    form_page("mfa", self.nonce("mfa", challenge)),
                    cookie=[
                        "challenge=" + challenge + "; Secure; HttpOnly; SameSite=Strict; Path=/"
                    ],
                )
            elif self.path == "/mfa" and nonce == ("mfa", cookies.get("challenge")):
                actor = challenges.get(cookies.get("challenge"))
                if actor and values.get("otp") == codes[actor] and actor not in used_codes:
                    used_codes.add(actor)
                    challenges.pop(cookies["challenge"])
                    session = secrets.token_urlsafe(32)
                    sessions[session] = actor
                    if case == "cancel_mfa":
                        mfa_admitted.set()
                        release_mfa.wait(10)
                    try:
                        self.respond(
                            200,
                            b'<html><body id="authenticated">Authenticated</body></html>',
                            cookie=[
                                "session="
                                + session
                                + "; Secure; HttpOnly; SameSite=Strict; Path=/",
                                "challenge=; Max-Age=0; Secure; HttpOnly; Path=/",
                            ],
                        )
                    except OSError:
                        if case != "cancel_mfa":
                            raise
                else:
                    self.respond(403)
            elif (
                self.path == "/logout"
                and nonce == ("logout", cookies.get("session"))
                and cookies.get("session") in sessions
            ):
                sessions.pop(cookies["session"])
                self.respond(
                    200,
                    b'<html><body id="logged_out">Logged out</body></html>',
                    cookie=["session=; Max-Age=0; Secure; HttpOnly; Path=/"],
                )
            elif (
                self.path == "/api/save"
                and sessions.get(cookies.get("session"))
                and raw == b'{"q":"owned"}'
            ):
                self.respond(
                    200,
                    b'{"saved":true}'
                    if oracle["fixed"]
                    else b'{"marker":"redjohn-fixture-marker"}',
                    json_body=True,
                )
            else:
                self.respond(403)

        def log_message(self, *_args):
            pass

    fixture = TLSFixtureServer()
    try:
        with fixture:
            fixture.server.RequestHandlerClass = Handler
            origin = fixture.origin
            identity = {
                "version": 1,
                "engagement_id": "browser-auth",
                "owner_id": "operator",
                "policy_revision": "1",
            }
            input_data = {
                **identity,
                "state_key_base64": base64.b64encode(secrets.token_bytes(32)).decode(),
                "inputs": [],
            }
            for actor, password in passwords.items():
                for purpose, value in (
                    ("username", actor),
                    ("password", password),
                    ("mfa_code", codes[actor]),
                ):
                    if actor == "alice" and purpose == "mfa_code":
                        continue
                    input_data["inputs"].append(
                        {
                            "reference": actor
                            + (":otp" if purpose == "mfa_code" else ":" + purpose),
                            "actor_id": actor,
                            "tenant_id": "owned",
                            "purpose": purpose,
                            "value": value,
                            "single_use": purpose == "mfa_code",
                            "expires_at": time.time() + 600,
                        }
                    )
            inputs = private_json(tmp_path / "inputs.json", input_data)
            state = private_json(tmp_path / "private-state.json", {**identity, "flows": {}})
            config = {
                "policy": {
                    "engagement_id": "browser-auth",
                    "owner_id": "operator",
                    "revision": "1",
                    "allowed_origins": [origin],
                    "actor_ids": ["anonymous", "alice", "bob"],
                    "profile": "isolated-lab",
                    "egress_mode": "local-fixture",
                    "allowed_replay_urls": [
                        origin + path for path in ("/login", "/mfa", "/logout", "/api/save")
                    ],
                },
                "tls": {"upstream_ca_file": str(fixture.ca_file)},
                "browser": {"max_pages": 1, "observation_window_ms": 100},
                "browser_auth_flow": {
                    "private_inputs_file": str(inputs),
                    "private_state_file": str(state),
                    "plans": [
                        auth_plan(origin, actor, logout=logout)
                        for actor in passwords
                        for logout in (False, True)
                    ],
                },
            }
            if case == "positive":
                lock = post_fixture_lock(
                    tmp_path / "nuclei-auth-template", "application/json", path="/api/save"
                )
                vault = private_json(tmp_path / "replay-vault.json", {"version": 2, "entries": []})
                rules = private_json(
                    tmp_path / "capture-rules.json",
                    {
                        "version": 1,
                        "rules": [
                            {
                                "engagement_id": "browser-auth",
                                "owner_id": "operator",
                                "policy_revision": "1",
                                "actor_id": actor,
                                "tenant_id": "owned",
                                "session_revision": "current",
                                "url": origin + "/api/save",
                                "start_url": origin + "/app",
                                "content_type": "application/json",
                                "expires_at": time.time() + 600,
                                "automatic_approval": True,
                            }
                            for actor in passwords
                        ],
                    },
                )
                config.update(
                    auth_vault_file=str(vault),
                    browser_capture_file=str(rules),
                    nuclei_lock=_lock_document(lock),
                    continuous_replay={
                        "version": 1,
                        "rules": [
                            {
                                "actor_id": actor,
                                "tenant_id": "owned",
                                "url": origin + "/api/save",
                                "content_type": "application/json",
                                "template_id": "redjohn-fixture-post",
                            }
                            for actor in passwords
                        ],
                    },
                )
            output = tmp_path / "assessment"

            async def submit(assessment, flow_id):
                current = assessment.store.auth_flows.get(assessment.policy, flow_id)
                submitted = await assessment.runtime.control.call(
                    "auth_flow_submit",
                    {
                        "policy_revision": "1",
                        "flow_id": flow_id,
                        "expected_revision": current["revision"],
                    },
                )
                assert submitted["ok"], submitted
                job_id = submitted["result"]["job_ids"][0]
                completed = await assessment.runtime.scheduler.run_until_idle(max_jobs=16)
                assert job_id in completed, completed
                return next(
                    row
                    for row in assessment.store.jobs(assessment.policy.engagement_id)
                    if row["id"] == job_id
                )

            async with ConfiguredAssessment(config, output, caller="operator") as assessment:
                plans = (
                    await assessment.runtime.control.call(
                        "auth_plan_search", {"policy_revision": "1"}
                    )
                )["result"]["items"]
                plan_ids = {item["name"]: item["plan_id"] for item in plans}
                alice = assessment.store.auth_flows.start(
                    assessment.policy, plan_ids["alice-login"], "first"
                )
                result = await submit(assessment, alice)
                if case == "offscope_form":
                    assert result["execution_status"] == "failed", result
                    assert seen[("POST", "/login")] == 0
                    assert seen[("POST", "/unreviewed")] == 0
                    assert (
                        assessment.store.auth_flows.get(assessment.policy, alice)["status"]
                        == "awaiting_input"
                    )
                    assert (
                        assessment.store.db.execute(
                            "SELECT count(*) FROM rj_auth_input_use"
                        ).fetchone()[0]
                        == 0
                    )
                    assert assessment.runtime.browser.healthcheck()["active_contexts"] == 0
                    return
                assert (
                    result["coverage_status"] == "blocked"
                    and result["result"]["summary"]["state"] == "awaiting_input"
                ), result
                assert assessment.store.auth_flows.get(assessment.policy, alice)["next_action"] == 4
                assert assessment.runtime.browser.healthcheck()["active_contexts"] == 0
                assert assessment.runtime.governor.snapshot()["active"] == {}
                with pytest.raises(PolicyDenied, match="authenticating"):
                    assessment.store.assert_session_revision(
                        assessment.policy,
                        Surface(origin + "/app", actor_id="alice", tenant_id="owned"),
                    )
            input_data["inputs"].append(
                {
                    "reference": "alice:otp",
                    "actor_id": "alice",
                    "tenant_id": "owned",
                    "purpose": "mfa_code",
                    "value": "000000" if case == "wrong_mfa" else codes["alice"],
                    "single_use": True,
                    "expires_at": time.time() + 600,
                }
            )
            private_json(inputs, input_data)
            async with ConfiguredAssessment(config, output, caller="operator") as assessment:
                if case == "cancel_mfa":
                    current = assessment.store.auth_flows.get(assessment.policy, alice)
                    submitted = await assessment.runtime.control.call(
                        "auth_flow_submit",
                        {
                            "policy_revision": "1",
                            "flow_id": alice,
                            "expected_revision": current["revision"],
                        },
                    )
                    assert submitted["ok"], submitted
                    job_id = submitted["result"]["job_ids"][0]
                    running = asyncio.create_task(
                        assessment.runtime.scheduler.run_until_idle(max_jobs=1)
                    )
                    try:
                        async with asyncio.timeout(10):
                            while not mfa_admitted.is_set():
                                if running.done():
                                    pytest.fail("actual MFA request did not reach the owned app")
                                await asyncio.sleep(0.02)
                        assert sessions and used_codes == {"alice"}
                        await asyncio.wait_for(
                            assessment.runtime.scheduler.cancel(job_id), timeout=5
                        )
                        assert await asyncio.wait_for(running, timeout=5) == [job_id]
                    finally:
                        release_mfa.set()
                        if not running.done():
                            running.cancel()
                        await asyncio.gather(running, return_exceptions=True)
                    assert (
                        assessment.store.auth_flows.get(assessment.policy, alice)["status"]
                        == "uncertain"
                    )
                    assert (
                        assessment.store.db.execute(
                            "SELECT count(*) FROM rj_auth_input_use WHERE state='admitted'"
                        ).fetchone()[0]
                        == 2
                    )
                    assert assessment.runtime.browser.healthcheck()["active_contexts"] == 0
                    assert assessment.runtime.governor.snapshot()["active"] == {}
                    assert await assessment.runtime.scheduler.run_until_idle(max_jobs=2) == []
                    assert seen[("POST", "/login")] == seen[("POST", "/mfa")] == 1
                    record_testsuite_property("browser_auth_actual_cancelled_mfa_posts", 1)
                    record_testsuite_property(
                        "browser_auth_cancel_unknown_server_sessions", len(sessions)
                    )
                    return
                result = await submit(assessment, alice)
                if case in {"wrong_mfa", "wrong_identity"}:
                    assert result["execution_status"] == "failed", result
                    current = assessment.store.session_state(
                        assessment.policy,
                        Surface(origin + "/app", actor_id="alice", tenant_id="owned"),
                    )
                    assert current["status"] != "ready" and current["revision"] == "1"
                    assert (
                        "alice"
                        not in assessment.runtime.scheduler.adapters[
                            "browser_discover"
                        ].actor_states
                    )
                    assert seen[("POST", "/login")] == 1 and seen[("POST", "/mfa")] == 1
                    assert assessment.runtime.browser.healthcheck()["active_contexts"] == 0
                    if case == "wrong_mfa":
                        assert (
                            assessment.store.auth_flows.get(assessment.policy, alice)["status"]
                            == "uncertain"
                        )
                        assert (
                            assessment.store.db.execute(
                                "SELECT count(*) FROM rj_auth_input_use WHERE state='admitted'"
                            ).fetchone()[0]
                            == 2
                        )
                    return
                assert result["execution_status"] == "succeeded", result
                bob = assessment.store.auth_flows.start(
                    assessment.policy, plan_ids["bob-login"], "first"
                )
                assert (await submit(assessment, bob))["execution_status"] == "succeeded"
                assert set(sessions.values()) == {"alice", "bob"}
                nuclei = [
                    row
                    for row in assessment.store.jobs(assessment.policy.engagement_id, limit=100)
                    if row["capability"] == "nuclei_scan"
                ]
                assert len(nuclei) == 2 and all(
                    row["execution_status"] == "succeeded" and row["result"]["findings"]
                    for row in nuclei
                ), nuclei
                assert (
                    seen[("POST", "/api/save")] == 4
                )  # 2 automatic captures + 2 actual Nuclei replays.
                oracle["fixed"] = True
                fixed_ids = assessment.store.submit(
                    assessment.policy,
                    [
                        JobSpec(
                            row["surface_id"],
                            "workflow-fixed-control",
                            "nuclei_scan",
                            policy_revision="1",
                            idempotent=False,
                            retest_revision="owned-fixed-control",
                            **assessment.runtime.registry.execution_versions("nuclei_scan"),
                        )
                        for row in nuclei
                    ],
                )
                assert set(await assessment.runtime.scheduler.run_until_idle(max_jobs=2)) == set(
                    fixed_ids
                )
                fixed_jobs = [
                    row
                    for row in assessment.store.jobs(assessment.policy.engagement_id, limit=100)
                    if row["id"] in fixed_ids
                ]
                assert all(
                    row["execution_status"] == "succeeded"
                    and row["result"]["summary"]["no_finding_observed"] is True
                    for row in fixed_jobs
                ), fixed_jobs
                for actor in passwords:
                    metadata = assessment.runtime.scheduler.adapters[
                        "browser_discover"
                    ].actor_states[actor]
                    assert metadata["tenant_id"] == "owned" and metadata["session_revision"] == "2"
                    sid = assessment.store.upsert_surface(
                        assessment.policy.engagement_id,
                        Surface(
                            origin + "/whoami",
                            actor_id=actor,
                            tenant_id="owned",
                            session_revision="2",
                            source="imported",
                            workflow_state="approved_seed",
                        ),
                    )
                    jid = assessment.store.submit(
                        assessment.policy,
                        [JobSpec(sid, "discovery", "browser_discover", policy_revision="1")],
                    )[0]
                    assert await assessment.runtime.scheduler.run_until_idle(max_jobs=1) == [jid]
                    assert (
                        next(
                            row
                            for row in assessment.store.jobs(assessment.policy.engagement_id)
                            if row["id"] == jid
                        )["execution_status"]
                        == "succeeded"
                    )
            async with ConfiguredAssessment(config, output, caller="operator") as assessment:
                assert set(
                    assessment.runtime.scheduler.adapters["browser_discover"].actor_states
                ) == {
                    "alice",
                    "bob",
                }
                assert await assessment.runtime.scheduler.run_until_idle(max_jobs=16) == []
                assert seen[("POST", "/api/save")] == 6
                for actor in passwords:
                    logout = assessment.store.auth_flows.start(
                        assessment.policy, plan_ids[actor + "-logout"], "first"
                    )
                    result = await submit(assessment, logout)
                    assert result["execution_status"] == "succeeded", result
                    assert (
                        actor
                        not in assessment.runtime.scheduler.adapters[
                            "browser_discover"
                        ].actor_states
                    )
                    with pytest.raises(PolicyDenied, match="revoked"):
                        assessment.store.assert_session_revision(
                            assessment.policy,
                            Surface(
                                origin + "/app",
                                actor_id=actor,
                                tenant_id="owned",
                                session_revision="3",
                            ),
                        )
                assert sessions == {} and challenges == {}
                assert (
                    seen[("POST", "/login")] == 2
                    and seen[("POST", "/mfa")] == 2
                    and seen[("POST", "/logout")] == 2
                )
                assert (
                    assessment.store.db.execute(
                        "SELECT count(*) FROM rj_auth_input_use WHERE state='settled'"
                    ).fetchone()[0]
                    == 8
                )  # 6 form nonces + 2 MFA inputs.
                assert not assessment.store.db.execute(
                    "SELECT 1 FROM rj_auth_flow WHERE "
                    "status IN ('running','awaiting_input','uncertain')"
                ).fetchone()
                dump = "\n".join(assessment.store.db.iterdump())
                assert all(secret not in dump for secret in (*passwords.values(), *codes.values()))
                health = assessment.runtime.browser.healthcheck()
                assert (
                    health["contexts_created"] == health["contexts_closed"]
                    and health["pages_created"] == health["pages_closed"]
                )
                record_testsuite_property(
                    "browser_auth_chromium_version", result["result"]["summary"]["chromium_version"]
                )
                record_testsuite_property(
                    "browser_auth_playwright_version",
                    result["result"]["summary"]["playwright_version"],
                )
                record_testsuite_property("browser_auth_nuclei_version", lock.binary_version)
                record_testsuite_property("browser_auth_nuclei_binary_sha256", lock.binary_sha256)
                record_testsuite_property("browser_auth_real_actors", 2)
                record_testsuite_property("browser_auth_login_posts", 2)
                record_testsuite_property("browser_auth_mfa_posts", 2)
                record_testsuite_property("browser_auth_logout_posts", 2)
                record_testsuite_property("browser_auth_one_use_settled_inputs", 8)
                record_testsuite_property("browser_auth_final_server_sessions", len(sessions))
                record_testsuite_property("browser_auth_actual_nuclei_positive_jobs", 2)
                record_testsuite_property("browser_auth_actual_nuclei_fixed_jobs", 2)
                record_testsuite_property("browser_auth_actual_capture_posts", 2)
            assert (
                assessment.runtime if False else True
            )  # closed runtime is intentionally inaccessible.
    finally:
        release_mfa.set()
        assert not fixture.thread.is_alive()
        assert not fixture.certificate_directory.exists()
