"""Actual Chromium/proxy automatic POST capture; separate private-rule unit faults."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import hashlib
import json
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler

import httpx
import pytest

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.browser import BrowserDiscoveryService, BrowserLimits
from redjohn.assessment.browser_capture import BrowserCaptureDenied, BrowserPostCaptureService
from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import ResourceEnvelope, ResourceGovernor
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer


AUTH = "private-browser-capture-auth"
CSRF = "private-browser-capture-csrf"
COOKIE = "private-browser-capture-cookie"
VALUE = "private-browser-capture-value"
PAGE = f"""<!doctype html><html><body><script>
(async () => {{
 const form = new URLSearchParams(); form.append('value','{VALUE}');
 form.append('tag','one'); form.append('tag','two'); form.append('csrf','{CSRF}');
 const upload = new FormData(); upload.append('value','{VALUE}');
 upload.append('csrf','{CSRF}');
 upload.append('upload',new Blob([new Uint8Array([0,1,255,13,10])],
   {{type:'application/octet-stream'}}),'proof.bin');
 await Promise.allSettled([
  fetch('/json',{{method:'POST',headers:{{'Content-Type':'application/json'}},
   body:JSON.stringify({{value:'{VALUE}',csrf:'{CSRF}'}})}}),
  fetch('/form',{{method:'POST',body:form}}),
  fetch('/multipart',{{method:'POST',body:upload}})
 ]);
 document.body.dataset.ready = 'true';
}})();</script></body></html>""".encode()


def configured_capture(tmp_path, origin, *, revision="current"):
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(
        EngagementPolicy(
            "browser-post-capture",
            "owner",
            (origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice", "bob"),
            allowed_replay_urls=tuple(origin + path for path in ("/json", "/form", "/multipart")),
        )
    )
    expiry = time.time() + 300
    vault = {
        "version": 2,
        "entries": [
            {
                "engagement_id": policy.engagement_id,
                "owner_id": policy.owner_id,
                "actor_id": "alice",
                "tenant_id": "tenant-a",
                "session_revision": "7",
                "policy_revision": policy.revision,
                "expires_at": expiry,
                "origin": origin,
                "allowed_requests": [
                    {"url": origin + "/start", "method": "GET", "request_ref": "anchor"}
                ],
                "headers": {"Authorization": "Bearer " + AUTH, "X-CSRF-Token": CSRF},
                "cookies": [{"name": "session", "value": COOKIE}],
            }
        ],
    }
    rules = {"version": 1, "rules": []}
    for path, media, location, selector in (
        ("/json", "application/json", "json", "/csrf"),
        ("/form", "application/x-www-form-urlencoded", "form", "csrf"),
        ("/multipart", "multipart/form-data", "multipart", "csrf"),
    ):
        rules["rules"].append(
            {
                "engagement_id": policy.engagement_id,
                "owner_id": policy.owner_id,
                "actor_id": "alice",
                "tenant_id": "tenant-a",
                "session_revision": revision,
                "policy_revision": policy.revision,
                "expires_at": expiry + 300,
                "url": origin + path,
                "content_type": media,
                "automatic_approval": True,
                "start_url": origin + "/start",
                "body_tokens": [
                    {
                        "location": location,
                        "selector": selector,
                        "occurrence": 0,
                        "source": {"kind": "header", "name": "X-CSRF-Token"},
                    }
                ],
            }
        )
    vault_file, rules_file = tmp_path / "vault.json", tmp_path / "capture-rules.json"
    for path, data in ((vault_file, vault), (rules_file, rules)):
        path.write_text(json.dumps(data))
        path.chmod(0o600)
    service = BrowserPostCaptureService(policy, store, vault_file, rules_file)
    return policy, store, service, vault_file, rules_file


async def test_actual_chromium_auto_posts_are_exact_private_captures_and_default_stays_readonly(
    tmp_path,
):
    pytest.importorskip("playwright.async_api")
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            correct = (
                self.headers.get("Authorization") == "Bearer " + AUTH
                or self.headers.get("Cookie") == "session=" + COOKIE
            )
            data = PAGE if self.path == "/start" and correct else b"<html>Unauthenticated</html>"
            self.send_response(200 if correct else 401)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            authenticated = (
                self.headers.get("Authorization") == "Bearer " + AUTH
                and self.headers.get("X-CSRF-Token") == CSRF
                and self.headers.get("Cookie") == "session=" + COOKIE
            )
            observed.append((self.path, body, self.headers.get("Content-Type"), authenticated))
            self.send_response(200 if authenticated else 401)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        policy, store, capture, vault_file, _rules_file = configured_capture(
            tmp_path, fixture.origin
        )
        governor = ResourceGovernor(ResourceEnvelope(total_memory_budget=2 * 1024**3))
        try:
            assert capture.scheduled_contexts() == (
                {
                    "actor_id": "alice",
                    "tenant_id": "tenant-a",
                    "session_revision": "7",
                    "start_urls": (fixture.origin + "/start",),
                },
            )
            async with BrowserDiscoveryService(
                policy,
                governor,
                BrowserLimits(
                    max_pages=1, readiness_selector="[data-ready='true']", observation_window_ms=100
                ),
                tls_config=BrowserTLSConfig(fixture.ca_file),
                post_capture=capture,
            ) as browser:
                result = await browser.discover(
                    [fixture.origin + "/start"],
                    actor_id="alice",
                    tenant_id="tenant-a",
                    session_revision="7",
                    capture_post=True,
                )
                assert result.execution_status == "succeeded", result
                posts = [item for item in result.observations if item.method == "POST"]
                assert len(posts) == len(observed) == 3, result
                assert all(
                    item.sent and item.status == 200 and item.request_ref and item.body_sha256
                    for item in posts
                )
                assert all(item.body_capture == "byte_exact_private_proxy" for item in posts)
                assert all(item[3] for item in observed)
                assert capture._active is None and not capture._tickets
                assert browser._proxy.request_capture is None
                assert browser._proxy.request_headers is None
                mapping = AuthReplayVault.from_file(vault_file, policy).to_mapping()
                actual_by_path = {path: body for path, body, _media, _auth in observed}
                for entry in mapping["entries"]:
                    for request in entry["allowed_requests"]:
                        if request["method"] == "POST":
                            body = base64.b64decode(request["body_base64"], validate=True)
                            assert (
                                body == actual_by_path[request["url"].removeprefix(fixture.origin)]
                            )
                            assert request["body_sha256"] == hashlib.sha256(body).hexdigest()
                            assert (
                                request["body_tokens"]
                                and request["replay_safety"] == "operator-approved"
                            )
                            assert entry["expires_at"] <= mapping["entries"][0]["expires_at"]
                raw = "\n".join(store.db.iterdump()).encode()
                raw += b"".join(
                    bytes(row[0]) for row in store.db.execute("SELECT payload FROM rj_evidence")
                )
                raw += json.dumps(asdict(result)).encode()
                assert all(value.encode() not in raw for value in (AUTH, CSRF, COOKIE, VALUE))
                assert (
                    store.db.execute(
                        "SELECT count(*) FROM rj_request_capture WHERE state='succeeded'"
                    ).fetchone()[0]
                    == 3
                )
                # With capture_post omitted, configuration alone grants no POST.
                # Use the original storage state so GET navigation still loads.
                readonly = await browser.discover(
                    [fixture.origin + "/start"],
                    actor_id="alice",
                    tenant_id="tenant-a",
                    session_revision="7",
                    storage_state={
                        "cookies": [
                            {
                                "name": "session",
                                "value": COOKIE,
                                "domain": "127.0.0.1",
                                "path": "/",
                                "expires": -1,
                                "httpOnly": True,
                                "secure": True,
                                "sameSite": "Lax",
                            }
                        ],
                        "origins": [],
                    },
                )
                assert len(observed) == 3
                assert "browser_mutating_request_blocked" in {
                    failure.code for failure in readonly.failures
                }
                assert not any(
                    item.sent and item.method == "POST" for item in readonly.observations
                )
                assert browser.healthcheck()["active_contexts"] == 0
            assert governor.snapshot()["active"] == {}
        finally:
            store.close()


async def test_actual_proxy_capture_preserves_operator_credentials_changed_during_response(
    tmp_path,
):
    accepted, release = threading.Event(), threading.Event()
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            accepted.set()
            release.wait(3)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            with contextlib.suppress(OSError):
                self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        policy, store, capture, vault_file, _rules_file = configured_capture(
            tmp_path, fixture.origin
        )
        capture.bind_context("alice", "tenant-a", "7")
        proxy = BrowserEgressProxy(
            policy,
            tls_config=BrowserTLSConfig(fixture.ca_file),
            request_headers=capture.headers_for_request,
            request_capture=capture.before_request,
        )
        await proxy.start()
        body = json.dumps({"value": VALUE, "csrf": CSRF}).encode()
        task = None
        try:
            async with httpx.AsyncClient(
                proxy=proxy.url, verify=proxy.client_tls_context, trust_env=False
            ) as client:
                task = asyncio.create_task(
                    client.post(
                        fixture.origin + "/json",
                        content=body,
                        headers={"Content-Type": "application/json"},
                    )
                )
                assert await asyncio.to_thread(accepted.wait, 2)
                manual = json.loads(vault_file.read_text())
                manual["entries"][0]["headers"]["Authorization"] = "Bearer operator-new-token"
                manual["entries"][0]["cookies"][0]["value"] = "operator-new-cookie"
                vault_file.write_text(json.dumps(manual))
                release.set()
                response = await asyncio.wait_for(task, 3)
                assert response.status_code == 200
                await proxy.drain_captures(2)
            assert seen == [body]
            assert json.loads(vault_file.read_text()) == manual
            assert capture.observations() == ()
            assert "browser_capture_commit_uncertain" in capture.failure_codes()
            assert (
                store.db.execute("SELECT state FROM rj_request_capture").fetchone()[0]
                == "uncertain"
            )
            assert store.surfaces(policy.engagement_id) == []
        finally:
            release.set()
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await proxy.close()
            capture.end_context()
            store.close()


def test_capture_lifetime_is_clamped_and_expired_seed_is_visible_but_cannot_execute(tmp_path):
    policy, store, capture, vault_file, _rules_file = configured_capture(
        tmp_path, "https://127.0.0.1:8443"
    )
    try:
        capture.bind_context("alice", "tenant-a", "7")
        headers = capture.headers_for_request(
            policy.allowed_replay_urls[0], "POST", [("Content-Type", "application/json")]
        )
        ticket = capture.before_request(
            policy.allowed_replay_urls[0],
            "POST",
            headers,
            json.dumps({"value": VALUE, "csrf": CSRF}).encode(),
        )
        assert (
            ticket.entry["expires_at"]
            == json.loads(vault_file.read_text())["entries"][0]["expires_at"]
        )
        capture.end_context()
        data = json.loads(vault_file.read_text())
        data["entries"][0]["expires_at"] = time.time() - 1
        vault_file.write_text(json.dumps(data))
        assert capture.scheduled_contexts()[0]["session_revision"] == "7"
        with pytest.raises(BrowserCaptureDenied, match="expired_or_superseded"):
            capture.bind_context("alice", "tenant-a", "7")
        assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 0
    finally:
        capture.end_context()
        store.close()


@pytest.mark.parametrize("mode", ["lost_response", "truncated", "oversize", "drain_cancel"])
async def test_actual_capture_fault_stays_uncertain_and_cannot_resend_after_restart(tmp_path, mode):
    accepted, release = threading.Event(), threading.Event()
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            accepted.set()
            if mode == "lost_response":
                self.close_connection = True
                return
            if mode == "drain_cancel":
                release.wait(3)
            response = b"x" * (80 * 1024 + 1) if mode == "oversize" else b"short"
            self.send_response(200)
            self.send_header("Content-Length", "100" if mode == "truncated" else str(len(response)))
            self.end_headers()
            with contextlib.suppress(OSError):
                self.wfile.write(response)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        policy, store, capture, vault_file, rules_file = configured_capture(
            tmp_path, fixture.origin
        )
        initial_vault = json.loads(vault_file.read_text())
        capture.bind_context("alice", "tenant-a", "7")
        proxy = BrowserEgressProxy(
            policy,
            tls_config=BrowserTLSConfig(fixture.ca_file),
            request_headers=capture.headers_for_request,
            request_capture=capture.before_request,
        )
        await proxy.start()
        body = json.dumps({"value": VALUE, "csrf": CSRF}).encode()
        task = None
        try:
            async with httpx.AsyncClient(
                proxy=proxy.url, verify=proxy.client_tls_context, trust_env=False
            ) as client:
                task = asyncio.create_task(
                    client.post(
                        fixture.origin + "/json",
                        content=body,
                        headers={"Content-Type": "application/json"},
                    )
                )
                assert await asyncio.to_thread(accepted.wait, 2)
                if mode == "drain_cancel":
                    await proxy.drain_captures(0.02)
                    assert not proxy._capture_tasks
                with pytest.raises(httpx.HTTPError):
                    await asyncio.wait_for(task, 3)
                await proxy.drain_captures(2)
                assert capture.observations() == ()
                assert json.loads(vault_file.read_text()) == initial_vault
                assert (
                    store.db.execute("SELECT state FROM rj_request_capture").fetchone()[0]
                    == "uncertain"
                )
                assert store.surfaces(policy.engagement_id) == []
                capture.end_context()
                store.close()
                store = AssessmentStore(tmp_path / "agents.db")
                capture = BrowserPostCaptureService(policy, store, vault_file, rules_file)
                capture.bind_context("alice", "tenant-a", "7")
                proxy.request_capture = capture.before_request
                proxy.request_headers = capture.headers_for_request
                duplicate = await client.post(
                    fixture.origin + "/json",
                    content=body,
                    headers={"Content-Type": "application/json"},
                )
                assert duplicate.status_code == 403
                assert seen == [body]
                assert (
                    store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 1
                )
                assert capture.observations() == ()
        finally:
            release.set()
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await proxy.close()
            capture.end_context()
            store.close()


async def test_actual_capture_preserves_distinct_existing_per_endpoint_credentials(tmp_path):
    observed, expected = [], {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            fixture = expected[self.path]
            valid = (
                body == fixture["body"]
                and self.headers.get("Authorization") == fixture["headers"]["Authorization"]
                and self.headers.get("X-CSRF-Token") == fixture["headers"]["X-CSRF-Token"]
                and self.headers.get("Cookie") == "session=" + fixture["cookie"]
            )
            observed.append((self.path, valid))
            self.send_response(200 if valid else 401)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        policy, store, capture, vault_file, _rules_file = configured_capture(
            tmp_path, fixture.origin
        )
        seed = json.loads(vault_file.read_text())
        for name, media in (
            ("json", "application/json"),
            ("form", "application/x-www-form-urlencoded"),
        ):
            csrf = "private-per-route-csrf-" + name
            body = (
                json.dumps({"value": VALUE, "csrf": csrf}).encode()
                if name == "json"
                else ("value=" + VALUE + "&csrf=" + csrf).encode()
            )
            headers = {"Authorization": "Bearer private-route-auth-" + name, "X-CSRF-Token": csrf}
            cookie = "private-per-route-cookie-" + name
            entry = copy.deepcopy(seed["entries"][0])
            entry["headers"], entry["cookies"] = headers, [{"name": "session", "value": cookie}]
            entry["allowed_requests"] = [
                {
                    "url": fixture.origin + "/" + name,
                    "method": "POST",
                    "request_ref": "prior-" + name,
                    "content_type": media,
                    "body_base64": base64.b64encode(body).decode(),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "replay_safety": "operator-approved",
                }
            ]
            seed["entries"].append(entry)
            expected["/" + name] = {
                "body": body,
                "headers": headers,
                "cookie": cookie,
                "media": media,
            }
        vault_file.write_text(json.dumps(seed))
        capture.bind_context("alice", "tenant-a", "7")
        proxy = BrowserEgressProxy(
            policy,
            tls_config=BrowserTLSConfig(fixture.ca_file),
            request_headers=capture.headers_for_request,
            request_capture=capture.before_request,
        )
        await proxy.start()
        try:
            async with httpx.AsyncClient(
                proxy=proxy.url, verify=proxy.client_tls_context, trust_env=False
            ) as client:
                for path, request in expected.items():
                    response = await client.post(
                        fixture.origin + path,
                        content=request["body"],
                        headers={"Content-Type": request["media"]},
                    )
                    assert response.status_code == 200
                    await proxy.drain_captures(2)
            assert observed == [("/json", True), ("/form", True)]
            assert len(capture.observations()) == 2
            assert capture.failure_codes() == ()
            assert json.loads(vault_file.read_text())["entries"][:3] == seed["entries"]
            assert (
                store.db.execute(
                    "SELECT count(*) FROM rj_request_capture WHERE state='succeeded'"
                ).fetchone()[0]
                == 2
            )
        finally:
            await proxy.close()
            capture.end_context()
            store.close()


async def test_failed_fenced_capture_never_activates_staged_vault(tmp_path, monkeypatch):
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            observed.append(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        policy, store, capture, vault_file, _rules_file = configured_capture(
            tmp_path, fixture.origin
        )
        initial = json.loads(vault_file.read_text())
        capture.bind_context("alice", "tenant-a", "7")
        monkeypatch.setattr(store, "finish_capture", lambda *_args: False)
        proxy = BrowserEgressProxy(
            policy,
            tls_config=BrowserTLSConfig(fixture.ca_file),
            request_headers=capture.headers_for_request,
            request_capture=capture.before_request,
        )
        await proxy.start()
        try:
            async with httpx.AsyncClient(
                proxy=proxy.url, verify=proxy.client_tls_context, trust_env=False
            ) as client:
                response = await client.post(
                    fixture.origin + "/json",
                    content=json.dumps({"value": VALUE, "csrf": CSRF}).encode(),
                    headers={"Content-Type": "application/json"},
                )
                assert response.status_code == 200
                await proxy.drain_captures(2)
            assert observed
            assert json.loads(vault_file.read_text()) == initial
            assert not (tmp_path / "vault.json.commit-staged").exists()
            assert "browser_capture_commit_uncertain" in capture.failure_codes()
            assert (
                store.db.execute("SELECT state FROM rj_request_capture").fetchone()[0]
                == "uncertain"
            )
        finally:
            await proxy.close()
            capture.end_context()
            store.close()
