"""Actual pinned engine + verified TLS + host-only credential replay.

This test uses the installed binary and a real loopback HTTPS server. Missing
engine support is a skipped capability, never a negative scan result.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault
from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import Surface
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.tools.hunt.nuclei import NucleiAdapter, NucleiOptions
from tests.test_nuclei_live import existing_live_lock


async def test_actual_authenticated_https_nuclei_identity_and_negative_boundaries(  # noqa: PLR0915 - actual engine boundary sequence
    tmp_path: Path,
):
    lock = existing_live_lock()
    credential = secrets.token_urlsafe(32)
    observed: list[dict] = []
    state = {"mode": "marker"}
    measurements: list[dict] = []

    class AuthHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            authorized = (
                self.headers.get("Authorization") == "Bearer " + credential
                and self.headers.get("Cookie") == "fixture_actor=alice"
            )
            observed.append(
                {"path": urlsplit(self.path).path, "actor": "alice" if authorized else "anonymous"}
            )
            if not authorized:
                status, body = 401, b"credentials required"
            elif state["mode"] == "redirect":
                status, body = 302, b""
            else:
                status = 200
                body = b"redjohn-fixture-marker" if state["mode"] == "marker" else b"fixed-control"
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "/other-private")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = AuthHandler
        policy = EngagementPolicy(
            "auth-live",
            "owner",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice", "bob"),
        )
        surface = Surface(
            fixture.origin + "/marker",
            actor_id="alice",
            tenant_id="tenant-a",
            session_revision="7",
            request_ref="actual-request-ref-1",
        )
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
                    "expires_at": time.time() + 300,
                    "origin": fixture.origin,
                    "allowed_requests": [
                        {"url": surface.url, "method": "GET", "request_ref": surface.request_ref}
                    ],
                    "headers": {"Authorization": "Bearer " + credential},
                    "cookies": [{"name": "fixture_actor", "value": "alice"}],
                }
            ],
        }
        vault = AuthReplayVault.from_mapping(data, policy)
        binding = vault.authorize(surface)
        tls = BrowserTLSConfig(upstream_ca_file=fixture.ca_file)
        raw_evidence: list[dict] = []
        async with NativeFixtureSession(policy, tmp_path / "worker", lock) as session:

            async def scan(label: str, replay=None) -> dict:
                responses: list[dict] = []
                proxy = BrowserEgressProxy(
                    policy,
                    tls_config=tls,
                    request_headers=replay.rewrite_headers if replay is not None else None,
                    on_response=lambda url, status, headers: responses.append(
                        {"url": url, "status": status, "headers": headers}
                    ),
                )
                await proxy.start()
                session.bind_proxy(proxy.url)
                started = time.monotonic()
                before = len(observed)
                try:
                    adapter = NucleiAdapter(
                        session,
                        lock,
                        proxy_url=proxy.url,
                        response_observations=lambda: tuple(responses),
                        auth_replay=replay,
                        evidence_sink=lambda raw: raw_evidence.append(raw) or "raw-auth-evidence",
                    )
                    result = await adapter.run(
                        surface.url, NucleiOptions(timeout_seconds=30), policy=policy
                    )
                finally:
                    session.bind_proxy(None)
                    await proxy.close()
                measurements.append(
                    {
                        "case": label,
                        "duration_seconds": time.monotonic() - started,
                        "requests": observed[before:],
                        "response_statuses": [r["status"] for r in responses],
                        "execution_status": result["execution_status"],
                        "coverage_status": result["coverage_status"],
                        "finding_count": len(result["findings"]),
                        "no_finding_observed": result["no_finding_observed"],
                        "error_code": (result.get("error") or {}).get("code"),
                    }
                )
                return result

            anonymous = await scan("anonymous_denied")
            assert anonymous["coverage_status"] == "blocked"
            assert anonymous["error"]["code"] == "authentication_expired"
            assert anonymous["no_finding_observed"] is False
            named = await scan("correct_named_actor", binding)
            assert named["execution_status"] == "succeeded", json.dumps(named)
            assert named["coverage_status"] == "completed"
            assert len(named["findings"]) == 1
            assert named["findings"][0]["finding_status"] == "candidate"
            assert named["findings"][0]["actor_ref"] == "alice"
            assert named["findings"][0]["tenant_ref"] == "tenant-a"
            state["mode"] = "fixed"
            fixed = await scan("fixed_authenticated_control", binding)
            assert fixed["coverage_status"] == "completed"
            assert fixed["no_finding_observed"] is True
            assert not fixed["findings"]
            state["mode"] = "redirect"
            redirect = await scan("redirect_not_replayed", binding)
            assert redirect["no_finding_observed"] is False
            assert redirect["coverage_status"] == "inconclusive"
            assert all(row["path"] != "/other-private" for row in observed)
            before = len(observed)
            for changes in (
                {"tenant_id": "tenant-b"},
                {"session_revision": "8"},
                {"actor_id": "bob"},
            ):
                with pytest.raises(AuthReplayDenied):
                    vault.authorize(replace(surface, **changes))
            expired = replace(binding, expires_at=time.time() - 1)
            rejected = await scan("expired_binding_no_request", expired)
            assert rejected["error"]["code"] == "auth_replay_expired"
            assert rejected["coverage_status"] == "blocked"
            assert len(observed) == before

        assert len(observed) == 4
        assert [row["actor"] for row in observed] == ["anonymous", "alice", "alice", "alice"]
        assert credential not in json.dumps(raw_evidence)
        assert credential not in json.dumps(measurements)
        assert all(
            credential.encode() not in path.read_bytes()
            for path in (tmp_path / "worker").rglob("*")
            if path.is_file()
        )
    if output := os.environ.get("REDJOHN_AUTH_E2E_MEASUREMENTS"):
        Path(output).write_text(
            json.dumps(
                {
                    "binary_version": lock.binary_version,
                    "binary_sha256": lock.binary_sha256,
                    "cases": measurements,
                    "http_requests": len(observed),
                    "model_calls": 0,
                },
                indent=2,
            )
            + "\n"
        )
