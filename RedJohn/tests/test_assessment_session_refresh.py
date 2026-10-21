"""Durable refresh CAS tests and actual, verified HTTPS provider integration."""

from __future__ import annotations

import base64
import contextlib
import json
import secrets
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler

import pytest

from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.cache import CacheContext, SmartCache
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.persistent_rate_limit import PersistentRateLimitDetector
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.session_refresh import SessionRefreshService
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer


def refresh_policy(origin="https://127.0.0.1:8443"):
    return EngagementPolicy(
        "refresh-test",
        "owner",
        (origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("anonymous", "alice", "bob"),
        allowed_refresh_urls=(origin + "/refresh",),
    )


def refresh_surface(origin="https://127.0.0.1:8443"):
    return Surface(
        origin + "/private",
        actor_id="alice",
        tenant_id="tenant-a",
        session_revision="7",
        request_ref="observed-private-request",
    )


def claim_refresh(store, policy, surface, *, idempotent=False):
    policy = store.register(policy)
    sid = store.upsert_surface(policy.engagement_id, surface)
    spec = JobSpec(
        sid,
        "session",
        "session_refresh",
        policy_revision=policy.revision,
        idempotent=idempotent,
        timeout_seconds=5,
    )
    store.submit(policy, [spec])
    job = store.claim(policy, "refresh-worker", lease_seconds=30)
    return policy, spec, job


def private_file(path, data):
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


def vault_data(policy, surface, *, expired=False):
    return {
        "version": 1,
        "entries": [
            {
                "engagement_id": policy.engagement_id,
                "owner_id": policy.owner_id,
                "actor_id": surface.actor_id,
                "tenant_id": surface.tenant_id,
                "session_revision": surface.session_revision,
                "policy_revision": policy.revision,
                "expires_at": time.time() + (-10 if expired else 300),
                "origin": policy.allowed_origins[0],
                "allowed_requests": [
                    {"url": surface.url, "method": "GET", "request_ref": surface.request_ref}
                ],
                "headers": {"Authorization": "Bearer old-private-session-token"},
                "cookies": [],
            }
        ],
    }


def provider_data(policy, surface, refresh_token):
    return {
        "version": 1,
        "providers": [
            {
                "engagement_id": policy.engagement_id,
                "owner_id": policy.owner_id,
                "actor_id": surface.actor_id,
                "tenant_id": surface.tenant_id,
                "policy_revision": policy.revision,
                "refresh_url": policy.allowed_refresh_urls[0],
                "headers": {"Authorization": "Bearer " + refresh_token},
                "body_base64": base64.b64encode(b'{"grant_type":"refresh_token"}').decode(),
                "content_type": "application/json",
            }
        ],
    }


def test_refresh_revision_cas_dedup_and_restart(tmp_path):
    path = tmp_path / "agents.db"
    store = AssessmentStore(path)
    surface = refresh_surface()
    policy, _spec, job = claim_refresh(store, refresh_policy(), surface)
    second = AssessmentStore(path)
    reservation = store.begin_session_refresh(policy, job, surface)
    assert reservation["next_revision"] == "8"
    with pytest.raises(PolicyDenied, match="already_inflight"):
        second.begin_session_refresh(policy, job, surface)
    with pytest.raises(PolicyDenied, match="refreshing"):
        second.assert_session_revision(policy, surface)
    assert not second.finish_session_refresh(
        policy, {**job, "owner": "wrong"}, surface, reservation["refresh_key"]
    )
    assert store.finish_session_refresh(policy, job, surface, reservation["refresh_key"])
    store.close()
    with pytest.raises(PolicyDenied, match="superseded"):
        second.assert_session_revision(policy, surface)
    second.assert_session_revision(policy, replace(surface, session_revision="8"))
    with pytest.raises(PolicyDenied, match="already_succeeded"):
        second.begin_session_refresh(policy, job, surface)
    assert second.session_state(policy, surface)["revision"] == "8"
    second.close()


def test_lost_refresh_lease_is_durable_uncertain_never_requeued(tmp_path):
    store = AssessmentStore(tmp_path / "agents.db")
    surface = refresh_surface()
    policy, _spec, job = claim_refresh(store, refresh_policy(), surface)
    reservation = store.begin_session_refresh(policy, job, surface)
    store.db.execute("UPDATE rj_job SET lease_until=? WHERE id=?", (time.time() - 1, job["id"]))
    assert not store.finish_session_refresh(policy, job, surface, reservation["refresh_key"])
    assert store.recover_expired(policy) == 1
    assert store.session_state(policy, surface)["status"] == "uncertain"
    assert store.claim(policy, "new-worker") is None
    assert store.db.execute("SELECT state FROM rj_session_refresh").fetchone()[0] == "uncertain"
    with pytest.raises(PolicyDenied, match="uncertain"):
        store.assert_session_revision(policy, surface)
    store.close()


@pytest.mark.parametrize(
    "change", ["idempotent", "opaque_revision", "anonymous", "wrong_owner", "expired_lease"]
)
def test_refresh_invalid_execution_contract_zero_reservation(tmp_path, change):
    store = AssessmentStore(tmp_path / "agents.db")
    surface = refresh_surface()
    policy, _spec, job = claim_refresh(
        store, refresh_policy(), surface, idempotent=change == "idempotent"
    )
    if change == "opaque_revision":
        surface = replace(surface, session_revision="rev-seven")
    elif change == "anonymous":
        surface = replace(surface, actor_id="anonymous")
    elif change == "wrong_owner":
        job = {**job, "owner": "imposter"}
    elif change == "expired_lease":
        store.db.execute("UPDATE rj_job SET lease_until=0 WHERE id=?", (job["id"],))
    with pytest.raises(PolicyDenied):
        store.begin_session_refresh(policy, job, surface)
    assert store.db.execute("SELECT count(*) FROM rj_session_refresh").fetchone()[0] == 0
    store.close()


def test_legacy_opaque_untracked_session_revision_still_accepted(tmp_path):
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(refresh_policy())
    surface = replace(refresh_surface(), session_revision="legacy-opaque-revision")
    store.assert_session_revision(policy, surface)
    assert store.session_state(policy, surface) is None
    store.close()


@pytest.mark.parametrize("expired", [False, True])
async def test_actual_https_refresh_atomic_rotation_expiry_and_secret_isolation(tmp_path, expired):
    refresh_token, new_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    seen = []

    class RefreshHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            authorized = self.headers.get("Authorization") == "Bearer " + refresh_token
            seen.append((self.path, authorized, body == b'{"grant_type":"refresh_token"}'))
            response = json.dumps(
                {
                    "headers": {"Authorization": "Bearer " + new_token},
                    "cookies": [],
                    "expires_at": time.time() + 300,
                }
            ).encode()
            self.send_response(200 if authorized else 401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = RefreshHandler
        store = AssessmentStore(tmp_path / "agents.db")
        surface = refresh_surface(fixture.origin)
        policy, spec, job = claim_refresh(store, refresh_policy(fixture.origin), surface)
        vault = private_file(tmp_path / "vault.json", vault_data(policy, surface, expired=expired))
        providers = private_file(
            tmp_path / "providers.json", provider_data(policy, surface, refresh_token)
        )
        if expired:
            with pytest.raises(AuthReplayDenied, match="expired"):
                AuthReplayVault.from_file(vault, policy)
        service = SessionRefreshService(
            policy, store, vault, providers, tls_config=BrowserTLSConfig(fixture.ca_file)
        )
        result = await service.run(job, surface, spec)
        assert result.execution_status == "succeeded", result
        assert result.summary["session_revision"] == "8"
        assert seen == [("/refresh", True, True)]
        assert stat_mode(vault) == 0o600
        assert store.session_state(policy, surface)["revision"] == "8"
        refreshed = AuthReplayVault.from_file(vault, policy)
        assert (
            dict(
                refreshed.authorize(replace(surface, session_revision="8")).headers_for(
                    surface.url, "GET"
                )
            )["Authorization"]
            == "Bearer " + new_token
        )
        with pytest.raises(AuthReplayDenied):
            refreshed.authorize(surface)
        duplicate = await service.run(job, surface, spec)
        assert duplicate.coverage_status == "blocked"
        assert len(seen) == 1
        store.finish(job, result)
        dump = "\n".join(store.db.iterdump())
        assert refresh_token not in dump and new_token not in dump
        assert refresh_token not in repr(result) and new_token not in repr(result)
        assert "old-private-session-token" not in dump
        assert not list(tmp_path.glob(".redjohn-session-*"))
        store.close()


def stat_mode(path):
    return path.stat().st_mode & 0o777


@pytest.mark.parametrize("mode", ["redirect", "oversize", "bad_json", "timeout", "rate_limit"])
async def test_actual_https_refresh_failure_blocks_old_session_without_retry(tmp_path, mode):
    token = secrets.token_urlsafe(24)
    seen = []

    class FailingHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(self.path)
            if mode == "timeout":
                time.sleep(0.5)
            response = b"{" if mode == "bad_json" else b"x" * (65537 if mode == "oversize" else 1)
            self.send_response(
                429 if mode == "rate_limit" else (302 if mode == "redirect" else 200)
            )
            if mode == "rate_limit":
                self.send_header("Retry-After", "30")
            self.send_header("Location", "/credential-trap")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            with contextlib.suppress(OSError):
                self.wfile.write(response)

        def do_GET(self):
            seen.append("LEAKED_REDIRECT")
            self.send_error(500)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = FailingHandler
        store = AssessmentStore(tmp_path / "agents.db")
        surface = refresh_surface(fixture.origin)
        policy, spec, job = claim_refresh(store, refresh_policy(fixture.origin), surface)
        spec = replace(spec, timeout_seconds=0.15 if mode == "timeout" else 5)
        data = vault_data(policy, surface)
        vault = private_file(tmp_path / "vault.json", data)
        providers = private_file(tmp_path / "providers.json", provider_data(policy, surface, token))
        service = SessionRefreshService(
            policy, store, vault, providers, tls_config=BrowserTLSConfig(fixture.ca_file)
        )
        rate_limits = PersistentRateLimitDetector(store, policy.engagement_id)
        service.rate_limits = rate_limits
        result = await service.run(job, surface, spec)
        assert result.execution_status == "failed"
        assert result.summary["requests"] == 1
        assert result.summary["requests_admitted"] == 1
        if mode == "rate_limit":
            assert 25 < rate_limits.remaining(fixture.origin) <= 30
            restarted_limits = PersistentRateLimitDetector(store, policy.engagement_id)
            assert restarted_limits.admit(fixture.origin) is False
        assert result.error["retryable"] is False
        assert result.coverage_status == (
            "blocked" if mode in {"redirect", "rate_limit"} else "inconclusive"
        )
        assert seen == ["/refresh"]
        assert json.loads(vault.read_text()) == data
        assert store.session_state(policy, surface)["status"] in {"blocked", "uncertain"}
        with pytest.raises(PolicyDenied):
            store.assert_session_revision(policy, surface)
        duplicate = await service.run(job, surface, spec)
        assert duplicate.execution_status == "failed"
        assert seen == ["/refresh"]
        store.close()


@pytest.mark.parametrize("mode", ["permission", "wrong_actor", "missing_file", "bad_body"])
async def test_refresh_configuration_failure_zero_io_preserves_existing_session(tmp_path, mode):
    store = AssessmentStore(tmp_path / "agents.db")
    surface = refresh_surface()
    policy, spec, job = claim_refresh(store, refresh_policy(), surface)
    vault = private_file(tmp_path / "vault.json", vault_data(policy, surface))
    config = provider_data(policy, surface, "private-refresh-token")
    if mode == "wrong_actor":
        config["providers"][0]["actor_id"] = "bob"
    elif mode == "bad_body":
        config["providers"][0]["body_base64"] = "not!base64"
    provider = private_file(tmp_path / "providers.json", config)
    if mode == "permission":
        provider.chmod(0o644)
    elif mode == "missing_file":
        provider.unlink()
    result = await SessionRefreshService(policy, store, vault, provider).run(job, surface, spec)
    assert result.execution_status == "failed"
    assert result.coverage_status == "blocked"
    assert result.summary == {"requests": 0, "requests_admitted": 0}
    assert store.session_state(policy, surface) is None
    store.assert_session_revision(policy, surface)
    assert AuthReplayVault.from_file(vault, policy).authorize(surface)
    store.close()


async def test_actual_https_refresh_concurrent_operator_vault_change_preserved(tmp_path):
    token = secrets.token_urlsafe(24)
    seen = []
    operator_data = {}
    vault = tmp_path / "vault.json"

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(self.path)
            # A non-cooperating manual edit during network I/O must win over
            # the response derived from an earlier private-vault snapshot.
            private_file(vault, operator_data)
            response = json.dumps(
                {
                    "headers": {"Authorization": "Bearer new-server-token"},
                    "cookies": [],
                    "expires_at": time.time() + 300,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        store = AssessmentStore(tmp_path / "agents.db")
        surface = refresh_surface(fixture.origin)
        policy, spec, job = claim_refresh(store, refresh_policy(fixture.origin), surface)
        private_file(vault, vault_data(policy, surface))
        operator_data.update(vault_data(policy, surface))
        operator_data["entries"][0]["headers"] = {"Authorization": "Bearer manual-operator-change"}
        provider = private_file(tmp_path / "providers.json", provider_data(policy, surface, token))
        service = SessionRefreshService(
            policy, store, vault, provider, tls_config=BrowserTLSConfig(fixture.ca_file)
        )
        result = await service.run(job, surface, spec)
        assert result.coverage_status == "inconclusive"
        assert result.error["code"] == "session_refresh_vault_changed"
        assert json.loads(vault.read_text()) == operator_data
        assert store.session_state(policy, surface)["status"] == "uncertain"
        assert seen == ["/refresh"]
        store.close()


async def test_actual_https_refresh_rejects_untrusted_upstream_before_http_delivery(tmp_path):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(self.path)
            self.send_error(500)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        store = AssessmentStore(tmp_path / "agents.db")
        surface = refresh_surface(fixture.origin)
        policy, spec, job = claim_refresh(store, refresh_policy(fixture.origin), surface)
        vault = private_file(tmp_path / "vault.json", vault_data(policy, surface))
        providers = private_file(
            tmp_path / "providers.json", provider_data(policy, surface, "refresh-secret")
        )
        result = await SessionRefreshService(
            policy, store, vault, providers, tls_config=BrowserTLSConfig(fixture.wrong_ca_file)
        ).run(job, surface, spec)
        assert result.coverage_status == "blocked"
        assert result.error["code"] == "session_refresh_upstream_tls_failed"
        assert result.summary["requests"] == 0
        assert result.summary["requests_admitted"] == 1
        assert seen == []
        store.close()


async def test_actual_https_refresh_invalidates_only_old_actor_runtime_cache(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            response = json.dumps(
                {
                    "headers": {"Authorization": "Bearer rotated-test-session"},
                    "cookies": [],
                    "expires_at": time.time() + 300,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            pass

    cache = SmartCache(max_bytes=4096)
    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        store = AssessmentStore(tmp_path / "agents.db")
        surface = refresh_surface(fixture.origin)
        policy, spec, job = claim_refresh(store, refresh_policy(fixture.origin), surface)
        context = CacheContext(
            tenant=surface.tenant_id,
            engagement=policy.engagement_id,
            asset="owned-asset",
            actor=surface.actor_id,
            session_revision=surface.session_revision,
            policy_revision=policy.revision,
            workflow_state="reviewed",
            input_fingerprint="digest",
            tool_version="1",
            profile_version="1",
            template_version="1",
            deploy_revision="1",
        )
        assert cache.set("old-alice", {"result": "old-metadata"}, 60, context=context)
        assert cache.set(
            "other-actor", {"result": "bob-metadata"}, 60, context=replace(context, actor="bob")
        )
        assert cache.set(
            "new-alice",
            {"result": "new-metadata"},
            60,
            context=replace(context, session_revision="8"),
        )
        vault = private_file(tmp_path / "vault.json", vault_data(policy, surface))
        providers = private_file(
            tmp_path / "providers.json", provider_data(policy, surface, "provider-test-secret")
        )
        try:
            result = await SessionRefreshService(
                policy,
                store,
                vault,
                providers,
                tls_config=BrowserTLSConfig(fixture.ca_file),
                cache=cache,
            ).run(job, surface, spec)
            assert result.execution_status == "succeeded", result
            assert result.summary["cache_invalidated"] == 1
            assert cache.get("old-alice") is None
            assert cache.get("other-actor") == {"result": "bob-metadata"}
            assert cache.get("new-alice") == {"result": "new-metadata"}
            assert cache.stats()["invalidation_session_changed"] == 1
        finally:
            store.close()
            cache.close()
