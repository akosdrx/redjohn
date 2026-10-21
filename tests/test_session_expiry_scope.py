"""Actual private-vault expiry selection, without HTTP/browser/scanner I/O."""

import base64
import copy
import hashlib
import json
import time

import pytest

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.browser_capture import BrowserCaptureDenied, BrowserPostCaptureService
from redjohn.assessment.models import Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.store import AssessmentStore


@pytest.mark.parametrize(
    ("expired_binding", "expected_expired"),
    [
        ("unrelated_get", False),
        ("other_start_post", False),
        ("selected_get", True),
        ("selected_post", True),
    ],
)
def test_expiry_recovery_only_uses_bindings_for_the_selected_capture_start(
    tmp_path, expired_binding, expected_expired
):
    origin = "https://127.0.0.1:8443"
    store = AssessmentStore(tmp_path / "agents.db")
    policy = store.register(
        EngagementPolicy(
            "expiry-scope",
            "operator",
            (origin,),
            actor_ids=("alice",),
            profile="isolated-lab",
            egress_mode="local-fixture",
            allowed_replay_urls=(origin + "/json-a", origin + "/json-b"),
        )
    )
    body = b'{"value":"approved-sample"}'
    digest = hashlib.sha256(body).hexdigest()
    expiry = time.time() + 300
    common = {
        "engagement_id": policy.engagement_id,
        "owner_id": policy.owner_id,
        "actor_id": "alice",
        "tenant_id": "tenant-a",
        "session_revision": "7",
        "policy_revision": policy.revision,
        "origin": origin,
        "expires_at": expiry,
        "headers": {"Authorization": "Bearer sample-fixture-credential"},
        "cookies": [],
    }
    entries = []
    for suffix in ("a", "b"):
        entries.append(
            {
                **copy.deepcopy(common),
                "allowed_requests": [
                    {
                        "url": origin + "/app-" + suffix,
                        "method": "GET",
                        "request_ref": "anchor-" + suffix,
                    }
                ],
            }
        )
        entries.append(
            {
                **copy.deepcopy(common),
                "allowed_requests": [
                    {
                        "url": origin + "/json-" + suffix,
                        "method": "POST",
                        "request_ref": "capture-" + suffix,
                        "content_type": "application/json",
                        "body_base64": base64.b64encode(body).decode(),
                        "body_sha256": digest,
                        "replay_safety": "operator-approved",
                    }
                ],
            }
        )
    if expired_binding == "unrelated_get":
        stale = copy.deepcopy(entries[0])
        stale["allowed_requests"] = [
            {"url": origin + "/unrelated", "method": "GET", "request_ref": "unrelated-anchor"}
        ]
        stale["expires_at"] = time.time() - 1
        entries.append(stale)
    else:
        entries[{"selected_get": 0, "selected_post": 1, "other_start_post": 3}[expired_binding]][
            "expires_at"
        ] = time.time() - 1
    vault = {"version": 2, "entries": entries}
    rules = {
        "version": 1,
        "rules": [
            {
                **{
                    key: common[key]
                    for key in (
                        "engagement_id",
                        "owner_id",
                        "actor_id",
                        "tenant_id",
                        "policy_revision",
                        "session_revision",
                    )
                },
                "url": origin + "/json-" + suffix,
                "start_url": origin + "/app-" + suffix,
                "content_type": "application/json",
                "expires_at": expiry,
                "automatic_approval": True,
            }
            for suffix in ("a", "b")
        ],
    }
    vault_file, rule_file = tmp_path / "vault.json", tmp_path / "rules.json"
    for path, value in ((vault_file, vault), (rule_file, rules)):
        path.write_text(json.dumps(value))
        path.chmod(0o600)
    try:
        # Validate the complete private schema, including unrelated expired
        # entries. Only selected matching bindings may trigger recovery.
        AuthReplayVault.read_for_rotation(vault_file, policy)
        service = BrowserPostCaptureService(policy, store, vault_file, rule_file)
        assert service.context_metadata("alice", "tenant-a", "7")["session_revision"] == "7"
        if expected_expired:
            with pytest.raises(BrowserCaptureDenied, match=r"browser_capture_credentials_expired$"):
                service.context_metadata(
                    "alice", "tenant-a", "7", detect_expiry=True, start_url=origin + "/app-a"
                )
        else:
            for url, method, ref in (
                ("/app-a", "GET", "anchor-a"),
                ("/json-a", "POST", "capture-a"),
            ):
                surface = Surface(
                    origin + url,
                    method=method,
                    actor_id="alice",
                    tenant_id="tenant-a",
                    session_revision="7",
                    request_ref=ref,
                    content_type="application/json" if method == "POST" else "",
                    body_sha256=digest if method == "POST" else "",
                )
                assert (
                    AuthReplayVault.from_file_for_surface(vault_file, policy, surface)
                    .authorize(surface)
                    .expires_at
                    > time.time()
                )
            assert (
                service.context_metadata(
                    "alice", "tenant-a", "7", detect_expiry=True, start_url=origin + "/app-a"
                )["session_revision"]
                == "7"
            )
        assert not store.jobs(policy.engagement_id)
        assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 0
        assert store.recovery_status(policy)["refreshes_used"] == 0
    finally:
        store.close()
