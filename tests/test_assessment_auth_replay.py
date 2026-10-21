"""Credential capability boundaries; no network or scanner doubles claim E2E."""

from __future__ import annotations

import copy
import json
import os
import time
from base64 import b64encode
from dataclasses import replace
from typing import TYPE_CHECKING
from urllib.parse import quote

import pytest

from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault
from redjohn.assessment.models import Surface
from redjohn.assessment.policy import EngagementPolicy


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def auth_policy() -> EngagementPolicy:
    return EngagementPolicy(
        "auth-fixture",
        "owner",
        ("https://127.0.0.1:8443",),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("anonymous", "alice", "bob"),
    )


@pytest.fixture
def captured_surface() -> Surface:
    return Surface(
        "https://127.0.0.1:8443/marker?a=1&a=2",
        actor_id="alice",
        tenant_id="tenant-a",
        session_revision="7",
        request_ref="evidence-request-1",
    )


def auth_data(policy: EngagementPolicy, surface: Surface) -> dict:
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
                "expires_at": time.time() + 300,
                "origin": "https://127.0.0.1:8443",
                "allowed_requests": [
                    {
                        "url": surface.url,
                        "method": surface.method,
                        "request_ref": surface.request_ref,
                    }
                ],
                "headers": {"Authorization": "Bearer private-token+/="},
                "cookies": [{"name": "session", "value": "private-cookie-token"}],
            }
        ],
    }


def test_private_file_and_exact_actor_revision_request_binding(
    tmp_path: Path, auth_policy: EngagementPolicy, captured_surface: Surface
) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps(auth_data(auth_policy, captured_surface)))
    path.chmod(0o600)
    vault = AuthReplayVault.from_file(path, auth_policy)
    binding = vault.authorize(captured_surface)
    headers = binding.rewrite_headers(
        captured_surface.url,
        "GET",
        [
            ("Accept", "*/*"),
            ("Cookie", "session=bob"),
            ("Authorization", "Bearer wrong"),
        ],
    )
    assert headers == [
        ("Accept", "*/*"),
        ("Authorization", "Bearer private-token+/="),
        ("Cookie", "session=private-cookie-token"),
    ]
    assert "private-token" not in repr(binding)
    assert "private-token" not in json.dumps(binding.metadata())


@pytest.mark.parametrize(
    "changes",
    [
        {"actor_id": "bob"},
        {"tenant_id": "tenant-b"},
        {"session_revision": "8"},
        {"request_ref": "other-evidence"},
        {"url": "https://127.0.0.1:8443/marker?a=2&a=1"},
        {"method": "HEAD"},
        {"source": "inferred"},
        {"source": "imported"},
        {"request_ref": ""},
    ],
)
def test_wrong_identity_or_capture_never_gets_credentials(
    auth_policy: EngagementPolicy, captured_surface: Surface, changes: dict
) -> None:
    vault = AuthReplayVault.from_mapping(auth_data(auth_policy, captured_surface), auth_policy)
    with pytest.raises(AuthReplayDenied):
        vault.authorize(replace(captured_surface, **changes))


@pytest.mark.parametrize(
    "url,method",
    [
        ("https://127.0.0.1:8444/marker?a=1&a=2", "GET"),
        ("https://127.0.0.1:8443/other", "GET"),
        ("https://127.0.0.1:8443/marker?a=1&a=2", "POST"),
    ],
)
def test_bound_proxy_denies_redirect_or_different_method(
    auth_policy: EngagementPolicy, captured_surface: Surface, url: str, method: str
) -> None:
    binding = AuthReplayVault.from_mapping(
        auth_data(auth_policy, captured_surface), auth_policy
    ).authorize(captured_surface)
    with pytest.raises(AuthReplayDenied, match="auth_replay_request_mismatch"):
        binding.rewrite_headers(url, method, [])


def test_rotation_cannot_mutate_existing_binding_and_expiry_rechecked(
    auth_policy: EngagementPolicy, captured_surface: Surface, monkeypatch
) -> None:
    data = auth_data(auth_policy, captured_surface)
    expiry = data["entries"][0]["expires_at"]
    vault = AuthReplayVault.from_mapping(data, auth_policy)
    data["entries"][0]["headers"]["Authorization"] = "Bearer unexpected"
    binding = vault.authorize(captured_surface)
    assert (
        dict(binding.headers_for(captured_surface.url, "GET"))["Authorization"]
        == "Bearer private-token+/="
    )
    monkeypatch.setattr("redjohn.assessment.auth_replay.time.time", lambda: expiry + 1)
    with pytest.raises(AuthReplayDenied, match="auth_replay_expired"):
        binding.headers_for(captured_surface.url, "GET")


def test_default_https_port_normalization_keeps_exact_path_and_query(
    auth_policy: EngagementPolicy, captured_surface: Surface
) -> None:
    data = auth_data(auth_policy, captured_surface)
    default_policy = replace(auth_policy, allowed_origins=("https://127.0.0.1:443",))
    surface = replace(captured_surface, url="https://127.0.0.1/marker?a=1&a=2")
    data["entries"][0]["origin"] = "https://127.0.0.1:443"
    data["entries"][0]["allowed_requests"][0]["url"] = surface.url
    binding = AuthReplayVault.from_mapping(data, default_policy).authorize(surface)
    assert binding.headers_for("https://127.0.0.1:443/marker?a=1&a=2", "GET")
    with pytest.raises(AuthReplayDenied, match="request_mismatch"):
        binding.headers_for("https://127.0.0.1:443/marker?a=2&a=1", "GET")


def test_secret_file_permissions_symlinks_and_hardlinks_denied(
    tmp_path: Path, auth_policy: EngagementPolicy, captured_surface: Surface
) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps(auth_data(auth_policy, captured_surface)))
    path.chmod(0o644)
    with pytest.raises(AuthReplayDenied, match="not_private"):
        AuthReplayVault.from_file(path, auth_policy)
    path.chmod(0o600)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(path)
    with pytest.raises(AuthReplayDenied, match="unavailable"):
        AuthReplayVault.from_file(symlink, auth_policy)
    os.link(path, tmp_path / "hardlink")
    with pytest.raises(AuthReplayDenied, match="not_private"):
        AuthReplayVault.from_file(path, auth_policy)


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("expires_at", 1, "expired"),
        ("owner_id", "other-owner", "policy_mismatch"),
        ("policy_revision", "2", "policy_mismatch"),
        ("headers", {"Authorization": "Bearer secret\r\nX-Evil: yes"}, "invalid_secret_schema"),
        ("headers", {"Host": "offscope.example"}, "invalid_headers"),
        ("cookies", [{"name": "a", "value": "token;other=x"}], "invalid_cookies"),
    ],
)
def test_invalid_vault_is_denial_with_secret_free_code(
    auth_policy: EngagementPolicy, captured_surface: Surface, field: str, value: object, code: str
) -> None:
    data = auth_data(auth_policy, captured_surface)
    data["entries"][0][field] = value
    with pytest.raises(AuthReplayDenied, match=code) as error:
        AuthReplayVault.from_mapping(data, auth_policy)
    assert "secret\r\n" not in str(error.value)


def test_reflected_secret_redaction_before_any_raw_evidence(
    auth_policy: EngagementPolicy, captured_surface: Surface
) -> None:
    binding = AuthReplayVault.from_mapping(
        auth_data(auth_policy, captured_surface), auth_policy
    ).authorize(captured_surface)
    token = "private-token+/="  # noqa: S105 - harmless local fixture credential
    raw = {
        "stdout": f"{token} {quote(token, safe='')} {b64encode(token.encode()).decode()}",
        "stderr": "session=private-cookie-token",
    }
    sanitized = binding.redact_raw(copy.deepcopy(raw))
    assert token not in json.dumps(sanitized)
    assert "private-cookie-token" not in json.dumps(sanitized)
    assert "[redacted]" in sanitized["stdout"]
