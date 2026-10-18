"""Remote scope/DNS authorization tests; these are not live network scans."""

from __future__ import annotations

import socket

import pytest

from redjohn.assessment.policy import EngagementPolicy, PolicyDenied


def remote_policy(**changes) -> EngagementPolicy:
    return EngagementPolicy(
        **{
            "engagement_id": "remote-scope",
            "owner_id": "owner",
            "allowed_origins": ("https://service.example:8443",),
            "allowed_ips": ("203.0.113.0/24", "2001:db8::/32"),
            "egress_mode": "enforced",
            **changes,
        }
    )


def answers(*addresses: str):
    return [
        (
            socket.AF_INET6 if ":" in address else socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (address, 8443),
        )
        for address in addresses
    ]


def test_scope_metadata_never_authorizes_unsandboxed_remote_execution():
    policy = remote_policy()
    policy.check_scope_url("https://service.example:8443/read")
    policy.check_readonly_request("https://service.example:8443/read", "GET")
    with pytest.raises(PolicyDenied, match="remote_egress_boundary_required"):
        policy.check_url("https://service.example:8443/read")


def test_remote_connection_returns_only_an_approved_numeric_ip(monkeypatch):
    calls = []

    def resolve(host, port, **kwargs):
        calls.append((host, port, kwargs))
        return answers("2001:db8::7", "203.0.113.20")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    assert remote_policy().connection_ip("https://service.example:8443/read") == "203.0.113.20"
    assert calls == [("service.example", 8443, {"type": socket.SOCK_STREAM})]


@pytest.mark.parametrize("address", ["192.0.2.8", "127.0.0.1", "169.254.169.254", "::1"])
def test_one_unapproved_dns_answer_blocks_the_entire_connection(monkeypatch, address):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *_args, **_kwargs: answers("203.0.113.20", address)
    )
    with pytest.raises(PolicyDenied, match="resolved_ip_denied"):
        remote_policy().connection_ip("https://service.example:8443/read")


def test_dns_rebinding_is_rechecked_at_each_connection(monkeypatch):
    current = ["203.0.113.20"]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: answers(*current))
    policy = remote_policy()
    assert policy.connection_ip("https://service.example:8443/read") == "203.0.113.20"
    current[:] = ["192.0.2.8"]
    with pytest.raises(PolicyDenied, match="resolved_ip_denied"):
        policy.connection_ip("https://service.example:8443/read")


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "::1", "0.0.0.0"])
def test_remote_mode_refuses_special_addresses_even_when_cidr_is_broad(address):
    authority = f"[{address}]" if ":" in address else address
    url = f"https://{authority}:8443/read"
    policy = remote_policy(
        allowed_origins=(f"https://{authority}:8443",), allowed_ips=("0.0.0.0/0", "::/0")
    )
    with pytest.raises(PolicyDenied, match="remote_special_address_denied"):
        policy.check_scope_url(url)


def test_remote_mode_requires_https_and_explicit_ip_authorization():
    with pytest.raises(PolicyDenied, match="explicit_ip_allowlist"):
        remote_policy(allowed_ips=()).check_scope_url("https://service.example:8443/read")
    with pytest.raises(PolicyDenied, match="explicit_ip_allowlist"):
        remote_policy(allowed_origins=("http://service.example:8443",)).check_scope_url(
            "http://service.example:8443/read"
        )


def test_redirect_cannot_expand_origin_or_port_authorization():
    policy = remote_policy()
    for url in ("https://other.example:8443/read", "https://service.example:9443/read"):
        with pytest.raises(PolicyDenied, match="origin_denied"):
            policy.check_scope_url(url)
