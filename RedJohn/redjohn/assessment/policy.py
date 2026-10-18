"""Explicit engagement authorization; observations never expand authorization."""

from __future__ import annotations

import ipaddress
import math
import re
import socket
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, unquote, urlsplit


if TYPE_CHECKING:
    from redjohn.assessment.models import Surface


class PolicyDenied(ValueError):  # noqa: N818 - public compatibility name
    code = "policy_denied"


def origin_for(url: str) -> str:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise PolicyDenied("invalid_url") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or any(ord(c) < 33 for c in url)
        or "\\" in url
    ):
        raise PolicyDenied("invalid_url")
    host = parsed.hostname.encode("idna").decode().lower()
    if ":" in host:
        host = f"[{host}]"
    default = 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{host}:{port or default}"


@dataclass(frozen=True)
class EngagementPolicy:
    engagement_id: str
    owner_id: str
    allowed_origins: tuple[str, ...]
    revision: str = "1"
    allowed_ips: tuple[str, ...] = ()
    profile: str = "safe-production"
    target_domains: tuple[str, ...] = ("web",)
    egress_mode: str = "unavailable"
    actor_ids: tuple[str, ...] = ("anonymous",)
    deadline: float = 0.0
    max_attempts: int = 2
    retry_budget: int = 4
    request_budget: int = 128
    allowed_replay_urls: tuple[str, ...] = ()
    allowed_refresh_urls: tuple[str, ...] = ()
    allowed_source_artifacts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all(
            isinstance(x, str) and 0 < len(x) <= 128
            for x in (
                self.engagement_id,
                self.owner_id,
                self.revision,
            )
        ):
            raise PolicyDenied("invalid_identity")
        if self.profile not in {"safe-production", "active-staging", "isolated-lab"}:
            raise PolicyDenied("invalid_profile")
        if (
            not set(self.target_domains).issubset(
                {"web", "network", "source", "cms", "cloud", "kubernetes", "binary-lab"}
            )
            or not self.target_domains
        ):
            raise PolicyDenied("invalid_target_domain")
        if self.egress_mode not in {"unavailable", "local-fixture", "enforced"}:
            raise PolicyDenied("invalid_egress_mode")
        if (
            not isinstance(self.allowed_source_artifacts, tuple)
            or len(self.allowed_source_artifacts) > 128
            or any(
                not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None
                for value in self.allowed_source_artifacts
            )
            or (self.allowed_source_artifacts and "source" not in self.target_domains)
        ):
            raise PolicyDenied("invalid_source_artifact_grants")
        if (not self.allowed_origins and not self.allowed_source_artifacts) or len(
            self.allowed_origins
        ) > 128:
            raise PolicyDenied("invalid_origin_allowlist")
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            origin_for(origin)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise PolicyDenied("allowlist_requires_origins")
        for address in self.allowed_ips:
            ipaddress.ip_network(address, strict=False)
        self._validate_post_allowlists()
        if not self.actor_ids or any(not x or len(x) > 128 for x in self.actor_ids):
            raise PolicyDenied("invalid_actor_allowlist")
        if (
            not math.isfinite(self.deadline)
            or self.deadline < 0
            or not 1 <= self.max_attempts <= 5
            or not 0 <= self.retry_budget <= 64
            or not 1 <= self.request_budget <= 100000
        ):
            raise PolicyDenied("invalid_execution_budget")

    def _validate_post_allowlists(self) -> None:
        for urls in (self.allowed_replay_urls, self.allowed_refresh_urls):
            if (
                not isinstance(urls, tuple)
                or len(urls) > 128
                or any(not isinstance(url, str) or len(url) > 4096 for url in urls)
            ):
                raise PolicyDenied("invalid_post_allowlist")
            for url in urls:
                if (
                    urlsplit(url).scheme != "https"
                    or urlsplit(url).fragment
                    or origin_for(url) not in {origin_for(item) for item in self.allowed_origins}
                ):
                    raise PolicyDenied("post_allowlist_requires_scoped_https")
        if (
            self.allowed_replay_urls or self.allowed_refresh_urls
        ) and self.profile == "safe-production":
            raise PolicyDenied("post_requires_active_profile")

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> EngagementPolicy:
        if not isinstance(value, dict) or set(value) - set(cls.__dataclass_fields__):
            raise PolicyDenied("invalid_policy_schema")
        value = dict(value)
        for field in (
            "allowed_origins",
            "allowed_ips",
            "actor_ids",
            "target_domains",
            "allowed_replay_urls",
            "allowed_refresh_urls",
            "allowed_source_artifacts",
        ):
            if field in value:
                if not isinstance(value[field], (list, tuple)) or not all(
                    isinstance(item, str) for item in value[field]
                ):
                    raise PolicyDenied("invalid_policy_schema")
                value[field] = tuple(value[field])
        return cls(**value)

    def to_dict(self) -> dict[str, Any]:
        document = asdict(self)
        # Old signed approvals and persisted policy JSON must remain byte-for-
        # byte canonical when no new source capability was granted.
        if not self.allowed_source_artifacts:
            document.pop("allowed_source_artifacts")
        return document

    def check_surface(self, surface: Surface) -> None:
        """Source permission comes from an explicit digest grant, never discovery."""
        if surface.resource_kind != "source_artifact":
            self.check_scope_url(surface.url)
            return
        if self.deadline and time.time() >= self.deadline:
            raise PolicyDenied("campaign_deadline_exceeded")
        if (
            "source" not in self.target_domains
            or surface.artifact_sha256 not in self.allowed_source_artifacts
        ):
            raise PolicyDenied("source_artifact_not_approved")

    @staticmethod
    def resource_identity(surface: Surface) -> str:
        if surface.resource_kind == "source_artifact":
            return "source_artifact:" + surface.artifact_sha256
        return origin_for(surface.url)

    def authorize(self, caller: str, revision: str | None = None) -> None:
        if caller != self.owner_id:
            raise PolicyDenied("engagement_access_denied")
        if revision is not None and revision != self.revision:
            raise PolicyDenied("stale_policy_revision")

    def check_actor(self, actor_id: str) -> None:
        if actor_id not in self.actor_ids:
            raise PolicyDenied("actor_denied")

    def check_url(self, url: str) -> None:
        self.check_scope_url(url)
        if self.egress_mode == "enforced":
            raise PolicyDenied("remote_egress_boundary_required")

    def check_inventory_url(self, url: str) -> None:
        """Authorize recording a target, without approving any network activity."""
        if self.deadline and time.time() >= self.deadline:
            raise PolicyDenied("campaign_deadline_exceeded")
        if origin_for(url) not in {origin_for(item) for item in self.allowed_origins}:
            raise PolicyDenied("origin_denied")

    def check_scope_url(self, url: str) -> None:
        """Validate authorization; this alone never authorizes worker execution."""
        self.check_inventory_url(url)
        host = urlsplit(url).hostname
        if host is None:
            raise PolicyDenied("invalid_url")
        if self.egress_mode == "local-fixture":
            # No DNS alias/rebinding. Only the operator's literal loopback fixture.
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError as exc:
                raise PolicyDenied("fixture_requires_literal_loopback") from exc
            if self.profile != "isolated-lab" or not loopback:
                raise PolicyDenied("fixture_requires_isolated_loopback_lab")
        elif self.egress_mode == "enforced":
            if urlsplit(url).scheme != "https" or not self.allowed_ips:
                raise PolicyDenied("remote_https_requires_explicit_ip_allowlist")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                pass  # DNS is resolved and pinned immediately before connect.
            else:
                self._check_addresses((str(address),), remote=True)
        else:
            raise PolicyDenied("blocked_egress_enforcement_unavailable")
        if self.egress_mode == "local-fixture" and self.allowed_ips:
            self._check_addresses((host,), remote=False)

    def _check_addresses(self, addresses: tuple[str, ...], *, remote: bool) -> None:
        nets = [ipaddress.ip_network(value, strict=False) for value in self.allowed_ips]
        if not addresses or any(
            not any(ipaddress.ip_address(ip) in net for net in nets) for ip in addresses
        ):
            raise PolicyDenied("resolved_ip_denied")
        if remote and any(
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            for address in map(ipaddress.ip_address, addresses)
        ):
            raise PolicyDenied("remote_special_address_denied")

    def connection_ip(self, url: str) -> str:
        """Return one approved numeric destination; the socket must use this IP.

        The original hostname remains the TLS server name and HTTP Host. All
        DNS answers must fit the explicit IP/CIDR allowlist, including IPv6.
        """
        self.check_scope_url(url)
        parsed = urlsplit(url)
        host = parsed.hostname
        assert host is not None
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            addresses = tuple(
                {
                    str(entry[4][0])
                    for entry in socket.getaddrinfo(
                        host, parsed.port or 443, type=socket.SOCK_STREAM
                    )
                }
            )
            self._check_addresses(addresses, remote=True)
            return sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, item))[0]

    def check_capability(self, *, domains: tuple[str, ...], profiles: tuple[str, ...]) -> None:
        if not set(domains).intersection(self.target_domains) or self.profile not in profiles:
            raise PolicyDenied("capability_profile_denied")

    def check_readonly_request(self, url: str, method: str) -> None:
        """Deny unsafe methods and known state-changing read routes before egress.

        URL spelling cannot establish arbitrary application semantics. Remote
        workers additionally require an attested OS egress boundary at launch.
        """
        self.check_scope_url(url)
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            raise PolicyDenied("readonly_method_denied")
        parsed = urlsplit(url)

        def decode(value: str) -> str:
            for _ in range(8):
                decoded = unquote(value, errors="strict")
                if decoded == value:
                    return value
                value = decoded
            raise PolicyDenied("ambiguous_readonly_url")

        decoded = decode(parsed.path)
        operations = {
            "logout",
            "signout",
            "delete",
            "remove",
            "destroy",
            "checkout",
            "purchase",
            "payment",
            "transfer",
            "unsubscribe",
            "revoke",
            "invite",
            "sendemail",
            "sendmail",
            "resetpassword",
        }

        def unsafe(value: str) -> bool:
            tokens = re.split(r"[^a-z0-9]+", value.casefold())
            return bool(operations.intersection(tokens)) or "".join(tokens) in operations

        if any(unsafe(segment) for segment in re.split(r"[/\\;]", decoded)) or any(
            unsafe(decode(value))
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if decode(key).casefold() in {"action", "operation", "command", "do"}
        ):
            raise PolicyDenied("state_changing_read_route_denied")

    @staticmethod
    def _request_url(url: str) -> str:
        parsed = urlsplit(url)
        if parsed.fragment:
            raise PolicyDenied("post_fragment_denied")
        return origin_for(url) + (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")

    def _check_post(self, url: str, method: str, urls: tuple[str, ...], code: str) -> None:
        self.check_scope_url(url)
        if (
            method != "POST"
            or self.profile not in {"active-staging", "isolated-lab"}
            or urlsplit(url).scheme != "https"
            or self._request_url(url) not in {self._request_url(item) for item in urls}
        ):
            raise PolicyDenied(code)

    def check_replay_request(self, url: str, method: str) -> None:
        """Permit only explicit POST endpoints; credentials/body need a separate binding."""
        if method in {"GET", "HEAD", "OPTIONS"}:
            self.check_readonly_request(url, method)
            return
        self._check_post(url, method, self.allowed_replay_urls, "post_replay_not_authorized")

    def check_refresh_request(self, url: str, method: str) -> None:
        """Refresh authorization does not grant ordinary scanner POST access."""
        self._check_post(url, method, self.allowed_refresh_urls, "session_refresh_not_authorized")
