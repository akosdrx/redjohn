"""Trusted-host, bounded observation of an explicitly approved authenticated POST.

This SDK helper is not an unrestricted agent tool. The operator supplies private
bytes/headers; only a digest and sent-request metadata enter durable inventory.
There are no redirects, automatic retries or inferred POST permissions.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import time
from dataclasses import replace
from typing import TYPE_CHECKING, NoReturn
from urllib.parse import urlsplit

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.policy import PolicyDenied, origin_for
from redjohn.assessment.request_body import MAX_REPLAY_BODY_BYTES, ApprovedRequestBody


if TYPE_CHECKING:
    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.models import Surface
    from redjohn.assessment.persistent_rate_limit import PersistentRateLimitDetector
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


class CaptureDenied(ValueError):  # noqa: N818 - stable SDK error contract
    """The approved request was rejected or its delivery needs reconciliation."""


def _url_key(url: str) -> str:
    parsed = urlsplit(url)
    return origin_for(url) + (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")


_AUTH_HEADERS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "cookie",
}


def _approved_capture(
    policy: EngagementPolicy,
    store: AssessmentStore,
    surface: Surface,
    body: bytes,
    headers: dict[str, str],
    *,
    body_contract_version: int = 1,
) -> ApprovedRequestBody:
    if store.policy(policy.engagement_id, policy.owner_id).to_dict() != policy.to_dict():
        raise PolicyDenied("stale_capture_policy")
    policy.check_actor(surface.actor_id)
    policy.check_replay_request(surface.url, surface.method)
    if surface.method != "POST" or surface.actor_id == "anonymous":
        raise CaptureDenied("capture_named_post_required")
    if not isinstance(body, bytes):
        raise CaptureDenied("capture_exact_bytes_required")
    if len(body) > MAX_REPLAY_BODY_BYTES:
        raise CaptureDenied("capture_body_limit")
    approved = ApprovedRequestBody.from_mapping(
        {
            "content_type": surface.content_type,
            "body_base64": base64.b64encode(body).decode(),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_contract_version": body_contract_version,
        }
    )
    if surface.body_sha256 and surface.body_sha256 != approved.sha256:
        raise CaptureDenied("capture_body_hash_mismatch")
    if (
        not isinstance(headers, dict)
        or not 1 <= len(headers) <= len(_AUTH_HEADERS)
        or any(
            not isinstance(name, str)
            or name.lower() not in _AUTH_HEADERS
            or not isinstance(value, str)
            or not value
            or len(value) > 8192
            or any(ord(char) < 32 or ord(char) > 126 for char in value)
            for name, value in headers.items()
        )
        or len({name.lower() for name in headers}) != len(headers)
        or sum(len(value) for value in headers.values()) > 8192
    ):
        raise CaptureDenied("capture_private_auth_headers_invalid")
    return approved


def _deny(code: str) -> NoReturn:
    raise CaptureDenied(code)


async def capture_authenticated_request(
    policy: EngagementPolicy,
    store: AssessmentStore,
    surface: Surface,
    *,
    body: bytes,
    headers: dict[str, str],
    tls_config: BrowserTLSConfig | None = None,
    rate_limits: PersistentRateLimitDetector | None = None,
    body_contract_version: int = 1,
) -> Surface:
    """Actually send one approved POST, then persist its secret-free observation.

    Body fields and upload bytes are retained byte-for-byte. A refreshed session
    needs a fresh observation; an old capture is never relabelled as a new actor
    or revision. Callers must authorize the endpoint's effects and own cleanup.
    """
    import httpx  # noqa: PLC0415 - selected optional HTTP adapter only

    approved = _approved_capture(
        policy, store, surface, body, headers, body_contract_version=body_contract_version
    )
    store.assert_session_revision(policy, surface)
    surface = replace(surface, body_sha256=approved.sha256)
    timeout = min(15.0, policy.deadline - time.time()) if policy.deadline else 15.0
    if timeout <= 0:
        raise PolicyDenied("campaign_deadline_exceeded")
    reservation = store.reserve_capture(policy, surface, timeout_seconds=timeout)
    if reservation["completed_surface_id"]:
        return store.surface(policy.engagement_id, reservation["completed_surface_id"])

    def replay(
        url: str, method: str, incoming: list[tuple[str, str]], data: bytes
    ) -> tuple[list[tuple[str, str]], bytes]:
        if _url_key(url) != _url_key(surface.url) or method != "POST" or data != approved.data:
            raise CaptureDenied("capture_request_mismatch")
        store.assert_session_revision(policy, surface)
        clean = [
            (name, value)
            for name, value in incoming
            if name.lower() not in _AUTH_HEADERS | {"content-type", "content-length"}
        ]
        return clean + list(headers.items()) + [("Content-Type", approved.content_type)], data

    def admit(url: str) -> None:
        policy.check_replay_request(url, "POST")
        if rate_limits is not None and not rate_limits.admit(origin_for(url)):
            raise CaptureDenied("capture_rate_limited")
        if not store.mark_capture_admitted(policy, reservation["key"], reservation["owner"]):
            raise CaptureDenied("capture_reservation_lost")

    def observe(url: str, status: int, response_headers: dict[str, str]) -> None:
        if rate_limits is not None:
            rate_limits.observe(origin_for(url), status, response_headers)

    proxy = BrowserEgressProxy(
        policy,
        tls_config=tls_config,
        request_replay=replay,
        request_admission=admit,
        on_response=observe,
        timeout_seconds=timeout,
        max_wire_bytes=80 * 1024,
    )
    try:
        await proxy.start()
        async with (
            asyncio.timeout(timeout),
            httpx.AsyncClient(
                proxy=proxy.url,
                verify=proxy.client_tls_context,
                trust_env=False,
                follow_redirects=False,
                timeout=timeout,
            ) as client,
            client.stream(
                "POST",
                surface.url,
                content=approved.data,
                headers={"Content-Type": approved.content_type, "Accept-Encoding": "identity"},
            ) as response,
        ):
            size = 0
            async for chunk in response.aiter_raw(chunk_size=4096):
                size += len(chunk)
                if size > 64 * 1024:
                    _deny("capture_response_limit")
            status = response.status_code
        metadata = {
            "url": surface.url,
            "method": "POST",
            "actor_id": surface.actor_id,
            "tenant_id": surface.tenant_id,
            "session_revision": surface.session_revision,
            "engagement_id": policy.engagement_id,
            "policy_revision": policy.revision,
            "content_type": approved.content_type,
            "request_content_type": approved.content_type,
            "body_sha256": approved.sha256,
            "body_bytes": len(approved.data),
            "sent": proxy.forwarded_requests == 1,
            "status": status,
            "response_complete": proxy.forwarded_requests == 1 and not proxy.limit_drops,
        }
        reference = store.evidence_put(
            policy.engagement_id, metadata, kind="authenticated_request_metadata"
        )
        if not metadata["sent"] or not metadata["response_complete"] or not 200 <= status < 300:
            _deny("capture_response_unverified")
        observed = replace(
            surface, source="observed", request_ref=reference, body_sha256=approved.sha256
        )
        if not store.finish_capture(policy, reservation["key"], reservation["owner"], observed):
            _deny("capture_commit_uncertain")
    except BaseException as exc:
        # A reservation outlives this process. Even a lost response or failed
        # evidence write must not cause a repeated state-changing request.
        # If storage itself is unavailable, its inflight lease later becomes
        # uncertain instead of permitting an automatic resend.
        with contextlib.suppress(Exception):
            store.fail_capture(
                policy, reservation["key"], reservation["owner"], "capture_request_failed"
            )
        if isinstance(exc, (httpx.HTTPError, TimeoutError, OSError)):
            raise CaptureDenied("capture_transport_inconclusive") from None
        raise
    else:
        return observed
    finally:
        await proxy.close()
