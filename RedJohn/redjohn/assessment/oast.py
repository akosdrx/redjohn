"""Bounded Interactsh 1.4.1 protocol adapter with durable late correlation.

This trusted host client implements registration, RSA-OAEP/AES-CTR polling
and deregistration. It does not start a public receiver or an upstream CLI.
One reviewed captured GET may carry a generated HTTP callback to an explicitly
approved, independently scoped receiver. A callback remains a candidate signal.
Secrets and private keys live only in private host files, never job/evidence JSON.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlsplit

from redjohn.assessment.auth_replay import AuthReplayBinding, AuthReplayDenied, AuthReplayVault
from redjohn.assessment.body_tokens import BodyTokenDenied
from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.input_replay import InputReplayDenied, PrivateBodyInput, validate_post_input
from redjohn.assessment.models import (
    AdapterResult,
    CoverageStatus,
    JobSpec,
    Surface,
    error_record,
    stable_key,
)
from redjohn.assessment.policy import PolicyDenied, origin_for
from redjohn.assessment.session_recovery import auth_recovery_marker
from redjohn.assessment.session_refresh import (
    SessionRefreshDenied,
    _atomic_private_json,
    _fingerprint,
    _private_json,
)
from redjohn.assessment.specialists import PARAMETER, captured_request, replace_query_value
from redjohn.assessment.store import CapacityExceeded


if TYPE_CHECKING:
    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.contracts import HTTPRateLimits
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


class OASTDenied(ValueError):  # noqa: N818 - stable secret-free policy code
    pass


@dataclass(frozen=True)
class OASTConfig:
    receiver_url: str
    receiver_ips: tuple[str, ...]
    callback_domain: str
    callback_port: int = 80
    token_file: Path | None = None
    window_seconds: int = 20
    poll_interval: int = 3
    max_polls: int = 8
    request_timeout: int = 3
    version: str = "1.4.1"

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> OASTConfig:
        if (
            not isinstance(value, dict)
            or set(value)
            - {
                "receiver_url",
                "receiver_ips",
                "callback_domain",
                "callback_port",
                "token_file",
                "window_seconds",
                "poll_interval",
                "max_polls",
                "request_timeout",
            }
            or not isinstance(value.get("receiver_url"), str)
            or not isinstance(value.get("receiver_ips"), list)
            or not 1 <= len(value["receiver_ips"]) <= 16
            or not all(isinstance(ip, str) for ip in value["receiver_ips"])
            or not isinstance(value.get("callback_domain"), str)
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,188}[a-z0-9])?", value["callback_domain"])
            or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in value["callback_domain"].split(".")
            )
        ):
            raise ValueError("invalid_owned_oast_configuration")
        parsed = urlsplit(value["receiver_url"])
        if (
            parsed.scheme != "https"
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("oast_requires_exact_https_receiver_origin")
        token = value.get("token_file")
        if token is not None and (not isinstance(token, str) or not Path(token).is_absolute()):
            raise ValueError("oast_private_token_file_required")
        result = cls(
            origin_for(value["receiver_url"]),
            tuple(str(ipaddress.ip_address(item)) for item in value["receiver_ips"]),
            value["callback_domain"],
            value.get("callback_port", 80),
            Path(token) if token else None,
            value.get("window_seconds", 20),
            value.get("poll_interval", 3),
            value.get("max_polls", 8),
            value.get("request_timeout", 3),
        )
        if any(
            type(x) is not int
            for x in (
                result.callback_port,
                result.window_seconds,
                result.poll_interval,
                result.max_polls,
                result.request_timeout,
            )
        ) or not (
            1 <= result.callback_port <= 65535
            and 3 <= result.window_seconds <= 60
            and 1 <= result.poll_interval <= 10
            and 2 <= result.max_polls <= 16
            and 1 <= result.request_timeout <= 10
            and (result.max_polls - 1) * result.poll_interval >= result.window_seconds
        ):
            raise ValueError("invalid_oast_window_or_request_bounds")
        return result

    @property
    def revision(self) -> str:
        return stable_key(
            [
                "redjohn-interactsh-protocol-v3-private-body-input",
                self.version,
                self.receiver_url,
                self.receiver_ips,
                self.callback_domain,
                self.callback_port,
                self.window_seconds,
                self.poll_interval,
                self.max_polls,
            ]
        )

    def service_policy(self, policy: EngagementPolicy) -> EngagementPolicy:
        return replace(
            policy,
            allowed_origins=(self.receiver_url,),
            allowed_ips=self.receiver_ips,
            allowed_replay_urls=(),
            allowed_refresh_urls=(),
            actor_ids=("anonymous",),
        )


def ensure_oast(store: AssessmentStore) -> None:
    with store.transaction() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS rj_oast_followup(
            allocation TEXT PRIMARY KEY, engagement TEXT NOT NULL, surface TEXT NOT NULL,
            parent_job TEXT NOT NULL, poll_index INTEGER NOT NULL, ready_at REAL NOT NULL,
            emitted INTEGER NOT NULL DEFAULT 0, revision TEXT NOT NULL)""")


def reconcile_oast(store: AssessmentStore, policy: EngagementPolicy, config: OASTConfig) -> None:
    rows = store.db.execute(
        "SELECT f.* FROM rj_oast_followup f JOIN rj_job j ON j.id=f.parent_job "
        "WHERE f.engagement=? AND f.emitted=0 AND j.execution_status='succeeded' LIMIT 32",
        (policy.engagement_id,),
    ).fetchall()
    for row in rows:
        if row["revision"] != config.revision:
            continue
        spec = JobSpec(
            row["surface"],
            "oast",
            "oast_poll",
            tool_version=config.version,
            template_version=config.revision,
            policy_revision=policy.revision,
            options={"allocation": row["allocation"], "poll_index": row["poll_index"]},
            timeout_seconds=min(30, config.request_timeout + 5),
            idempotent=store.surface(policy.engagement_id, row["surface"]).method != "POST",
        )
        child = store.submit(policy, [spec])[0]
        with store.transaction() as db:
            db.execute(
                "UPDATE rj_job SET ready_at=MAX(ready_at,?) "
                "WHERE id=? AND execution_status='queued'",
                (row["ready_at"], child),
            )
            db.execute(
                "UPDATE rj_oast_followup SET emitted=1 "
                "WHERE allocation=? AND parent_job=? AND poll_index=?",
                (row["allocation"], row["parent_job"], row["poll_index"]),
            )


class OASTAdapter:
    resource_class = "worker"
    owner_process_only = True

    def __init__(
        self,
        config: OASTConfig,
        policy: EngagementPolicy,
        store: AssessmentStore,
        rate_limits: HTTPRateLimits,
        *,
        tls_config: BrowserTLSConfig | None = None,
        auth_vault_file: str | Path | None = None,
        session_recovery_enabled: bool = False,
    ) -> None:
        self.config, self.policy, self.store, self.rate_limits = config, policy, store, rate_limits
        self.tls_config = tls_config
        self.auth_vault_file = auth_vault_file
        self.session_recovery_enabled = session_recovery_enabled
        self.private_root = store.path.parent / "oast-private"
        self.proxy: BrowserEgressProxy | None = None
        self.partial_evidence_refs: tuple[str, ...] = ()
        self.requests = 0
        ensure_oast(store)

    def _file(self, allocation: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{64}", allocation):
            raise OASTDenied("invalid_oast_allocation")
        self.private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.private_root.is_symlink() or self.private_root.stat().st_mode & 0o077:
            raise OASTDenied("oast_private_directory_required")
        return self.private_root / (allocation + ".json")

    def _save(self, allocation: str, value: dict[str, Any]) -> None:
        path = self._file(allocation)
        _atomic_private_json(path, value, _fingerprint(path.stat(follow_symlinks=False)))

    def _new(self, allocation: str, surface: Surface, spec: JobSpec) -> dict[str, Any]:
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415

        if len(list(self.private_root.glob("*.json"))) >= 64:
            raise OASTDenied("oast_allocation_capacity")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # XID wire format: 4-byte epoch + 8 cryptographically random bytes,
        # RFC4648 base32hex lowercase. No machine/process identifier.
        correlation = (
            base64.b32hexencode(int(time.time()).to_bytes(4, "big") + secrets.token_bytes(8))
            .decode()
            .lower()
            .rstrip("=")
        )
        # Upstream validates the suffix as z-base-32, not hex/base32hex.
        full_id = correlation + "".join(
            secrets.choice("ybndrfg8ejkmcpqxot1uwisza345h769") for _ in range(13)
        )
        public = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public = public.replace(
            b"PUBLIC KEY", b"RSA PUBLIC KEY"
        )  # upstream PKIX bytes with this PEM label
        state = {
            "engagement": self.policy.engagement_id,
            "policy": self.policy.revision,
            "surface": surface.key,
            "job_key": spec.key,
            "revision": self.config.revision,
            "created_at": time.time(),
            "expires_at": time.time() + self.config.window_seconds,
            "correlation": correlation,
            "full_id": full_id,
            "secret": secrets.token_hex(32),
            "public": base64.b64encode(public).decode(),
            "private": key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            "phase": "prepared",
            "dispatch_complete": False,
            "nonce": secrets.token_hex(16),
            "event_hashes": [],
            "event_refs": {},
            "pending_events": [],
            "poll_inflight": False,
            "request_ref": surface.request_ref,
        }
        descriptor = os.open(
            self._file(allocation), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "w") as stream:
            json.dump(state, stream)
            stream.flush()
            os.fsync(stream.fileno())
        return state

    async def _request(  # noqa: PLR0915 - bounded host transport and complete-response auth gate
        self,
        policy: EngagementPolicy,
        url: str,
        method: str = "GET",
        body: bytes = b"",
        *,
        token: str = "",
        binding: AuthReplayBinding | None = None,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        import httpx  # noqa: PLC0415 - explicit adapter only

        def admit(actual: str) -> None:
            if actual != url or self.requests >= 6:
                raise OASTDenied("oast_request_budget_exhausted")
            if not self.rate_limits.admit(origin_for(actual)):
                raise OASTDenied("shared_origin_cooldown")
            if binding is not None:
                binding.validate(binding.url, method, self.policy)
            self.store.consume_requests(self.policy)
            self.requests += 1

        def check(actual: str, actual_method: str) -> None:
            policy.check_scope_url(actual)
            if actual != url or actual_method != method:
                raise OASTDenied("oast_exact_host_request_required")

        def replay(
            actual: str, actual_method: str, fields: list[tuple[str, str]], data: bytes
        ) -> tuple[list[tuple[str, str]], bytes]:
            check(actual, actual_method)
            if data != body:
                raise OASTDenied("oast_host_body_mismatch")
            clean = [
                (k, v)
                for k, v in fields
                if k.lower() not in {"authorization", "cookie", "content-length"}
            ]
            if token:
                clean.append(("Authorization", token))
            if binding is not None:
                clean = binding.rewrite_headers(binding.url, method, clean)
            return clean, body

        proxy = BrowserEgressProxy(
            policy,
            max_connections=1,
            max_wire_bytes=128 * 1024,
            timeout_seconds=self.config.request_timeout,
            tls_config=self.tls_config,
            request_policy=check,
            request_replay=replay,
            request_admission=admit,
        )
        self.proxy = proxy
        try:
            await proxy.start()
            async with (
                httpx.AsyncClient(
                    proxy=proxy.url,
                    verify=proxy.client_tls_context,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=self.config.request_timeout,
                ) as client,
                client.stream(
                    method,
                    url,
                    content=body,
                    headers={"Content-Type": content_type, "Accept-Encoding": "identity"},
                ) as response,
            ):
                self.rate_limits.observe(origin_for(url), response.status_code, response.headers)
                if proxy.upstream_tls_failures:
                    raise OASTDenied("oast_upstream_tls_failed")
                if proxy.denied_requests or proxy.admission_denials or proxy.limit_drops:
                    raise OASTDenied("oast_receiver_egress_or_admission_denied")
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise OASTDenied("oast_http_response_or_encoding_invalid")
                raw = bytearray()
                async for chunk in response.aiter_raw(chunk_size=4096):
                    if len(raw) + len(chunk) > 65536:
                        raise OASTDenied("oast_response_limit")
                    raw.extend(chunk)
                # Only a complete bounded response may authorize refresh.
                if response.status_code == 401 and binding is not None:
                    raise AuthReplayDenied("authentication_expired")
                if response.status_code in {401, 403}:
                    raise OASTDenied("oast_receiver_or_target_auth_denied")
                if response.status_code in {429, 503}:
                    raise OASTDenied("oast_rate_limited_or_unavailable")
                if 300 <= response.status_code < 400:
                    raise OASTDenied("oast_redirect_denied")
                if response.status_code != 200:
                    raise OASTDenied("oast_http_response_or_encoding_invalid")
            if proxy.upstream_tls_failures or proxy.denied_requests or proxy.admission_denials:
                raise OASTDenied("oast_proxy_or_tls_denied")
            return {"body": bytes(raw), "status": 200}
        finally:
            await proxy.close()
            self.proxy = None

    def _events(self, response: dict[str, Any], state: dict[str, Any]) -> list[dict[str, Any]]:
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: PLC0415
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: PLC0415

        if not isinstance(response, dict):
            raise OASTDenied("oast_poll_document_invalid")
        data = response.get("data")
        if data is None:
            data = []
        if (
            not isinstance(data, list)
            or len(data) > 16
            or response.get("extra")
            or response.get("tlddata")
        ):
            raise OASTDenied("oast_poll_schema_or_event_limit")
        key = serialization.load_pem_private_key(state["private"].encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise OASTDenied("oast_private_key_invalid")
        aes = key.decrypt(
            base64.b64decode(response["aes_key"], validate=True),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        if len(aes) != 32:
            raise OASTDenied("oast_invalid_session_aes_key")
        if not data:
            return []
        events = []
        for encoded in data:
            encrypted = base64.b64decode(encoded, validate=True)
            if len(encrypted) < 16 or len(encrypted) > 32768:
                raise OASTDenied("oast_encrypted_event_size")
            cipher = Cipher(algorithms.AES(aes), modes.CTR(encrypted[:16])).decryptor()
            item = json.loads(cipher.update(encrypted[16:]) + cipher.finalize())
            instant = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
            if instant.tzinfo is None:
                raise OASTDenied("oast_event_timestamp_requires_timezone")
            timestamp = instant.timestamp()
            if (
                item.get("unique-id") != state["full_id"]
                or item.get("full-id") != state["full_id"]
                or item.get("protocol") not in {"http", "https"}
                or not state.get("dispatch_at")
                or not state["dispatch_at"] - 1
                <= timestamp
                <= min(state["expires_at"], time.time()) + 1
                or not item.get("raw-request", "").startswith(
                    "GET /rj/" + state["nonce"] + " HTTP/1.1\r\n"
                )
            ):
                raise OASTDenied("oast_event_correlation_or_window_mismatch")
            events.append(
                {
                    "event_sha256": stable_key(item),
                    "protocol": item["protocol"],
                    "callback_timestamp": timestamp,
                    "received_at": time.time(),
                    "token_fingerprint": hashlib.sha256(state["full_id"].encode()).hexdigest(),
                    "request_ref": state["request_ref"],
                    "impact": "callback_only_execution_unproven",
                }
            )
        return events

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:  # noqa: PLR0912, PLR0915
        import httpx  # noqa: PLC0415

        self.requests, self.partial_evidence_refs = 0, ()
        c, p = self.config, self.policy
        allocation = (
            spec.key if spec.capability == "oast_correlate" else spec.options.get("allocation", "")
        )
        try:
            polling = spec.capability == "oast_poll"
            if surface.method == "POST":
                validate_post_input(p, surface, spec)
            else:
                p.check_readonly_request(surface.url, surface.method)
            p.check_actor(surface.actor_id)
            if (
                (
                    surface.method != "POST"
                    and (
                        surface.method != "GET"
                        or surface.content_type
                        or surface.body_sha256
                        or surface.input_location != "query"
                        or not PARAMETER.fullmatch(surface.input_name)
                    )
                )
                or spec.tool_version != c.version
                or spec.template_version != c.revision
            ):
                raise OASTDenied("oast_requires_reviewed_supported_input")
            captured_request(self.store, p, surface, current_session=not polling)
            binding = None
            selected = None
            if not polling and surface.actor_id != "anonymous":
                if self.auth_vault_file is None:
                    raise AuthReplayDenied("auth_replay_credentials_missing")
                binding = AuthReplayVault.from_file_for_surface(
                    self.auth_vault_file, p, surface
                ).authorize(surface)
                if surface.method == "POST":
                    capture = json.loads(
                        self.store.evidence_get(p.engagement_id, surface.request_ref)["excerpt"]
                    )
                    if (
                        capture.get("response_complete") is not True
                        or capture.get("status") != 200
                        or capture.get("body_sha256") != surface.body_sha256
                        or capture.get("request_content_type", capture.get("content_type"))
                        != surface.content_type
                    ):
                        raise OASTDenied("oast_complete_post_capture_required")
                    selected = PrivateBodyInput.from_binding(binding, surface)
            if spec.capability == "oast_correlate":
                if (
                    set(spec.options) != {"hint_ref"}
                    or not isinstance(spec.options["hint_ref"], str)
                    or not re.fullmatch(r"[a-f0-9]{32}", spec.options["hint_ref"])
                ):
                    raise OASTDenied("oast_reviewed_hint_required")
                hint = self.store.evidence_get(p.engagement_id, spec.options["hint_ref"])
                signal = json.loads(hint["excerpt"])
                if hint["truncated"] or signal != {
                    "signal": "oast_http",
                    "request_ref": surface.request_ref,
                    "input_name": surface.input_name,
                }:
                    raise OASTDenied("oast_hint_capture_mismatch")
            elif spec.capability != "oast_poll" or set(spec.options) != {
                "allocation",
                "poll_index",
            }:
                raise OASTDenied("invalid_oast_poll_job")
            file = self._file(allocation)
            if spec.capability == "oast_poll" and not file.exists():
                raise OASTDenied("oast_poll_private_allocation_missing")
            state = _private_json(file) if file.exists() else self._new(allocation, surface, spec)
            if any(
                state.get(k) != v
                for k, v in {
                    "engagement": p.engagement_id,
                    "policy": p.revision,
                    "surface": surface.key,
                    "revision": c.revision,
                }.items()
            ):
                raise OASTDenied("oast_allocation_binding_mismatch")
            if state.get("poll_inflight"):
                raise OASTDenied("oast_poll_delivery_uncertain")
            if state["phase"] == "close_reserved":
                raise OASTDenied("oast_deregistration_delivery_uncertain")
            if spec.capability == "oast_poll":
                row = self.store.db.execute(
                    "SELECT * FROM rj_oast_followup WHERE allocation=? AND engagement=?",
                    (allocation, p.engagement_id),
                ).fetchone()
                if row is None or row["poll_index"] != spec.options["poll_index"]:
                    raise OASTDenied("oast_poll_outbox_binding_required")
                index = spec.options["poll_index"]
                if type(index) is not int or not 1 <= index < c.max_polls:
                    raise OASTDenied("oast_poll_index_invalid")
            else:
                index = 0
            ref = self.store.evidence_put(
                p.engagement_id,
                {
                    "allocation": allocation,
                    "phase": "prepared_not_sent",
                    "request_ref": surface.request_ref,
                },
                job_id=job["id"],
                kind="oast_attempt",
            )
            self.partial_evidence_refs = (ref,)
            token = ""
            if c.token_file is not None:
                value = _private_json(c.token_file)
                if (
                    set(value) != {"token"}
                    or not isinstance(value["token"], str)
                    or not re.fullmatch(r"[A-Za-z0-9._-]{16,256}", value["token"])
                ):
                    raise OASTDenied("oast_receiver_token_invalid")
                token = value["token"]
            service = c.service_policy(p)
            if state["phase"] == "prepared":
                if time.time() >= state["expires_at"]:
                    raise OASTDenied("oast_window_expired_before_registration")
                # Persist uncertainty before registration; an interrupted POST is
                # never automatically re-registered or silently replaced.
                state["phase"] = "register_reserved"
                self._save(allocation, state)
                reply = await self._request(
                    service,
                    c.receiver_url + "/register",
                    "POST",
                    json.dumps(
                        {
                            "public-key": state["public"],
                            "secret-key": state["secret"],
                            "correlation-id": state["correlation"],
                        }
                    ).encode(),
                    token=token,
                )
                registered = json.loads(reply["body"])
                if (
                    not isinstance(registered, dict)
                    or registered.get("message") != "registration successful"
                ):
                    raise OASTDenied("oast_registration_rejected")
                state["phase"] = "registered"
                self._save(allocation, state)
            if state["phase"] == "register_reserved":
                raise OASTDenied("oast_registration_delivery_uncertain")
            if state["phase"] == "registered":
                if time.time() >= state["expires_at"]:
                    raise OASTDenied("oast_window_expired_before_dispatch")
                callback = f"http://{state['full_id']}.{c.callback_domain}:{c.callback_port}/rj/{state['nonce']}"
                from urllib.parse import parse_qsl  # noqa: PLC0415

                if surface.method == "GET":
                    pairs = parse_qsl(urlsplit(surface.url).query, keep_blank_values=True)
                    if sum(k == surface.input_name for k, _ in pairs) != 1:
                        raise OASTDenied("oast_duplicate_selected_parameter_unsupported")
                state.update(phase="dispatch_reserved", dispatch_at=time.time())
                self._save(allocation, state)
                if binding is not None:
                    binding.validate(surface.url, surface.method, p)
                    self.store.assert_session_revision(p, surface)
                await self._request(
                    p,
                    surface.url
                    if selected
                    else replace_query_value(surface.url, surface.input_name, callback),
                    surface.method,
                    selected.mutate(callback) if selected else b"",
                    binding=binding,
                    content_type=binding.content_type
                    if selected and binding
                    else "application/json",
                )
                state["phase"] = "dispatched"
                state["dispatch_complete"] = True
                self._save(allocation, state)
            if state["phase"] not in {"dispatch_reserved", "dispatched", "closed"}:
                raise OASTDenied("oast_allocation_phase_invalid")
            events = state["pending_events"]
            if state["phase"] != "closed" and not events:
                url = (
                    c.receiver_url
                    + "/poll?id="
                    + state["correlation"]
                    + "&secret="
                    + quote(state["secret"])
                )
                # Polling drains the receiver queue. A crash before a local
                # checkpoint must not turn a potentially lost event into a
                # completed negative after lease recovery.
                state["poll_inflight"] = True
                self._save(allocation, state)
                reply = await self._request(service, url, token=token)
                events = self._events(json.loads(reply["body"]), state)
                state.update(pending_events=events, poll_inflight=False)
                self._save(allocation, state)
            refs = []
            for event in events:
                digest = event["event_sha256"]
                if digest not in state["event_refs"]:
                    state["event_refs"][digest] = self.store.evidence_put(
                        p.engagement_id, event, job_id=job["id"], kind="oast_correlated_event"
                    )
                refs.append(state["event_refs"][digest])
                if digest not in state["event_hashes"]:
                    state["event_hashes"].append(digest)
            if len(state["event_hashes"]) > 16:
                raise OASTDenied("oast_persistent_event_budget")
            window_elapsed = time.time() >= state["expires_at"]
            done = bool(state["event_hashes"]) or window_elapsed or index + 1 >= c.max_polls
            if done and state["phase"] != "closed":
                state["phase"] = "close_reserved"
                self._save(allocation, state)
                closed = await self._request(
                    service,
                    c.receiver_url + "/deregister",
                    "POST",
                    json.dumps(
                        {"correlation-id": state["correlation"], "secret-key": state["secret"]}
                    ).encode(),
                    token=token,
                )
                acknowledgement = json.loads(closed["body"])
                if (
                    not isinstance(acknowledgement, dict)
                    or acknowledgement.get("message") != "deregistration successful"
                ):
                    raise OASTDenied("oast_deregistration_not_acknowledged")
                state["phase"] = "closed"
                # Keep a bounded metadata tombstone so a resumed job cannot
                # allocate or deliver a second payload. Retire the private key
                # and receiver secret after acknowledged deregistration.
                state.update(private="", public="", secret="")
            self._save(allocation, state)
            if not done:
                with self.store.transaction() as db:
                    db.execute(
                        "INSERT INTO rj_oast_followup VALUES(?,?,?,?,?,?,0,?) "
                        "ON CONFLICT(allocation) DO UPDATE SET "
                        "parent_job=excluded.parent_job,poll_index=excluded.poll_index,ready_at=excluded.ready_at,emitted=0",
                        (
                            allocation,
                            p.engagement_id,
                            spec.surface_id,
                            job["id"],
                            index + 1,
                            min(state["expires_at"], time.time() + c.poll_interval),
                            c.revision,
                        ),
                    )
            outcome = (
                "callback_observed"
                if state["event_hashes"]
                else "dispatch_delivery_uncertain_no_callback"
                if done and not state["dispatch_complete"]
                else "poll_budget_exhausted_before_window"
                if done and not window_elapsed
                else "no_callback_observed_in_window"
                if done
                else "waiting_for_callback"
            )
            summary = {
                "outcome": outcome,
                "allocation": allocation,
                "requests": self.requests,
                "events": len(state["event_hashes"]),
                "poll_index": index,
                "window_closed": done,
                "window_elapsed": window_elapsed,
                "dispatch": state["phase"],
                "receiver_protocol_version": c.version,
                "receiver_version_source": "configured_protocol; independently pinned E2E server",
                "model_calls": 0,
                "impact": "callback_only_no_rce_or_data_access_claim",
                "evidence_refs": list(self.partial_evidence_refs) + refs,
            }
            ref = self.store.evidence_put(
                p.engagement_id, summary, job_id=job["id"], kind="oast_execution"
            )
            self.partial_evidence_refs += (*refs, ref)
            summary["evidence_refs"] = list(self.partial_evidence_refs)
            findings = (
                (
                    {
                        "id": stable_key([allocation, "http_callback"]),
                        "finding_status": "candidate",
                        "family": "oast",
                        "surface_id": spec.surface_id,
                        "evidence_refs": refs,
                        "validation": "correlated_callback_only_independent_impact_unproven",
                    },
                )
                if refs
                else ()
            )
            if done and not state["dispatch_complete"] and not state["event_hashes"]:
                return AdapterResult(
                    "failed",
                    "inconclusive",
                    summary,
                    error=error_record("oast_dispatch_delivery_uncertain"),
                )
            if done and not window_elapsed and not state["event_hashes"]:
                return AdapterResult(
                    "failed",
                    "partial",
                    summary,
                    error=error_record("oast_poll_budget_exhausted", coverage_effect="partial"),
                )
            return AdapterResult(
                "succeeded",
                "completed" if done and state["dispatch_complete"] else "partial",
                summary,
                findings,
            )
        except (ValueError, KeyError, TypeError, OSError, httpx.HTTPError, CapacityExceeded) as exc:
            code = (
                str(exc)
                if isinstance(
                    exc,
                    (
                        OASTDenied,
                        PolicyDenied,
                        AuthReplayDenied,
                        InputReplayDenied,
                        BodyTokenDenied,
                    ),
                )
                else "oast_private_credentials_or_state_unavailable"
                if isinstance(exc, SessionRefreshDenied)
                else "oast_transport_schema_or_private_state_failed"
            )
            coverage: CoverageStatus = (
                "blocked"
                if isinstance(exc, (PolicyDenied, SessionRefreshDenied, AuthReplayDenied))
                or code
                in {
                    "oast_upstream_tls_failed",
                    "oast_receiver_egress_or_admission_denied",
                    "oast_receiver_or_target_auth_denied",
                    "oast_rate_limited_or_unavailable",
                    "shared_origin_cooldown",
                    "oast_allocation_capacity",
                    "oast_request_budget_exhausted",
                }
                else "unsupported"
                if isinstance(exc, (InputReplayDenied, BodyTokenDenied))
                or code
                in {
                    "oast_requires_reviewed_supported_input",
                    "oast_hint_capture_mismatch",
                    "oast_reviewed_hint_required",
                    "oast_duplicate_selected_parameter_unsupported",
                }
                else "inconclusive"
            )
            return AdapterResult(
                "failed",
                coverage,
                {
                    "requests": self.requests,
                    "evidence_refs": list(self.partial_evidence_refs),
                    **(
                        {
                            "auth_recovery": auth_recovery_marker(
                                surface,
                                "http_401"
                                if code == "authentication_expired"
                                else "credential_expired",
                            )
                        }
                        if self.session_recovery_enabled
                        and not polling
                        and code in {"authentication_expired", "auth_replay_expired"}
                        else {}
                    ),
                },
                error=error_record(code, coverage_effect=coverage),
            )

    async def cancel(self) -> None:
        if self.proxy is not None:
            await self.proxy.close()

    async def close(self) -> None:
        await self.cancel()

    async def cleanup(self) -> None:
        await self.cancel()
