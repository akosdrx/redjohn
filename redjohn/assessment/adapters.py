"""Small worker contract and actual browser/HTTP/Nuclei pipeline adapters."""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from typing import TYPE_CHECKING, Any, Protocol

from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record
from redjohn.assessment.policy import PolicyDenied, origin_for


if TYPE_CHECKING:
    import ssl
    from collections.abc import AsyncIterator
    from pathlib import Path

    import httpx

    from redjohn.assessment.auth_replay import AuthReplayBinding, AuthReplayVault
    from redjohn.assessment.browser import BrowserDiscoveryService
    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.contracts import HTTPRateLimits, ScannerSession
    from redjohn.assessment.intelligence import TechnologyDetector
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore
    from redjohn.tools.hunt.nuclei import NucleiAdapter


class WorkerAdapter(Protocol):
    resource_class: str

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult: ...
    async def cancel(self) -> None: ...
    async def cleanup(self) -> None: ...


def _auth_recovery_marker(surface: Surface, signal: str) -> dict[str, Any]:
    marker: dict[str, Any] = {
        "admitted": True,
        "signal": signal,
        "actor_id": surface.actor_id,
        "tenant_id": surface.tenant_id,
        "session_revision": surface.session_revision,
    }
    if signal == "http_401":
        marker.update(response_complete=True, status=401)
    return marker


class HTTPObservationAdapter:
    resource_class = "worker"
    owner_process_only = True

    def __init__(
        self,
        policy: EngagementPolicy,
        store: AssessmentStore,
        rate_limits: HTTPRateLimits,
        *,
        header_audit: bool = False,
        technology_detector: TechnologyDetector | None = None,
        tls_config: BrowserTLSConfig | None = None,
    ) -> None:
        self.policy, self.store, self.rate_limits = policy, store, rate_limits
        self.header_audit = header_audit
        self.technology_detector = technology_detector
        self.tls_config = tls_config

    @asynccontextmanager
    async def _client(self, timeout: float) -> AsyncIterator[httpx.AsyncClient]:
        import httpx  # noqa: PLC0415 - selected adapter only

        from redjohn.assessment.browser_proxy import BrowserEgressProxy  # noqa: PLC0415

        proxy = None
        try:
            proxy_url: str | None = None
            verify: ssl.SSLContext | bool = True
            if self.policy.egress_mode == "enforced":
                proxy = BrowserEgressProxy(self.policy, tls_config=self.tls_config)
                await proxy.start()
                proxy_url, verify = proxy.url, proxy.client_tls_context
            elif self.tls_config:
                verify = self.tls_config.upstream_context()
            async with httpx.AsyncClient(
                trust_env=False,
                follow_redirects=False,
                timeout=timeout,
                proxy=proxy_url,
                verify=verify,
            ) as client:
                yield client
        finally:
            if proxy is not None:
                await proxy.close()

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:  # noqa: PLR0911, PLR0912 - explicit status boundaries
        if surface.method not in {"GET", "HEAD"} or spec.options:
            return AdapterResult(
                "failed",
                "unsupported",
                error=error_record("unsupported_input", coverage_effect="unsupported"),
            )
        self.policy.check_readonly_request(surface.url, surface.method)
        if surface.actor_id != "anonymous":
            # Do not silently drop authentication on a captured authenticated request.
            return AdapterResult(
                "failed",
                "unsupported",
                error=error_record(
                    "authenticated_replay_not_implemented", coverage_effect="unsupported"
                ),
            )
        origin = origin_for(surface.url)
        if not self.rate_limits.admit(origin):
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    "rate_limited",
                    category="rate_limit",
                    retryable=True,
                    terminal=False,
                    retry_after=self.rate_limits.remaining(origin),
                    coverage_effect="blocked",
                ),
            )
        self.store.consume_requests(self.policy)
        # No env proxy, redirects, auto-retries or disabled TLS verification.
        async with (
            self._client(spec.timeout_seconds) as client,
            client.stream(surface.method, surface.url) as response,
        ):
            status = response.status_code
            self.rate_limits.observe(origin, status, response.headers)
            data, truncated = bytearray(), False
            # Raw encoded content avoids allocating decompression bombs before
            # the streaming byte quota is applied. This adapter tests metadata.
            async for chunk in response.aiter_raw(chunk_size=4096):
                remaining = self.store.artifact_max_bytes - len(data)
                if len(chunk) > remaining:
                    data.extend(chunk[:remaining])
                    truncated = True
                    break
                data.extend(chunk)
            ref = self.store.evidence_put(
                self.policy.engagement_id,
                {
                    "url": surface.url,
                    "method": surface.method,
                    "status": status,
                    "headers": dict(response.headers),
                    "body_sha256": hashlib.sha256(data).hexdigest(),
                    "body_bytes": len(data),
                    "body_truncated": truncated,
                    "actor_id": surface.actor_id,
                    "session_revision": surface.session_revision,
                },
                job_id=job["id"],
                kind="http_metadata",
            )
            summary = {
                "status": status,
                "evidence_refs": [ref],
                "requests": 1,
                "body_bytes": len(data),
                "truncated": truncated,
                "outcome": "http_metadata_observed",
            }
            self.store.upsert_surface(
                self.policy.engagement_id, replace(surface, source="observed", request_ref=ref)
            )
            if self.technology_detector is not None:
                self.technology_detector.detect_headers(
                    self.policy.engagement_id,
                    response.headers,
                    evidence_ref=ref,
                    asset_ref=job["surface_id"],
                    actor_ref=surface.actor_id,
                )
            if status == 401:
                return AdapterResult(
                    "failed",
                    "blocked",
                    summary,
                    error=error_record(
                        "authentication_expired", category="auth", coverage_effect="blocked"
                    ),
                )
            if status == 403:
                return AdapterResult(
                    "failed",
                    "blocked",
                    summary,
                    error=error_record(
                        "permission_or_challenge",
                        category="permission",
                        coverage_effect="blocked",
                    ),
                )
            if status == 429 or (status == 503 and "retry-after" in response.headers):
                return AdapterResult(
                    "failed",
                    "blocked",
                    summary,
                    error=error_record(
                        "rate_limited",
                        category="rate_limit",
                        retryable=True,
                        terminal=False,
                        retry_after=self.rate_limits.remaining(origin),
                        coverage_effect="blocked",
                    ),
                )
            if 300 <= status < 400:
                # A redirect is evidence, not permission to follow it.
                return AdapterResult("succeeded", "partial", summary)
            if status >= 500:
                return AdapterResult(
                    "failed",
                    "inconclusive",
                    summary,
                    error=error_record("server_error", retryable=True, terminal=False),
                )
            if truncated:
                return AdapterResult(
                    "succeeded",
                    "partial",
                    summary,
                    error=error_record("body_truncated", coverage_effect="partial"),
                )
            findings: tuple[dict[str, Any], ...] = ()
            if self.header_audit:
                missing = [
                    name
                    for name in ("content-security-policy", "x-content-type-options")
                    if name not in response.headers
                ]
                findings = tuple(
                    {
                        "finding_status": "candidate",
                        "title": f"Missing {name}",
                        "evidence_refs": [ref],
                        "proof_level": "header_observation",
                        "expected": "review_applicable_response_header_policy",
                        "observed": "header_absent",
                        "actor_id": surface.actor_id,
                        "session_revision": surface.session_revision,
                    }
                    for name in missing
                )
                summary["outcome"] = "candidate" if findings else "no_finding_observed"
            return AdapterResult("succeeded", "completed", summary, findings)

    async def cancel(self) -> None:
        return None  # cancelling run closes the client/stream via async with

    async def cleanup(self) -> None:
        return None  # no retained client or subprocess


class BrowserInventoryAdapter:
    resource_class = "browser"  # service itself owns browser/context/page leases

    def __init__(
        self,
        service: BrowserDiscoveryService,
        policy: EngagementPolicy,
        store: AssessmentStore,
        actor_states: dict[str, Any] | None = None,
        *,
        capture_post: bool = False,
        session_recovery_enabled: bool = False,
    ) -> None:
        self.service, self.policy, self.store = service, policy, store
        self.actor_states = actor_states or {}
        self.capture_post = capture_post
        self.session_recovery_enabled = session_recovery_enabled

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:  # noqa: PLR0911, PLR0912 - actor/session/input status boundaries
        if spec.options or surface.method != "GET":
            return AdapterResult(
                "failed",
                "unsupported",
                error=error_record("unsupported_browser_input", coverage_effect="unsupported"),
            )
        self.policy.check_actor(surface.actor_id)
        actor_state = self.actor_states.get(surface.actor_id)
        if self.capture_post:
            if spec.idempotent or self.service.post_capture is None:
                return AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record(
                        "browser_post_capture_configuration_missing", coverage_effect="blocked"
                    ),
                )
            try:
                self.store.assert_session_revision(self.policy, surface)
                if self.session_recovery_enabled:
                    metadata = self.service.post_capture.context_metadata(
                        surface.actor_id,
                        surface.tenant_id,
                        surface.session_revision,
                        detect_expiry=True,
                        start_url=surface.url,
                    )
                else:
                    metadata = self.service.post_capture.context_metadata(
                        surface.actor_id, surface.tenant_id, surface.session_revision
                    )
                if metadata["session_revision"] != surface.session_revision:
                    raise PolicyDenied("browser_capture_session_mismatch")
            except (ValueError, PermissionError) as exc:
                expired = (
                    self.session_recovery_enabled
                    and str(exc) == "browser_capture_credentials_expired"
                )
                return AdapterResult(
                    "failed",
                    "blocked",
                    {"auth_recovery": _auth_recovery_marker(surface, "credential_expired")}
                    if expired
                    else {},
                    error=error_record(
                        "browser_capture_credentials_expired"
                        if expired
                        else "browser_capture_context_unavailable",
                        category="auth",
                        coverage_effect="blocked",
                    ),
                )
            # The capture service injects the current private origin-bound
            # credential at the trusted proxy, including after refresh.
            actor_state = None
        elif surface.actor_id != "anonymous":
            if not isinstance(actor_state, dict):
                return AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record(
                        "authentication_state_missing", category="auth", coverage_effect="blocked"
                    ),
                )
            if "storage_state" in actor_state:
                if (
                    str(actor_state.get("session_revision")) != surface.session_revision
                    or actor_state.get("actor_id", surface.actor_id) != surface.actor_id
                    or actor_state.get("tenant_id", "") != surface.tenant_id
                ):
                    return AdapterResult(
                        "failed",
                        "blocked",
                        error=error_record(
                            "authentication_state_revision_mismatch",
                            category="auth",
                            coverage_effect="blocked",
                        ),
                    )
                actor_state = actor_state["storage_state"]
            elif surface.session_revision != "1" or surface.tenant_id:
                return AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record(
                        "authentication_state_revision_required",
                        category="auth",
                        coverage_effect="blocked",
                    ),
                )
            if (
                not isinstance(actor_state, dict)
                or not isinstance(actor_state.get("cookies", []), list)
                or not isinstance(actor_state.get("origins", []), list)
                or not any(actor_state.get(key) for key in ("cookies", "origins"))
            ):
                return AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record(
                        "authentication_state_missing", category="auth", coverage_effect="blocked"
                    ),
                )
        from redjohn.assessment.browser import (  # noqa: PLC0415 - lazy optional browser
            BrowserUnavailableError,
            UnsupportedBrowserInputError,
        )

        try:
            result = await self.service.discover(
                [surface.url],
                actor_id=surface.actor_id,
                tenant_id=surface.tenant_id,
                session_revision=surface.session_revision,
                storage_state=actor_state,
                capture_post=self.capture_post,
            )
        except UnsupportedBrowserInputError:
            return AdapterResult(
                "failed",
                "unsupported",
                error=error_record("unsupported_browser_input", coverage_effect="unsupported"),
            )
        except BrowserUnavailableError:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    "blocked_missing_dependency", category="capability", coverage_effect="blocked"
                ),
            )
        ids, refs = [], []
        for observation in result.observations:
            payload = asdict(observation)
            # A proxy-confirmed capture already owns fenced sent-request
            # evidence. Replacing it with a Playwright metadata reference would
            # erase the body integrity/completion proof required by replay.
            ref = observation.request_ref or self.store.evidence_put(
                self.policy.engagement_id,
                payload,
                job_id=job["id"],
                kind="browser_request_metadata",
            )
            refs.append(ref)
            ids.append(
                self.store.upsert_surface(
                    self.policy.engagement_id,
                    Surface(
                        url=observation.url,
                        method=observation.method,
                        content_type=observation.request_content_type,
                        actor_id=observation.actor_id,
                        tenant_id=observation.tenant_id,
                        session_revision=observation.session_revision,
                        workflow_state="initial"
                        if observation.body_sha256
                        else surface.workflow_state,
                        request_ref=ref,
                        source=observation.source,
                        body_sha256=observation.body_sha256,
                    ),
                )
            )
        for link in result.links:
            ids.append(  # noqa: PERF401 - each iteration is a durable state mutation
                self.store.upsert_surface(
                    self.policy.engagement_id,
                    Surface(
                        url=link,
                        actor_id=surface.actor_id,
                        tenant_id=surface.tenant_id,
                        session_revision=surface.session_revision,
                        source="inferred",
                    ),
                )
            )
        for form in result.forms:
            ref = self.store.evidence_put(
                self.policy.engagement_id, asdict(form), job_id=job["id"], kind="browser_form"
            )
            refs.append(ref)
            for item in form.inputs:
                ids.append(  # noqa: PERF401 - each iteration is a durable state mutation
                    self.store.upsert_surface(
                        self.policy.engagement_id,
                        Surface(
                            url=form.action,
                            method=form.method.upper(),
                            content_type=form.enctype,
                            input_location="form",
                            input_name=item["name"],
                            actor_id=form.actor_id,
                            tenant_id=surface.tenant_id,
                            session_revision=str(form.session_revision),
                            source="inferred",
                            request_ref=ref,
                        ),
                    )
                )
        summary = {
            "surface_ids": ids,
            "evidence_refs": refs,
            "metrics": result.metrics,
            "limitations": result.limitations,
            "failures": [asdict(value) for value in result.failures],
            "tool": self.service.healthcheck(),
        }
        statuses = {observation.status for observation in result.observations}
        if (
            self.capture_post
            and self.session_recovery_enabled
            and int(result.metrics.get("complete_http_401_responses", 0)) > 0
            and not any(
                failure.code
                in {
                    "browser_capture_request_inconclusive",
                    "browser_cleanup_failed",
                    "browser_proxy_limit",
                    "browser_upstream_tls_denied",
                    "browser_request_admission_denied",
                }
                for failure in result.failures
            )
        ):
            summary["auth_recovery"] = _auth_recovery_marker(surface, "http_401")
            return AdapterResult(
                "failed",
                "blocked",
                summary,
                error=error_record(
                    "authentication_expired", category="auth", coverage_effect="blocked"
                ),
            )
        if any(failure.code == "browser_request_admission_denied" for failure in result.failures):
            return AdapterResult(
                "failed",
                "blocked",
                summary,
                error=error_record(
                    "request_admission_denied",
                    category="resource",
                    coverage_effect="blocked",
                    recovery_action="wait_for_origin_cooldown_or_review_request_budget",
                ),
            )
        for status, code, category in (
            (401, "authentication_expired", "auth"),
            (403, "permission_or_challenge", "permission"),
            (429, "rate_limited", "rate_limit"),
        ):
            if status in statuses:
                return AdapterResult(
                    "failed",
                    "blocked",
                    summary,
                    error=error_record(code, category=category, coverage_effect="blocked"),
                )
        if result.execution_status == "succeeded" and result.coverage_status in {
            "completed",
            "partial",
        }:
            error = None
        else:
            error = error_record(
                "browser_discovery_incomplete", coverage_effect=result.coverage_status
            )
        return AdapterResult(result.execution_status, result.coverage_status, summary, error=error)

    async def cancel(self) -> None:
        await self.service.close()

    async def cleanup(self) -> None:
        # Service lifetime belongs to the scheduler; each discover closes its context.
        return None

    async def close_idle(self) -> None:
        # A batch must release retained browser processes before its shared lock.
        await self.service.close()


class NucleiPipelineAdapter:
    resource_class = "scanner"

    def __init__(
        self,
        policy: EngagementPolicy,
        store: AssessmentStore,
        *,
        session: ScannerSession | None = None,
        lock: dict[str, Any] | None = None,
        tls_config: BrowserTLSConfig | None = None,
        rate_limits: HTTPRateLimits | None = None,
        auth_vault: AuthReplayVault | None = None,
        auth_vault_file: str | Path | None = None,
        session_recovery_enabled: bool = False,
    ) -> None:
        self.policy, self.store, self.session, self.lock = policy, store, session, lock
        self.adapter: NucleiAdapter | None = None
        self.tls_config, self.rate_limits = tls_config, rate_limits
        self.auth_vault = auth_vault
        self.auth_vault_file = auth_vault_file
        self.session_recovery_enabled = session_recovery_enabled

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:  # noqa: PLR0911, PLR0912, PLR0915 - explicit prerequisite and cleanup boundaries
        import shutil  # noqa: PLC0415 - health only on selected scanner

        if not shutil.which("nuclei") and self.session is None:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    "tool_missing",
                    category="capability",
                    coverage_effect="blocked",
                    tool_id="nuclei",
                ),
            )
        if self.session is None or self.lock is None:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    "nuclei_lock_or_sandbox_missing",
                    category="capability",
                    coverage_effect="blocked",
                    tool_id="nuclei",
                ),
            )
        if (
            surface.method not in {"GET", "HEAD", "POST"}
            or (surface.method != "POST" and surface.content_type)
            or (
                surface.method == "POST"
                and (not surface.body_sha256 or surface.actor_id == "anonymous")
            )
        ):
            return AdapterResult(
                "failed",
                "unsupported",
                error=error_record(
                    "unsupported_nuclei_replay_input", coverage_effect="unsupported"
                ),
            )
        if set(spec.options) - {"cve_id"}:
            return AdapterResult(
                "failed",
                "unsupported",
                error=error_record("unsupported_scanner_options", coverage_effect="unsupported"),
            )
        from redjohn.assessment.browser_proxy import BrowserEgressProxy  # noqa: PLC0415
        from redjohn.tools.hunt.nuclei import NucleiAdapter, NucleiLock, NucleiOptions  # noqa: PLC0415

        self.policy.check_replay_request(surface.url, surface.method)
        locked = NucleiLock.from_mapping(self.lock)
        if (
            spec.tool_version != locked.binary_version
            or spec.template_version != locked.bundle_sha256
        ):
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record("nuclei_job_lock_version_mismatch", coverage_effect="blocked"),
            )
        responses: list[dict[str, Any]] = []
        binding: AuthReplayBinding | None = None
        if surface.actor_id != "anonymous":
            from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault  # noqa: PLC0415

            try:
                vault = (
                    AuthReplayVault.from_file_for_surface(
                        self.auth_vault_file, self.policy, surface
                    )
                    if self.auth_vault_file is not None
                    else self.auth_vault
                )
                if vault is None:
                    raise AuthReplayDenied("auth_replay_credentials_missing")
                binding = vault.authorize(surface)
                evidence = self.store.evidence_get(self.policy.engagement_id, surface.request_ref)
                import json  # noqa: PLC0415

                captured = json.loads(evidence["excerpt"])
                if (
                    not isinstance(captured, dict)
                    or any(
                        captured.get(key) != getattr(surface, key)
                        for key in ("url", "method", "actor_id", "tenant_id", "session_revision")
                    )
                    or captured.get("sent") is not True
                    or captured.get("engagement_id") != self.policy.engagement_id
                    or captured.get("policy_revision") != self.policy.revision
                ):
                    raise AuthReplayDenied("auth_replay_capture_identity_mismatch")
                if surface.method == "POST":
                    if captured.get("body_sha256") != surface.body_sha256:
                        raise AuthReplayDenied("auth_replay_capture_body_mismatch")
                    captured_type = captured.get(
                        "request_content_type", captured.get("content_type", "")
                    )
                    captured_digest = captured.get("body_sha256", "")
                    if not isinstance(captured_type, str) or not isinstance(captured_digest, str):
                        raise AuthReplayDenied("auth_replay_capture_body_mismatch")
                    binding.validate_capture(captured_type, captured_digest)
                self.store.assert_session_revision(self.policy, surface)
            except (ValueError, KeyError) as exc:
                code = (
                    str(exc)
                    if isinstance(exc, (AuthReplayDenied, PolicyDenied))
                    else "auth_replay_capture_unavailable"
                )
                return AdapterResult(
                    "failed",
                    "blocked",
                    {"auth_recovery": _auth_recovery_marker(surface, "credential_expired")}
                    if self.session_recovery_enabled and code == "auth_replay_expired"
                    else {},
                    error=error_record(code, category="auth", coverage_effect="blocked"),
                )

        def admit(url: str) -> None:
            self.policy.check_replay_request(url, surface.method)
            if self.rate_limits is not None and not self.rate_limits.admit(origin_for(url)):
                from redjohn.assessment.store import CapacityExceeded  # noqa: PLC0415

                raise CapacityExceeded("shared_origin_cooldown")
            self.store.consume_requests(self.policy)

        def replay_request(
            url: str, method: str, headers: list[tuple[str, str]], body: bytes
        ) -> tuple[list[tuple[str, str]], bytes]:
            self.store.assert_session_revision(self.policy, surface)
            if binding is None:
                raise PolicyDenied("auth_replay_credentials_missing")
            return binding.rewrite_request(url, method, headers, body)

        def observe(url: str, status: int, headers: dict[str, str]) -> None:
            if self.rate_limits is not None:
                self.rate_limits.observe(origin_for(url), status, headers)
            if len(responses) >= 256:
                raise ValueError("nuclei_response_capture_limit")
            responses.append({"url": url, "status": status, "headers": headers})

        proxy = BrowserEgressProxy(
            self.policy,
            request_admission=admit,
            tls_config=self.tls_config,
            on_response=observe,
            timeout_seconds=min(60, spec.timeout_seconds),
            max_wire_bytes=max(1024, min(64 * 1024**2, self.store.artifact_max_bytes)),
            request_replay=replay_request if binding else None,
        )
        bound = False
        boundary = None
        try:
            await proxy.start()
            if self.policy.egress_mode == "enforced":
                from pathlib import Path  # noqa: PLC0415

                from redjohn.assessment.egress import LinuxEgressBoundary  # noqa: PLC0415

                boundary = LinuxEgressBoundary(
                    proxy.url,
                    self.session.workspace,
                    read_only_paths=(
                        Path(locked.binary_path),
                        *(Path(locked.bundle_root) / name for name in locked.files),
                    ),
                    timeout_seconds=min(180, spec.timeout_seconds),
                )
                await boundary.start()
                await boundary.attest()
                self.session.bind_egress_boundary(boundary)
            self.session.bind_proxy(proxy.url)
            bound = True
            self.adapter = NucleiAdapter(
                self.session,
                locked,
                proxy_url=proxy.url,
                response_observations=lambda: tuple(responses),
                auth_replay=binding,
                evidence_sink=lambda raw: self.store.evidence_put(
                    self.policy.engagement_id, raw, job_id=job["id"], kind="nuclei_raw"
                ),
            )
            result = await self.adapter.run(
                surface.url,
                options=NucleiOptions(
                    timeout_seconds=int(spec.timeout_seconds),
                    max_output_bytes=min(65536, self.store.artifact_max_bytes),
                ),
                cve_id=spec.options.get("cve_id", ""),
                policy=self.policy,
            )
        finally:
            try:
                if self.adapter is not None:
                    await self.adapter.cleanup()
            finally:
                try:
                    if bound:
                        self.session.bind_proxy(None)
                finally:
                    try:
                        await proxy.close()
                    finally:
                        if boundary is not None:
                            try:
                                self.session.bind_egress_boundary(None)
                            finally:
                                await boundary.close()
        network = {
            "forwarded_requests": proxy.forwarded_requests,
            "complete_response_statuses": [item["status"] for item in responses],
            "upstream_tls_failures": proxy.upstream_tls_failures,
            "denied_requests": proxy.denied_requests,
            "admission_denials": proxy.admission_denials,
            "limit_drops": proxy.limit_drops,
            "egress_attestations": list(boundary.attestations) if boundary else [],
        }
        network_code = (
            "nuclei_upstream_tls_denied"
            if proxy.upstream_tls_failures
            else "nuclei_request_admission_denied"
            if proxy.admission_denials
            else "nuclei_request_policy_denied"
            if proxy.denied_requests
            else "nuclei_proxy_limit_exceeded"
            if proxy.limit_drops
            else None
        )
        if network_code:
            result.update(
                execution_status="failed",
                coverage_status="blocked",
                no_finding_observed=False,
                error=error_record(network_code, coverage_effect="blocked"),
            )
        result["network"] = network
        recovery = (
            _auth_recovery_marker(surface, "http_401")
            if self.session_recovery_enabled
            and surface.actor_id != "anonymous"
            and not network_code
            and (result.get("error") or {}).get("code") == "authentication_expired"
            and any(item["status"] == 401 for item in responses)
            else None
        )
        ref = self.store.evidence_put(
            self.policy.engagement_id, result, job_id=job["id"], kind="nuclei_result"
        )
        findings = tuple(
            {**finding, "evidence_refs": [*result.get("evidence_refs", []), ref]}
            for finding in result.get("findings", ())
        )
        return AdapterResult(
            result["execution_status"],
            result["coverage_status"],
            {
                "evidence_refs": [ref],
                "tool": result.get("tool"),
                "telemetry": result.get("telemetry"),
                "network": network,
                "requests": proxy.forwarded_requests,
                "no_finding_observed": result.get("no_finding_observed", False),
                "auth_replay": binding.metadata() if binding else None,
                **({"auth_recovery": recovery} if recovery is not None else {}),
            },
            findings,
            result.get("error"),
        )

    async def cancel(self) -> None:
        if self.adapter is not None:
            await self.adapter.cancel()

    async def cleanup(self) -> None:
        if self.adapter is not None:
            await self.adapter.cleanup()
