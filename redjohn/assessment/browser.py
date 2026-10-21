"""Bounded, deterministic Playwright discovery for RedJohn.

This adapter observes DOM and browser HTTP metadata without clicking actions.
Explicit capture jobs can admit application-initiated approved POST traffic;
only the host proxy may establish exact capture and durable replay approval. The
existing agent-browser/Caido integration remains available. Remote operation
requires the policy's separately enforced worker egress boundary. Routing is
defence in depth, not a replacement for that infrastructure boundary.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self, cast
from urllib.parse import urldefrag, urlsplit

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.policy import origin_for


if TYPE_CHECKING:
    from collections.abc import Callable

    from playwright.async_api import (
        Browser,
        BrowserContext,
        Page,
        Playwright,
        Request,
        Route,
        StorageState,
    )

    from redjohn.assessment.browser_action_models import BrowserAuthPlan
    from redjohn.assessment.browser_capture import BrowserPostCaptureService
    from redjohn.assessment.browser_workflow_actions import ReviewedBrowserResult
    from redjohn.assessment.egress import LinuxEgressBoundary
    from redjohn.assessment.models import CoverageStatus, ExecutionStatus
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.resources import ResourceGovernor, ResourceLease
    from redjohn.assessment.workflow_inputs import WorkflowInputVault


@dataclass(frozen=True)
class BrowserLimits:
    max_pages: int = 8
    max_frontier: int = 32
    max_requests: int = 128
    max_links: int = 128
    max_forms: int = 32
    max_inputs_per_form: int = 64
    max_dom_nodes: int = 5000
    max_url_bytes: int = 4096
    navigation_timeout_ms: int = 5000
    readiness_timeout_ms: int = 3000
    readiness_selector: str = "body"
    observation_window_ms: int = 100
    total_timeout_seconds: float = 30.0
    cleanup_timeout_seconds: float = 5.0
    browser_memory_estimate: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_pages",
            "max_frontier",
            "max_requests",
            "max_links",
            "max_forms",
            "max_inputs_per_form",
            "max_dom_nodes",
            "max_url_bytes",
            "navigation_timeout_ms",
            "readiness_timeout_ms",
            "browser_memory_estimate",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not 0 <= self.observation_window_ms <= 10000:
            raise ValueError("observation window must be between 0 and 10000 ms")
        if not 0 < self.total_timeout_seconds <= 3600:
            raise ValueError("browser deadline must be positive and at most one hour")
        if not 0 < self.cleanup_timeout_seconds <= 30:
            raise ValueError("browser cleanup deadline must be positive and at most 30 seconds")
        if not self.readiness_selector or len(self.readiness_selector) > 512:
            raise ValueError("a bounded readiness selector is required")


@dataclass
class BrowserObservation:
    url: str
    method: str
    resource_type: str
    content_type: str
    actor_id: str
    tenant_id: str
    session_revision: str
    policy_revision: str
    engagement_id: str
    status: int | None = None
    source: str = "observed"
    request_content_type: str = ""
    response_content_type: str = ""
    # Bodies and auth headers are intentionally absent from inventory metadata.
    body_capture: str = "omitted_metadata_only"
    sent: bool = True
    blocked_reason: str = ""
    body_sha256: str = ""
    request_ref: str = ""


@dataclass(frozen=True)
class BrowserForm:
    page_url: str
    action: str
    method: str
    enctype: str
    inputs: tuple[dict[str, str], ...]
    actor_id: str
    session_revision: str
    source: str = "observed"


@dataclass(frozen=True)
class BrowserFailure:
    code: str
    url: str = ""
    coverage_effect: str = "partial"


@dataclass
class BrowserDiscoveryResult:
    observations: list[BrowserObservation] = field(default_factory=list)
    forms: list[BrowserForm] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    failures: list[BrowserFailure] = field(default_factory=list)
    execution_status: ExecutionStatus = "succeeded"
    coverage_status: CoverageStatus = "completed"
    metrics: dict[str, int | float | str] = field(default_factory=dict)
    limitations: tuple[str, ...] = (
        "browser_metadata_not_byte_exact_proxy_capture",
        "service_workers_blocked_for_visibility",
        "websockets_blocked_no_websocket_coverage",
        "automatic_mutating_requests_blocked",
        "only_explicit_navigation_urls_are_followed",
        "response_bodies_not_captured",
    )


class BrowserUnavailableError(RuntimeError):
    code = "blocked_missing_dependency"


class UnsupportedBrowserInputError(ValueError):
    code = "unsupported_input"


class BrowserDiscoveryService:
    """One admitted Chromium process; one isolated context/page at a time.

    Multiple services must share the same governor. A fresh context is created
    for every discover call, including calls for the same actor. The caller owns
    secret storage state and increments session_revision when it changes.
    """

    capabilities = ("headless-browser-discovery", "browser-http-observation", "dom-forms")

    def __init__(
        self,
        policy: EngagementPolicy,
        governor: ResourceGovernor,
        limits: BrowserLimits | None = None,
        *,
        request_admission: Callable[[str], None] | None = None,
        on_response: Callable[[str, int, dict[str, str]], None] | None = None,
        tls_config: BrowserTLSConfig | None = None,
        egress_workspace: Path | None = None,
        post_capture: BrowserPostCaptureService | None = None,
    ) -> None:
        self.policy = policy
        self.governor = governor
        self.limits = limits or BrowserLimits()
        self.request_admission = request_admission
        self.on_response = on_response
        self.tls_config = tls_config or BrowserTLSConfig()
        self.egress_workspace = egress_workspace
        self.post_capture = post_capture
        self._egress: LinuxEgressBoundary | None = None
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._browser_lease: ResourceLease | None = None
        self._browser_closed = False
        self._driver_stopped = False
        self._lock = asyncio.Lock()
        self._contexts_created = 0
        self._contexts_closed = 0
        self._pages_created = 0
        self._pages_closed = 0
        self._cleanup_errors = 0
        self._proxy: BrowserEgressProxy | None = None
        self._complete_http_401_responses = 0
        self._active_recovery_requests: frozenset[tuple[str, str]] = frozenset()

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.close()

    def _completed_recovery_response(
        self, url: str, method: str, status: int, _headers: dict[str, str]
    ) -> None:
        # Only the proxy's completed framing callback can supply this proof.
        if status == 401 and (method, url) in self._active_recovery_requests:
            self._complete_http_401_responses += 1

    async def start(self) -> None:
        if self._browser is not None:
            return
        if self.policy.egress_mode == "unavailable":
            raise BrowserUnavailableError("blocked_missing_egress_enforcement")
        for origin in self.policy.allowed_origins:
            self._check_url(origin)
        # Heavy optional dependencies load only when the adapter is activated.
        try:
            from playwright.async_api import Error as PlaywrightError  # noqa: PLC0415
            from playwright.async_api import async_playwright  # noqa: PLC0415
        except ImportError as exc:
            raise BrowserUnavailableError("Install the RedJohn browser extra and Chromium") from exc
        self._browser_closed = False
        self._driver_stopped = False
        self._browser_lease = self.governor.acquire(
            "browser",
            estimated_bytes=self.limits.browser_memory_estimate,
            cleanup_guard=self._browser_cleanup_verified,
        )
        try:
            self._proxy = BrowserEgressProxy(
                self.policy,
                request_admission=self.request_admission,
                tls_config=self.tls_config,
                on_complete=self._completed_recovery_response,
            )
            await self._proxy.start()
            self._playwright = await async_playwright().start()
            launch: dict[str, Any] = {}
            if self.policy.egress_mode == "enforced":
                from redjohn.assessment.egress import LinuxEgressBoundary  # noqa: PLC0415

                if self.egress_workspace is None:
                    raise BrowserUnavailableError("blocked_egress_workspace_missing")  # noqa: TRY301
                executable = Path(self._playwright.chromium.executable_path)
                self._egress = LinuxEgressBoundary(
                    self._proxy.url,
                    self.egress_workspace,
                    read_only_paths=(executable.parent,),
                    timeout_seconds=min(180, self.limits.total_timeout_seconds),
                )
                await self._egress.start()
                await self._egress.attest()
                launch = {
                    "executable_path": str(self._egress.executable_wrapper(executable)),
                    "env": self._egress.environment,
                }
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                chromium_sandbox=True,
                proxy={"server": self._proxy.url, "bypass": "<-loopback>"},
                timeout=self.limits.navigation_timeout_ms,
                args=[
                    "--disable-quic",
                    "--disable-background-networking",
                    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                    "--block-new-web-contents",
                    *self._proxy.chromium_tls_arguments,
                ],
                **launch,
            )
        except PlaywrightError as exc:
            await self.close()
            code = (
                "chromium_executable_missing"
                if "Executable doesn't exist" in str(exc)
                else "browser_launch_failed"
            )
            # Do not reflect executable paths, internal logs or launch arguments.
            # Sandbox errors stay blocked; there is no no-sandbox fallback.
            raise BrowserUnavailableError(code) from None
        except BaseException:
            await self.close()
            raise

    def _browser_cleanup_verified(self) -> bool:
        """Only a completed browser/driver shutdown may free the browser slot."""
        return self._browser_closed and self._driver_stopped

    async def _close_browser(self) -> None:  # noqa: PLR0912 - explicit cleanup branches
        from redjohn.assessment.resources import ResourceAdmissionError  # noqa: PLC0415

        browser_failed = driver_failed = False
        if self._browser is not None:
            browser = self._browser
            try:
                await asyncio.wait_for(browser.close(), self.limits.cleanup_timeout_seconds)
            except (Exception, asyncio.CancelledError):  # noqa: BLE001 - cleanup must continue
                browser_failed = True
                self._cleanup_errors += 1
                self._browser_closed = False
            else:
                self._browser = None
                self._browser_closed = True
        else:
            self._browser_closed = True
        if self._playwright is not None:
            driver = self._playwright
            try:
                await asyncio.wait_for(driver.stop(), self.limits.cleanup_timeout_seconds)
            except (Exception, asyncio.CancelledError):  # noqa: BLE001 - cleanup must continue
                driver_failed = True
                self._cleanup_errors += 1
                self._driver_stopped = False
            else:
                self._playwright = None
                self._driver_stopped = True
        else:
            self._driver_stopped = True
        if self._proxy is not None:
            proxy, self._proxy = self._proxy, None
            try:
                await proxy.close()
            finally:
                if self._egress is not None:
                    boundary, self._egress = self._egress, None
                    await boundary.close()
        if self._browser_lease is not None:
            lease = self._browser_lease
            try:
                lease.release()
            except ResourceAdmissionError:
                # Keep the same quarantined reservation. Retrying close() may
                # later prove cleanup; a new browser must not be admitted yet.
                if not (browser_failed or driver_failed):
                    self._cleanup_errors += 1
            else:
                self._browser_lease = None

    async def close(self) -> None:
        # A cancellation may interrupt a navigation but must not strand Chromium.
        cleanup = asyncio.create_task(self._close_browser())
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            await cleanup
            raise

    async def run_reviewed_actions(
        self,
        plan: BrowserAuthPlan,
        inputs: WorkflowInputVault,
        checkpoint: dict[str, Any],
        *,
        on_read: Callable[[str], None],
        on_admit: Callable[[tuple[str, ...]], None],
        on_checkpoint: Callable[[int, dict[str, Any], str], None],
    ) -> ReviewedBrowserResult:
        """Run only typed reviewed actions through this service's existing boundary."""
        from redjohn.assessment.browser_action_models import BrowserAuthPlan  # noqa: PLC0415
        from redjohn.assessment.browser_workflow_actions import run_actions  # noqa: PLC0415
        from redjohn.assessment.workflow_inputs import WorkflowInputVault  # noqa: PLC0415

        if not isinstance(plan, BrowserAuthPlan) or not isinstance(inputs, WorkflowInputVault):
            raise TypeError("typed_reviewed_browser_plan_required")
        plan.authorize(self.policy)
        async with self._lock:
            await self.start()
            async with asyncio.timeout(self.limits.total_timeout_seconds):
                return await run_actions(
                    self,
                    plan,
                    inputs,
                    checkpoint,
                    on_read=on_read,
                    on_admit=on_admit,
                    on_checkpoint=on_checkpoint,
                )

    def healthcheck(self) -> dict[str, Any]:
        try:
            playwright_version = version("playwright")
        except PackageNotFoundError:
            playwright_version = "missing"
        contexts = self._browser.contexts if self._browser is not None else []
        return {
            "tool": "playwright-chromium",
            "playwright_version": playwright_version,
            "chromium_version": self._browser.version if self._browser is not None else "stopped",
            "ready": self._browser is not None and self._browser.is_connected(),
            "active_contexts": len(contexts),
            "active_pages": sum(len(context.pages) for context in contexts),
            "contexts_created": self._contexts_created,
            "contexts_closed": self._contexts_closed,
            "pages_created": self._pages_created,
            "pages_closed": self._pages_closed,
            "cleanup_errors": self._cleanup_errors,
            "active_proxy_connections": len(self._proxy._tasks) if self._proxy else 0,
            "proxy_upstream_tls_failures": self._proxy.upstream_tls_failures if self._proxy else 0,
            "egress_attestations": list(self._egress.attestations) if self._egress else [],
        }

    def _check_url(self, url: str) -> None:
        if len(url.encode("utf-8")) > self.limits.max_url_bytes:
            raise ValueError("browser URL exceeds configured byte limit")
        if urlsplit(url).scheme not in {"http", "https"}:
            raise ValueError("only HTTP(S) browser targets are supported")
        self.policy.check_scope_url(url)

    def validate_input(self, start_urls: list[str], actor_id: str, session_revision: str) -> None:
        if not start_urls or len(start_urls) > self.limits.max_frontier:
            raise ValueError("browser start frontier must be nonempty and bounded")
        if not actor_id or len(actor_id) > 256 or not session_revision:
            raise ValueError("actor identity and session revision are required")
        self.policy.check_actor(actor_id)
        for url in start_urls:
            self._check_url(url)

    async def confirm_dialog(self, baseline: str, proof: str, nonce: str) -> dict[str, Any]:  # noqa: PLR0915 - one bounded context lifecycle
        """Observe a target-delivered nonce alert, without injecting browser JS.

        Uses the same admitted Chromium process, kernel boundary and TLS proxy.
        A fresh anonymous context visits a benign control before the proof URL.
        Only these two navigations and bounded same-origin readonly resources
        are permitted. No stored-XSS, POST or authenticated confirmation here.
        """
        from playwright.async_api import Error as PlaywrightError  # noqa: PLC0415

        for url in (baseline, proof):
            self._check_url(url)
            self.policy.check_readonly_request(url, "GET")
        if origin_for(baseline) != origin_for(proof) or not nonce.startswith("redjohn-"):
            raise ValueError("invalid_xss_confirmation_contract")
        async with self._lock:
            await self.start()
            assert self._browser is not None and self._proxy is not None
            context_lease = self.governor.acquire("context", estimated_bytes=8 * 1024 * 1024)
            page_lease: ResourceLease | None = None
            context: BrowserContext | None = None
            requests, denied, phase = 0, 0, "baseline"
            dialogs: dict[str, int] = {"baseline": 0, "proof": 0}
            before_tls = self._proxy.upstream_tls_failures
            before_denials = self._proxy.denied_requests
            previous_navigation = self._proxy.navigation_urls
            self._proxy.navigation_urls = {baseline, proof}

            async def route_request(route: Route, request: Request) -> None:
                nonlocal requests, denied
                try:
                    self.policy.check_readonly_request(request.url, request.method)
                    if (
                        origin_for(request.url) != origin_for(baseline)
                        or requests >= min(32, self.limits.max_requests)
                        or request.method != "GET"
                        or (
                            request.is_navigation_request() and request.url not in {baseline, proof}
                        )
                    ):
                        raise ValueError("xss_confirmation_request_denied")  # noqa: TRY301
                    requests += 1
                    await route.continue_()
                except ValueError:
                    denied += 1
                    await route.abort("blockedbyclient")

            async def dialog_seen(dialog: Any) -> None:
                if dialog.type == "alert" and dialog.message == nonce:
                    dialogs[phase] += 1
                await dialog.dismiss()

            try:
                context = await self._browser.new_context(
                    service_workers="block", accept_downloads=False
                )
                self._contexts_created += 1
                await context.route("**/*", route_request)
                await context.route_web_socket("**/*", lambda socket: socket.close())
                page_lease = self.governor.acquire("page", estimated_bytes=16 * 1024 * 1024)
                page = await context.new_page()
                self._pages_created += 1
                page.on("dialog", dialog_seen)
                for next_phase, url in (("baseline", baseline), ("proof", proof)):
                    phase = next_phase
                    response = await page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=self.limits.navigation_timeout_ms,
                    )
                    if response is None or not 200 <= response.status < 300:
                        raise ValueError("xss_confirmation_http_incomplete")
                    await page.wait_for_timeout(
                        min(1000, max(100, self.limits.observation_window_ms))
                    )
                return {
                    "confirmed": dialogs["baseline"] == 0 and dialogs["proof"] > 0,
                    "baseline_nonce_dialogs": dialogs["baseline"],
                    "proof_nonce_dialogs": dialogs["proof"],
                    "requests": requests,
                    "blocked_requests": denied + self._proxy.denied_requests - before_denials,
                    "upstream_tls_failures": self._proxy.upstream_tls_failures - before_tls,
                    "browser": self.healthcheck(),
                }
            except PlaywrightError:
                raise ValueError("xss_confirmation_browser_failed") from None
            finally:
                try:
                    if context is not None:
                        await asyncio.wait_for(context.close(), self.limits.cleanup_timeout_seconds)
                        self._contexts_closed += 1
                        self._pages_closed += 1
                finally:
                    if self._proxy is not None:
                        self._proxy.navigation_urls = previous_navigation
                    if page_lease is not None:
                        page_lease.release()
                    context_lease.release()

    async def discover(
        self,
        start_urls: list[str],
        *,
        actor_id: str,
        session_revision: str | int,
        tenant_id: str = "",
        storage_state: dict[str, Any] | None = None,
        navigation_urls: tuple[str, ...] = (),
        capture_post: bool = False,
    ) -> BrowserDiscoveryResult:
        revision = str(session_revision)
        self.validate_input(start_urls, actor_id, revision)
        if capture_post and (self.post_capture is None or actor_id == "anonymous"):
            raise UnsupportedBrowserInputError("browser_post_capture_named_provider_required")
        if len(navigation_urls) > self.limits.max_frontier:
            raise ValueError("explicit navigation allowlist exceeds frontier limit")
        for url in navigation_urls:
            self._check_url(url)
        # Queue wait consumes the overall deadline too.
        started = time.monotonic()
        result = BrowserDiscoveryResult()
        if capture_post:
            result.limitations = (
                *(
                    value
                    for value in result.limitations
                    if value != "automatic_mutating_requests_blocked"
                ),
                "only_explicit_private_rules_allow_application_post_capture",
            )
        try:
            async with asyncio.timeout(self.limits.total_timeout_seconds):
                async with self._lock:
                    if capture_post and self.post_capture is not None:
                        self._active_recovery_requests = frozenset(
                            ("GET", url) for url in start_urls
                        ) | frozenset(
                            ("POST", rule["url"])
                            for rule in self.post_capture.reviewed_rule_metadata()
                            if rule["actor_id"] == actor_id
                            and rule["tenant_id"] == tenant_id
                            and rule["session_revision"] in {"current", revision}
                            and rule["expires_at"] > time.time()
                        )
                    try:
                        await self.start()
                        before_401 = self._complete_http_401_responses
                        await self._discover(
                            result,
                            start_urls,
                            actor_id,
                            revision,
                            tenant_id,
                            storage_state,
                            navigation_urls,
                            capture_post,
                        )
                        result.metrics["complete_http_401_responses"] = (
                            self._complete_http_401_responses - before_401
                        )
                    finally:
                        self._active_recovery_requests = frozenset()
        except TimeoutError:
            result.execution_status = "timed_out"
            result.coverage_status = "inconclusive"
            result.failures.append(
                BrowserFailure(
                    "browser_deadline",
                    coverage_effect="inconclusive",
                )
            )
        except asyncio.CancelledError:
            # _discover finally closes page/context; service owner can still
            # inspect health before the surrounding async-with closes Chromium.
            raise
        result.metrics["elapsed_seconds"] = round(time.monotonic() - started, 6)
        result.metrics["model_calls"] = 0
        result.metrics["input_tokens"] = 0
        result.metrics["output_tokens"] = 0
        result.metrics["observed_requests"] = len(result.observations)
        if result.failures and result.coverage_status == "completed":
            result.coverage_status = "partial"
        return result

    async def _discover(  # noqa: PLR0912, PLR0915 - explicit bounded crawl and finally cleanup
        self,
        result: BrowserDiscoveryResult,
        start_urls: list[str],
        actor_id: str,
        revision: str,
        tenant_id: str,
        storage_state: dict[str, Any] | None,
        navigation_urls: tuple[str, ...],
        capture_post: bool,
    ) -> None:
        from playwright.async_api import Error as PlaywrightError  # noqa: PLC0415
        from playwright.async_api import TimeoutError as PlaywrightTimeout  # noqa: PLC0415

        assert self._browser is not None
        context: BrowserContext | None = None
        page: Page | None = None
        context_lease = self.governor.acquire("context", estimated_bytes=8 * 1024 * 1024)
        page_lease: ResourceLease | None = None
        requests: dict[Request, BrowserObservation] = {}
        pending_operations: set[asyncio.Task[Any]] = set()
        frontier = deque(dict.fromkeys(urldefrag(url)[0] for url in start_urls))
        queued = set(frontier)
        approved_navigation = queued | {urldefrag(url)[0] for url in navigation_urls}
        metrics: dict[str, int] = {
            "visited_pages": 0,
            "blocked_requests": 0,
            "frontier_peak": len(frontier),
            "discarded_frontier_urls": 0,
            "request_limit_drops": 0,
            "routed_requests": 0,
            "captured_post_requests": 0,
        }
        failure_codes: set[str] = set()
        assert self._proxy is not None
        proxy = self._proxy
        capture_bound = False
        self._proxy.navigation_urls = approved_navigation
        proxy_denials_before = self._proxy.denied_requests
        proxy_limits_before = self._proxy.limit_drops
        proxy_admission_before = self._proxy.admission_denials
        proxy_tls_before = self._proxy.upstream_tls_failures

        def fail(code: str, url: str = "") -> None:
            if code not in failure_codes and len(result.failures) < 32:
                failure_codes.add(code)
                result.failures.append(BrowserFailure(code, url))

        async def browser_operation(operation: Any) -> Any:
            # Keep Playwright's channel call alive until context.close() resolves
            # it on cancellation; cancelling its transport future can otherwise
            # leave an unobserved exception after the context has been released.
            task = asyncio.create_task(operation)
            pending_operations.add(task)
            try:
                return await asyncio.shield(task)
            finally:
                if task.done():
                    pending_operations.discard(task)

        async def route_request(route: Route, request: Request) -> None:  # noqa: PLR0911
            try:
                self._check_url(request.url)
            except (ValueError, PermissionError):
                metrics["blocked_requests"] += 1
                fail("browser_scope_denied")
                await route.abort("blockedbyclient")
                return
            if (
                request.is_navigation_request()
                and request.frame.parent_frame is None
                and urldefrag(request.url)[0] not in approved_navigation
            ):
                metrics["blocked_requests"] += 1
                fail("browser_unapproved_navigation")
                await route.abort("blockedbyclient")
                return
            if metrics["routed_requests"] >= min(
                self.limits.max_requests, self.policy.request_budget
            ):
                metrics["request_limit_drops"] += 1
                fail("browser_request_limit")
                await route.abort("blockedbyclient")
                return
            metrics["routed_requests"] += 1
            if request.method == "POST" and capture_post:
                try:
                    self.policy.check_replay_request(request.url, "POST")
                except (ValueError, PermissionError):
                    metrics["blocked_requests"] += 1
                    fail("browser_post_capture_policy_denied")
                    await route.abort("blockedbyclient")
                    return
                # Never use Request.post_data or route metadata as capture
                # evidence. The proxy will append only proven exact requests.
                await route.continue_()
                return
            content_type = request.headers.get("content-type", "")[:256]
            observation = BrowserObservation(
                url=request.url,
                method=request.method,
                resource_type=request.resource_type,
                content_type=content_type,
                request_content_type=content_type,
                actor_id=actor_id,
                tenant_id=tenant_id,
                session_revision=revision,
                policy_revision=str(self.policy.revision),
                engagement_id=self.policy.engagement_id,
            )
            requests[request] = observation
            result.observations.append(observation)
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                observation.sent = False
                observation.source = "inferred"
                observation.blocked_reason = "browser_mutating_request_blocked"
                metrics["blocked_requests"] += 1
                fail("browser_mutating_request_blocked")
                await route.abort("blockedbyclient")
                return
            try:
                self.policy.check_readonly_request(request.url, request.method)
            except (ValueError, PermissionError):
                observation.sent = False
                observation.source = "inferred"
                observation.blocked_reason = "browser_stateful_request_blocked"
                metrics["blocked_requests"] += 1
                fail("browser_stateful_request_blocked")
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        def response_observed(response: Any) -> None:
            observation = requests.get(response.request)
            if observation is not None:
                observation.status = response.status
                observation.response_content_type = response.headers.get("content-type", "")[:256]
                if not observation.content_type:
                    observation.content_type = observation.response_content_type
                if response.status in {401, 403, 429, 503}:
                    fail(f"browser_http_{response.status}")
                if self.on_response is not None:
                    self.on_response(
                        response.url,
                        response.status,
                        {
                            name: response.headers[name]
                            for name in ("retry-after", "content-type")
                            if name in response.headers
                        },
                    )

        async def block_websocket(socket: Any) -> None:
            metrics["blocked_requests"] += 1
            fail("browser_websocket_unsupported")
            await socket.close(code=1008, reason="RedJohn discovery has no websocket capability")

        try:
            if capture_post:
                assert self.post_capture is not None
                self.post_capture.bind_context(actor_id, tenant_id, revision)
                capture_bound = True
                proxy.request_capture = self.post_capture.before_request
                proxy.request_headers = self.post_capture.headers_for_request
            context = await self._browser.new_context(
                storage_state=cast("StorageState | None", storage_state),
                accept_downloads=False,
                service_workers="block",
                ignore_https_errors=False,
            )
            self._contexts_created += 1
            await context.route("**/*", route_request)
            await context.route_web_socket("**/*", block_websocket)
            context.on("response", response_observed)
            page_lease = self.governor.acquire("page", estimated_bytes=8 * 1024 * 1024)
            page = await context.new_page()
            self._pages_created += 1
            page.set_default_timeout(self.limits.readiness_timeout_ms)
            page.on("crash", lambda _page: fail("browser_page_crashed"))
            while frontier and metrics["visited_pages"] < self.limits.max_pages:
                url = frontier.popleft()
                try:
                    self._check_url(url)
                    await browser_operation(
                        page.goto(
                            url,
                            wait_until="domcontentloaded",
                            timeout=self.limits.navigation_timeout_ms,
                        ),
                    )
                    await browser_operation(
                        page.wait_for_selector(
                            self.limits.readiness_selector,
                            state="attached",
                            timeout=self.limits.readiness_timeout_ms,
                        ),
                    )
                    if self.limits.observation_window_ms:
                        await page.wait_for_timeout(self.limits.observation_window_ms)
                    self._check_url(page.url)
                    metrics["visited_pages"] += 1
                    if page.url != url:
                        if len(result.observations) < self.limits.max_requests:
                            result.observations.append(
                                BrowserObservation(
                                    url=page.url,
                                    method="GET",
                                    resource_type="spa_route",
                                    content_type="",
                                    actor_id=actor_id,
                                    tenant_id=tenant_id,
                                    session_revision=revision,
                                    policy_revision=str(self.policy.revision),
                                    engagement_id=self.policy.engagement_id,
                                    source="observed",
                                    sent=False,
                                )
                            )
                        else:
                            fail("browser_request_limit")
                    dom = await page.evaluate(
                        _DOM_EXTRACT,
                        {
                            "links": self.limits.max_links,
                            "forms": self.limits.max_forms,
                            "inputs": self.limits.max_inputs_per_form,
                            "nodes": self.limits.max_dom_nodes,
                            "string": self.limits.max_url_bytes,
                        },
                    )
                    for link in dom["links"]:
                        if len(result.links) >= self.limits.max_links:
                            fail("browser_link_limit")
                            break
                        try:
                            self._check_url(link)
                        except (ValueError, PermissionError):
                            continue
                        if link not in result.links:
                            result.links.append(link)
                        target = urldefrag(link)[0]
                        if target not in queued and target in approved_navigation:
                            if len(queued) >= self.limits.max_frontier:
                                metrics["discarded_frontier_urls"] += 1
                                fail("browser_frontier_limit")
                            else:
                                queued.add(target)
                                frontier.append(target)
                                metrics["frontier_peak"] = max(
                                    metrics["frontier_peak"],
                                    len(frontier),
                                )
                    for form in dom["forms"]:
                        if len(result.forms) >= self.limits.max_forms:
                            fail("browser_form_limit")
                            break
                        result.forms.append(
                            BrowserForm(
                                page_url=page.url,
                                action=form["action"],
                                method=form["method"],
                                enctype=form["enctype"],
                                inputs=tuple(form["inputs"]),
                                actor_id=actor_id,
                                session_revision=revision,
                            )
                        )
                    if dom["truncated"]:
                        fail("browser_dom_truncated")
                except PlaywrightTimeout:
                    fail("browser_readiness_timeout", url)
                except PlaywrightError:
                    fail("browser_navigation_failed", url)
                except (ValueError, PermissionError):
                    # Chromium may expose an error page's redirect URL after the
                    # proxy denies its connection. Preserve that lost coverage.
                    fail("browser_scope_denied", url)
            if frontier:
                fail("browser_page_limit")
            if metrics["visited_pages"] == 0:
                result.execution_status = "failed"
                result.coverage_status = "inconclusive"
        finally:
            if self._proxy is not None:
                denials = self._proxy.denied_requests - proxy_denials_before
                drops = self._proxy.limit_drops - proxy_limits_before
                admission_denials = self._proxy.admission_denials - proxy_admission_before
                tls_denials = self._proxy.upstream_tls_failures - proxy_tls_before
                metrics["proxy_denied_requests"] = denials
                metrics["proxy_limit_drops"] = drops
                metrics["proxy_upstream_tls_failures"] = tls_denials
                if tls_denials:
                    fail("browser_upstream_tls_denied")
                    result.execution_status = "failed"
                    result.coverage_status = "inconclusive"
                if denials:
                    fail("browser_scope_denied")
                if admission_denials:
                    fail("browser_request_admission_denied")
                if drops:
                    fail("browser_proxy_limit")
            result.metrics.update(metrics)
            # Drop listener closures and retained Request objects before context disposal.
            if context is not None:
                context.remove_listener("response", response_observed)
                try:
                    await asyncio.wait_for(context.close(), self.limits.cleanup_timeout_seconds)
                    self._contexts_closed += 1
                    if page is not None:
                        self._pages_closed += 1
                except (Exception, asyncio.CancelledError):  # noqa: BLE001 - cleanup must continue
                    self._cleanup_errors += 1
                    fail("browser_cleanup_failed")
                    # A context cleanup failure invalidates this browser process.
                    await self.close()
            if pending_operations:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*pending_operations, return_exceptions=True),
                        self.limits.cleanup_timeout_seconds,
                    )
                except (TimeoutError, asyncio.CancelledError):
                    self._cleanup_errors += 1
                    fail("browser_cleanup_failed")
                    for operation in pending_operations:
                        operation.cancel()
                pending_operations.clear()
            requests.clear()
            try:
                if capture_bound:
                    assert self.post_capture is not None
                    try:
                        await proxy.drain_captures(self.limits.cleanup_timeout_seconds)
                        for captured in self.post_capture.observations():
                            if len(result.observations) >= self.limits.max_requests:
                                fail("browser_request_limit")
                                break
                            result.observations.append(
                                BrowserObservation(
                                    url=captured.url,
                                    method="POST",
                                    resource_type="proxy_capture",
                                    content_type=captured.content_type,
                                    request_content_type=captured.content_type,
                                    actor_id=captured.actor_id,
                                    tenant_id=captured.tenant_id,
                                    session_revision=captured.session_revision,
                                    policy_revision=self.policy.revision,
                                    engagement_id=self.policy.engagement_id,
                                    status=self.post_capture.response_status(captured.request_ref),
                                    body_capture="byte_exact_private_proxy",
                                    body_sha256=captured.body_sha256,
                                    request_ref=captured.request_ref,
                                )
                            )
                            metrics["captured_post_requests"] += 1
                        for code in self.post_capture.failure_codes():
                            fail(code)
                    finally:
                        proxy.request_capture = None
                        proxy.request_headers = None
                        self.post_capture.end_context()
                    result.metrics.update(metrics)
            finally:
                if page_lease is not None:
                    page_lease.release()
                context_lease.release()


_DOM_EXTRACT = """limits => {
  const links = [], forms = [];
  let truncated = false;
  const walker = document.createTreeWalker(document, NodeFilter.SHOW_ELEMENT);
  let nodes = 0, node;
  while ((node = walker.nextNode())) {
    if (++nodes > limits.nodes) { truncated = true; break; }
    if (!((node.tagName === 'A' && node.hasAttribute('href')) ||
          (node.tagName === 'IFRAME' && node.hasAttribute('src')))) continue;
    if (links.length >= limits.links) { truncated = true; break; }
    const value = node.href || node.src;
    if (value && value.length <= limits.string) links.push(value);
    else if (value) truncated = true;
  }
  for (const node of document.forms) {
    if (forms.length >= limits.forms) { truncated = true; break; }
    const inputs = [];
    for (const input of node.elements) {
      if (inputs.length >= limits.inputs) { truncated = true; break; }
      if (input.name) inputs.push({name: input.name.slice(0, 256),
        type: (input.type || input.tagName.toLowerCase()).slice(0, 64)});
    }
    const action = node.action || location.href;
    if (action.length > limits.string) { truncated = true; continue; }
    forms.push({action, method: (node.method || 'get').toUpperCase(),
      enctype: node.enctype || 'application/x-www-form-urlencoded', inputs});
  }
  return {links, forms, truncated};
}"""
