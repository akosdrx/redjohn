"""Reviewed Playwright actions using the existing admitted Chromium service."""

from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import parse_qsl, urljoin

from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.workflow_inputs import WorkflowInputUnavailable


if TYPE_CHECKING:
    from collections.abc import Callable

    from playwright.async_api import Route, StorageState

    from redjohn.assessment.browser import BrowserDiscoveryService
    from redjohn.assessment.browser_action_models import BrowserAuthPlan, ReviewedBrowserAction
    from redjohn.assessment.workflow_inputs import PrivateWorkflowInput, WorkflowInputVault


@dataclass(repr=False)
class ReviewedBrowserResult:
    outcome: str
    next_action: int
    storage_state: dict[str, Any] = field(repr=False)
    url: str = field(repr=False)
    requests: int = 0
    identity_status: int = 0


async def run_actions(  # noqa: PLR0912, PLR0915 - bounded typed browser lifecycle
    service: BrowserDiscoveryService,
    plan: BrowserAuthPlan,
    inputs: WorkflowInputVault,
    checkpoint: dict[str, Any],
    *,
    on_read: Callable[[str], None],
    on_admit: Callable[[tuple[str, ...]], None],
    on_checkpoint: Callable[[int, dict[str, Any], str], None],
) -> ReviewedBrowserResult:
    assert service._browser is not None and service._proxy is not None
    proxy = service._proxy
    saved = (
        proxy.request_admission,
        proxy.request_capture,
        proxy.request_headers,
        proxy.request_policy,
        proxy.on_complete,
        proxy.on_response,
        proxy.navigation_urls,
        proxy.max_wire_bytes,
    )
    context = None
    page = None
    context_lease = service.governor.acquire("context", estimated_bytes=8 * 1024 * 1024)
    page_lease = None
    filled: dict[str, PrivateWorkflowInput] = {}
    active: ReviewedBrowserAction | None = None
    active_nonce = ""
    completed = asyncio.Event()
    admitted = False
    requests = 0
    index = int(checkpoint.get("next_action", 0))
    pending: set[asyncio.Task[Any]] = set()

    async def operation(awaitable: Any) -> Any:
        task = asyncio.create_task(awaitable)
        pending.add(task)
        try:
            return await asyncio.shield(task)
        finally:
            if task.done():
                pending.discard(task)

    def request_policy(url: str, method: str) -> None:
        if active is None or url != active.url or method != "POST":
            raise PolicyDenied("auth_unreviewed_form_request")
        service.policy.check_replay_request(url, method)

    class Ticket:
        def admit(self) -> None:
            nonlocal admitted, requests
            if admitted or active is None:
                raise PolicyDenied("auth_form_already_admitted")
            refs = tuple(value.reference for value in filled.values() if value.single_use)
            refs += (
                inputs.nonce_reference(plan.actor_id, plan.tenant_id, active.url, active_nonce),
            )
            on_admit(refs)
            requests += 1
            admitted = True

        def complete(self, status: int, _headers: dict[str, str]) -> None:
            if status != 200:
                raise PolicyDenied("auth_form_response_rejected")
            completed.set()

        def fail(self) -> None:
            pass  # SQLite retains admitted state; the adapter records uncertainty.

    def capture(url: str, method: str, headers: list[tuple[str, str]], body: bytes) -> Ticket:
        request_policy(url, method)
        assert active is not None
        content_types = [value for name, value in headers if name.lower() == "content-type"]
        if content_types != ["application/x-www-form-urlencoded"] or len(body) > 65536:
            raise PolicyDenied("auth_form_wire_type_denied")
        fields = parse_qsl(
            body.decode("utf-8", errors="strict"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=16,
        )
        values = dict(fields)
        if (
            len(values) != len(fields)
            or set(values) != set(active.fields)
            or values.get(active.nonce_field) != active_nonce
            or set(filled) != set(active.fields) - {active.nonce_field}
            or any(values.get(name) != value.value for name, value in filled.items())
        ):
            raise PolicyDenied("auth_form_private_input_mismatch")
        return Ticket()

    def read_admit(url: str) -> None:
        nonlocal requests
        if url not in plan.allowed_get_urls or requests >= 16:
            raise PolicyDenied("auth_read_boundary_denied")
        on_read(url)
        requests += 1

    async def route_request(route: Route) -> None:
        request = route.request
        if (request.method == "GET" and request.url in plan.allowed_get_urls) or (
            request.method == "POST" and active is not None and request.url == active.url
        ):
            await route.continue_()
        else:
            await route.abort("blockedbyclient")

    try:
        proxy.request_admission, proxy.request_capture = read_admit, capture
        proxy.request_headers = None
        proxy.request_policy, proxy.on_complete = request_policy, None
        proxy.on_response = service.on_response
        proxy.navigation_urls = set(plan.allowed_get_urls) | {
            action.url for action in plan.actions if action.kind == "submit"
        }
        proxy.max_wire_bytes = 128 * 1024
        context = await service._browser.new_context(
            storage_state=cast("StorageState | None", checkpoint.get("storage_state")),
            accept_downloads=False,
            service_workers="block",
            ignore_https_errors=False,
        )
        service._contexts_created += 1
        await context.route("**/*", route_request)
        await context.route_web_socket("**/*", lambda socket: socket.close())
        page_lease = service.governor.acquire("page", estimated_bytes=8 * 1024 * 1024)
        page = await context.new_page()
        service._pages_created += 1
        page.set_default_timeout(service.limits.readiness_timeout_ms)
        if index:
            url = checkpoint.get("url")
            if url not in plan.allowed_get_urls:
                raise PolicyDenied("auth_checkpoint_navigation_denied")
            await operation(
                page.goto(
                    url, wait_until="domcontentloaded", timeout=service.limits.navigation_timeout_ms
                )
            )
        start_index = index
        for index in range(start_index, len(plan.actions)):
            action = plan.actions[index]
            if action.kind == "navigate":
                await operation(
                    page.goto(
                        action.url,
                        wait_until="domcontentloaded",
                        timeout=service.limits.navigation_timeout_ms,
                    )
                )
                continue
            target = page.locator(action.selector)
            if await operation(target.count()) != 1:
                raise PolicyDenied("auth_action_requires_unique_element")
            if action.kind == "fill":
                try:
                    value = inputs.get(action.input_ref, plan.actor_id, plan.tenant_id)
                except WorkflowInputUnavailable:
                    return ReviewedBrowserResult(
                        "awaiting_input",
                        index,
                        dict(await operation(context.storage_state())),
                        page.url,
                        requests,
                    )
                name = await operation(target.get_attribute("name"))
                if (
                    not name
                    or name in filled
                    or (
                        value.purpose == "password"
                        and await operation(target.get_attribute("type")) != "password"
                    )
                ):
                    raise PolicyDenied("auth_input_element_denied")
                await operation(target.fill(value.value))
                filled[name] = value
            elif action.kind == "wait":
                await operation(target.wait_for(state="visible"))
            elif action.kind == "submit":
                if (
                    await operation(target.get_attribute("method")) or "get"
                ).upper() != "POST" or urljoin(
                    page.url, await operation(target.get_attribute("action")) or page.url
                ) != action.url:
                    raise PolicyDenied("auth_reviewed_form_action_mismatch")
                nonce = page.locator(action.nonce_selector)
                if (
                    await operation(nonce.count()) != 1
                    or await operation(nonce.get_attribute("name")) != action.nonce_field
                ):
                    raise PolicyDenied("auth_reviewed_nonce_element_required")
                active_nonce = await operation(nonce.input_value())
                inputs.nonce_reference(plan.actor_id, plan.tenant_id, action.url, active_nonce)
                active, admitted = action, False
                completed.clear()
                button = target.locator('button[type="submit"],input[type="submit"]')
                if await operation(button.count()) != 1:
                    raise PolicyDenied("auth_single_submit_control_required")
                await operation(button.click())
                await asyncio.wait_for(
                    completed.wait(), service.limits.navigation_timeout_ms / 1000
                )
                await operation(page.wait_for_load_state("domcontentloaded"))
                storage = dict(await operation(context.storage_state()))
                on_checkpoint(index + 1, storage, page.url)
                active, admitted = None, False
                filled.clear()
        response = await operation(
            page.goto(
                plan.identity_url,
                wait_until="domcontentloaded",
                timeout=service.limits.navigation_timeout_ms,
            )
        )
        if response is None:
            raise PolicyDenied("auth_identity_response_missing")
        if plan.outcome == "authenticated":
            raw = await operation(response.body())
            if response.status != 200 or len(raw) > 16384:
                raise PolicyDenied("auth_identity_response_rejected")
            identity = json.loads(raw)
            if (
                not isinstance(identity, dict)
                or identity.get("actor") != plan.actor_id
                or identity.get("tenant") != plan.tenant_id
            ):
                raise PolicyDenied("auth_identity_mismatch")
        elif response.status not in {401, 403}:
            raise PolicyDenied("logout_not_verified")
        return ReviewedBrowserResult(
            plan.outcome,
            len(plan.actions),
            dict(await operation(context.storage_state())),
            page.url,
            requests,
            response.status,
        )
    finally:

        async def cleanup_all() -> None:
            try:
                if context is not None:
                    try:
                        await asyncio.wait_for(
                            context.close(), service.limits.cleanup_timeout_seconds
                        )
                    except Exception:  # noqa: BLE001 - resource release must continue
                        service._cleanup_errors += 1
                    finally:
                        service._contexts_closed += 1
                        service._pages_closed += int(page is not None)
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
            finally:
                if page_lease is not None:
                    page_lease.release()
                context_lease.release()
                with contextlib.suppress(TimeoutError):
                    await proxy.drain_captures(service.limits.cleanup_timeout_seconds)
                (
                    proxy.request_admission,
                    proxy.request_capture,
                    proxy.request_headers,
                    proxy.request_policy,
                    proxy.on_complete,
                    proxy.on_response,
                    proxy.navigation_urls,
                    proxy.max_wire_bytes,
                ) = saved

        cleanup = asyncio.create_task(cleanup_all())
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            await cleanup
            raise
