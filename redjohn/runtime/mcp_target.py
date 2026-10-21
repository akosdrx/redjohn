"""Durable, host-reviewed local MCP target reads inside an attested worker.

Only observed anonymous GET surfaces and host-fixed argument contexts are
supported here. The job stores references and contract digests, never live
credentials or an opaque replay payload. Remote target workers remain blocked.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import platform
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record, stable_key
from redjohn.assessment.policy import PolicyDenied
from redjohn.runtime.legacy_shell_boundary import LegacyShellBoundary
from redjohn.tools.mcp.authorization import (
    authorize_arguments,
    authorize_descriptor,
    contract_for,
)
from redjohn.tools.mcp.stdio_boundary import McpStdioLaunch


if TYPE_CHECKING:
    from agents.mcp import MCPServer

    from redjohn.assessment.models import CoverageStatus
    from redjohn.runtime.legacy_execution import LegacyExecution
    from redjohn.tools.mcp.config import McpConnectionConfig, McpToolAuthorization
    from redjohn.tools.mcp.registry import McpConnectionEntry, McpRegistry


CAPABILITY = "mcp_target_read"
VERSION = "redjohn-stdio-target-1"
_RESERVED_ENV = {
    "PATH",
    "HOME",
    "WORKSPACE",
    "TMPDIR",
    "TMP",
    "TEMP",
    "SHELL",
    "BASH_ENV",
    "ENV",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
}


def _target_config(config: McpConnectionConfig | None) -> bool:
    return bool(
        config is not None
        and config.transport == "stdio"
        and config.tool_authorizations
        and all(rule.effect.startswith("target-") for rule in config.tool_authorizations)
    )


def _linux_pid_boundary() -> bool:
    return platform.system() == "Linux"


def _executable(config: McpConnectionConfig) -> str:
    value = config.command or ""
    return value if Path(value).is_absolute() else shutil.which(value) or value


def _configuration_digest(config: McpConnectionConfig) -> str:
    """Pin explicit local launch files, not only self-reported server metadata."""
    executable = _executable(config)
    artifacts: dict[str, str] = {}
    for value in [executable, *config.args]:
        path = Path(value)
        if not path.is_absolute() or not path.is_file():
            continue
        path = path.resolve()
        if len(artifacts) >= 16 or path.stat().st_size > 64 * 1024**2:
            raise PolicyDenied("mcp_target_runtime_artifact_limit")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        artifacts[str(path)] = digest.hexdigest()
    return stable_key([config.model_dump(), artifacts])


class McpTargetAdapter:
    resource_class = "worker"
    owner_process_only = True
    dispatch_memory_bytes = 64 * 1024 * 1024

    def __init__(self, owner: LegacyExecution, registry: McpRegistry) -> None:
        if owner.control is None or owner.control.scheduler is None:
            raise PolicyDenied("mcp_target_durable_scheduler_required")
        self.owner, self.registry = owner, registry
        self.control = owner.control
        self._permit = contextvars.ContextVar[object | None](
            "redjohn_mcp_target_permit", default=None
        )
        self._permit_token = object()
        self._active: McpConnectionEntry | None = None
        self._active_url: str | None = None
        self._boundaries: dict[str, LegacyShellBoundary] = {}
        self._configuration: dict[str, str] = {}
        self._configuration_errors: dict[str, str] = {}
        for name in registry.names():
            entry = registry.get(name)
            assert entry is not None
            if _target_config(entry.config):
                if entry.session is not None or entry._connect_task is not None:
                    raise PolicyDenied("mcp_target_binding_requires_inert_registry")
                assert entry.config is not None
                try:
                    self._configuration[name] = _configuration_digest(entry.config)
                except (OSError, PolicyDenied) as exc:
                    code = (
                        str(exc)
                        if isinstance(exc, PolicyDenied)
                        else "mcp_target_artifact_unreadable"
                    )
                    self._configuration_errors[name] = code
                    self._configuration[name] = stable_key([entry.config.model_dump(), code])
        digest = stable_key(self._configuration)
        self.control.registry.bind_mcp_target(contract_sha256=digest, server_version=VERSION)
        assert self.control.scheduler is not None
        self.control.scheduler.adapters[CAPABILITY] = self
        for name in self._configuration:
            entry = registry.get(name)
            assert entry is not None
            entry._target_adapter = self

    def dispatching(self, entry: McpConnectionEntry) -> bool:
        return self._permit.get() is self._permit_token and self._active is entry

    def _entry(self, name: str) -> McpConnectionEntry:
        self.owner.check_policy()
        if name in self._configuration_errors:
            raise PolicyDenied(self._configuration_errors[name])
        entry = self.registry.get(name)
        if (
            entry is None
            or entry.config is None
            or _configuration_digest(entry.config) != self._configuration.get(name)
            or entry._target_adapter is not self
        ):
            raise PolicyDenied("mcp_target_host_configuration_changed")
        return entry

    def _rule(self, entry: McpConnectionEntry, tool: str) -> McpToolAuthorization:
        rule = contract_for(entry, tool)
        if (
            rule.effect != "target-read"
            or rule.actor_id != "anonymous"
            or len(rule.url_arguments) != 1
            or set(rule.fixed_arguments) & set(rule.url_arguments)
            or set(rule.allowed_arguments) != set(rule.fixed_arguments) | set(rule.url_arguments)
        ):
            raise PolicyDenied("mcp_target_argument_replay_not_implemented")
        return rule

    def _arguments(self, rule: McpToolAuthorization, surface: Surface) -> dict[str, Any]:
        if (
            surface.source != "observed"
            or surface.actor_id != "anonymous"
            or surface.tenant_id
            or surface.method != "GET"
            or surface.body_sha256
            or surface.resource_kind
        ):
            raise PolicyDenied("mcp_target_observed_anonymous_get_required")
        arguments = {**rule.fixed_arguments, rule.url_arguments[0]: surface.url}
        authorize_arguments(rule, arguments, self.control.policy)
        return arguments

    async def submit(
        self,
        entry: McpConnectionEntry,
        tool: str,
        arguments: dict[str, Any],
        surface_id: str | None,
    ) -> dict[str, Any]:
        self._entry(entry.name)
        if not surface_id:
            raise PolicyDenied("mcp_target_surface_reference_required")
        rule = self._rule(entry, tool)
        surface = self.control.store.surface(self.control.policy.engagement_id, surface_id)
        if stable_key(arguments) != stable_key(self._arguments(rule, surface)):
            raise PolicyDenied("mcp_target_arguments_do_not_match_surface")
        spec = JobSpec(
            surface_id,
            "mcp_readonly_observation",
            CAPABILITY,
            policy_revision=self.control.policy.revision,
            # Delivery can be unknown even for a reviewed GET. A restart or
            # broken transport never silently repeats a possibly delivered call.
            idempotent=False,
            timeout_seconds=min(110, entry.config.session_timeout_seconds if entry.config else 60),
            options={
                "connection": entry.name,
                "tool": tool,
                "contract_sha256": stable_key(rule.model_dump()),
            },
            **self.control.registry.execution_versions(CAPABILITY),
        )
        return await self.control.call(
            "jobs_submit_batch",
            {"policy_revision": self.control.policy.revision, "jobs": [spec.__dict__]},
        )

    def _job(
        self, surface: Surface, spec: JobSpec
    ) -> tuple[McpConnectionEntry, McpToolAuthorization, dict[str, Any]]:
        if set(spec.options) != {"connection", "tool", "contract_sha256"} or any(
            not isinstance(value, str) or not 0 < len(value) <= 256
            for value in spec.options.values()
        ):
            raise PolicyDenied("mcp_target_job_schema_invalid")
        entry = self._entry(spec.options["connection"])
        rule = self._rule(entry, spec.options["tool"])
        if (
            stable_key(rule.model_dump()) != spec.options["contract_sha256"]
            or {"tool_version": spec.tool_version, "template_version": spec.template_version}
            != self.control.registry.execution_versions(CAPABILITY)
            or spec.idempotent
        ):
            raise PolicyDenied("mcp_target_job_contract_changed")
        return entry, rule, self._arguments(rule, surface)

    async def launch(self, config: McpConnectionConfig) -> McpStdioLaunch:
        entry = self._entry(config.name)
        if not self.dispatching(entry):
            raise PolicyDenied("mcp_target_dispatch_requires_scheduled_job")
        # Seatbelt restricts sockets, but an arbitrary fork/setsid stdio server
        # also needs an attested process-tree lifetime boundary. Never claim the
        # Linux PID-namespace guarantee across another kernel or macOS backend.
        self._check_backend()
        executable = _executable(config)
        if not Path(executable).is_absolute() or not Path(executable).is_file():
            raise PolicyDenied("mcp_target_executable_unavailable")
        if any(
            name.upper() in _RESERVED_ENV
            or name.upper().startswith(("LD_", "DYLD_", "PYTHON", "BASH_FUNC_"))
            for name in config.env
        ):
            raise PolicyDenied("mcp_target_environment_override_denied")
        boundary = self._boundaries.get(config.name)
        if boundary is None:
            transport = self.owner._shell_transport
            if transport is None or transport.request_admission is None:
                raise PolicyDenied("mcp_target_shared_proxy_transport_required")
            paths = tuple(
                Path(arg).resolve()
                for arg in [executable, *config.args]
                if Path(arg).is_absolute() and Path(arg).is_file()
            )
            if len(paths) > 16:
                raise PolicyDenied("mcp_target_runtime_path_limit")
            boundary = LegacyShellBoundary(
                self.owner._sandbox_session,
                self.control,
                admission=lambda url: self._admit_target(entry, url),
                tls_config=transport.tls_config,
                on_response=transport.on_response,
                additional_read_paths=paths,
                attach_session=False,
                request_headers=self._anonymous_headers,
            )
            self._boundaries[config.name] = boundary
            await boundary.start()
        boundary.assert_active()
        environment = {**boundary.environment, **config.env}
        # wrap() creates its own env -i; pass explicitly reviewed non-reserved
        # operator values after it, before the actual executable is invoked.
        command = [
            "/usr/bin/env",
            *(f"{key}={value}" for key, value in config.env.items()),
            executable,
            *config.args,
        ]
        return McpStdioLaunch(
            tuple(boundary.wrap(command, cwd=boundary.workspace)),
            environment,
            str(boundary.workspace),
        )

    def _check_backend(self) -> None:
        if not _linux_pid_boundary():
            raise PolicyDenied("mcp_target_process_tree_boundary_unavailable")
        inner = getattr(self.owner._sandbox_session, "_inner", self.owner._sandbox_session)
        if not callable(getattr(inner, "bind_assessment_shell_boundary", None)):
            raise PolicyDenied("mcp_target_local_backend_attachment_unavailable")

    @staticmethod
    def _anonymous_headers(
        _url: str, _method: str, headers: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        allowed = {
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "accept-language",
            "cache-control",
            "pragma",
            "connection",
            "proxy-connection",
        }
        if any(name.lower() not in allowed for name, _value in headers):
            raise PolicyDenied("mcp_target_authenticated_headers_not_implemented")
        return headers

    def _admit_target(self, entry: McpConnectionEntry, url: str) -> None:
        self.owner.check_policy()
        if (
            self._active is not entry
            or self._active_url is None
            or self.control.policy._request_url(url)
            != self.control.policy._request_url(self._active_url)
        ):
            raise PolicyDenied("mcp_target_request_outside_scheduled_surface")
        transport = self.owner._shell_transport
        assert transport is not None and transport.request_admission is not None
        transport.request_admission(url)

    async def prepare(self, _job: dict[str, Any], surface: Surface, spec: JobSpec) -> None:
        entry, _rule, _arguments = self._job(surface, spec)
        self._check_backend()
        self._active = entry
        self._active_url = surface.url
        token = self._permit.set(self._permit_token)
        lease = None
        try:
            lease = self.owner.governor.acquire("worker", estimated_bytes=0)
            await entry.ensure_connected()
        except BaseException:
            if lease is not None:
                await self._cancel_entry(entry)
            raise
        finally:
            if lease is not None:
                lease.release()
            self._permit.reset(token)
            self._active = None
            self._active_url = None

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:
        entry, rule, arguments = self._job(surface, spec)
        self._active = entry
        self._active_url = surface.url
        token = self._permit.set(self._permit_token)
        try:

            async def authorize(server: MCPServer) -> None:
                self._job(surface, spec)
                boundary = self._boundaries[entry.name]
                boundary.assert_active()
                descriptors = await server.list_tools()
                descriptor = next((item for item in descriptors if item.name == rule.tool), None)
                if descriptor is None:
                    raise PolicyDenied("mcp_authorized_tool_unavailable")  # noqa: TRY301
                authorize_descriptor(entry, rule, descriptor, server=server)

            session = await entry.ensure_connected()
            result = await session.dispatch(
                rule.tool,
                arguments,
                label=f"mcp-target:{entry.name}:{rule.tool}",
                result_transform=entry.result_transform,
                supports_images=False,
                before_call=authorize,
                allow_replay=False,
            )
            encoded = json.dumps(result, allow_nan=False).encode()
            if len(encoded) > self.control.store.artifact_max_bytes:
                raise PolicyDenied("mcp_target_result_evidence_limit")  # noqa: TRY301
            failed = isinstance(result, dict) and result.get("success") is False
            coverage = (
                result.get("coverage_effect") if failed and isinstance(result, dict) else None
            )
            blocked = coverage in {"blocked", "unsupported"}
            coverage_status: CoverageStatus = "completed"
            if failed:
                coverage_status = (
                    "blocked"
                    if coverage == "blocked"
                    else "unsupported"
                    if coverage == "unsupported"
                    else "inconclusive"
                )
            evidence = self.control.store.evidence_put(
                self.control.policy.engagement_id, result, job_id=job["id"], kind="mcp_target"
            )
            return AdapterResult(
                "failed" if failed else "succeeded",
                coverage_status,
                summary={
                    "evidence_refs": [evidence],
                    "server_name": rule.server_name,
                    "server_version": rule.server_version,
                    "schema_sha256": rule.schema_sha256,
                    "boundary": "linux_local_attested_namespace",
                },
                error=error_record(
                    str(result.get("code", "mcp_target_tool_failed"))
                    if blocked
                    else "mcp_target_tool_failed",
                    coverage_effect=coverage_status,
                )
                if failed
                else None,
            )
        except BaseException:
            await self._cancel_entry(entry)
            raise
        finally:
            self._permit.reset(token)
            self._active = None
            self._active_url = None

    async def _cancel_entry(self, entry: McpConnectionEntry) -> None:
        try:
            await entry.close()
        finally:
            if (boundary := self._boundaries.get(entry.name)) is not None:
                await boundary.close()
                del self._boundaries[entry.name]

    async def cancel(self) -> None:
        if self._active is not None:
            await self._cancel_entry(self._active)

    async def cleanup(self) -> None:
        # A completed read retains the selected stateful session and its full
        # context memory lease; the next job may reuse it. Run shutdown owns it.
        return

    async def close(self) -> None:
        for name in list(self._configuration):
            entry = self.registry.get(name)
            if entry is not None:
                await self._cancel_entry(entry)
