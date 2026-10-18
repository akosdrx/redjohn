"""Reuse the assessed worker namespace for the local SDK Shell transport.

There is one policy proxy and no browser process. Commands keep the SDK's
workspace/filesystem contract; all their descendants lose direct networking.
Unsupported backends fail before executing the selected shell command.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary


if TYPE_CHECKING:
    from collections.abc import Callable

    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.control import AssessmentControl


class LegacyShellBoundary:
    def __init__(
        self,
        session: Any,
        control: AssessmentControl,
        *,
        admission: Callable[[str], None],
        tls_config: BrowserTLSConfig | None = None,
        on_response: Callable[[str, int, dict[str, str]], None] | None = None,
    ) -> None:
        self.session, self.control = session, control
        self.inner = getattr(session, "_inner", session)
        if not callable(getattr(self.inner, "bind_assessment_shell_boundary", None)):
            raise EgressUnavailable("legacy_shell_backend_namespace_attachment_unavailable")
        self.workspace = Path(self.inner.state.manifest.root).resolve()
        self._admission = admission
        self.proxy = BrowserEgressProxy(
            control.policy,
            request_admission=self._admit,
            tls_config=tls_config,
            on_response=on_response,
        )
        self.boundary: LinuxEgressBoundary | None = None
        self._assets: tempfile.TemporaryDirectory[str] | None = None
        self.environment: dict[str, str] = {}

    def _admit(self, url: str) -> None:
        current = self.control.store.policy(self.control.policy.engagement_id, self.control.caller)
        current.authorize(self.control.caller, self.control.policy.revision)
        if current != self.control.policy or self.control.store.is_stopped(current):
            raise EgressUnavailable("legacy_shell_policy_changed")
        self._admission(url)

    async def start(self) -> None:
        try:
            await self.proxy.start()
            self._assets = tempfile.TemporaryDirectory(prefix="redjohn-shell-trust-")
            certificate = Path(self._assets.name) / "proxy-ca.pem"
            if self.proxy.client_ca_certificate is not None:
                certificate.write_bytes(self.proxy.client_ca_certificate)
                certificate.chmod(0o600)
            read_only: list[Path] = []
            writable: list[Path] = []
            for grant in self.inner.state.manifest.extra_path_grants:
                path = Path(grant.path).expanduser().resolve()
                if path == self.workspace or self.workspace in path.parents or not path.exists():
                    continue
                (read_only if grant.read_only else writable).append(path)
            if certificate.exists():
                read_only.append(certificate)
            self.boundary = LinuxEgressBoundary(
                self.proxy.url,
                self.workspace,
                read_only_paths=tuple(read_only),
                writable_paths=tuple(writable),
                timeout_seconds=60,
            )
            await self.boundary.start()
            await self.boundary.attest()
            self.environment = {
                **self.boundary.environment,
                "PATH": "/usr/local/bin:/usr/local/go/bin:/usr/bin:/bin",
                "http_proxy": self.proxy.url,
                "https_proxy": self.proxy.url,
                "HTTP_PROXY": self.proxy.url,
                "HTTPS_PROXY": self.proxy.url,
                "NO_PROXY": "",
                "no_proxy": "",
            }
            if certificate.exists():
                for name in (
                    "SSL_CERT_FILE",
                    "REQUESTS_CA_BUNDLE",
                    "CURL_CA_BUNDLE",
                    "NODE_EXTRA_CA_CERTS",
                ):
                    self.environment[name] = str(certificate)
            self.inner.bind_assessment_shell_boundary(self)
        except BaseException:
            await self.close()
            raise

    def wrap(self, command: list[str], *, cwd: Path) -> list[str]:
        if self.boundary is None:
            raise EgressUnavailable("legacy_shell_boundary_not_started")
        self.boundary.assert_active()
        if not command:
            raise EgressUnavailable("legacy_shell_empty_command")
        executable = command[0]
        if not Path(executable).is_absolute():
            executable = shutil.which(executable, path=self.environment["PATH"]) or ""
        if not executable:
            raise EgressUnavailable("legacy_shell_executable_unavailable")
        # Only controller-built variables cross the namespace. Provider tokens,
        # inherited cloud credential chains, HOME and ambient proxy settings do
        # not cross the clearenv boundary.
        return self.boundary.wrap_argv(
            [
                "/usr/bin/env",
                *(f"{name}={value}" for name, value in self.environment.items()),
                executable,
                *command[1:],
            ],
            cwd=cwd,
        )

    async def close(self) -> None:
        if getattr(self.inner, "redjohn_shell_boundary", None) is self:
            self.inner.bind_assessment_shell_boundary(None)
        try:
            if self.boundary is not None:
                await self.boundary.close()
                self.boundary = None
        finally:
            await self.proxy.close()
            if self._assets is not None:
                self._assets.cleanup()
                self._assets = None
