"""Structural boundaries for controller-owned scanner and HTTP services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol


if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from redjohn.assessment.egress import LinuxEgressBoundary
    from redjohn.assessment.recovery import RateLimitObservation


class ScannerOutput(Protocol):
    @property
    def stdout(self) -> bytes: ...

    @property
    def stderr(self) -> bytes: ...

    @property
    def exit_code(self) -> int: ...


class ScannerReadStream(Protocol):
    def read(self, size: int = -1) -> bytes | str: ...
    def close(self) -> None: ...


class ScannerSession(Protocol):
    workspace: Path

    def bind_proxy(self, url: str | None) -> None: ...
    def bind_egress_boundary(self, boundary: LinuxEgressBoundary | None) -> None: ...
    def assert_remote_boundary(self) -> None: ...
    async def read(self, path: Path) -> ScannerReadStream: ...
    async def exec(self, *command: str, timeout: float, shell: bool) -> ScannerOutput: ...


class HTTPRateLimits(Protocol):
    def admit(self, origin: str) -> bool: ...
    def remaining(self, origin: str) -> float: ...
    def observe(
        self, origin: str, status: int, headers: Mapping[str, str] | None = None
    ) -> RateLimitObservation: ...
