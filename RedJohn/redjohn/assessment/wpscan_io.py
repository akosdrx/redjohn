"""Selected-job WP file IO through the shared owned subprocess lifecycle."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.os_memory import _current_owner_guard, current_memory_fence
from redjohn.assessment.pinned_tools import BinaryPin, PinnedToolRunner
from redjohn.assessment.resources import ResourceAdmissionError


if TYPE_CHECKING:
    from collections.abc import Callable


class WPScanIOUnverified(ResourceAdmissionError):  # noqa: N818 - scheduler retention protocol
    requires_lease_retention = True


def trusted_python_pin() -> BinaryPin:
    # Only the trusted host installation is read on the controller. Operator
    # runtime/source/license/HTML IO is exclusively in the fixed child below.
    executable = Path(sys.executable).resolve()
    if not executable.is_file() or executable.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("wpscan_trusted_python_installation_unavailable")
    return BinaryPin(executable, hashlib.sha256(executable.read_bytes()).hexdigest(), "host-python")


class WPScanIO(PinnedToolRunner):
    def __init__(self, root: Path, guard: Callable[[], None]) -> None:
        super().__init__("wordpress_observe_io", trusted_python_pin(), root)
        self.guard = guard
        self.destination: Path | None = None
        self.nonce = ""
        self.fence: tuple[str, int] | None = None
        self.payload: dict[str, Any] = {}
        self._operation: asyncio.Task[dict[str, Any]] | None = None
        self._owned_cleanup: asyncio.Task[None] | None = None
        self._admission = asyncio.Lock()
        self.cleanup_uncertain = False

    def resource_cleanup_verified(self) -> bool:
        return (
            getattr(super(), "resource_cleanup_verified", lambda: False)() is True
            and self.destination is None
            and not self.cleanup_uncertain
            and (self._operation is None or self._operation.done())
            and (self._owned_cleanup is None or self._owned_cleanup.done())
        )

    def _worker_argv(self, argv: list[str]) -> list[str]:
        if argv != [str(self.binary.path), "__redjohn_wpscan_owned_io__"]:
            raise ValueError("wpscan_io_only_fixed_operation_allowed")
        if self.payload["operation"] == "prepare":
            self.guard()
        installation = str(Path(__file__).parents[2])
        fixed = (
            f"import sys;sys.path.insert(0,{installation!r});"
            "from redjohn.assessment.wpscan_io_worker import main;raise SystemExit(main())"
        )
        return [str(self.binary.path), "-I", "-S", "-c", fixed, json.dumps(self.payload)]

    async def _fixed(
        self, operation: str, configuration: dict[str, Any], seconds: float
    ) -> dict[str, Any]:
        from redjohn.assessment.wpscan_runtime import runtime_document  # noqa: PLC0415

        assert self.fence is not None and self.destination is not None
        self.payload = {
            "operation": operation,
            "configuration": configuration,
            "destination": str(self.destination),
            "nonce": self.nonce,
            "controller": os.getpid(),
            "uid": os.getuid(),
            "fence_path": self.fence[0],
            "fence_inode": self.fence[1],
        }
        raw = await self.execute([str(self.binary.path), "__redjohn_wpscan_owned_io__"], seconds)
        if (
            raw.get("error")
            or raw.get("timed_out")
            or raw.get("truncated")
            or raw.get("exit_code") != 0
        ):
            raise ValueError("wpscan_owned_io_operation_unavailable")
        return runtime_document(raw.get("stdout", "").encode())

    async def prepare_bundle(
        self, configuration: dict[str, Any], destination: Path, timeout: float
    ) -> dict[str, Any]:
        async with self._admission:
            if self.destination is not None or self._operation is not None:
                raise WPScanIOUnverified("wpscan_previous_owned_io_not_reconciled")
            self.guard()
            fence = current_memory_fence()
            if fence is None:
                raise ResourceAdmissionError("wpscan_owned_io_current_memory_fence_required")
            _current_owner_guard(Path(fence[0]))
            self.fence, self.destination, self.nonce = fence, destination, uuid.uuid4().hex
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._temporary = tempfile.TemporaryDirectory(prefix="io-", dir=self.root)
            self.workspace = Path(self._temporary.name).resolve()
            self._ca_file = self.workspace / "proxy-ca.pem"
            self._ca_file.write_bytes(b"fixed_file_io_has_no_network_client\n")
            (self.workspace / "empty-ca-directory").mkdir(mode=0o700)
            self._operation = asyncio.create_task(self._fixed("prepare", configuration, timeout))
            operation = self._operation
        return await asyncio.shield(operation)

    @staticmethod
    async def _join(task: asyncio.Task[Any]) -> Any:
        while True:
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                if task.done():
                    return task.result()

    async def _cleanup_io_bundle(self) -> None:
        operation = self._operation
        if operation is not None and not operation.done():
            operation.cancel()
            try:
                await self._join(operation)
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001, S110 - teardown is the explicit recovery action
                pass
        # The shared runner proves pending delivery/process/worker teardown
        # before admitting a cleanup helper. Unknown resources retain paths.
        await super().cancel()
        if self.destination is not None:
            try:
                result = await self._fixed("cleanup", {}, 5)
                if result != {"cleaned": True, "nonce": self.nonce}:
                    raise ValueError("wpscan_owned_cleanup_unbound")  # noqa: TRY301
            except BaseException:
                self.cleanup_uncertain = True
                raise
            self.destination = None
        await super().cleanup()
        self.cleanup_uncertain = False

    async def cleanup(self) -> None:
        if self._owned_cleanup is None or self._owned_cleanup.done():
            self._owned_cleanup = asyncio.create_task(self._cleanup_io_bundle())
        await self._join(self._owned_cleanup)
