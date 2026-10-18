"""Opt-in Linux cgroup v2 backstop for a dedicated assessment controller.

The administrator supplies an already delegated subtree. This code neither
elevates privileges nor changes host-wide controls. The controller starts in
the group before exec; moving an already allocated controller would not move
its memory charges. Cleanup kills and verifies remaining descendants first.
"""

from __future__ import annotations

import os
import platform
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Self

from redjohn.assessment.resources import MIB, ResourceAdmissionError


_MOUNT = Path("/sys/fs/cgroup")
_GROUP = re.compile(r"redjohn-[a-f0-9]{32}")

# Internal argv only. The helper joins the group before a fresh Python exec,
# and dies if its supervising parent disappears before or after that exec.
_BOOTSTRAP = """
import ctypes,os,signal,sys
group,parent,executable,*arguments=sys.argv[1:]
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(1,signal.SIGKILL,0,0,0)!=0:
    raise OSError(ctypes.get_errno(),'parent-death fence unavailable')
if os.getppid()!=int(parent):
    raise SystemExit(2)
with open(group+'/cgroup.procs','w') as handle:
    handle.write(str(os.getpid()))
with open('/proc/self/cgroup') as handle:
    membership=next(line[3:].strip() for line in handle if line.startswith('0::'))
if '/sys/fs/cgroup'+membership!=group:
    raise SystemExit(2)
os.environ['REDJOHN_CONTAINED_GROUP']=group
os.execv(executable,[executable,*arguments])
"""


class MemoryLimitUnavailableError(ResourceAdmissionError):
    code = "blocked_os_memory_limit_unavailable"


class MemoryLimitExceededError(ResourceAdmissionError):
    code = "resource_exhausted"

    def __init__(self, measurement: dict[str, Any]) -> None:
        self.measurement = measurement
        self.evidence_ref: str | None = None
        self.evidence_error: str | None = None
        super().__init__("os_memory_limit_exceeded")


def _current_group() -> Path:
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            group = _MOUNT / line[3:].lstrip("/")
            resolved = group.resolve(strict=True)
            if resolved != group or (group != _MOUNT and _MOUNT not in group.parents):
                raise MemoryLimitUnavailableError("invalid_cgroup_membership")
            return group
    raise MemoryLimitUnavailableError("cgroup_v2_required")


def _populated(group: Path) -> bool:
    counters = dict(line.split() for line in (group / "cgroup.events").read_text().splitlines())
    return counters["populated"] != "0"


def _owned_group(group: Path, inode: int) -> bool:
    return (
        group.is_absolute()
        and _MOUNT in group.parents
        and group.resolve() == group
        and _GROUP.fullmatch(group.name) is not None
        and group.stat().st_uid == os.getuid()
        and group.stat().st_ino == inode
        and (group / "memory.max").read_text().strip().isdigit()
        and (group / "memory.oom.group").read_text().strip() == "1"
    )


def current_memory_fence() -> tuple[str, int] | None:
    """Only RedJohn-owned, kernel-enforced groups can authorize crash reclaim."""
    if platform.system() != "Linux":
        return None
    try:
        group = _current_group()
        inode = group.stat().st_ino
        if _owned_group(group, inode):
            return str(group), inode
    except (OSError, ValueError, KeyError, MemoryLimitUnavailableError):
        pass
    return None


def reap_memory_fence(path: str, inode: int) -> bool:
    """After owner death, terminate the attested group before reclaiming leases.

    Callers must first prove that every ledger owner sharing this fence is dead.
    A TTL, missing heartbeat or controller restart is never that proof.
    """
    group = Path(path)
    if (
        platform.system() != "Linux"
        or not group.is_absolute()
        or _MOUNT not in group.parents
        or group.resolve() != group
        or not _GROUP.fullmatch(group.name)
    ):
        return False
    try:
        if not group.exists():
            # Kernel cgroups can only be removed after their complete subtree is empty.
            return True
        if not _owned_group(group, inode):
            return False
        if _populated(group):
            (group / "cgroup.kill").write_text("1")
        deadline = time.monotonic() + 2
        while _populated(group):
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        group.rmdir()
    except (OSError, ValueError, KeyError):
        return False
    return True


class LinuxMemoryBoundary:
    """The supervising caller stays outside; controller and descendants join."""

    def __init__(self, config: object, memory_budget_bytes: int) -> None:
        if (
            not isinstance(config, dict)
            or set(config) - {"delegated_root", "pids_max"}
            or not isinstance(config.get("delegated_root"), str)
            or not Path(config["delegated_root"]).is_absolute()
            or type(memory_budget_bytes) is not int
            or not 32 * MIB <= memory_budget_bytes <= 2**50
        ):
            raise ValueError("invalid_os_memory_configuration")
        pids = config.get("pids_max", 512)
        if type(pids) is not int or not 64 <= pids <= 4096:
            raise ValueError("invalid_os_pids_limit")
        self.root = Path(config["delegated_root"])
        self.memory_budget_bytes = memory_budget_bytes
        self.pids_max = pids
        self.group: Path | None = None
        self.entered = False
        self.borrowed = False
        self._last: dict[str, Any] = {}

    def __enter__(self) -> Self:
        if self.borrowed:
            return self
        if platform.system() != "Linux" or not (_MOUNT / "cgroup.controllers").is_file():
            raise MemoryLimitUnavailableError("linux_cgroup_v2_required")
        try:
            if (
                _MOUNT not in self.root.parents
                or self.root.resolve(strict=True) != self.root
                or self.root.stat().st_uid != os.getuid()
                or not {"memory", "pids"}
                <= set((self.root / "cgroup.subtree_control").read_text().split())
            ):
                raise MemoryLimitUnavailableError("memory_and_pids_controllers_not_delegated")  # noqa: TRY301 - explicit enforcement gate
            group = self.root / ("redjohn-" + uuid.uuid4().hex)
            group.mkdir(mode=0o700)
            self.group = group
            for name, value in (
                ("memory.max", self.memory_budget_bytes),
                ("memory.swap.max", 0),
                ("memory.oom.group", 1),
                ("pids.max", self.pids_max),
            ):
                (group / name).write_text(str(value))
                if (group / name).read_text().strip() != str(value):
                    raise MemoryLimitUnavailableError("os_memory_limit_readback_mismatch")  # noqa: TRY301 - explicit enforcement gate
            self.entered = True
            self._last = self.snapshot()
        except (OSError, KeyError, ValueError) as exc:
            self._cleanup()
            raise MemoryLimitUnavailableError("os_memory_delegation_unavailable") from exc
        except BaseException:
            self._cleanup()
            raise
        return self

    @classmethod
    def current(cls, config: object, memory_budget_bytes: int) -> Self | None:
        boundary = cls(config, memory_budget_bytes)
        fence = current_memory_fence()
        claimed = os.environ.get("REDJOHN_CONTAINED_GROUP")
        if claimed is not None and (fence is None or fence[0] != claimed):
            raise MemoryLimitUnavailableError("os_memory_membership_not_enforced")
        if fence is None:
            return None
        group = Path(fence[0])
        if group.parent != boundary.root:
            return None
        if (
            int((group / "memory.max").read_text()) != memory_budget_bytes
            or int((group / "memory.swap.max").read_text()) != 0
            or int((group / "pids.max").read_text()) != boundary.pids_max
        ):
            raise MemoryLimitUnavailableError("os_memory_limit_readback_mismatch")
        boundary.group, boundary.entered, boundary.borrowed = group, True, True
        return boundary

    def wrap_argv(self, argv: list[str]) -> list[str]:
        if not self.entered or self.borrowed or self.group is None or not argv:
            raise MemoryLimitUnavailableError("os_memory_boundary_not_ready")
        return [
            sys.executable,
            "-I",
            "-S",
            "-c",
            _BOOTSTRAP,
            str(self.group),
            str(os.getpid()),
            *argv,
        ]

    def snapshot(self) -> dict[str, Any]:
        if not self.entered or self.group is None:
            return dict(self._last)
        if not self.group.exists():
            return {**self._last, "reclaimed_after_owner_death": True}
        events = dict(
            line.split() for line in (self.group / "memory.events").read_text().splitlines()
        )
        peak = self.group / "memory.peak"
        return {
            "enforced": True,
            "method": "linux_cgroup_v2_before_controller_exec",
            "memory_max_bytes": int((self.group / "memory.max").read_text()),
            "memory_current_bytes": int((self.group / "memory.current").read_text()),
            "memory_peak_bytes": int(peak.read_text()) if peak.is_file() else None,
            "swap_max_bytes": int((self.group / "memory.swap.max").read_text()),
            "pids_max": int((self.group / "pids.max").read_text()),
            "oom_events": int(events["oom"]),
            "oom_kills": int(events["oom_kill"]),
        }

    def _cleanup(self) -> None:
        if self.group is None:
            return
        group = self.group
        self.entered = False
        if not group.exists():
            self.group = None
            return
        if not reap_memory_fence(str(group), group.stat().st_ino):
            # Incomplete setup may not yet have memory.oom.group enabled. Such
            # an empty, never-used group can still be removed without reclaim.
            if not _populated(group):
                group.rmdir()
            else:
                raise MemoryLimitUnavailableError("os_memory_cleanup_not_verified")
        self.group = None

    def __exit__(self, *_args: object) -> None:
        if self.borrowed:
            self.entered = False
            return
        try:
            self._last = self.snapshot()
        finally:
            self._cleanup()
