"""Opt-in Linux cgroup v2 backstop for a dedicated assessment controller.

The administrator supplies an already delegated subtree. This code neither
elevates privileges nor changes host-wide controls. The controller starts in
the group before exec; moving an already allocated controller would not move
its memory charges. Cleanup kills and verifies remaining descendants first.
"""

from __future__ import annotations

import errno
import json
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from redjohn.assessment.resources import MIB, ResourceAdmissionError


if TYPE_CHECKING:
    from redjohn.assessment.memory_pool import LinuxMemoryPool


_MOUNT = Path("/sys/fs/cgroup")
_PROC = Path("/proc")
_GROUP = re.compile(r"redjohn-[a-f0-9]{32}")

_OWNER_BOOTSTRAP = """
import json,os,stat,sys
group,parent,prior_userns,uid,attestation,executable,*arguments=sys.argv[1:]
with open('/proc/self/status') as handle:
    status=dict(line.strip().split(':',1) for line in handle if ':' in line)
if (os.getuid()!=int(uid) or os.readlink('/proc/self/ns/user')==prior_userns
    or int(status['CapEff'],16)!=0 or status['NoNewPrivs'].strip()!='1'):
    raise SystemExit(125)
device=os.stat('/sys/fs/cgroup').st_dev
for name in os.listdir('/proc/self/fd'):
    try:
        info=os.fstat(int(name))
    except OSError:
        continue
    if info.st_dev==device or stat.S_ISDIR(info.st_mode):
        raise SystemExit(125)
for candidate in (group+'/memory.max','/proc/'+parent+'/root'+group+'/memory.max'):
    try:
        descriptor=os.open(candidate,os.O_WRONLY)
    except OSError:
        pass
    else:
        os.close(descriptor)
        raise SystemExit(125)
os.environ['REDJOHN_MEMORY_OWNER_NAMESPACE']='readonly_cgroupfs_no_capabilities'
descriptor=os.open(attestation,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(descriptor,'w') as handle:
    json.dump({'verified':True,'pid':os.getpid(),'uid':os.getuid(),
        'user_namespace':os.readlink('/proc/self/ns/user'),
        'capabilities_zero':True,'no_new_privileges':True,'direct_control_open_denied':True,
        'supervisor_proc_root_open_denied':True},handle)
    handle.flush()
    os.fsync(handle.fileno())
os.execv(executable,[executable,*arguments])
"""

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
os.environ['REDJOHN_REQUIRE_OWNED_MEMORY']='1'
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


def require_inline_memory_boundary(config: dict[str, Any], budget: int) -> None:
    """An explicit inline profile must be contained before any SDK/model start."""
    if "os_memory" in config and LinuxMemoryBoundary.current(config["os_memory"], budget) is None:
        raise MemoryLimitUnavailableError("inline_controller_requires_precontained_process")


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


def _write_open_denied(path: Path) -> bool:
    """Probe permissions without writing a control or changing its value."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        return exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS}
    os.close(descriptor)
    return False


def _current_owner_guard(group: Path) -> dict[str, Any]:
    """Recheck the actual caller, never infer confinement from an env marker."""
    try:
        status = dict(
            line.split(":", 1)
            for line in (_PROC / "self/status").read_text().splitlines()
            if ":" in line
        )
        uid_map = [line.split() for line in (_PROC / "self/uid_map").read_text().splitlines()]
        if (
            any(int(status[key], 16) != 0 for key in ("CapInh", "CapPrm", "CapEff", "CapAmb"))
            or status["NoNewPrivs"].strip() != "1"
            or uid_map != [[str(os.getuid()), str(os.getuid()), "1"]]
            or not os.statvfs(_MOUNT).f_flag & os.ST_RDONLY
        ):
            raise MemoryLimitUnavailableError("os_memory_owner_guard_unverified")
        # A pre-opened control or directory can retain its original mount even
        # after a read-only bind. Reject every inherited directory, including a
        # root/sysfs handle on another device that could reach cgroupfs by openat.
        descriptors = list((_PROC / "self/fd").iterdir())
        if len(descriptors) > 4096:
            raise MemoryLimitUnavailableError("os_memory_owner_guard_unverified")
        device = _MOUNT.stat().st_dev
        for descriptor in descriptors:
            try:
                info = descriptor.stat()
            except FileNotFoundError:
                continue  # The directory enumeration itself has already closed.
            if info.st_dev == device or stat.S_ISDIR(info.st_mode):
                raise MemoryLimitUnavailableError("os_memory_owner_guard_unverified")
        controls = (group / "memory.max", group.parent / "cgroup.procs", _MOUNT / "cgroup.procs")
        if not all(_write_open_denied(path) for path in controls):
            raise MemoryLimitUnavailableError("os_memory_owner_guard_unverified")
        # Check the real kernel parent chain, including the outside supervisor.
        # Its /proc/root must not expose a writable alias of the original mount.
        parent = int(status["PPid"])
        seen: set[int] = set()
        while parent:
            if parent in seen or len(seen) >= 64:
                raise MemoryLimitUnavailableError("os_memory_owner_guard_unverified")
            seen.add(parent)
            root = _PROC / str(parent) / "root"
            if not all(_write_open_denied(root / str(path).lstrip("/")) for path in controls):
                raise MemoryLimitUnavailableError("os_memory_owner_guard_unverified")
            parent_status = dict(
                line.split(":", 1)
                for line in (_PROC / str(parent) / "status").read_text().splitlines()
                if ":" in line
            )
            parent = int(parent_status["PPid"])
        return {
            "verified": True,
            "pid": os.getpid(),
            "uid": os.getuid(),
            "user_namespace": str((_PROC / "self/ns/user").readlink()),
            "mount_namespace": str((_PROC / "self/ns/mnt").readlink()),
            "capabilities_zero": True,
            "no_new_privileges": True,
            "direct_control_open_denied": True,
            "supervisor_proc_root_open_denied": True,
            "inherited_cgroup_descriptors_absent": True,
            "inherited_directory_descriptors_absent": True,
            "source": "current_kernel_state_rechecked",
        }
    except (OSError, ValueError, KeyError) as exc:
        raise MemoryLimitUnavailableError("os_memory_owner_guard_unverified") from exc


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


def active_memory_measurement() -> dict[str, Any]:
    """Kernel telemetry only; a ledger or environment flag is never enforcement."""
    fence = current_memory_fence()
    if fence is None:
        return {
            "enforced": False,
            "reason": "no_attested_owned_linux_memory_fence",
            "cooperative_admission_is_not_a_hard_limit": True,
        }
    group = Path(fence[0])
    try:
        events = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
        peak = group / "memory.peak"
        return {
            "enforced": True,
            "method": "linux_cgroup_v2_owned_fence",
            "scope": "local_owner_and_inherited_descendants",
            "memory_max_bytes": int((group / "memory.max").read_text()),
            "memory_current_bytes": int((group / "memory.current").read_text()),
            "memory_peak_bytes": int(peak.read_text()) if peak.is_file() else None,
            "swap_max_bytes": int((group / "memory.swap.max").read_text()),
            "memory_oom_group": int((group / "memory.oom.group").read_text()),
            "pids_max": int((group / "pids.max").read_text()),
            "oom_events": int(events["oom"]),
            "oom_kills": int(events["oom_kill"]),
        }
    except (OSError, KeyError, ValueError):
        return {"enforced": False, "reason": "owned_memory_fence_telemetry_unavailable"}


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
            or set(config)
            - {
                "delegated_root",
                "pids_max",
                "aggregate_memory_budget_bytes",
                "pool_state_directory",
            }
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
        aggregate = config.get("aggregate_memory_budget_bytes")
        if aggregate is not None and (
            type(aggregate) is not int or not memory_budget_bytes <= aggregate <= 2**50
        ):
            raise ValueError("invalid_aggregate_memory_budget")
        directory = config.get("pool_state_directory")
        if directory is not None and (
            aggregate is None or not isinstance(directory, str) or not Path(directory).is_absolute()
        ):
            raise ValueError("invalid_aggregate_memory_state_directory")
        self.aggregate_budget: int | None = aggregate
        self.pool_state_directory = (
            Path(directory)
            if directory is not None
            else Path.home() / ".redjohn/resources/memory-pools"
        )
        self._pool: LinuxMemoryPool | None = None
        self._attestation_directory: tempfile.TemporaryDirectory[str] | None = None
        self._borrowed_attestation: dict[str, Any] | None = None
        self.memory_budget_bytes = memory_budget_bytes
        self.pids_max = pids
        self.group: Path | None = None
        self.entered = False
        self.borrowed = False
        self._last: dict[str, Any] = {}

    def _resolve_root(self) -> None:
        if self.aggregate_budget is not None and self._pool is None:
            from redjohn.assessment.memory_pool import LinuxMemoryPool  # noqa: PLC0415

            if (
                _MOUNT not in self.root.parents
                or self.root.resolve(strict=True) != self.root
                or self.root.stat().st_uid != os.getuid()
                or not {"memory", "pids"}
                <= set((self.root / "cgroup.subtree_control").read_text().split())
            ):
                raise MemoryLimitUnavailableError("memory_and_pids_controllers_not_delegated")
            self._pool = LinuxMemoryPool(
                self.root, self.aggregate_budget, self.pool_state_directory
            )
            self.root = self._pool.ensure()

    def __enter__(self) -> Self:
        if self.borrowed:
            return self
        if platform.system() != "Linux" or not (_MOUNT / "cgroup.controllers").is_file():
            raise MemoryLimitUnavailableError("linux_cgroup_v2_required")
        if current_memory_fence() is not None:
            raise MemoryLimitUnavailableError("contained_owner_must_reuse_existing_memory_fence")
        try:
            self._resolve_root()
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
            self._attestation_directory = tempfile.TemporaryDirectory(
                prefix="redjohn-memory-owner-"
            )
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
        boundary._resolve_root()
        group = Path(fence[0])
        if group.parent != boundary.root:
            return None
        if (
            int((group / "memory.max").read_text()) != memory_budget_bytes
            or int((group / "memory.swap.max").read_text()) != 0
            or int((group / "pids.max").read_text()) != boundary.pids_max
        ):
            raise MemoryLimitUnavailableError("os_memory_limit_readback_mismatch")
        boundary._borrowed_attestation = _current_owner_guard(group)
        boundary.group, boundary.entered, boundary.borrowed = group, True, True
        return boundary

    def wrap_argv(self, argv: list[str]) -> list[str]:
        if (
            not self.entered
            or self.borrowed
            or self.group is None
            or self._attestation_directory is None
            or not argv
        ):
            raise MemoryLimitUnavailableError("os_memory_boundary_not_ready")
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            raise MemoryLimitUnavailableError("os_memory_owner_mount_boundary_unavailable")
        # Keep host PID identities for the shared ledger. A private user/mount
        # namespace prevents descendants from reopening delegated controls via
        # the controller's /proc/root. The filesystem/build contract stays RW.
        contained = [
            bwrap,
            "--unshare-user",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--bind",
            "/",
            "/",
            "--dev-bind",
            "/dev",
            "/dev",
            "--ro-bind",
            str(_MOUNT),
            str(_MOUNT),
            "--chdir",
            str(Path.cwd()),
            "--",
            sys.executable,
            "-I",
            "-S",
            "-c",
            _OWNER_BOOTSTRAP,
            str(self.group),
            str(os.getpid()),
            str(Path("/proc/self/ns/user").readlink()),
            str(os.getuid()),
            str(Path(self._attestation_directory.name) / "attestation.json"),
            *argv,
        ]
        return [
            sys.executable,
            "-I",
            "-S",
            "-c",
            _BOOTSTRAP,
            str(self.group),
            str(os.getpid()),
            *contained,
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
        result = {
            "enforced": True,
            "method": "linux_cgroup_v2_before_controller_exec",
            "scope": "fresh_exec_local_owner_and_inherited_descendants",
            "memory_max_bytes": int((self.group / "memory.max").read_text()),
            "memory_current_bytes": int((self.group / "memory.current").read_text()),
            "memory_peak_bytes": int(peak.read_text()) if peak.is_file() else None,
            "swap_max_bytes": int((self.group / "memory.swap.max").read_text()),
            "memory_oom_group": int((self.group / "memory.oom.group").read_text()),
            "pids_max": int((self.group / "pids.max").read_text()),
            "oom_events": int(events["oom"]),
            "oom_kills": int(events["oom_kill"]),
            "owner_namespace": self._owner_attestation(),
        }
        if self._pool is not None:
            result["aggregate"] = self._pool.snapshot()
        return result

    def _owner_attestation(self) -> dict[str, Any]:
        if self._borrowed_attestation is not None:
            return dict(self._borrowed_attestation)
        if self._attestation_directory is None:
            return {"verified": False, "reason": "borrowed_owner_attestation_not_local"}
        path = Path(self._attestation_directory.name) / "attestation.json"
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as handle:
                info = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_size > 2048
                    or info.st_mode & 0o077
                ):
                    return {"verified": False, "reason": "owner_attestation_not_private"}
                value = json.loads(handle.read(2049))
            if (
                not isinstance(value, dict)
                or set(value)
                != {
                    "verified",
                    "pid",
                    "uid",
                    "user_namespace",
                    "capabilities_zero",
                    "no_new_privileges",
                    "direct_control_open_denied",
                    "supervisor_proc_root_open_denied",
                }
                or type(value.get("pid")) is not int
                or value["pid"] <= 0
                or value.get("uid") != os.getuid()
                or not isinstance(value.get("user_namespace"), str)
                or re.fullmatch(r"user:\[\d+\]", value["user_namespace"]) is None
                or any(
                    value.get(key) is not True
                    for key in (
                        "verified",
                        "capabilities_zero",
                        "no_new_privileges",
                        "direct_control_open_denied",
                        "supervisor_proc_root_open_denied",
                    )
                )
            ):
                return {"verified": False, "reason": "owner_attestation_invalid"}
        except (OSError, ValueError):
            return {"verified": False, "reason": "owner_attestation_unavailable"}
        return value

    def _cleanup(self) -> None:
        if self.group is None:
            self._release_attestation()
            return
        group = self.group
        self.entered = False
        if not group.exists():
            self.group = None
            self._release_attestation()
            return
        if not reap_memory_fence(str(group), group.stat().st_ino):
            # Incomplete setup may not yet have memory.oom.group enabled. Such
            # an empty, never-used group can still be removed without reclaim.
            if not _populated(group):
                group.rmdir()
            else:
                raise MemoryLimitUnavailableError("os_memory_cleanup_not_verified")
        self.group = None
        self._release_attestation()

    def _release_attestation(self) -> None:
        if self._attestation_directory is not None:
            self._attestation_directory.cleanup()
            self._attestation_directory = None

    def __exit__(self, *_args: object) -> None:
        if self.borrowed:
            self.entered = False
            return
        try:
            self._last = self.snapshot()
        finally:
            self._cleanup()
