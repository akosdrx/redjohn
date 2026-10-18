"""Immutable private cgroup parent for opt-in local RedJohn owners.

The pool persists when idle so one owner cannot silently replace a live host
budget. Only a delegated subtree supplied by the operator is touched.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

from redjohn.assessment.os_memory import MemoryLimitUnavailableError


_NAME = "redjohn-aggregate-v1"
_MAX_CONTRACT = 4096
_MOUNT = Path("/sys/fs/cgroup")


class LinuxMemoryPool:
    def __init__(self, root: Path, budget: int, state_directory: Path) -> None:
        self.root, self.budget, self.state_directory = root, budget, state_directory
        self.group = root / _NAME
        self._inode: int | None = None

    def _directory(self) -> None:
        self.state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_directory.stat()
        if (
            not self.state_directory.is_absolute()
            or self.state_directory.resolve() != self.state_directory
            or info.st_uid != os.getuid()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_mode & 0o077
        ):
            raise MemoryLimitUnavailableError("aggregate_memory_state_not_private")

    def _expected(self) -> dict[str, Any]:
        info = self.root.stat()
        if (
            _MOUNT not in self.root.parents
            or self.root.resolve() != self.root
            or info.st_uid != os.getuid()
        ):
            raise MemoryLimitUnavailableError("aggregate_memory_root_not_owned")
        return {
            "version": 1,
            "root": str(self.root),
            "root_inode": info.st_ino,
            "group": _NAME,
            "memory_max_bytes": self.budget,
            "pids_max": 4096,
        }

    def _validate(self, contract: dict[str, Any]) -> None:
        info = self.group.stat()
        if (
            self.group.resolve() != self.group
            or info.st_uid != os.getuid()
            or info.st_ino != contract.get("group_inode")
        ):
            raise MemoryLimitUnavailableError("aggregate_memory_group_identity_changed")
        for name, value in (
            ("memory.max", self.budget),
            ("memory.swap.max", 0),
            ("memory.oom.group", 0),
            ("pids.max", 4096),
        ):
            if (self.group / name).read_text().strip() != str(value):
                raise MemoryLimitUnavailableError("aggregate_memory_limit_readback_mismatch")
        if not {"memory", "pids"} <= set(
            (self.group / "cgroup.subtree_control").read_text().split()
        ):
            raise MemoryLimitUnavailableError("aggregate_memory_controllers_not_delegated")
        if (self.group / "cgroup.procs").read_text().strip():
            raise MemoryLimitUnavailableError("aggregate_memory_parent_has_processes")
        self._inode = info.st_ino

    def ensure(self) -> Path:
        """Serialize creation; an existing contract can only be read, never reset."""
        self._directory()
        expected = self._expected()
        key = hashlib.sha256(str(self.root).encode()).hexdigest()
        path = self.state_directory / (key + ".json")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (
                info.st_uid != os.getuid()
                or not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_size > _MAX_CONTRACT
            ):
                raise MemoryLimitUnavailableError("aggregate_memory_contract_not_private")
            deadline = time.monotonic() + 2
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise MemoryLimitUnavailableError(
                            "aggregate_memory_contract_busy"
                        ) from None
                    time.sleep(0.01)
            raw = os.read(fd, _MAX_CONTRACT + 1)
            if raw:
                contract = json.loads(raw)
                if (
                    not isinstance(contract, dict)
                    or {key: value for key, value in contract.items() if key != "group_inode"}
                    != expected
                ):
                    raise MemoryLimitUnavailableError("aggregate_memory_contract_mismatch")
            else:
                # A pre-existing unknown group is never adopted or reconfigured.
                self.group.mkdir(mode=0o700)
                for name, value in (
                    ("memory.max", self.budget),
                    ("memory.swap.max", 0),
                    ("memory.oom.group", 0),
                    ("pids.max", 4096),
                ):
                    (self.group / name).write_text(str(value))
                (self.group / "cgroup.subtree_control").write_text("+memory +pids")
                contract = {**expected, "group_inode": self.group.stat().st_ino}
                self._validate(contract)
                payload = json.dumps(contract, sort_keys=True).encode()
                if len(payload) > _MAX_CONTRACT:
                    raise MemoryLimitUnavailableError("aggregate_memory_contract_byte_limit")
                os.write(fd, payload)
                os.fsync(fd)
            self._validate(contract)
        except (OSError, ValueError, KeyError) as exc:
            raise MemoryLimitUnavailableError("aggregate_memory_pool_unavailable") from exc
        finally:
            os.close(fd)
        return self.group

    def snapshot(self) -> dict[str, Any]:
        if self._inode is None or self.group.stat().st_ino != self._inode:
            raise MemoryLimitUnavailableError("aggregate_memory_group_identity_changed")
        events = dict(
            line.split() for line in (self.group / "memory.events").read_text().splitlines()
        )
        peak = self.group / "memory.peak"
        return {
            "enforced": True,
            "scope": "all_opted_in_local_owner_cgroups_in_this_private_pool",
            "memory_max_bytes": int((self.group / "memory.max").read_text()),
            "memory_current_bytes": int((self.group / "memory.current").read_text()),
            "memory_peak_bytes": int(peak.read_text()) if peak.is_file() else None,
            "swap_max_bytes": int((self.group / "memory.swap.max").read_text()),
            "pids_max": int((self.group / "pids.max").read_text()),
            "oom_events": int(events["oom"]),
            "oom_kills": int(events["oom_kill"]),
        }
