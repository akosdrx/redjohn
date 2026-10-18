"""Fresh-exec a complete local RedJohn owner under explicit kernel limits.

Usage: python -m redjohn.assessment.memory_exec --help
The small supervisor stays outside the budget to save OOM/cleanup evidence.
No application argv, environment or credentials enter the receipt.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import resource
import shutil
import signal
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from redjohn.assessment.os_memory import LinuxMemoryBoundary, MemoryLimitUnavailableError
from redjohn.assessment.resources import MIB


class _CancelledError(Exception):
    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__("owned_memory_controller_cancelled")


def _cancel(signum: int, _frame: object) -> None:
    # A second terminal signal cannot interrupt the kernel-owned tree cleanup.
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, signal.SIG_IGN)
    raise _CancelledError(signum)


def _save(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.stat()
    if path.parent.resolve() != path.parent or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("memory_receipt_directory_not_private")
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("memory_receipt_not_private")
    payload = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    if len(payload) > 65536:
        raise ValueError("memory_receipt_byte_limit")
    temporary = path.parent / (".memory-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _final_outcome(result: dict[str, Any], code: int) -> int:
    measurement = result["os_memory"]
    if measurement.get("oom_kills", 0):
        result["outcome"] = "resource_exhausted"
        return 2
    if result.get("outcome") == "owner_exited" and not measurement.get("owner_namespace", {}).get(
        "verified"
    ):
        result.update(outcome="blocked", reason="owned_memory_namespace_attestation_unavailable")
        return 2
    return code


def supervise(
    command: list[str],
    config: dict[str, Any],
    budget: int,
    *,
    timeout: float,
    receipt: Path,
) -> int:
    """Run an unchanged CLI/TUI with inherited TTY and kernel-owned descendants."""
    if not command or not 0 < timeout <= 86400 or not receipt.is_absolute():
        raise ValueError("invalid_memory_exec_configuration")
    executable = shutil.which(command[0])
    if executable is None:
        raise ValueError("memory_exec_executable_unavailable")
    boundary = LinuxMemoryBoundary(config, budget)
    result: dict[str, Any] = {
        "product": "RedJohn",
        "mode": "owned_local_process_tree_hard_memory",
        "coverage_status": "inconclusive",
        "supervisor_outside_budget": True,
        "external_daemon_or_remote_workers_included": False,
        "process_cleanup_verified": False,
    }
    _save(receipt, result)  # Resolve receipt permission failures before launching.
    process: subprocess.Popen[bytes] | None = None
    started = time.monotonic()
    previous = {s: signal.signal(s, _cancel) for s in (signal.SIGINT, signal.SIGTERM)}
    code = 2
    try:
        with boundary:
            process = subprocess.Popen(  # noqa: S603 - operator argv, never a shell string
                boundary.wrap_argv([executable, *command[1:]]),
            )
            try:
                returncode = process.wait(timeout=timeout)
                result.update(owner_returncode=returncode, outcome="owner_exited")
                code = returncode if returncode >= 0 else 128 - returncode
            finally:
                result["os_memory"] = boundary.snapshot()
        result["process_cleanup_verified"] = True
    except subprocess.TimeoutExpired:
        result["outcome"] = "timed_out"
        result["process_cleanup_verified"] = boundary.group is None
    except _CancelledError as exc:
        result["outcome"] = "cancelled"
        result["signal"] = exc.signum
        result["process_cleanup_verified"] = boundary.group is None
        code = 128 + exc.signum
    except MemoryLimitUnavailableError as exc:
        result.update(outcome="blocked", reason=str(exc))
    except OSError:
        result.update(outcome="blocked", reason="owned_memory_controller_launch_unavailable")
        result["process_cleanup_verified"] = boundary.group is None
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if process is not None:
            # The owned cgroup is killed first, then the direct child is reaped.
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=3)
        result.setdefault("os_memory", boundary.snapshot() or {"enforced": False})
        code = _final_outcome(result, code)
        result["duration_seconds"] = time.monotonic() - started
        result["supervisor_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (
            1024 if os.uname().sysname == "Linux" else 1
        )
        result["supervisor_rss_method"] = "getrusage_maxrss_not_inside_owner_budget"
        _save(receipt, result)
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delegated-root", type=Path, required=True)
    parser.add_argument("--memory-budget-mib", type=int, default=1024)
    parser.add_argument("--aggregate-budget-mib", type=int, default=4096)
    parser.add_argument("--pool-state-directory", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=3600)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    config: dict[str, Any] = {
        "delegated_root": str(args.delegated_root),
        "aggregate_memory_budget_bytes": args.aggregate_budget_mib * MIB,
    }
    if args.pool_state_directory is not None:
        config["pool_state_directory"] = str(args.pool_state_directory)
    return supervise(
        command,
        config,
        args.memory_budget_mib * MIB,
        timeout=args.timeout_seconds,
        receipt=args.receipt,
    )


if __name__ == "__main__":
    raise SystemExit(main())
