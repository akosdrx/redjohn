"""Per-profile single-engine lock (``<profile>/profile.lock``).

Lock file content: ``{"pid": int, "port": int, "token": str}``.

Attach rule
-----------
* Lock missing or stale (owning PID dead) -> take the lock (atomic O_EXCL
  create; stale file is unlinked first).
* Lock present and owning PID alive -> another engine already serves this
  data profile. Callers must ATTACH to that engine (connect to
  ``http://127.0.0.1:<port>`` with the bearer token from the lock file /
  ``<profile>/token``) instead of starting a second engine. We raise
  :class:`EngineAlreadyRunning` carrying the attach coordinates.
* The token in the lock file lets local attachers authenticate without
  re-reading the token file; it never appears in logs or URLs.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


class EngineAlreadyRunning(RuntimeError):
    def __init__(self, pid: int, port: int | None, token: str | None) -> None:
        super().__init__(
            f"an engine already serves this data profile (pid={pid}, port={port}); "
            "attach to it instead of starting a second one"
        )
        self.pid = pid
        self.port = port
        self.token = token


@dataclass
class ProfileLock:
    path: Path
    pid: int
    port: int | None
    token: str | None

    def release(self) -> None:
        try:
            if self.path.exists():
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if data.get("pid") == self.pid:
                    self.path.unlink()
        except (OSError, json.JSONDecodeError):
            pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def acquire_profile_lock(lock_path: Path, *, port: int | None, token: str | None) -> ProfileLock:
    """Acquire the per-profile lock or raise :class:`EngineAlreadyRunning`."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    pid = os.getpid()
    payload = json.dumps({"pid": pid, "port": port, "token": token})

    for _attempt in range(2):
        try:
            fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                data = json.loads(lock_path.read_text(encoding="utf-8"))
                other_pid = int(data.get("pid", -1))
            except (OSError, json.JSONDecodeError, ValueError):
                other_pid = -1
                data = {}
            if other_pid > 0 and _pid_alive(other_pid):
                raise EngineAlreadyRunning(
                    other_pid, data.get("port"), data.get("token")
                ) from None
            # stale lock: remove and retry once
            try:
                lock_path.unlink()
            except OSError:
                raise EngineAlreadyRunning(other_pid, data.get("port"), data.get("token")) from None
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        return ProfileLock(path=lock_path, pid=pid, port=port, token=token)
    raise EngineAlreadyRunning(-1, None, None)
