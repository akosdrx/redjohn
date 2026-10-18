"""Private, host-wide reservations shared by independent assessment databases.

SQLite serializes admission across processes. A lost owner is quarantined, never
expired by a wall-clock TTL: a paused controller or orphan worker may still use
its resources. Process-owning claims require a verified OS containment fence.
Trusted in-process HTTP workers can instead prove their lifetime ended with
their owner process; this classification is never inferred for legacy rows.
No scanner is launched by this module.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sqlite3
import stat
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.os_memory import current_memory_fence, reap_memory_fence
from redjohn.assessment.resources import MIB, ResourceAdmissionError, process_forest_memory


if TYPE_CHECKING:
    from collections.abc import Iterator


_IDENTIFIER = re.compile(r"[a-f0-9]{32}")
_KINDS = frozenset({"worker", "scanner", "browser", "page", "context"})
_MAX_LEASES = 256


@dataclass(frozen=True)
class HostResourceLimits:
    """Explicit host policy, independent of each campaign's narrower envelope."""

    memory_budget_bytes: int = 4096 * MIB
    max_workers: int = 4
    max_browsers: int = 1
    max_pages: int = 4
    max_contexts: int = 4

    def __post_init__(self) -> None:
        if (
            type(self.memory_budget_bytes) is not int
            or not MIB <= self.memory_budget_bytes <= 2**50
        ):
            raise ValueError("invalid_host_memory_budget")
        for name in ("max_workers", "max_browsers", "max_pages", "max_contexts"):
            if type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= 64:
                raise ValueError("invalid_host_resource_capacity")
        if self.max_browsers > self.max_workers:
            raise ValueError("host_browser_capacity_exceeds_workers")


def process_identity(pid: int) -> str | None:
    """Kernel start identity; zombie processes do not qualify as live owners.

    macOS ps has second precision. A coincident PID reuse can conservatively
    retain a reservation, but never authorizes reclaiming an occupied slot.
    """
    if type(pid) is not int or pid <= 0:
        return None
    try:
        proc = Path(f"/proc/{pid}/stat")
        if Path("/proc/self/stat").is_file():
            fields = proc.read_text().rpartition(") ")[2].split()
            if fields[0] in {"Z", "X"}:
                return None
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            return f"linux:{boot}:{fields[19]}"
        result = subprocess.run(  # noqa: S603 - fixed ps argv with positive integer PID
            ["/bin/ps", "-p", str(pid), "-o", "lstart=", "-o", "uid=", "-o", "stat="],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        fields = result.stdout.split()
        if len(fields) != 7 or fields[-1].startswith("Z"):
            return None
        return "ps:" + " ".join(fields[:-1])
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None


def default_pool_path() -> Path:
    configured = os.environ.get("REDJOHN_RESOURCE_POOL_PATH")
    path = Path(configured) if configured else Path.home() / ".redjohn/resources/host.sqlite3"
    if not path.is_absolute():
        raise ValueError("host_resource_pool_path_must_be_absolute")
    return path


def _confirmed_dead(pid: int, expected: str) -> bool:
    identity = process_identity(pid)
    if identity is not None:
        return identity != expected
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    # An observation failure is not proof of death, even if a heartbeat expired.
    return False


class HostResourcePool:
    """One transactional capacity ledger for all participating controllers."""

    def __init__(self, path: str | Path, limits: HostResourceLimits | None = None) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("host_resource_pool_path_must_be_absolute")
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        parent = self.path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise ResourceAdmissionError("host_resource_directory_not_private")
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ResourceAdmissionError("host_resource_store_not_private")
        finally:
            os.close(fd)
        self.pid = os.getpid()
        self.identity = process_identity(self.pid)
        if self.identity is None:
            raise ResourceAdmissionError("host_owner_identity_unavailable")
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS leases ("
                "id TEXT PRIMARY KEY, owner TEXT NOT NULL, pid INTEGER NOT NULL, "
                "identity TEXT NOT NULL, kind TEXT NOT NULL, estimated_bytes INTEGER NOT NULL)"
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(leases)")}
            if "fence_path" not in columns:
                db.execute("ALTER TABLE leases ADD COLUMN fence_path TEXT")
                db.execute("ALTER TABLE leases ADD COLUMN fence_inode INTEGER")
            if "owner_process_only" not in columns:
                db.execute(
                    "ALTER TABLE leases ADD COLUMN owner_process_only "
                    "INTEGER NOT NULL DEFAULT 0 CHECK (owner_process_only IN (0, 1))"
                )
            if "cleanup_unverified" not in columns:
                db.execute(
                    "ALTER TABLE leases ADD COLUMN cleanup_unverified "
                    "INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_unverified IN (0, 1))"
                )
            saved = db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()
            if saved is None:
                self.limits = limits or HostResourceLimits()
                db.execute(
                    "INSERT INTO metadata VALUES ('policy', ?)",
                    (json.dumps({"schema": 1, "limits": asdict(self.limits)}, sort_keys=True),),
                )
            else:
                self.limits = self._read_limits(db)
                if limits is not None and limits != self.limits:
                    raise ValueError("host_resource_policy_mismatch")

    @staticmethod
    def _read_limits(db: sqlite3.Connection) -> HostResourceLimits:
        saved = db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()
        try:
            policy = json.loads(saved[0]) if saved is not None else None
            if (
                not isinstance(policy, dict)
                or set(policy) != {"schema", "limits"}
                or policy["schema"] != 1
            ):
                raise ValueError("invalid_host_resource_policy")  # noqa: TRY301 - trusted store validation
            return HostResourceLimits(**policy["limits"])
        except (TypeError, ValueError) as exc:
            raise ResourceAdmissionError("host_resource_policy_invalid") from exc

    def configure(self, limits: HostResourceLimits) -> None:
        """Explicit operator update, only while no reservation is outstanding."""
        with self._transaction() as db:
            if self._rows(db):
                raise ResourceAdmissionError("host_resource_policy_busy")
            db.execute(
                "UPDATE metadata SET value=? WHERE key='policy'",
                (json.dumps({"schema": 1, "limits": asdict(limits)}, sort_keys=True),),
            )
            self.limits = limits

    def recover(self) -> int:
        with self._transaction() as db:
            rows = self._rows(db)
            self._recover_lost(db, rows)
            return len(rows) - len(self._rows(db))

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            db = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        except sqlite3.Error as exc:
            raise ResourceAdmissionError("host_resource_store_unavailable") from exc
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA cache_size=-512")
            db.execute("PRAGMA max_page_count=1024")
            db.execute("PRAGMA wal_autocheckpoint=64")
            db.execute("PRAGMA journal_size_limit=262144")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                if db.in_transaction:
                    db.execute("ROLLBACK")
            raise ResourceAdmissionError("host_resource_store_unavailable") from exc
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def _check_owner(self, owner: str) -> None:
        if _IDENTIFIER.fullmatch(owner) is None:
            raise ValueError("invalid_host_resource_owner")
        if os.getpid() != self.pid or process_identity(self.pid) != self.identity:
            raise ResourceAdmissionError("host_resource_owner_process_changed")

    @staticmethod
    def _rows(db: sqlite3.Connection) -> list[sqlite3.Row]:
        rows = db.execute("SELECT * FROM leases LIMIT ?", (_MAX_LEASES + 1,)).fetchall()
        if len(rows) > _MAX_LEASES:
            raise ResourceAdmissionError("host_resource_ledger_capacity")
        return rows

    @staticmethod
    def _lost_owners(rows: list[sqlite3.Row]) -> set[str]:
        identities = {pid: process_identity(pid) for pid in {row["pid"] for row in rows}}
        return {row["owner"] for row in rows if identities[row["pid"]] != row["identity"]}

    def _recover_lost(self, db: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
        lost = self._lost_owners(rows)
        dead = {
            owner
            for owner in lost
            if all(
                _confirmed_dead(row["pid"], row["identity"])
                for row in rows
                if row["owner"] == owner
            )
        }
        for owner in lost:
            owned = [row for row in rows if row["owner"] == owner]
            if owner in dead:
                # Only trusted, explicitly classified in-process work dies
                # with its owner. Unknown/legacy claims may have orphaned
                # children and must retain the OS-fence recovery requirement.
                # Fenced claims still reap their group before releasing it.
                db.execute(
                    "DELETE FROM leases WHERE owner=? AND owner_process_only=1 "
                    "AND kind='worker' AND fence_path IS NULL AND fence_inode IS NULL "
                    "AND cleanup_unverified=0",
                    (owner,),
                )
                owned = [
                    row
                    for row in owned
                    if not (
                        row["owner_process_only"] == 1
                        and row["kind"] == "worker"
                        and row["fence_path"] is None
                        and row["fence_inode"] is None
                        and row["cleanup_unverified"] == 0
                    )
                ]
            fences = {(row["fence_path"], row["fence_inode"]) for row in owned}
            if len(fences) != 1:
                continue
            path, inode = fences.pop()
            if path is None or inode is None:
                continue
            participants = {row["owner"] for row in rows if row["fence_path"] == path}
            if participants <= dead and reap_memory_fence(path, inode):
                db.execute("DELETE FROM leases WHERE fence_path=? AND fence_inode=?", (path, inode))

    def _accounting_roots(self, rows: list[sqlite3.Row], *, own_fence: bool) -> set[int]:
        roots = {self.pid, *(row["pid"] for row in rows)}
        contained = {row["pid"] for row in rows if row["fence_path"] is not None}
        if own_fence:
            contained.add(self.pid)
        # The bounded CLI supervisor stays outside the child's hard limit, but
        # its RSS must still count against shared host admission. Overlapping
        # supervisor/controller trees are deduplicated by process_forest_memory.
        try:
            for pid in contained:
                fields = Path(f"/proc/{pid}/stat").read_text().rpartition(") ")[2].split()
                parent = int(fields[1])
                if parent <= 0:
                    raise ValueError("missing_controller_supervisor")  # noqa: TRY301
                roots.add(parent)
        except (OSError, ValueError, IndexError) as exc:
            raise ResourceAdmissionError("host_memory_measurement_unavailable") from exc
        return roots

    def reserve(
        self,
        owner: str,
        lease_id: str,
        kind: str,
        estimated_bytes: int,
        *,
        owner_process_only: bool = False,
    ) -> None:
        self._check_owner(owner)
        if (
            _IDENTIFIER.fullmatch(lease_id) is None
            or kind not in _KINDS
            or type(estimated_bytes) is not int
            or estimated_bytes < 0
            or type(owner_process_only) is not bool
            or (owner_process_only and kind != "worker")
        ):
            raise ValueError("invalid_host_resource_reservation")
        with self._transaction() as db:
            self.limits = self._read_limits(db)
            rows = self._rows(db)
            self._recover_lost(db, rows)
            rows = self._rows(db)
            if self._lost_owners(rows):
                raise ResourceAdmissionError("host_owner_lost_requires_recovery")
            if any(row["cleanup_unverified"] for row in rows):
                raise ResourceAdmissionError("host_cleanup_unverified_requires_recovery")
            counts = Counter(row["kind"] for row in rows)
            workers = sum(counts[kind] for kind in ("worker", "scanner", "browser"))
            caps = {
                "browser": self.limits.max_browsers,
                "page": self.limits.max_pages,
                "context": self.limits.max_contexts,
            }
            if len(rows) >= _MAX_LEASES:
                raise ResourceAdmissionError("host_resource_ledger_capacity")
            if kind in {"worker", "scanner", "browser"} and workers >= self.limits.max_workers:
                raise ResourceAdmissionError("host_worker_capacity_exhausted")
            if kind in caps and counts[kind] >= caps[kind]:
                raise ResourceAdmissionError(f"host_{kind}_capacity_exhausted")
            fence = current_memory_fence()
            claimed = os.environ.get("REDJOHN_CONTAINED_GROUP")
            if claimed is not None and (fence is None or fence[0] != claimed):
                raise ResourceAdmissionError("host_memory_measurement_unavailable")
            memory = process_forest_memory(
                self._accounting_roots(rows, own_fence=fence is not None)
            )
            if not memory.available:
                raise ResourceAdmissionError("host_memory_measurement_unavailable")
            reserved = sum(row["estimated_bytes"] for row in rows)
            if (
                memory.admission_bytes + reserved + estimated_bytes
                > self.limits.memory_budget_bytes
            ):
                raise ResourceAdmissionError("host_memory_reservation_exhausted")
            db.execute(
                "INSERT INTO leases "
                "(id,owner,pid,identity,kind,estimated_bytes,fence_path,fence_inode,"
                "owner_process_only) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    lease_id,
                    owner,
                    self.pid,
                    self.identity,
                    kind,
                    estimated_bytes,
                    *(fence or (None, None)),
                    int(owner_process_only),
                ),
            )

    def quarantine(self, owner: str, lease_id: str) -> None:
        """Retain an existing owned claim when its child cleanup is unverified."""
        self._check_owner(owner)
        with self._transaction() as db:
            changed = db.execute(
                "UPDATE leases SET cleanup_unverified=1 "
                "WHERE id=? AND owner=? AND pid=? AND identity=?",
                (lease_id, owner, self.pid, self.identity),
            ).rowcount
            if changed != 1:
                raise ResourceAdmissionError("host_cleanup_reservation_missing")

    def release(self, owner: str, lease_id: str, *, cleanup_verified: bool = False) -> None:
        self._check_owner(owner)
        if type(cleanup_verified) is not bool:
            raise ValueError("invalid_cleanup_verification")
        with self._transaction() as db:
            row = db.execute(
                "SELECT cleanup_unverified FROM leases "
                "WHERE id=? AND owner=? AND pid=? AND identity=?",
                (lease_id, owner, self.pid, self.identity),
            ).fetchone()
            if row is not None and row[0] and not cleanup_verified:
                raise ResourceAdmissionError("host_cleanup_unverified_requires_recovery")
            db.execute(
                "DELETE FROM leases WHERE id=? AND owner=? AND pid=? AND identity=?",
                (lease_id, owner, self.pid, self.identity),
            )

    def snapshot(self) -> dict[str, Any]:
        with self._transaction() as db:
            self.limits = self._read_limits(db)
            rows = self._rows(db)
            lost = self._lost_owners(rows)
            quarantined = sum(bool(row["cleanup_unverified"]) for row in rows)
            process_only = all(
                row["owner_process_only"] == 1
                and row["kind"] == "worker"
                and row["fence_path"] is None
                and row["fence_inode"] is None
                and row["cleanup_unverified"] == 0
                for row in rows
                if row["owner"] in lost
            )
            return {
                "scope": "host_user",
                "limits": asdict(self.limits),
                "active": dict(Counter(row["kind"] for row in rows)),
                "reserved_bytes": sum(row["estimated_bytes"] for row in rows),
                "owners": len({row["owner"] for row in rows}),
                "lost_owners": len(lost),
                "admission_blocked": bool(lost) or bool(quarantined),
                "cleanup_quarantined": quarantined,
                "recovery": (
                    "requires_confirmed_owner_death"
                    if process_only
                    else "requires_verified_os_fence"
                )
                if lost
                else "requires_verified_owned_cleanup"
                if quarantined
                else "not_required",
                "measurement_method": "deduplicated_process_forest_summed_rss",
                "os_hard_limit": False,
            }
