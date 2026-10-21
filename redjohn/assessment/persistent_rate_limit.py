"""SQLite-backed shared HTTP windows and cooldowns that survive runtime restart.

Only hashed origin/group/account keys are retained. Active limits are never
evicted to admit another scope: exhaustion sets a persisted global cooldown.
The per-engagement bound is ``max_scopes`` hashed keys plus one control row.
"""

from __future__ import annotations

import math
import time
from typing import TYPE_CHECKING

from redjohn.assessment.recovery import RateLimitDetector, RateLimitObservation, parse_retry_after


if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Callable, Mapping

    from redjohn.assessment.store import AssessmentStore


_GLOBAL_SCOPE = "global-cooldown"


class PersistentRateLimitDetector:
    """Atomic three-scope admission over the assessment store's SQLite database.

    Absolute UTC deadlines are stored instead of process-relative monotonic
    times. File/lock integrity and engagement authorization remain the caller's
    responsibility, as with the original in-memory detector.
    """

    _keys = staticmethod(RateLimitDetector._keys)

    def __init__(
        self,
        store: AssessmentStore,
        engagement_id: str,
        *,
        requests_per_window: int = 60,
        window_seconds: float = 60,
        default_cooldown: float = 5,
        max_scopes: int = 2048,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            not isinstance(engagement_id, str)
            or not 0 < len(engagement_id) <= 128
            or type(requests_per_window) is not int
            or requests_per_window <= 0
            or type(max_scopes) is not int
            or not 3 <= max_scopes <= 2048
            or not math.isfinite(window_seconds)
            or window_seconds <= 0
            or not math.isfinite(default_cooldown)
            or default_cooldown <= 0
        ):
            raise ValueError("invalid_persistent_rate_limit_budgets")
        self.store, self.engagement_id = store, engagement_id
        self.requests_per_window, self.window_seconds = requests_per_window, window_seconds
        self.default_cooldown, self.max_scopes = default_cooldown, max_scopes
        self._wall_clock = wall_clock
        with self.store.transaction() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS rj_rate_limit(
                  engagement TEXT NOT NULL, scope TEXT NOT NULL,
                  window_until REAL NOT NULL, requests INTEGER NOT NULL,
                  cooldown_until REAL NOT NULL, expires_at REAL NOT NULL,
                  PRIMARY KEY(engagement,scope))
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS rj_rate_limit_expiry
                  ON rj_rate_limit(engagement,expires_at)
            """)
            self._prune(db, self._now())

    def _now(self) -> float:
        now = self._wall_clock()
        if not math.isfinite(now) or now < 0:
            raise ValueError("invalid_persistent_rate_limit_clock")
        return now

    def _prune(self, db: sqlite3.Connection, now: float) -> None:
        db.execute(
            "DELETE FROM rj_rate_limit WHERE engagement=? AND expires_at<=?",
            (self.engagement_id, now),
        )

    def _states(self, db: sqlite3.Connection, keys: tuple[str, ...]) -> dict[str, sqlite3.Row]:
        rows = db.execute(
            "SELECT * FROM rj_rate_limit WHERE engagement=? AND scope IN (?,?,?,?)",
            (self.engagement_id, _GLOBAL_SCOPE, *keys),
        ).fetchall()
        return {row["scope"]: row for row in rows}

    def _wait(self, states: dict[str, sqlite3.Row], now: float) -> float:
        wait = 0.0
        for state in states.values():
            wait = max(wait, state["cooldown_until"] - now)
            if state["requests"] >= self.requests_per_window:
                wait = max(wait, state["window_until"] - now)
        return wait

    def _global_cooldown(self, db: sqlite3.Connection, until: float) -> None:
        db.execute(
            """INSERT INTO rj_rate_limit VALUES(?,?,0,0,?,?)
               ON CONFLICT(engagement,scope) DO UPDATE SET
                 cooldown_until=MAX(cooldown_until,excluded.cooldown_until),
                 expires_at=MAX(expires_at,excluded.expires_at)""",
            (self.engagement_id, _GLOBAL_SCOPE, until, until),
        )

    def _prepare(
        self,
        db: sqlite3.Connection,
        states: dict[str, sqlite3.Row],
        keys: tuple[str, ...],
        now: float,
    ) -> bool:
        missing = tuple(key for key in keys if key not in states)
        if not missing:
            return True
        count = db.execute(
            "SELECT COUNT(*) FROM rj_rate_limit WHERE engagement=? AND scope<>?",
            (self.engagement_id, _GLOBAL_SCOPE),
        ).fetchone()[0]
        if count + len(missing) > self.max_scopes:
            self._global_cooldown(db, now + self.default_cooldown)
            return False
        db.executemany(
            "INSERT INTO rj_rate_limit VALUES(?,?,?,0,0,?)",
            [
                (self.engagement_id, key, now + self.window_seconds, now + self.window_seconds)
                for key in missing
            ],
        )
        return True

    def admit(
        self, origin: str, *, account: str = "anonymous", endpoint_group: str = "default"
    ) -> bool:
        keys = self._keys(origin, endpoint_group, account)
        with self.store.transaction() as db:
            now = self._now()
            self._prune(db, now)
            states = self._states(db, keys)
            if self._wait(states, now) > 0 or not self._prepare(db, states, keys, now):
                return False
            db.executemany(
                """UPDATE rj_rate_limit SET
                     requests=CASE WHEN window_until<=? THEN 1 ELSE requests+1 END,
                     window_until=CASE WHEN window_until<=? THEN ? ELSE window_until END,
                     expires_at=MAX(cooldown_until,
                       CASE WHEN window_until<=? THEN ? ELSE window_until END)
                   WHERE engagement=? AND scope=?""",
                [
                    (
                        now,
                        now,
                        now + self.window_seconds,
                        now,
                        now + self.window_seconds,
                        self.engagement_id,
                        key,
                    )
                    for key in keys
                ],
            )
            return True

    def remaining(
        self, origin: str, *, account: str = "anonymous", endpoint_group: str = "default"
    ) -> float:
        keys = self._keys(origin, endpoint_group, account)
        with self.store.transaction() as db:
            return self._wait(self._states(db, keys), self._now())

    def observe(
        self,
        origin: str,
        status: int,
        headers: Mapping[str, str] | None = None,
        *,
        account: str = "anonymous",
        endpoint_group: str = "default",
    ) -> RateLimitObservation:
        keys = self._keys(origin, endpoint_group, account)
        now = self._now()
        value = next((v for k, v in (headers or {}).items() if k.lower() == "retry-after"), None)
        retry_after = parse_retry_after(value, now=now)
        limited = status == 429 or (status == 503 and retry_after is not None)
        classification = (
            "rate_limited"
            if limited
            else ("permission_or_challenge" if status == 403 else "not_rate_limited")
        )
        delay = (
            (retry_after if retry_after is not None else self.default_cooldown) if limited else 0.0
        )
        if limited:
            with self.store.transaction() as db:
                self._prune(db, now)
                states = self._states(db, keys)
                if self._prepare(db, states, keys, now):
                    db.executemany(
                        """UPDATE rj_rate_limit SET
                             cooldown_until=MAX(cooldown_until,?),
                             expires_at=MAX(expires_at,?)
                           WHERE engagement=? AND scope=?""",
                        [(now + delay, now + delay, self.engagement_id, key) for key in keys],
                    )
                else:
                    self._global_cooldown(db, now + delay)
        return RateLimitObservation(classification, limited, delay, keys[0])
