"""Bounded recovery decisions and shared HTTP cooldowns, without hidden retries."""

from __future__ import annotations

import hashlib
import math
import random
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, TypedDict, Unpack
from urllib.parse import urlsplit


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


@dataclass(frozen=True)
class NormalizedError:
    code: str
    category: str
    message: str
    retryable: bool = False
    terminal: bool = True
    job_id: str | None = None
    attempt_id: str | None = None
    tool_id: str | None = None
    cause_ref: str | None = None
    retry_after: float | None = None
    partial_evidence_refs: tuple[str, ...] = ()
    coverage_effect: str = "inconclusive"
    recovery_action: str = "none"

    def __post_init__(self) -> None:
        if self.retry_after is not None and (
            not math.isfinite(self.retry_after) or self.retry_after < 0
        ):
            raise ValueError("retry_after must be finite and nonnegative")
        if len(self.partial_evidence_refs) > 64:
            raise ValueError("too many partial evidence references")


_ERRORS: dict[str, tuple[str, str, bool, str, str]] = {
    "policy_denied": ("policy", "Action denied by engagement policy", False, "blocked", "block"),
    "scope_denied": ("policy", "Target is outside the approved scope", False, "blocked", "block"),
    "unsupported_input": (
        "input",
        "Adapter does not support this input",
        False,
        "unsupported",
        "correct_input",
    ),
    "schema_invalid": (
        "input",
        "Input schema validation failed",
        False,
        "unsupported",
        "correct_input",
    ),
    "tool_missing": (
        "capability",
        "Required executable is unavailable",
        False,
        "blocked",
        "disable_capability",
    ),
    "credentials_missing": (
        "capability",
        "Required credential reference is unavailable",
        False,
        "blocked",
        "disable_capability",
    ),
    "version_mismatch": (
        "compatibility",
        "Tool version or output schema is incompatible",
        False,
        "inconclusive",
        "disable_capability",
    ),
    "session_expired": (
        "authentication",
        "The existing actor session expired",
        True,
        "blocked",
        "reauthenticate_existing_actor",
    ),
    "permission_denied": (
        "authorization",
        "Access denied or challenge requires classification",
        False,
        "blocked",
        "classify_denial",
    ),
    "rate_limited": (
        "rate_limit",
        "Shared service request limit was reached",
        True,
        "partial",
        "cooldown",
    ),
    "network_transient": (
        "network",
        "Temporary network failure",
        True,
        "inconclusive",
        "retry_safe",
    ),
    "provider_unavailable": (
        "provider",
        "Provider is temporarily unavailable",
        True,
        "partial",
        "retry_safe",
    ),
    "scanner_timeout": (
        "timeout",
        "Tool execution deadline exceeded",
        True,
        "partial",
        "retry_safe",
    ),
    "parser_error": (
        "parser",
        "Output could not be parsed",
        False,
        "inconclusive",
        "preserve_partial_evidence",
    ),
    "output_truncated": (
        "parser",
        "Output exceeded its configured byte limit",
        False,
        "partial",
        "preserve_partial_evidence",
    ),
    "browser_crash": (
        "resource",
        "Browser process terminated unexpectedly",
        True,
        "partial",
        "cleanup_and_reconcile",
    ),
    "worker_crash": (
        "resource",
        "Worker process terminated unexpectedly",
        True,
        "partial",
        "cleanup_and_reconcile",
    ),
    "resource_exhausted": (
        "resource",
        "Resource envelope was exhausted",
        False,
        "partial",
        "pause_admission_cleanup",
    ),
    "host_resource_busy": (
        "resource",
        "Shared host capacity is occupied before request admission",
        True,
        "blocked",
        "wait_for_capacity",
    ),
    "evidence_write_failed": (
        "storage",
        "Evidence persistence failed",
        False,
        "inconclusive",
        "stop_evidence_dependent_jobs",
    ),
    "cancelled": ("cancellation", "Execution was cancelled", False, "partial", "cleanup"),
    "unknown_execution_outcome": (
        "uncertain_outcome",
        "Request side effects require reconciliation",
        False,
        "inconclusive",
        "reconcile",
    ),
}


class _ErrorReferences(TypedDict, total=False):
    job_id: str | None
    attempt_id: str | None
    tool_id: str | None
    cause_ref: str | None
    retry_after: float | None
    partial_evidence_refs: tuple[str, ...]


def error_from_code(code: str, **references: Unpack[_ErrorReferences]) -> NormalizedError:
    """Use stable messages: exception strings and target data are never reflected."""
    category, message, retryable, coverage, action = _ERRORS.get(
        code, ("unknown", "Unclassified execution failure", False, "inconclusive", "review")
    )
    allowed = {
        "job_id",
        "attempt_id",
        "tool_id",
        "cause_ref",
        "retry_after",
        "partial_evidence_refs",
    }
    if not set(references).issubset(allowed):
        raise ValueError("unknown normalized error reference")
    return NormalizedError(
        code,
        category,
        message,
        retryable,
        not retryable,
        coverage_effect=coverage,
        recovery_action=action,
        **references,
    )


def parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    if not value or len(value) > 256:
        return None
    try:
        seconds = float(value)
    except ValueError:
        pass
    else:
        if math.isfinite(seconds) and seconds >= 0:
            return seconds
        return None
    try:
        stamp = parsedate_to_datetime(value)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        return max(0.0, stamp.timestamp() - (time.time() if now is None else now))
    except (ValueError, TypeError, OverflowError):
        return None


@dataclass(frozen=True)
class RateLimitObservation:
    classification: str
    limited: bool
    retry_after: float
    scope_ref: str


@dataclass
class _RateState:
    cooldown_until: float
    window_start: float
    requests: int = 0


class RateLimitDetector:
    """All tools share per-origin, endpoint group and actor/account request limits.

    At scope-table exhaustion the detector applies global cooldown instead of
    evicting an active limit. Its keys are hashes; metrics expose no target labels.
    """

    def __init__(
        self,
        *,
        requests_per_window: int = 60,
        window_seconds: float = 60,
        default_cooldown: float = 5,
        max_scopes: int = 256,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            requests_per_window <= 0
            or max_scopes < 3
            or window_seconds <= 0
            or default_cooldown <= 0
        ):
            raise ValueError("rate limit budgets must be positive")
        self.requests_per_window, self.window_seconds = requests_per_window, window_seconds
        self.default_cooldown, self.max_scopes = default_cooldown, max_scopes
        self._clock, self._wall_clock = clock, wall_clock
        self._states: dict[str, _RateState] = {}
        self._lock = threading.RLock()
        self._global_cooldown = 0.0

    @staticmethod
    def _keys(origin: str, endpoint_group: str, account: str) -> tuple[str, ...]:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError("valid HTTP origin without credentials required")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        canonical = f"{parsed.scheme}://{parsed.hostname.lower()}:{port}"
        if len(endpoint_group) > 256 or len(account) > 256:
            raise ValueError("rate limit context reference too long")
        scopes = (
            canonical,
            f"{canonical}\0group\0{endpoint_group}",
            f"{canonical}\0account\0{account}",
        )
        return tuple(hashlib.sha256(scope.encode()).hexdigest() for scope in scopes)

    def _prepare(self, keys: tuple[str, ...], now: float) -> bool:
        expired = [
            key
            for key, state in self._states.items()
            if state.cooldown_until <= now and state.window_start + self.window_seconds <= now
        ]
        for key in expired:
            self._states.pop(key, None)
        if len(self._states) + sum(key not in self._states for key in keys) > self.max_scopes:
            self._global_cooldown = max(self._global_cooldown, now + self.default_cooldown)
            return False
        for key in keys:
            self._states.setdefault(key, _RateState(0, now))
        return True

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
        value = next((v for k, v in (headers or {}).items() if k.lower() == "retry-after"), None)
        retry_after = parse_retry_after(value, now=self._wall_clock())
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
            with self._lock:
                now = self._clock()
                if self._prepare(keys, now):
                    for key in keys:
                        self._states[key].cooldown_until = max(
                            self._states[key].cooldown_until, now + delay
                        )
                else:
                    self._global_cooldown = max(self._global_cooldown, now + delay)
        return RateLimitObservation(classification, limited, delay, keys[0])

    def remaining(
        self, origin: str, *, account: str = "anonymous", endpoint_group: str = "default"
    ) -> float:
        keys = self._keys(origin, endpoint_group, account)
        with self._lock:
            now = self._clock()
            waits = [self._global_cooldown - now]
            for key in keys:
                state = self._states.get(key)
                if state:
                    waits.append(state.cooldown_until - now)
                    if state.requests >= self.requests_per_window:
                        waits.append(state.window_start + self.window_seconds - now)
            return max(0.0, *waits)

    def admit(
        self, origin: str, *, account: str = "anonymous", endpoint_group: str = "default"
    ) -> bool:
        keys = self._keys(origin, endpoint_group, account)
        with self._lock:
            now = self._clock()
            if self.remaining(
                origin, account=account, endpoint_group=endpoint_group
            ) > 0 or not self._prepare(keys, now):
                return False
            for key in keys:
                state = self._states[key]
                if state.window_start + self.window_seconds <= now:
                    state.window_start, state.requests = now, 0
                state.requests += 1
            return True


@dataclass(frozen=True)
class RecoveryDecision:
    action: str
    retry: bool
    delay: float
    coverage_status: str
    reason: str


class FailureRecoverySystem:
    """Only plans retries; scheduler owns execution and one shared retry budget."""

    def __init__(
        self,
        *,
        max_attempts: int = 3,
        retry_budget: int = 8,
        max_reauth: int = 1,
        base_delay: float = 0.5,
        max_delay: float = 30,
        clock: Callable[[], float] = time.monotonic,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        if (
            max_attempts < 1
            or retry_budget < 0
            or max_reauth < 0
            or base_delay < 0
            or max_delay < base_delay
        ):
            raise ValueError("invalid recovery budgets")
        self.max_attempts, self.retry_budget, self.max_reauth = (
            max_attempts,
            retry_budget,
            max_reauth,
        )
        self.base_delay, self.max_delay = base_delay, max_delay
        self._clock, self._jitter = clock, jitter
        self._lock = threading.Lock()
        self._retries = 0
        self._reauth = 0

    def plan(  # noqa: PLR0911 - explicit terminal recovery cases are deliberately separate
        self,
        error: NormalizedError,
        *,
        attempt: int,
        idempotent: bool,
        deadline: float,
        existing_actor: bool = False,
        reconciled: bool = False,
    ) -> RecoveryDecision:
        if attempt < 1 or not math.isfinite(deadline):
            raise ValueError("attempt and absolute deadline required")
        with self._lock:
            if error.category == "uncertain_outcome":
                return RecoveryDecision(
                    action="reconcile",
                    retry=False,
                    delay=0,
                    coverage_status="inconclusive",
                    reason="side effects are unknown",
                )
            if not error.retryable or error.terminal:
                return RecoveryDecision(
                    action=error.recovery_action,
                    retry=False,
                    delay=0,
                    coverage_status=error.coverage_effect,
                    reason=error.code,
                )
            if error.code in {"browser_crash", "worker_crash"} and not reconciled:
                return RecoveryDecision(
                    action="cleanup_and_reconcile",
                    retry=False,
                    delay=0,
                    coverage_status="partial",
                    reason="crash requires side-effect reconciliation",
                )
            if not idempotent:
                return RecoveryDecision(
                    action="reconcile",
                    retry=False,
                    delay=0,
                    coverage_status="inconclusive",
                    reason="automatic replay of non-idempotent work denied",
                )
            if attempt >= self.max_attempts or self._retries >= self.retry_budget:
                return RecoveryDecision(
                    action="stop",
                    retry=False,
                    delay=0,
                    coverage_status=error.coverage_effect,
                    reason="retry budget exhausted",
                )
            if error.code == "session_expired":
                if not existing_actor or self._reauth >= self.max_reauth:
                    return RecoveryDecision(
                        action="block",
                        retry=False,
                        delay=0,
                        coverage_status="blocked",
                        reason="existing actor reauthentication budget unavailable",
                    )
                delay, action = 0.0, "reauthenticate_existing_actor"
            else:
                delay = min(self.max_delay, self.base_delay * 2 ** min(attempt - 1, 30))
                delay *= 0.5 + min(1.0, max(0.0, self._jitter())) * 0.5
                delay = max(delay, error.retry_after or 0)
                action = {"rate_limit": "cooldown", "resource": "wait_for_capacity"}.get(
                    error.category, "retry_safe"
                )
            if self._clock() + delay >= deadline:
                return RecoveryDecision(
                    action="stop",
                    retry=False,
                    delay=0,
                    coverage_status=error.coverage_effect,
                    reason="campaign deadline exhausted",
                )
            self._retries += 1
            if error.code == "session_expired":
                self._reauth += 1
            return RecoveryDecision(
                action=action,
                retry=True,
                delay=delay,
                coverage_status=error.coverage_effect,
                reason=error.code,
            )


@dataclass
class _CircuitState:
    failures: int = 0
    opened_until: float = 0
    probes: int = 0
    probe_deadline: float = 0


class CircuitBreaker:
    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        cooldown: float = 10,
        half_open_probes: int = 1,
        max_circuits: int = 128,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if min(failure_threshold, half_open_probes, max_circuits) < 1 or cooldown <= 0:
            raise ValueError("invalid circuit breaker limits")
        self.failure_threshold, self.cooldown = failure_threshold, cooldown
        self.half_open_probes, self.max_circuits = half_open_probes, max_circuits
        self._clock = clock
        self._states: OrderedDict[str, _CircuitState] = OrderedDict()
        self._lock = threading.RLock()

    def _state(self, key: str) -> _CircuitState | None:
        if len(key) > 512:
            raise ValueError("circuit reference too long")
        state = self._states.get(key)
        if state is None:
            if len(self._states) >= self.max_circuits:
                # Only inactive healthy circuits may be discarded.
                evict = next(
                    (k for k, s in self._states.items() if s.failures == 0 and s.probes == 0), None
                )
                if evict is None:
                    return None
                self._states.pop(evict)
            state = self._states[key] = _CircuitState()
        self._states.move_to_end(key)
        return state

    def allow(self, key: str) -> bool:
        with self._lock:
            state, now = self._state(key), self._clock()
            if state is None or state.opened_until > now:
                return False
            if state.failures >= self.failure_threshold:
                if state.probes and state.probe_deadline <= now:
                    state.probes = 0
                if state.probes >= self.half_open_probes:
                    return False
                state.probes += 1
                state.probe_deadline = now + self.cooldown
            return True

    def record(self, key: str, *, success: bool) -> None:
        with self._lock:
            state = self._state(key)
            if state is None:
                return
            state.probes = max(0, state.probes - 1)
            if success:
                state.failures = 0
                state.opened_until = 0
            else:
                state.failures += 1
                if state.failures >= self.failure_threshold:
                    state.opened_until = self._clock() + self.cooldown
