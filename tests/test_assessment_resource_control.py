"""Deterministic resource/cache/recovery contracts plus an actual RSS measurement.

These tests execute no scanner and make no network requests. Clock injection and
fake memory samples are unit tests; ProcessMemoryIntegrationTest uses real ps.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import subprocess
import sys
import threading
import time
import unittest
from datetime import UTC, datetime
from email.utils import format_datetime

from redjohn.assessment.cache import CacheBusyError, CacheContext, SmartCache
from redjohn.assessment.recovery import (
    CircuitBreaker,
    FailureRecoverySystem,
    RateLimitDetector,
    error_from_code,
    parse_retry_after,
)
from redjohn.assessment.resources import (
    ContextTokenBudget,
    MemoryBudgetManager,
    ProcessTreeMemory,
    ResourceAdmissionError,
    ResourceEnvelope,
    ResourceGovernor,
    process_tree_memory,
)


class Clock:
    def __init__(self, value: float = 100) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class CacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.cache = SmartCache(20, 2, clock=self.clock)

    def tearDown(self) -> None:
        self.cache.close()

    def test_lru_reads_move_hot_entry(self) -> None:
        self.cache.set("a", "aaa", 10)
        self.cache.set("b", "bbb", 10)
        self.assertEqual(self.cache.get("a"), "aaa")
        self.cache.set("c", "ccc", 10)
        self.assertIsNone(self.cache.get("b"))
        self.assertEqual(self.cache.get("a"), "aaa")
        self.assertEqual(self.cache.stats()["eviction"], 1)

    def test_exact_stored_bytes_oversized_and_ttl(self) -> None:
        self.cache.set("a", "hello", 10)  # JSON adds two quote bytes.
        self.assertEqual(self.cache.stats()["bytes"], 7)
        self.assertFalse(self.cache.set("huge", "x" * 100, 10))
        self.assertEqual(self.cache.get("a"), "hello")
        self.clock.value += 10
        self.assertIsNone(self.cache.get("a"))
        self.assertEqual(self.cache.stats()["bytes"], 0)

    def test_byte_limit_independent_of_item_limit(self) -> None:
        self.cache.set("a", "x" * 10, 10)
        self.cache.set("b", "y" * 10, 10)
        self.assertIsNone(self.cache.get("a"))
        self.assertEqual(self.cache.stats()["bytes"], 12)

    def test_return_value_is_not_mutable_stored_reference(self) -> None:
        self.cache.set("a", {"x": [1]}, 10)
        value = self.cache.get("a")
        value["x"].append(2)
        self.assertEqual(self.cache.get("a"), {"x": [1]})

    def test_json_null_is_cached_and_key_and_deadlines_are_bounded(self) -> None:
        self.cache.set("null", None, 10)
        self.assertIsNone(self.cache.get_or_compute("null", lambda: "unexpected_refresh", 10))
        with self.assertRaises(ValueError):
            self.cache.set("x" * 513, 1, 10)
        self.assertFalse(self.cache.set("infinite", 1, float("inf")))
        with self.assertRaises(ValueError):
            self.cache.get_or_compute("deadline", lambda: 1, 10, timeout=float("nan"))

    def test_errors_stateful_and_retests_are_not_cached(self) -> None:
        self.assertFalse(self.cache.set("bad", [], 10, success=False))
        self.assertFalse(self.cache.set("auth", [], 10, family="authz"))
        self.cache.set("a", "old", 10)
        self.assertIsNone(self.cache.get("a", retest=True))
        self.assertEqual(self.cache.get_or_compute("a", lambda: "new", 10, retest=True), "new")
        self.assertEqual(self.cache.get("a"), "old")

    def test_all_context_dimensions_change_key(self) -> None:
        context = CacheContext(*["v1"] * 12)
        original = context.key("js", "parse")
        for field in dataclasses.fields(context):
            changed = dataclasses.replace(context, **{field.name: "v2"})
            self.assertNotEqual(changed.key("js", "parse"), original, field.name)
        self.cache.set("a", 1, 10, context=context)
        self.assertEqual(
            self.cache.invalidate(context={"session_revision": "v1"}, reason="session_changed"), 1
        )
        self.assertIsNone(self.cache.get("a"))

    def test_singleflight_shares_one_refresh(self) -> None:
        entered, release = threading.Event(), threading.Event()
        count = 0

        def load() -> object:
            nonlocal count
            count += 1
            entered.set()
            self.assertTrue(release.wait(2))
            return {"n": 1}

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            first = pool.submit(self.cache.get_or_compute, "same", load, 10)
            self.assertTrue(entered.wait(2))
            waiters = [pool.submit(self.cache.get_or_compute, "same", load, 10) for _ in range(4)]
            limit = time.monotonic() + 2
            while self.cache.stats().get("singleflight_waiter", 0) < 4 and time.monotonic() < limit:
                time.sleep(0.001)
            release.set()
            self.assertEqual(first.result(), {"n": 1})
            self.assertEqual([x.result() for x in waiters], [{"n": 1}] * 4)
        self.assertEqual(count, 1)

    def test_waiter_timeout_and_late_refresh_not_published(self) -> None:
        entered, release = threading.Event(), threading.Event()

        def load() -> str:
            entered.set()
            release.wait(2)
            self.clock.value += 10
            return "late"

        with self.assertRaises(TimeoutError):
            self.cache.get_or_compute("slow", load, 10, timeout=0.02, refresh_timeout=1)
        self.assertTrue(entered.is_set())
        release.set()
        limit = time.monotonic() + 2
        while self.cache.stats()["inflight"] and time.monotonic() < limit:
            time.sleep(0.001)
        self.assertEqual(self.cache.stats().get("refresh_expired"), 1)
        self.assertIsNone(self.cache.get("slow"))

    def test_invalidation_fences_inflight_result(self) -> None:
        entered, release = threading.Event(), threading.Event()

        def load() -> str:
            entered.set()
            release.wait(2)
            return "old-session"

        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(self.cache.get_or_compute, "a", load, 10)
            self.assertTrue(entered.wait(2))
            self.cache.invalidate(reason="session_changed")
            release.set()
            self.assertEqual(future.result(), "old-session")
        self.assertIsNone(self.cache.get("a"))

    def test_refresh_backpressure(self) -> None:
        bounded = SmartCache(100, max_refreshes=1)
        release = threading.Event()
        try:
            with self.assertRaises(TimeoutError):
                bounded.get_or_compute("a", lambda: release.wait(2), 1, timeout=0.01)
            with self.assertRaises(CacheBusyError):
                bounded.get_or_compute("b", lambda: 2, 1)
        finally:
            release.set()
            bounded.close()

    def test_close_releases_retained_payloads_even_while_cache_is_referenced(self) -> None:
        self.assertTrue(self.cache.set("retained", "payload", 10))
        self.assertEqual(self.cache.stats()["bytes"], 9)
        self.cache.close()
        self.assertEqual(self.cache.stats()["bytes"], 0)
        self.assertEqual(self.cache.stats()["items"], 0)
        self.assertIsNone(self.cache.get("retained"))
        self.assertFalse(self.cache.set("new", "payload", 10))
        self.cache.close()  # Existing owners can close repeatedly.

    def test_close_fences_inflight_publication_without_releasing_running_slot(self) -> None:
        entered, release = threading.Event(), threading.Event()

        def load() -> str:
            entered.set()
            self.assertTrue(release.wait(2))
            return "late"

        try:
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(self.cache.get_or_compute, "inflight", load, 10)
                self.assertTrue(entered.wait(2))
                self.assertTrue(self.cache.set("retained", "payload", 10))
                self.cache.close()
                self.assertEqual(self.cache.stats()["inflight"], 1)
                self.assertEqual(self.cache.stats()["bytes"], 0)
                release.set()
                self.assertEqual(future.result(timeout=2), "late")
            self.assertIsNone(self.cache.get("inflight"))
            self.assertEqual(self.cache.stats()["bytes"], 0)
            self.assertEqual(self.cache.stats()["inflight"], 0)
        finally:
            release.set()


class ResourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rss = 100
        self.envelope = ResourceEnvelope(
            total_memory_budget=1000, worker_memory_budget=400, cache_max_bytes=100, max_workers=2
        )
        self.governor = ResourceGovernor(
            self.envelope, memory_reader=lambda: ProcessTreeMemory(1, self.rss, 1, 1)
        )

    def test_worker_and_browser_capacity_and_idempotent_release(self) -> None:
        lease = self.governor.acquire("browser", 100)
        with self.assertRaises(ResourceAdmissionError):
            self.governor.acquire("browser", 100)
        second = self.governor.acquire("scanner", 100)
        with self.assertRaises(ResourceAdmissionError):
            self.governor.acquire("worker", 100)
        lease.release()
        lease.release()
        second.release()
        self.assertEqual(self.governor.snapshot()["active"], {})

    def test_pressure_hysteresis(self) -> None:
        self.rss = 920
        with self.assertRaises(ResourceAdmissionError):
            self.governor.acquire()
        self.rss = 700
        self.governor.sample()
        self.assertEqual(self.governor.snapshot()["pressure"], "high")
        self.rss = 640
        with self.governor.acquire():
            self.assertEqual(self.governor.snapshot()["pressure"], "normal")
        self.assertEqual(self.governor.snapshot()["peak_rss_bytes"], 920)

    def test_context_budget_includes_every_component_and_output(self) -> None:
        budget = MemoryBudgetManager(dataclasses.replace(self.envelope, max_model_input_tokens=10))
        self.assertEqual(budget.validate_context(ContextTokenBudget(1, 1, 1, 1, 1, 5)), 10)
        with self.assertRaises(ResourceAdmissionError):
            budget.validate_context(ContextTokenBudget(1, 1, 1, 1, 1, 6))
        with self.assertRaises(ValueError):
            budget.validate_context(ContextTokenBudget(inputs=-1))

    def test_envelope_and_worker_reservations_are_validated(self) -> None:
        with self.assertRaises(ValueError):
            dataclasses.replace(self.envelope, resume_watermark=0.95)
        with self.assertRaises(ResourceAdmissionError):
            self.governor.acquire(estimated_bytes=401)

    def test_unavailable_measurement_blocks_admission(self) -> None:
        governor = ResourceGovernor(
            self.envelope, memory_reader=lambda: ProcessTreeMemory(1, 0, 0, 1, available=False)
        )
        with self.assertRaises(ResourceAdmissionError):
            governor.acquire()

    def test_reclaimable_cache_does_not_block_a_small_worker(self) -> None:
        sample = ProcessTreeMemory(
            1, 100, 1, 1, cgroup_current_bytes=3000, cgroup_inactive_file_bytes=2800
        )
        governor = ResourceGovernor(self.envelope, memory_reader=lambda: sample)
        with governor.acquire(estimated_bytes=100):
            self.assertEqual(governor.snapshot()["admission_bytes"], 200)
            self.assertEqual(governor.snapshot()["cgroup_current_bytes"], 3000)

    def test_working_set_preserves_rss_floor_and_active_charges(self) -> None:
        for sample in (
            ProcessTreeMemory(
                1, 920, 1, 1, cgroup_current_bytes=3000, cgroup_inactive_file_bytes=2800
            ),
            ProcessTreeMemory(
                1, 100, 1, 1, cgroup_current_bytes=3000, cgroup_inactive_file_bytes=2000
            ),
            ProcessTreeMemory(1, 100, 1, 1, cgroup_current_bytes=3000),
        ):
            governor = ResourceGovernor(self.envelope, memory_reader=lambda sample=sample: sample)
            with self.assertRaises(ResourceAdmissionError):
                governor.acquire()


class RecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock(1000)

    def test_retry_after_seconds_date_invalid_and_403(self) -> None:
        self.assertEqual(parse_retry_after("7", now=1000), 7)
        stamp = format_datetime(datetime.fromtimestamp(1010, UTC), usegmt=True)
        self.assertEqual(parse_retry_after(stamp, now=1000), 10)
        for invalid in ("nan", "inf", "-1", "junk"):
            self.assertIsNone(parse_retry_after(invalid, now=1000))
        limiter = RateLimitDetector(clock=self.clock, wall_clock=self.clock)
        result = limiter.observe("https://example.test", 403, {"Retry-After": "20"})
        self.assertFalse(result.limited)
        self.assertEqual(result.classification, "permission_or_challenge")
        self.assertEqual(limiter.remaining("https://example.test"), 0)
        self.assertFalse(limiter.observe("https://example.test", 503).limited)
        self.assertTrue(
            limiter.observe("https://example.test", 503, {"retry-after": stamp}).limited
        )

    def test_origin_limit_is_shared_between_accounts_tools_and_endpoints(self) -> None:
        limiter = RateLimitDetector(clock=self.clock, wall_clock=self.clock)
        limiter.observe(
            "https://example.test",
            429,
            {"Retry-After": "10"},
            account="alice",
            endpoint_group="api",
        )
        self.assertFalse(
            limiter.admit("https://example.test", account="bob", endpoint_group="page")
        )
        self.assertTrue(limiter.admit("https://other.test"))
        self.clock.value += 10
        self.assertTrue(limiter.admit("https://example.test", account="bob"))

    def test_aggregate_request_window(self) -> None:
        limiter = RateLimitDetector(requests_per_window=2, window_seconds=5, clock=self.clock)
        self.assertTrue(limiter.admit("https://example.test", account="a"))
        self.assertTrue(limiter.admit("https://example.test", account="b"))
        self.assertFalse(limiter.admit("https://example.test", account="c"))
        self.clock.value += 5
        self.assertTrue(limiter.admit("https://example.test", account="c"))

    def test_scope_capacity_fails_closed(self) -> None:
        limiter = RateLimitDetector(max_scopes=3, clock=self.clock)
        self.assertTrue(limiter.admit("https://a.test"))
        self.assertFalse(limiter.admit("https://b.test"))
        self.assertGreater(limiter.remaining("https://a.test"), 0)

    def test_retry_budget_deadline_and_server_wait(self) -> None:
        recovery = FailureRecoverySystem(retry_budget=1, clock=self.clock, jitter=lambda: 0)
        error = error_from_code("rate_limited", retry_after=10)
        decision = recovery.plan(error, attempt=1, idempotent=True, deadline=1020)
        self.assertTrue(decision.retry)
        self.assertEqual(decision.delay, 10)
        self.assertFalse(recovery.plan(error, attempt=1, idempotent=True, deadline=1020).retry)
        fresh = FailureRecoverySystem(clock=self.clock)
        self.assertFalse(fresh.plan(error, attempt=1, idempotent=True, deadline=1005).retry)

    def test_denials_parser_and_unknown_outcomes_are_not_negative_or_retried(self) -> None:
        recovery = FailureRecoverySystem(clock=self.clock)
        for code in (
            "policy_denied",
            "unsupported_input",
            "parser_error",
            "output_truncated",
            "evidence_write_failed",
            "unknown_execution_outcome",
        ):
            decision = recovery.plan(
                error_from_code(code), attempt=1, idempotent=True, deadline=1020
            )
            self.assertFalse(decision.retry, code)
            self.assertNotEqual(decision.coverage_status, "completed", code)
        unknown = recovery.plan(
            error_from_code("unknown_execution_outcome"), attempt=1, idempotent=True, deadline=1020
        )
        self.assertEqual(unknown.action, "reconcile")

    def test_nonidempotent_retry_crash_and_session_constraints(self) -> None:
        recovery = FailureRecoverySystem(clock=self.clock)
        self.assertFalse(
            recovery.plan(
                error_from_code("scanner_timeout"), attempt=1, idempotent=False, deadline=1020
            ).retry
        )
        self.assertFalse(
            recovery.plan(
                error_from_code("browser_crash"), attempt=1, idempotent=True, deadline=1020
            ).retry
        )
        self.assertTrue(
            recovery.plan(
                error_from_code("browser_crash"),
                attempt=1,
                idempotent=True,
                reconciled=True,
                deadline=1020,
            ).retry
        )
        error = error_from_code("session_expired")
        self.assertFalse(recovery.plan(error, attempt=1, idempotent=True, deadline=1020).retry)
        self.assertTrue(
            recovery.plan(
                error, attempt=1, idempotent=True, existing_actor=True, deadline=1020
            ).retry
        )
        self.assertFalse(
            recovery.plan(
                error, attempt=1, idempotent=True, existing_actor=True, deadline=1020
            ).retry
        )

    def test_circuit_cooldown_bounded_halfopen_and_capacity(self) -> None:
        breaker = CircuitBreaker(failure_threshold=1, cooldown=5, max_circuits=1, clock=self.clock)
        self.assertTrue(breaker.allow("provider"))
        breaker.record("provider", success=False)
        self.assertFalse(breaker.allow("provider"))
        self.assertFalse(breaker.allow("other"))
        self.clock.value += 5
        self.assertTrue(breaker.allow("provider"))
        self.assertFalse(breaker.allow("provider"))
        breaker.record("provider", success=True)
        self.assertTrue(breaker.allow("provider"))


class ProcessMemoryIntegrationTest(unittest.TestCase):
    def test_actual_controller_and_child_process_memory_measurement(self) -> None:
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import time; x=bytearray(8*1024*1024); print('ready',flush=True); time.sleep(5)",
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(child.stdout.readline().strip(), "ready")
            sample = process_tree_memory()
            self.assertTrue(sample.available)
            self.assertGreater(sample.rss_bytes, 8 * 1024 * 1024)
            self.assertGreaterEqual(sample.process_count, 2)
            self.assertIn("summed_rss", sample.method)
        finally:
            child.terminate()
            child.wait(timeout=2)
            child.stdout.close()


if __name__ == "__main__":
    unittest.main()
