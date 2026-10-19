"""Fixture/unit tests: structured advisory data is not a live CVE provider test."""

from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from redjohn.assessment.cache import SmartCache
from redjohn.assessment.intelligence import (
    AdvisoryRecord,
    CorrelationEdge,
    CVEIntelligenceManager,
    GracefulDegradation,
    OptimizationParameters,
    ParameterOptimizer,
    PerformanceMonitor,
    TechnologyDetector,
    TechnologyObservation,
    VulnerabilityCorrelator,
)


class TechnologyTest(unittest.TestCase):
    def test_persists_conflicting_sources_and_never_guesses_hidden_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agents.db"
            detector = TechnologyDetector(path)
            detector.detect_headers("e", {"Server": "nginx"}, evidence_ref="ev1", asset_ref="a")
            detector.observe(
                "e",
                TechnologyObservation(
                    "nginx", "1.26.0", "manifest", "ev2", "a", version_confidence="explicit"
                ),
            )
            detector.observe(
                "e",
                TechnologyObservation(
                    "nginx", "1.27.0", "httpx", "ev3", "a", version_confidence="explicit"
                ),
            )
            detector.close()
            reopened = TechnologyDetector(path)
            observations = reopened.observations("e", "a")
            self.assertEqual([item.version for item in observations], [None, "1.26.0", "1.27.0"])
            self.assertEqual(observations[0].version_confidence, "unknown")
            self.assertEqual(reopened.observations("other", "a"), [])
            self.assertEqual(len(reopened.observations("e", "a", limit=1, offset=1)), 1)
            reopened.close()

    def test_boundaries_and_observation_quota(self) -> None:
        detector = TechnologyDetector(":memory:", max_observations=1)
        observation = TechnologyObservation("nginx", None, "header", "ev1", "a")
        detector.observe("e", observation)
        detector.observe("e", observation)  # idempotent duplicate
        with self.assertRaises(ValueError):
            detector.observe("e", dataclasses.replace(observation, evidence_ref="ev2"))
        with self.assertRaises(ValueError):
            detector.observations("e", "a", limit=101)
        with self.assertRaises(ValueError):
            TechnologyObservation(
                "nginx", None, "header", "ev1", "a", version_confidence="explicit"
            )
        detector.close()


class AdvisoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.record = AdvisoryRecord(
            "CVE-fixture",
            "nginx",
            "fixture:advisory",
            100,
            "fixture-v1",
            lower_version="1.2.0",
            upper_version="1.4.0",
            ttl_seconds=100,
        )
        self.observation = TechnologyObservation(
            "nginx", "1.3.0", "manifest", "ev1", "a", version_confidence="explicit"
        )

    def test_structured_version_boundaries_and_product_identity(self) -> None:
        for version, expected in (
            ("1.2", "confirmed_affected"),
            ("1.3.0", "confirmed_affected"),
            ("1.4", "not_affected"),
            ("1.1.99", "not_affected"),
            ("1.3.0-rc1", "unknown"),
            (None, "potentially_affected"),
        ):
            observation = dataclasses.replace(
                self.observation,
                version=version,
                version_confidence="explicit" if version else "unknown",
            )
            self.assertEqual(self.record.applicability(observation, now=150), expected)
        self.assertEqual(
            self.record.applicability(
                dataclasses.replace(self.observation, product="apache"), now=150
            ),
            "not_affected",
        )

    def test_stale_inferred_and_invalid_range_cannot_confirm_or_exclude(self) -> None:
        self.assertEqual(self.record.applicability(self.observation, now=200), "unknown")
        inferred = dataclasses.replace(self.observation, version_confidence="inferred")
        self.assertEqual(self.record.applicability(inferred, now=150), "potentially_affected")
        self.assertEqual(
            self.record.applicability(dataclasses.replace(inferred, version="9"), now=150),
            "unknown",
        )
        invalid = dataclasses.replace(self.record, lower_version="2.0", upper_version="1.0")
        self.assertEqual(invalid.applicability(self.observation, now=150), "unknown")

    def test_exact_version_and_zero_normalization(self) -> None:
        record = dataclasses.replace(self.record, exact_versions=("1.3", "1.5"))
        self.assertEqual(record.applicability(self.observation, now=150), "confirmed_affected")
        self.assertEqual(
            record.applicability(dataclasses.replace(self.observation, version="1.30"), now=150),
            "not_affected",
        )

    def test_single_provider_cache_missing_and_outage_do_not_become_negative_findings(self) -> None:
        cache = SmartCache(10000)
        calls = []

        def provider(product: str):
            calls.append(product)
            return [self.record]

        try:
            manager = CVEIntelligenceManager(provider, cache)
            result = manager.query("nginx", provider_version="v1")
            again = manager.query("nginx", provider_version="v1")
            self.assertEqual(result.status, "available")
            self.assertEqual(again.records, result.records)
            self.assertEqual(calls, ["nginx"])
            manager.query("nginx", provider_version="v2")
            self.assertEqual(len(calls), 2)
            missing = CVEIntelligenceManager(None, cache).query("nginx", provider_version="v1")
            self.assertEqual(missing.status, "blocked_missing_dependency")

            def unavailable(_product: str):
                raise OSError("fixture provider unavailable")

            outage = CVEIntelligenceManager(unavailable, cache).query(
                "apache", provider_version="v1"
            )
            self.assertEqual(outage.status, "provider_unavailable")
            self.assertEqual(outage.records, ())
            with self.assertRaises(ValueError):
                manager.query("https://private.example/api?token=secret", provider_version="v1")
        finally:
            cache.close()

    def test_oversized_provider_response_is_visible_schema_failure(self) -> None:
        cache = SmartCache(10000)
        try:
            manager = CVEIntelligenceManager(lambda _: [self.record] * 2, cache, max_records=1)
            result = manager.query("nginx", provider_version="v1")
            self.assertEqual(result.status, "incompatible_provider_output")
            self.assertIsNotNone(result.error_code)
        finally:
            cache.close()


class CorrelationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.correlator = VulnerabilityCorrelator(
            ":memory:",
            evidence_exists=lambda engagement, ref: engagement == "e" and ref.startswith("ev"),
        )

    def tearDown(self) -> None:
        self.correlator.close()

    def edge(self, source: str, target: str, status: str = "hypothesized") -> CorrelationEdge:
        return CorrelationEdge(source, target, "prerequisite", ("actor-a",), ("ev1",), status)

    def test_evidence_and_prerequisites_mandatory_lab_validation_not_inferred(self) -> None:
        with self.assertRaises(ValueError):
            self.correlator.add("other", self.edge("a", "b"))
        with self.assertRaises(ValueError):
            dataclasses.replace(self.edge("a", "b"), prerequisites=())
        with self.assertRaises(ValueError):
            self.edge("a", "b", "validated_in_lab")
        self.correlator.add("e", self.edge("a", "b"))
        self.correlator.add("e", self.edge("b", "c"))
        result = self.correlator.query("e", "a")
        self.assertEqual(result.chain_status, "hypothesized")
        self.assertEqual(len(result.edges), 2)

    def test_traversal_depth_nodes_cycles_and_edges_are_bounded(self) -> None:
        for index in range(12):
            self.correlator.add("e", self.edge(str(index), str(index + 1)))
        self.correlator.add("e", self.edge("2", "0"))
        depth = self.correlator.query("e", "0", max_depth=2)
        self.assertTrue(depth.truncated)
        self.assertEqual(len(depth.edges), 2)
        nodes = self.correlator.query("e", "0", max_nodes=2)
        self.assertLessEqual(nodes.visited_nodes, 2)
        self.assertTrue(nodes.truncated)
        edges = self.correlator.query("e", "0", max_edges=1)
        self.assertEqual(len(edges.edges), 1)
        self.assertTrue(edges.truncated)
        with self.assertRaises(ValueError):
            self.correlator.query("e", "0", max_depth=100)

    def test_validated_and_hypothesized_chain_is_only_partially_supported(self) -> None:
        validated = dataclasses.replace(
            self.edge("a", "b"),
            status="validated_in_lab",
            lab_fixture_ref="lab1",
            validation_assertion_ref="ev-assertion",
        )
        with self.assertRaisesRegex(ValueError, "persisted_paired_lab_proof"):
            self.correlator.add("e", validated)
        self.correlator.add("e", dataclasses.replace(validated, status="partially_supported"))
        self.correlator.add("e", self.edge("b", "c"))
        self.assertEqual(self.correlator.query("e", "a").chain_status, "partially_supported")
        self.assertEqual(self.correlator.query("other", "a").edges, ())

    def test_persistent_edges_and_actual_evidence_access_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agents.db"
            first = VulnerabilityCorrelator(path)
            first.db.execute("CREATE TABLE rj_evidence(engagement TEXT,id TEXT)")
            first.db.execute("INSERT INTO rj_evidence VALUES('e','ev1')")
            first.db.commit()
            first.add("e", self.edge("a", "b"))
            first.close()
            reopened = VulnerabilityCorrelator(path)
            self.assertEqual(len(reopened.query("e", "a").edges), 1)
            with self.assertRaises(ValueError):
                reopened.add("wrong-engagement", self.edge("c", "d"))
            reopened.close()


class TelemetryOptimizerTest(unittest.TestCase):
    def test_metrics_aggregate_histograms_and_labels_are_bounded(self) -> None:
        monitor = PerformanceMonitor(["nuclei"])
        for duration in (0.01, 0.02, 0.1, 0.3, 1):
            monitor.record(
                "nuclei",
                "execution",
                duration=duration,
                requests=1,
                input_tokens=3,
                peak_memory_bytes=100,
                model_cost=0.01,
                cost_estimated=True,
            )
        result = monitor.snapshot()["nuclei:execution"]
        self.assertEqual(result["count"], 5)
        self.assertEqual(result["requests"], 5)
        self.assertEqual(result["input_tokens"], 15)
        self.assertEqual(result["p50_upper_bound_seconds"], 0.1)
        self.assertEqual(result["p95_upper_bound_seconds"], 1)
        self.assertAlmostEqual(result["estimated_model_cost"], 0.05)
        self.assertEqual(result["measured_model_cost"], 0)
        self.assertEqual(len(result["histogram"]), len(monitor.BUCKETS) + 1)
        with self.assertRaises(ValueError):
            monitor.record("https://private.example?token=secret", "execution", duration=1)
        with self.assertRaises(ValueError):
            monitor.record("nuclei", "execution", duration=float("nan"))

    def test_optimizer_changes_two_throughput_fields_with_hysteresis_and_ceiling(self) -> None:
        now = [100.0]
        optimizer = ParameterOptimizer(
            max_concurrency=4, max_batch_size=16, cooldown_seconds=10, clock=lambda: now[0]
        )
        current = OptimizationParameters(concurrency=4, batch_size=16)
        reduced, changes = optimizer.suggest(current, pressure="high")
        self.assertEqual((reduced.concurrency, reduced.batch_size), (2, 8))
        self.assertEqual({change.field for change in changes}, {"concurrency", "batch_size"})
        unchanged, changes = optimizer.suggest(reduced, pressure="high")
        self.assertEqual((unchanged, changes), (reduced, ()))
        self.assertEqual(reduced.input_subset, current.input_subset)
        self.assertEqual(reduced.bounded_depth, current.bounded_depth)
        now[0] += 10
        optimizer.suggest(reduced)
        optimizer.suggest(reduced)
        raised, changes = optimizer.suggest(reduced)
        self.assertEqual(raised.concurrency, 3)
        self.assertTrue(changes)
        self.assertLessEqual(len(optimizer.history), 32)

    def test_unavailable_capability_records_lost_coverage_and_policy_checks_fallback(self) -> None:
        decision = GracefulDegradation.plan(
            "spa-dom",
            unavailable_reason="browser_crash",
            equivalent_fallback="http-only",
            policy_allows_fallback=False,
        )
        self.assertEqual(decision.coverage_lost, ("spa-dom",))
        self.assertIsNone(decision.fallback_used)
        allowed = GracefulDegradation.plan(
            "http-meta",
            unavailable_reason="provider_down",
            equivalent_fallback="http-meta-local",
            policy_allows_fallback=True,
        )
        self.assertEqual(allowed.fallback_used, "http-meta-local")
        self.assertNotEqual(allowed.coverage_status, "completed")


if __name__ == "__main__":
    unittest.main()
