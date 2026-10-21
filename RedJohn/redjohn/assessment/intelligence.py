"""Evidence-backed technology/intelligence/correlation, bounded observation metrics.

No module in this file starts a tool or contacts a provider automatically.
Advisory matches are product applicability records, never dynamic findings.
"""

from __future__ import annotations

import bisect
import json
import math
import re
import sqlite3
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping
    from pathlib import Path

    from redjohn.assessment.cache import SmartCache
    from redjohn.assessment.lab_validation import LabValidation
    from redjohn.assessment.proof_bound_correlation import ProofBoundCorrelation


_PRODUCT = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._ -]{0,127}$")
_VERSION = re.compile(r"^v?(\d+(?:\.\d+){0,7})$")


def _version(value: str) -> tuple[int, ...] | None:
    match = _VERSION.fullmatch(value)
    if not match or len(value) > 128:
        return None
    parts = tuple(int(part) for part in match[1].split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


@dataclass(frozen=True)
class TechnologyObservation:
    product: str
    version: str | None
    source: str
    evidence_ref: str
    asset_ref: str
    actor_ref: str = "anonymous"
    confidence: float = 0.5
    version_confidence: str = "unknown"
    observed_at: float = 0

    def __post_init__(self) -> None:
        if not _PRODUCT.fullmatch(self.product) or not self.evidence_ref or not self.asset_ref:
            raise ValueError("technology product, asset and evidence reference required")
        if not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
            raise ValueError("invalid technology confidence")
        if self.version_confidence not in {"unknown", "inferred", "explicit"}:
            raise ValueError("invalid version confidence")
        if self.version_confidence == "explicit" and not self.version:
            raise ValueError("an explicit version must be observed")
        for value in (
            self.version or "",
            self.source,
            self.evidence_ref,
            self.asset_ref,
            self.actor_ref,
        ):
            if len(value) > 512:
                raise ValueError("technology observation field too large")


class TechnologyDetector:
    """Preserve contradictory evidence in indexed SQLite, read in bounded pages."""

    def __init__(self, database: Path | str, *, max_observations: int = 10000) -> None:
        self.db = sqlite3.connect(str(database), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.max_observations = max_observations
        if max_observations < 1:
            raise ValueError("invalid technology observation quota")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS rj_technology(
          engagement TEXT NOT NULL, asset TEXT NOT NULL, product TEXT NOT NULL,
          evidence_ref TEXT NOT NULL, payload TEXT NOT NULL,
          UNIQUE(engagement,asset,product,evidence_ref));
        CREATE INDEX IF NOT EXISTS rj_technology_lookup ON rj_technology(engagement,asset,product);
        """)

    def observe(self, engagement: str, observation: TechnologyObservation) -> None:
        if not engagement or len(engagement) > 128:
            raise ValueError("engagement reference required")
        item = replace(observation, observed_at=observation.observed_at or time.time())
        with self._lock, self.db:
            duplicate = self.db.execute(
                "SELECT 1 FROM rj_technology WHERE engagement=? AND asset=? "
                "AND product=? AND evidence_ref=?",
                (engagement, item.asset_ref, item.product.lower(), item.evidence_ref),
            ).fetchone()
            count = self.db.execute(
                "SELECT count(*) FROM rj_technology WHERE engagement=?", (engagement,)
            ).fetchone()[0]
            if not duplicate and count >= self.max_observations:
                raise ValueError("technology_observation_quota_exhausted")
            self.db.execute(
                "INSERT OR IGNORE INTO rj_technology VALUES(?,?,?,?,?)",
                (
                    engagement,
                    item.asset_ref,
                    item.product.lower(),
                    item.evidence_ref,
                    json.dumps(asdict(item), separators=(",", ":")),
                ),
            )

    def detect_headers(
        self,
        engagement: str,
        headers: Mapping[str, str],
        *,
        evidence_ref: str,
        asset_ref: str,
        actor_ref: str = "anonymous",
    ) -> list[TechnologyObservation]:
        if len(headers) > 128:
            raise ValueError("header observation count exceeded")
        observations = []
        for name, value in headers.items():
            if name.lower() not in {"server", "x-powered-by"}:
                continue
            if len(value) > 4096:
                raise ValueError("header observation size exceeded")
            # A header is claimed product identity; an absent version stays unknown.
            match = re.fullmatch(
                r"([A-Za-z][A-Za-z0-9._-]*)(?:/([0-9][A-Za-z0-9.+_-]*))?", value.strip()
            )
            if not match:
                continue
            observation = TechnologyObservation(
                match[1],
                match[2],
                f"header:{name.lower()}",
                evidence_ref,
                asset_ref,
                actor_ref,
                0.5,
                "explicit" if match[2] else "unknown",
            )
            self.observe(engagement, observation)
            observations.append(observation)
        return observations

    def observations(
        self, engagement: str, asset_ref: str, *, limit: int = 50, offset: int = 0
    ) -> list[TechnologyObservation]:
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("bounded page required")
        with self._lock:
            rows = self.db.execute(
                "SELECT payload FROM rj_technology WHERE engagement=? AND asset=? "
                "ORDER BY rowid LIMIT ? OFFSET ?",
                (engagement, asset_ref, limit, offset),
            ).fetchall()
        return [TechnologyObservation(**json.loads(row[0])) for row in rows]

    def close(self) -> None:
        self.db.close()


@dataclass(frozen=True)
class AdvisoryRecord:
    advisory_id: str
    product: str
    source: str
    fetched_at: float
    data_version: str
    lower_version: str | None = None
    upper_version: str | None = None
    lower_inclusive: bool = True
    upper_inclusive: bool = False
    exact_versions: tuple[str, ...] = ()
    ttl_seconds: float = 86400

    def __post_init__(self) -> None:
        if (
            not self.advisory_id
            or not _PRODUCT.fullmatch(self.product)
            or not self.source
            or not self.data_version
        ):
            raise ValueError("advisory identity, source and data version required")
        if (
            not math.isfinite(self.fetched_at)
            or not math.isfinite(self.ttl_seconds)
            or self.ttl_seconds <= 0
        ):
            raise ValueError("invalid advisory freshness")
        if len(self.exact_versions) > 256:
            raise ValueError("advisory version list too large")
        for value in (
            self.advisory_id,
            self.source,
            self.data_version,
            self.lower_version or "",
            self.upper_version or "",
            *self.exact_versions,
        ):
            if len(value) > 1024:
                raise ValueError("advisory field too large")

    def applicability(  # noqa: PLR0911 - preserve unknown/stale/affected distinctions
        self, observation: TechnologyObservation, *, now: float | None = None
    ) -> str:
        now = time.time() if now is None else now
        if observation.product.lower() != self.product.lower():
            return "not_affected"
        if self.fetched_at > now or self.fetched_at + self.ttl_seconds <= now:
            return "unknown"
        if not observation.version:
            return "potentially_affected"
        parsed = _version(observation.version)
        if parsed is None:
            return "unknown"
        if self.exact_versions:
            versions = [_version(value) for value in self.exact_versions]
            if any(value is None for value in versions):
                return "unknown"
            affected = parsed in versions
        elif self.lower_version is not None or self.upper_version is not None:
            lower = _version(self.lower_version) if self.lower_version is not None else None
            upper = _version(self.upper_version) if self.upper_version is not None else None
            if (
                (self.lower_version is not None and lower is None)
                or (self.upper_version is not None and upper is None)
                or (lower is not None and upper is not None and lower > upper)
            ):
                return "unknown"
            affected = (
                lower is None or parsed > lower or (parsed == lower and self.lower_inclusive)
            ) and (upper is None or parsed < upper or (parsed == upper and self.upper_inclusive))
        else:
            return "potentially_affected"
        if not affected:
            # An inferred version cannot exclude a product reliably.
            return "not_affected" if observation.version_confidence == "explicit" else "unknown"
        return (
            "confirmed_affected"
            if observation.version_confidence == "explicit"
            else "potentially_affected"
        )


@dataclass(frozen=True)
class IntelligenceResult:
    status: str
    records: tuple[AdvisoryRecord, ...]
    error_code: str | None = None


class CVEIntelligenceManager:
    """One injected VulnX/CVEMap-compatible provider, product identifiers only."""

    def __init__(
        self,
        provider: Callable[[str], Iterable[AdvisoryRecord]] | None,
        cache: SmartCache,
        *,
        max_records: int = 100,
        timeout: float = 5,
    ) -> None:
        if not 1 <= max_records <= 1000 or timeout <= 0:
            raise ValueError("invalid intelligence budgets")
        self.provider, self.cache, self.max_records, self.timeout = (
            provider,
            cache,
            max_records,
            timeout,
        )

    def query(
        self, product: str, *, provider_version: str, refresh: bool = False
    ) -> IntelligenceResult:
        if not _PRODUCT.fullmatch(product) or not provider_version or len(provider_version) > 128:
            raise ValueError("structured product identifier and provider version required")
        provider = self.provider
        if provider is None:
            return IntelligenceResult(
                "blocked_missing_dependency", (), "intelligence_provider_missing"
            )
        key = f"intelligence:{product.lower()}:{provider_version}"

        def fetch() -> list[dict[str, Any]]:
            records: list[dict[str, Any]] = []
            for record in provider(product):
                if not isinstance(record, AdvisoryRecord) or len(records) >= self.max_records:
                    raise ValueError("intelligence_provider_schema_or_count_exceeded")
                records.append(asdict(record))
            return records

        try:
            payload = self.cache.get_or_compute(
                key, fetch, 300, timeout=self.timeout, retest=refresh
            )
            if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
                raise ValueError("intelligence_provider_schema_mismatch")  # noqa: TRY301 - normalized below
            records = tuple(
                AdvisoryRecord(
                    **{**value, "exact_versions": tuple(value.get("exact_versions", ()))}
                )
                for value in payload
            )
            return IntelligenceResult("available", records)
        except TimeoutError:
            return IntelligenceResult("provider_unavailable", (), "intelligence_provider_timeout")
        except (OSError, RuntimeError):
            return IntelligenceResult(
                "provider_unavailable", (), "intelligence_provider_unavailable"
            )
        except (TypeError, ValueError):
            return IntelligenceResult(
                "incompatible_provider_output", (), "intelligence_provider_schema_mismatch"
            )


@dataclass(frozen=True)
class CorrelationEdge:
    source_ref: str
    target_ref: str
    relation: str
    prerequisites: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    status: str = "hypothesized"
    lab_fixture_ref: str = ""
    validation_assertion_ref: str = ""

    def __post_init__(self) -> None:
        if self.relation not in {
            "common_root_cause",
            "prerequisite",
            "reachability",
            "potential_impact",
        }:
            raise ValueError("unsupported correlation relation")
        if self.status not in {
            "hypothesized",
            "partially_supported",
            "validated_in_lab",
            "rejected",
        }:
            raise ValueError("unsupported correlation status")
        if (
            not self.source_ref
            or not self.target_ref
            or not self.prerequisites
            or not self.evidence_refs
        ):
            raise ValueError("correlation requires nodes, prerequisites and evidence")
        if len(self.prerequisites) > 16 or len(self.evidence_refs) > 16:
            raise ValueError("correlation reference limit exceeded")
        if any(
            len(value) > 512
            for value in (
                self.source_ref,
                self.target_ref,
                self.lab_fixture_ref,
                self.validation_assertion_ref,
                *self.prerequisites,
                *self.evidence_refs,
            )
        ):
            raise ValueError("correlation field size exceeded")
        if self.status == "validated_in_lab" and not (
            self.lab_fixture_ref and self.validation_assertion_ref
        ):
            raise ValueError("validated correlation requires fixture and assertion evidence")


@dataclass(frozen=True)
class CorrelationQuery:
    edges: tuple[CorrelationEdge, ...]
    visited_nodes: int
    truncated: bool
    chain_status: str


class VulnerabilityCorrelator:
    def __init__(
        self,
        database: Path | str,
        *,
        max_edges: int = 10000,
        evidence_exists: Callable[[str, str], bool] | None = None,
        lab_validation: LabValidation | None = None,
    ) -> None:
        if max_edges < 1:
            raise ValueError("invalid correlation edge quota")
        self._lab_proof: ProofBoundCorrelation | None = None
        if lab_validation is not None:
            from pathlib import Path  # noqa: PLC0415 - runtime same-store check

            from redjohn.assessment.lab_validation import LabValidation  # noqa: PLC0415
            from redjohn.assessment.proof_bound_correlation import ProofBoundCorrelation  # noqa: PLC0415

            if (
                type(lab_validation) is not LabValidation
                or Path(database).resolve() != lab_validation.store.path.resolve()
            ):
                raise ValueError("correlation_exact_lab_store_required")
            self._lab_proof = ProofBoundCorrelation(lab_validation)
        self.db = sqlite3.connect(str(database), check_same_thread=False)
        self._lock = threading.RLock()
        self.max_edges = max_edges
        self._evidence_exists = evidence_exists or self._stored_evidence
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS rj_correlation(
          engagement TEXT NOT NULL, source_ref TEXT NOT NULL, target_ref TEXT NOT NULL,
          relation TEXT NOT NULL, payload TEXT NOT NULL,
          UNIQUE(engagement,source_ref,target_ref,relation));
        CREATE INDEX IF NOT EXISTS rj_correlation_source ON rj_correlation(engagement,source_ref);
        """)

    def _stored_evidence(self, engagement: str, reference: str) -> bool:
        try:
            return (
                self.db.execute(
                    "SELECT 1 FROM rj_evidence WHERE engagement=? AND id=?", (engagement, reference)
                ).fetchone()
                is not None
            )
        except sqlite3.OperationalError:
            return False

    def _authorize_lab_edge(self, engagement: str, edge: CorrelationEdge) -> None:
        if edge.status != "validated_in_lab":
            return
        if self._lab_proof is None or engagement != self._lab_proof.validation.policy.engagement_id:
            raise ValueError("correlation_persisted_paired_lab_proof_required")
        self._lab_proof.authorize_edge(edge)

    def add(self, engagement: str, edge: CorrelationEdge) -> None:
        self._authorize_lab_edge(engagement, edge)
        refs = (
            *edge.evidence_refs,
            *((edge.validation_assertion_ref,) if edge.validation_assertion_ref else ()),
        )
        with self._lock, self.db:
            if not all(self._evidence_exists(engagement, ref) for ref in refs):
                raise ValueError("correlation_evidence_missing_or_wrong_engagement")
            existing = self.db.execute(
                "SELECT 1 FROM rj_correlation WHERE engagement=? AND source_ref=? "
                "AND target_ref=? AND relation=?",
                (engagement, edge.source_ref, edge.target_ref, edge.relation),
            ).fetchone()
            if (
                not existing
                and self.db.execute(
                    "SELECT count(*) FROM rj_correlation WHERE engagement=?", (engagement,)
                ).fetchone()[0]
                >= self.max_edges
            ):
                raise ValueError("correlation_edge_quota_exhausted")
            self.db.execute(
                "INSERT OR REPLACE INTO rj_correlation VALUES(?,?,?,?,?)",
                (
                    engagement,
                    edge.source_ref,
                    edge.target_ref,
                    edge.relation,
                    json.dumps(asdict(edge), separators=(",", ":")),
                ),
            )

    def query(  # noqa: PLR0912 - traversal bounds and explicit chain status branches
        self,
        engagement: str,
        root_ref: str,
        *,
        max_depth: int = 3,
        max_nodes: int = 64,
        max_edges: int = 64,
    ) -> CorrelationQuery:
        if not 1 <= max_depth <= 8 or not 1 <= max_nodes <= 256 or not 1 <= max_edges <= 256:
            raise ValueError("correlation query exceeds traversal limits")
        pending = deque([(root_ref, 0)])
        visited: set[str] = set()
        edges: list[CorrelationEdge] = []
        truncated = False
        with self._lock:
            while pending:
                node, depth = pending.popleft()
                if node in visited:
                    continue
                if len(visited) >= max_nodes:
                    truncated = True
                    break
                visited.add(node)
                if depth >= max_depth:
                    truncated |= (
                        self.db.execute(
                            "SELECT 1 FROM rj_correlation "
                            "WHERE engagement=? AND source_ref=? LIMIT 1",
                            (engagement, node),
                        ).fetchone()
                        is not None
                    )
                    continue
                rows = self.db.execute(
                    "SELECT payload FROM rj_correlation WHERE engagement=? AND source_ref=? "
                    "ORDER BY target_ref LIMIT ?",
                    (engagement, node, max_edges - len(edges) + 1),
                ).fetchall()
                for row in rows:
                    if len(edges) >= max_edges:
                        truncated = True
                        break
                    payload = json.loads(row[0])
                    edge = CorrelationEdge(
                        **{
                            **payload,
                            "prerequisites": tuple(payload["prerequisites"]),
                            "evidence_refs": tuple(payload["evidence_refs"]),
                        }
                    )
                    # Re-read the durable paired assertion even for historical
                    # rows. Caller labels or a formerly valid policy cannot
                    # turn a stale graph into a validated chain after reopen.
                    self._authorize_lab_edge(engagement, edge)
                    edges.append(edge)
                    if edge.status != "rejected":
                        # Frontier itself is bounded, not only visited count.
                        if len(pending) + len(visited) >= max_nodes:
                            truncated = True
                        else:
                            pending.append((edge.target_ref, depth + 1))
        statuses = {edge.status for edge in edges}
        status = "hypothesized"
        if statuses and statuses == {"rejected"}:
            status = "rejected"
        elif statuses == {"validated_in_lab"} and not truncated:
            status = "validated_in_lab"
        elif statuses.intersection({"partially_supported", "validated_in_lab"}):
            status = "partially_supported"
        return CorrelationQuery(tuple(edges), len(visited), truncated, status)

    def close(self) -> None:
        self.db.close()


class PerformanceMonitor:
    """Fixed histogram buckets and bounded labels; no retained per-job samples."""

    BUCKETS = (0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 120.0, 600.0)
    PHASES = frozenset({"discovery", "queue", "execution", "validation", "report", "retest"})

    def __init__(self, allowed_tools: Iterable[str], *, max_tools: int = 64) -> None:
        tools = frozenset(allowed_tools)
        if len(tools) > max_tools or any(
            not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", tool) for tool in tools
        ):
            raise ValueError("metrics require bounded registered tool labels")
        self.allowed_tools = tools
        self._metrics: dict[tuple[str, str], dict[str, Any]] = {}
        self._lock = threading.Lock()

    def record(
        self,
        tool: str,
        phase: str,
        *,
        duration: float,
        queue_wait: float = 0,
        requests: int = 0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        model_calls: int = 0,
        errors: int = 0,
        retries: int = 0,
        new_inputs: int = 0,
        confirmed_findings: int = 0,
        candidate_findings: int = 0,
        peak_memory_bytes: int = 0,
        cache_hits: int = 0,
        cache_evictions: int = 0,
        model_cost: float = 0,
        cost_estimated: bool = False,
    ) -> None:
        if tool not in self.allowed_tools or phase not in self.PHASES:
            raise ValueError("unregistered telemetry label")
        counts = {
            "requests": requests,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "model_calls": model_calls,
            "errors": errors,
            "retries": retries,
            "new_inputs": new_inputs,
            "confirmed_findings": confirmed_findings,
            "candidate_findings": candidate_findings,
            "cache_hits": cache_hits,
            "cache_evictions": cache_evictions,
        }
        if any(type(v) is not int or v < 0 for v in (*counts.values(), peak_memory_bytes)):
            raise ValueError("metric counters must be nonnegative integers")
        if any(not math.isfinite(v) or v < 0 for v in (duration, queue_wait, model_cost)):
            raise ValueError("metric measurements must be finite and nonnegative")
        with self._lock:
            item = self._metrics.setdefault(
                (tool, phase),
                {
                    "count": 0,
                    "duration_seconds": 0,
                    "queue_wait_seconds": 0,
                    "histogram": [0] * (len(self.BUCKETS) + 1),
                    "peak_memory_bytes": 0,
                    "measured_model_cost": 0,
                    "estimated_model_cost": 0,
                },
            )
            item["count"] += 1
            item["duration_seconds"] += duration
            item["queue_wait_seconds"] += queue_wait
            item["histogram"][bisect.bisect_left(self.BUCKETS, duration)] += 1
            item["peak_memory_bytes"] = max(item["peak_memory_bytes"], peak_memory_bytes)
            item["estimated_model_cost" if cost_estimated else "measured_model_cost"] += model_cost
            for name, value in counts.items():
                item[name] = item.get(name, 0) + value

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            result = {}
            for (tool, phase), metrics in self._metrics.items():
                item = {**metrics, "histogram": list(metrics["histogram"])}
                for percentile in (50, 95):
                    rank, seen = math.ceil(item["count"] * percentile / 100), 0
                    for index, value in enumerate(item["histogram"]):
                        seen += value
                        if seen >= rank:
                            item[f"p{percentile}_upper_bound_seconds"] = (
                                self.BUCKETS[index] if index < len(self.BUCKETS) else None
                            )
                            break
                result[f"{tool}:{phase}"] = item
            return result


@dataclass(frozen=True)
class OptimizationParameters:
    concurrency: int = 1
    batch_size: int = 8
    timeout_seconds: float = 30
    bounded_depth: int = 3
    input_subset: int = 100
    evidence_excerpt_bytes: int = 4096

    def __post_init__(self) -> None:
        if (
            not 1 <= self.concurrency <= 16
            or not 1 <= self.batch_size <= 128
            or not 1 <= self.timeout_seconds <= 600
            or not 1 <= self.bounded_depth <= 8
            or not 1 <= self.input_subset <= 10000
            or not 128 <= self.evidence_excerpt_bytes <= 65536
        ):
            raise ValueError("optimizer parameters outside allowed envelope")


@dataclass(frozen=True)
class ParameterChange:
    field: str
    old: int | float
    new: int | float
    reason: str
    at: float


class ParameterOptimizer:
    """Proposes at most two safe throughput changes; governor must admit them."""

    def __init__(
        self,
        *,
        max_concurrency: int = 2,
        max_batch_size: int = 16,
        cooldown_seconds: float = 30,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 1 <= max_concurrency <= 16 or not 1 <= max_batch_size <= 128 or cooldown_seconds < 0:
            raise ValueError("invalid optimizer ceilings")
        self.max_concurrency, self.max_batch_size = max_concurrency, max_batch_size
        self.cooldown_seconds, self._clock = cooldown_seconds, clock
        self._last_change = -math.inf
        self._healthy = 0
        self.history: deque[ParameterChange] = deque(maxlen=32)

    def suggest(
        self,
        current: OptimizationParameters,
        *,
        pressure: str = "normal",
        rate_limited: bool = False,
    ) -> tuple[OptimizationParameters, tuple[ParameterChange, ...]]:
        if pressure not in {"normal", "soft", "high", "measurement_unavailable"}:
            raise ValueError("unknown resource pressure")
        now = self._clock()
        self._healthy = self._healthy + 1 if pressure == "normal" and not rate_limited else 0
        if now - self._last_change < self.cooldown_seconds:
            return current, ()
        if pressure != "normal" or rate_limited:
            values = {
                "concurrency": max(1, current.concurrency // 2),
                "batch_size": max(1, current.batch_size // 2),
            }
            reason = "rate_limit" if rate_limited else "memory_pressure"
        elif self._healthy >= 3:
            values = {
                "concurrency": min(self.max_concurrency, current.concurrency + 1),
                "batch_size": min(self.max_batch_size, current.batch_size + 1),
            }
            reason = "sustained_healthy_capacity"
        else:
            return current, ()
        changes = tuple(
            ParameterChange(name, getattr(current, name), value, reason, now)
            for name, value in values.items()
            if getattr(current, name) != value
        )
        if changes:
            self._last_change = now
            self._healthy = 0
            self.history.extend(changes)
        return replace(current, **values), changes


@dataclass(frozen=True)
class DegradationDecision:
    capability: str
    coverage_lost: tuple[str, ...]
    fallback_used: str | None
    coverage_status: str
    reason: str


class GracefulDegradation:
    @staticmethod
    def plan(
        capability: str,
        *,
        unavailable_reason: str,
        equivalent_fallback: str | None = None,
        policy_allows_fallback: bool = False,
    ) -> DegradationDecision:
        if equivalent_fallback and policy_allows_fallback:
            return DegradationDecision(
                capability, (), equivalent_fallback, "partial", unavailable_reason
            )
        return DegradationDecision(capability, (capability,), None, "blocked", unavailable_reason)
