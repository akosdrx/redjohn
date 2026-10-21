"""SQLite/control/fault tests; fake workers are explicitly not live scanners."""

import asyncio
import json
import time
from dataclasses import replace

import pytest

from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.scheduler import IntelligentDecisionEngine, Scheduler
from redjohn.assessment.store import AssessmentStore, CapacityExceeded, EvidenceWriteError


@pytest.fixture
def state(tmp_path):
    policy = EngagementPolicy(
        "eng",
        "owner",
        ("http://127.0.0.1:12345",),
        actor_ids=("anonymous", "alice", "bob"),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )
    store = AssessmentStore(tmp_path / ".state" / "agents.db", queue_max_items=8)
    store.register(policy)
    surface = store.upsert_surface("eng", Surface("http://127.0.0.1:12345/?x=1&x=2&v=%2f"))
    yield store, policy, surface
    store.close()


def test_exact_semantic_keys_and_actor_isolation():
    base = Surface("http://127.0.0.1/?x=1&x=2&v=%2f")
    variants = [
        base,
        replace(base, url="http://127.0.0.1/?x=2&x=1&v=%2f"),
        replace(base, url="http://127.0.0.1/?x=1&x=2&v=%2F"),
        replace(base, actor_id="alice"),
        replace(base, tenant_id="tenant2"),
        replace(base, session_revision="2"),
        replace(base, content_type="application/json"),
        replace(base, workflow_state="checkout"),
    ]
    assert len({x.key for x in variants}) == len(variants)


def test_persistence_idempotency_and_existing_sdk_tables(state):
    store, policy, surface = state
    store.db.execute("CREATE TABLE sdk_existing_sessions(id TEXT)")
    spec = JobSpec(surface, "sqli", "http_observe")
    first = store.submit(policy, [spec])
    assert store.submit(policy, [replace(spec, priority=5)]) == first
    assert len(store.jobs("eng")) == 1
    other = AssessmentStore(store.path)
    assert other.jobs("eng")[0]["id"] == first[0]
    assert other.db.execute("SELECT * FROM sdk_existing_sessions").fetchall() == []
    assert other.surfaces("eng")[0]["url"].endswith("?x=1&x=2&v=%2f")
    other.close()


def test_fairness_prevents_sql_family_starvation(state):
    store, policy, surface = state
    store.submit(
        policy,
        [
            JobSpec(surface, "sqli", "http_observe", retest_revision=str(n), priority=99)
            for n in range(5)
        ]
        + [
            JobSpec(surface, "configuration", "headers_audit", priority=1),
            JobSpec(surface, "discovery", "browser_discover", priority=1),
        ],
    )
    families = []
    for _index in range(3):
        job = store.claim(policy, "worker")
        families.append(job["family"])
        assert store.finish(job, AdapterResult("succeeded", "completed"))
    assert set(families) == {"sqli", "configuration", "discovery"}


def test_atomic_queue_limit_and_duplicate_no_extra_capacity(state):
    store, policy, surface = state
    spec = JobSpec(surface, "configuration", "headers_audit")
    store.submit(policy, [replace(spec, retest_revision=str(n)) for n in range(8)])
    assert store.submit(policy, [replace(spec, retest_revision="0")])
    with pytest.raises(CapacityExceeded):
        store.submit(policy, [replace(spec, retest_revision="9")])
    assert len(store.jobs("eng")) == 8


def test_expired_lease_is_inconclusive_and_stale_worker_fenced(state):
    store, policy, surface = state
    store.submit(policy, [JobSpec(surface, "traffic", "http_observe")])
    job = store.claim(policy, "lost-worker", lease_seconds=-1)
    assert store.recover_expired(policy) == 1
    row = store.jobs("eng")[0]
    assert (row["execution_status"], row["coverage_status"]) == ("failed", "inconclusive")
    assert row["result"]["error"]["code"] == "unknown_execution_outcome"
    assert store.claim(policy, "new-worker") is None
    assert not store.finish(job, AdapterResult("succeeded", "completed"))


def test_policy_domains_egress_and_actor_checks(state):
    store, policy, surface = state
    with pytest.raises(PolicyDenied):
        policy.check_url("http://localhost:12345/")
    with pytest.raises(PolicyDenied):
        replace(policy, egress_mode="enforced").check_url("http://127.0.0.1:12345/")
    with pytest.raises(PolicyDenied):
        policy.check_capability(domains=("network",), profiles=("isolated-lab",))
    with pytest.raises(PolicyDenied):
        policy.check_actor("root")
    with pytest.raises(PolicyDenied):
        store.submit(policy, [JobSpec(surface, "test", "http_observe", policy_revision="old")])


def test_evidence_quota_access_and_redaction(state):
    store, _policy, _surface = state
    ref = store.evidence_put("eng", {"Authorization": "private", "safe": "ok"})
    preview = store.evidence_get("eng", ref)
    assert "private" not in preview["excerpt"] and "redacted" in preview["excerpt"]
    with pytest.raises(PolicyDenied):
        store.evidence_get("other", ref)
    with pytest.raises(EvidenceWriteError):
        store.evidence_put("eng", "x" * (store.artifact_max_bytes + 1))
    store.evidence_quota_bytes = 1
    with pytest.raises(EvidenceWriteError):
        store.evidence_put("eng", {})
    assert store.evidence_get("eng", ref)["digest"] == preview["digest"]


class FakeWorker:
    """Fault injection only; never counted as a scanner integration."""

    def __init__(self, action="success"):
        self.action = action
        self.calls = 0
        self.cleaned = 0
        self.cancelled = 0

    async def run(self, _job, _surface, _spec):
        self.calls += 1
        if self.action == "hang":
            await asyncio.sleep(10)
        if self.action == "diskfull":
            raise EvidenceWriteError("disk_full")
        if self.action == "429":
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record("rate_limited", retryable=True, terminal=False, retry_after=1),
            )
        return AdapterResult(
            "succeeded",
            "completed",
            findings=({"title": "fake match", "finding_status": "confirmed_impact"},),
        )

    async def cleanup(self):
        self.cleaned += 1

    async def cancel(self):
        self.cancelled += 1


def make_scheduler(store, policy, worker):
    return Scheduler(
        store,
        policy,
        ResourceGovernor(),
        CapabilityRegistry(),
        {"http_observe": worker},
        lease_seconds=0.1,
    )


@pytest.mark.asyncio
async def test_fake_match_never_automatically_confirms_impact(state):
    store, policy, surface = state
    store.submit(policy, [JobSpec(surface, "test", "http_observe")])
    worker = FakeWorker()
    await make_scheduler(store, policy, worker).run_batch()
    assert worker.calls == worker.cleaned == 1
    assert store.findings("eng")[0]["status"] == "candidate"


@pytest.mark.asyncio
async def test_timeout_cleans_and_never_retries_unknown_delivery(state):
    store, policy, surface = state
    store.submit(policy, [JobSpec(surface, "test", "http_observe", timeout_seconds=0.02)])
    worker = FakeWorker("hang")
    scheduler = make_scheduler(store, policy, worker)
    await scheduler.run_batch()
    job = store.jobs("eng")[0]
    assert (job["execution_status"], job["coverage_status"]) == ("timed_out", "inconclusive")
    assert worker.calls == worker.cleaned == worker.cancelled == 1
    assert scheduler.governor.snapshot()["active"] == {}


@pytest.mark.asyncio
async def test_cancellation_releases_lease_and_stops_queued_jobs(state):
    store, policy, surface = state
    store.submit(
        policy,
        [JobSpec(surface, "test", "http_observe"), JobSpec(surface, "other", "http_observe")],
    )
    worker = FakeWorker("hang")
    scheduler = make_scheduler(store, policy, worker)
    task = asyncio.create_task(scheduler.run_batch())
    await asyncio.sleep(0.05)
    await scheduler.cancel()
    await task
    assert all(row["execution_status"] == "cancelled" for row in store.jobs("eng"))
    assert worker.cleaned == 1 and worker.cancelled >= 1
    assert scheduler.governor.snapshot()["active"] == {}
    assert store.claim(policy, "worker") is None


@pytest.mark.asyncio
async def test_disk_fault_stops_evidence_dependent_admission(state):
    store, policy, surface = state
    store.submit(
        policy,
        [JobSpec(surface, "test", "http_observe"), JobSpec(surface, "other", "http_observe")],
    )
    worker = FakeWorker("diskfull")
    await make_scheduler(store, policy, worker).run_batch()
    jobs = store.jobs("eng")
    assert worker.calls == 1
    assert sum(row["execution_status"] == "cancelled" for row in jobs) >= 1
    assert all(row["coverage_status"] != "completed" for row in jobs)


@pytest.mark.asyncio
async def test_presend_cooldown_queues_bounded_retry_and_persists_budget(state):
    store, policy, surface = state
    policy = replace(policy, retry_budget=1)
    store.submit(policy, [JobSpec(surface, "test", "http_observe")])
    worker = FakeWorker("429")
    scheduler = make_scheduler(store, policy, worker)
    await scheduler.run_batch()
    assert store.jobs("eng")[0]["execution_status"] == "retry_wait"
    store.db.execute("UPDATE rj_job SET ready_at=0")
    await make_scheduler(store, policy, worker).run_batch()
    row = store.jobs("eng")[0]
    assert row["attempt"] == 2 and row["execution_status"] == "failed"
    assert store.db.execute("SELECT retries_used FROM rj_engagement").fetchone()[0] == 1


@pytest.mark.asyncio
async def test_control_authorization_revision_schema_and_bounded_output(state):
    store, policy, surface = state
    control = AssessmentControl(store, policy, caller="owner")
    assert (await control.call("surface_search", {"policy_revision": "1"}))["ok"]
    assert not (await control.call("surface_get", {"policy_revision": "0", "surface_id": surface}))[
        "ok"
    ]
    assert not (await control.call("surface_search", {"policy_revision": "1", "limit": 100000}))[
        "ok"
    ]
    assert not (
        await control.call(
            "jobs_submit_batch", {"policy_revision": "1", "jobs": [{"run_any_command": "true"}]}
        )
    )["ok"]
    health = await control.call("system_health", {"policy_revision": "1"})
    assert health["ok"] and len(json.dumps(health).encode()) <= 65536
    other = AssessmentControl(store, policy, caller="intruder")
    assert not (await other.call("evidence_get", {"policy_revision": "1", "ref": "arbitrary"}))[
        "ok"
    ]
    control.close()
    other.close()


def _with_fake_browser(tmp_path, monkeypatch):
    browser = tmp_path / "fixture-chromium"
    browser.write_text("contract fixture")
    browser.chmod(0o700)
    monkeypatch.setattr(
        "redjohn.assessment.registry._playwright_chromium_executable", lambda: browser
    )


def test_decision_engine_explains_missing_capability_without_llm(state, tmp_path, monkeypatch):
    store, policy, _surface = state
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: None)
    _with_fake_browser(tmp_path, monkeypatch)
    plan = IntelligentDecisionEngine(CapabilityRegistry(repository_root=tmp_path)).plan(
        store, policy
    )
    assert plan["estimated_budget"]["model_calls"] == 0
    assert any(
        value["capability"] == "nuclei_scan" and value["reason"] == "blocked_missing_dependency"
        for value in plan["rejected"]
    )
    assert set(plan["coverage_delta"]) == {"discovery", "configuration"}


def test_inferred_surface_promotes_to_observed_with_evidence(state):
    store, _policy, _surface = state
    inferred = Surface("http://127.0.0.1:12345/later", source="inferred")
    first = store.upsert_surface("eng", inferred)
    assert (
        store.upsert_surface("eng", replace(inferred, source="observed", request_ref="evidence-1"))
        == first
    )
    assert store.surface("eng", first).source == "observed"
    assert store.surface("eng", first).request_ref == "evidence-1"
    store.upsert_surface("eng", inferred)
    assert store.surface("eng", first).source == "observed"


@pytest.mark.asyncio
async def test_serialized_evidence_query_secret_redaction_preserves_metric_counts(state):
    store, policy, _surface = state
    url = "http://127.0.0.1:12345/?x=1&x=2&encoded=%2f&token=fixture-private"
    ref = store.evidence_put("eng", {"url": url, "input_tokens": 0})
    control = AssessmentControl(store, policy, caller="owner")
    response = await control.call("evidence_get", {"ref": ref, "policy_revision": "1"})
    assert response["ok"]
    assert "fixture-private" not in json.dumps(response)
    assert "encoded=%2f" in response["result"]["excerpt"]
    assert '"input_tokens":0' in response["result"]["excerpt"]
    control.close()


@pytest.mark.asyncio
async def test_multiple_coordinators_cannot_bypass_shared_budget(state):
    store, policy, surface = state
    store.submit(policy, [JobSpec(surface, "test", "http_observe")])
    worker = FakeWorker("hang")
    first = make_scheduler(store, policy, worker)
    task = asyncio.create_task(first.run_batch())
    await asyncio.sleep(0.03)
    with pytest.raises(CapacityExceeded, match="coordinator_already_running"):
        await make_scheduler(store, policy, worker).run_batch()
    await first.cancel()
    await task
    assert worker.calls == 1


def test_policy_revision_migration_fences_queued_jobs(state):
    store, policy, surface = state
    store.submit(policy, [JobSpec(surface, "test", "http_observe")])
    new = replace(policy, revision="2", request_budget=50)
    store.register(new)
    assert store.jobs("eng")[0]["coverage_status"] == "blocked"
    assert store.policy("eng", "owner").revision == "2"
    with pytest.raises(PolicyDenied):
        store.register(policy)


def test_planner_advances_past_completed_jobs_and_relevant_families(state, tmp_path, monkeypatch):
    store, policy, _surface = state
    for number in range(3):
        store.upsert_surface("eng", Surface(f"http://127.0.0.1:12345/route-{number}"))
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: None)
    _with_fake_browser(tmp_path, monkeypatch)
    engine = IntelligentDecisionEngine(CapabilityRegistry(repository_root=tmp_path))
    used = set()
    families = set()
    for _ in range(8):
        plan = engine.plan(store, policy, limit=1)
        assert len(plan["jobs"]) == 1
        spec = JobSpec(**plan["jobs"][0]["spec"])
        assert spec.key not in used
        used.add(spec.key)
        families.add(spec.family)
        store.submit(policy, [spec])
        job = store.claim(policy, "fake-worker")
        assert store.finish(job, AdapterResult("succeeded", "completed"))
    assert families == {"discovery", "configuration"}
    assert not engine.plan(store, policy, limit=1)["jobs"]


def test_direct_submit_cannot_turn_inferred_link_into_active_target(state):
    store, policy, _surface = state
    link = store.upsert_surface("eng", Surface("http://127.0.0.1:12345/logout", source="inferred"))
    with pytest.raises(PolicyDenied, match="observed_or_operator_approved_input_required"):
        store.submit(policy, [JobSpec(link, "discovery", "browser_discover")])
    assert store.jobs("eng") == []


def test_default_campaign_deadline_is_durable_across_restart(state):
    store, policy, _surface = state
    first = store.policy("eng", "owner").deadline
    assert first > time.time()
    assert store.register(policy).deadline == first
    reopened = AssessmentStore(store.path)
    assert reopened.register(policy).deadline == first
    reopened.close()


@pytest.mark.asyncio
async def test_campaign_deadline_blocks_execution_but_preserves_read_access(state):
    store, _policy, surface = state
    deadline = time.time() + 0.03
    current = replace(store.policy("eng", "owner"), revision="2", deadline=deadline)
    store.register(current)
    store.submit(current, [JobSpec(surface, "test", "http_observe", policy_revision="2")])
    await asyncio.sleep(0.04)
    assert store.claim(current, "worker") is None
    assert store.jobs("eng")[0]["execution_status"] == "timed_out"
    assert store.jobs("eng")[0]["coverage_status"] == "blocked"
    control = AssessmentControl(store, current, caller="owner")
    assert (await control.call("coverage_get", {"policy_revision": "2"}))["ok"]
    control.close()
