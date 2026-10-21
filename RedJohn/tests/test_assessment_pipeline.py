"""Real browser -> persisted inventory -> scheduler -> HTTP evidence -> report.

Nuclei remains a separately asserted missing capability here; no fake Nuclei
result is used to label this Chromium/HTTP integration as a live scanner run.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict

import pytest

from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.fixture import FixtureServer
from redjohn.assessment.models import AdapterResult, JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.report import build_report, write_report
from redjohn.assessment.resources import ResourceEnvelope, process_tree_memory
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore


@pytest.mark.asyncio
async def test_real_browser_persistent_pipeline_restart_report_and_explicit_retest(  # noqa: PLR0915
    tmp_path,
):
    pytest.importorskip("playwright.async_api")
    started = time.monotonic()
    database = tmp_path / ".state" / "agents.db"
    with FixtureServer() as fixture:
        policy = EngagementPolicy(
            engagement_id="browser-pipeline",
            owner_id="operator",
            allowed_origins=(fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice", "bob"),
            request_budget=40,
        )
        store = AssessmentStore(database)
        actor_states = {actor: fixture.actor_state(actor) for actor in ("alice", "bob")}
        envelope = ResourceEnvelope(total_memory_budget=2 * 1024**3)
        specs = []
        async with AssessmentRuntime(
            store,
            policy,
            caller="operator",
            envelope=envelope,
            browser_limits=BrowserLimits(readiness_selector="body[data-actor]"),
            actor_states=actor_states,
        ) as runtime:
            seeds = {}
            for actor in ("anonymous", "alice", "bob"):
                seeds[actor] = store.upsert_surface(
                    policy.engagement_id,
                    Surface(
                        fixture.origin + "/",
                        actor_id=actor,
                        session_revision="1",
                    ),
                )
            specs.extend(
                JobSpec(
                    seeds[actor],
                    "discovery",
                    "browser_discover",
                    policy_revision=policy.revision,
                )
                for actor in ("alice", "bob")
            )
            header_spec = JobSpec(
                seeds["anonymous"],
                "configuration",
                "headers_audit",
                policy_revision=policy.revision,
            )
            nuclei_spec = JobSpec(
                seeds["anonymous"],
                "known_vulnerability",
                "nuclei_scan",
                policy_revision=policy.revision,
            )
            specs.extend((header_spec, nuclei_spec))
            submitted = await runtime.control.call(
                "jobs_submit_batch",
                {
                    "policy_revision": policy.revision,
                    "jobs": [asdict(spec) for spec in specs],
                },
            )
            assert submitted["ok"]
            job_ids = submitted["result"]["job_ids"]
            assert len(await runtime.scheduler.run_batch(max_jobs=8)) == 4
            rows = {row["id"]: row for row in store.jobs(policy.engagement_id)}
            browser_jobs = [row for row in rows.values() if row["capability"] == "browser_discover"]
            assert all(row["execution_status"] == "succeeded" for row in browser_jobs)
            assert all(row["coverage_status"] == "partial" for row in browser_jobs)
            assert all(
                row["result"]["summary"]["metrics"]["model_calls"] == 0 for row in browser_jobs
            )
            assert runtime.browser.healthcheck()["contexts_created"] == 2
            assert runtime.browser.healthcheck()["active_contexts"] == 0
            surfaces = store.surfaces(policy.engagement_id, limit=100)
            for actor in ("alice", "bob"):
                actor_surfaces = [surface for surface in surfaces if surface["actor_id"] == actor]
                assert any(
                    surface["url"].endswith("/api/search?q=one&q=two&encoded=%2f")
                    and surface["source"] == "observed"
                    for surface in actor_surfaces
                )
                assert any(
                    surface["url"].endswith("/spa/dashboard") and surface["source"] == "observed"
                    for surface in actor_surfaces
                )
                assert any(
                    surface["url"].endswith("/api/dynamic") and surface["source"] == "inferred"
                    for surface in actor_surfaces
                )
                for path, content_type in (
                    ("/api/json", "application/json"),
                    ("/api/xml", "application/xml"),
                ):
                    matching = [
                        surface for surface in actor_surfaces if surface["url"].endswith(path)
                    ]
                    assert len(matching) == 1
                    assert matching[0]["method"] == "POST"
                    assert matching[0]["content_type"] == content_type
                    assert matching[0]["source"] == "inferred"
                    evidence = store.evidence_get(policy.engagement_id, matching[0]["request_ref"])
                    assert json.loads(evidence["excerpt"])["sent"] is False
                assert any(
                    surface["input_name"] == "file"
                    and surface["content_type"] == "multipart/form-data"
                    for surface in actor_surfaces
                )
            assert fixture.counts["unexpected_post"] == 0
            assert fixture.counts["/logout"] == 0
            assert fixture.counts["/api/json"] == fixture.counts["/api/xml"] == 0
            findings = store.findings(policy.engagement_id)
            assert len(findings) == 2
            assert all(finding["status"] == "candidate" for finding in findings)
            assert all(
                finding["payload"]["proof_level"] == "header_observation" for finding in findings
            )
            for finding in findings:
                evidence = store.evidence_get(
                    policy.engagement_id,
                    finding["payload"]["evidence_refs"][0],
                )
                assert json.loads(evidence["excerpt"])["status"] == 200
            scanner = next(row for row in rows.values() if row["capability"] == "nuclei_scan")
            assert scanner["execution_status"] == "failed"
            assert scanner["coverage_status"] == "blocked"
            expected_error = (
                "tool_missing"
                if shutil.which("nuclei") is None
                else "nuclei_lock_or_sandbox_missing"
            )
            assert scanner["result"]["error"]["code"] == expected_error
            assert not scanner["result"]["findings"]
            report = build_report(
                store,
                policy.engagement_id,
                metrics={
                    "untrusted_target_label": "<script>alert(1)</script>",
                    "model_calls": runtime.scheduler.metrics["model_calls"],
                },
            )
            json_path, html_path = write_report(tmp_path / "reports", report)
            assert json.loads(json_path.read_text())["product"] == "RedJohn"
            assert "<script>alert(1)</script>" not in html_path.read_text()
            assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_path.read_text()
            assert report["rce_regression"] == "not_reproduced_missing_fixture"
            assert len(report["jobs_page"]) == 4
            counts_before_restart = dict(fixture.counts)
            persisted_requests = store.db.execute(
                "SELECT requests_used FROM rj_engagement WHERE id=?",
                (policy.engagement_id,),
            ).fetchone()[0]
        store.close()

        # A new store and runtime read persisted surfaces/jobs/evidence. Merely
        # resubmitting identical keys does not produce another network request.
        restarted_store = AssessmentStore(database)
        async with AssessmentRuntime(
            restarted_store,
            policy,
            caller="operator",
            envelope=envelope,
            actor_states=actor_states,
        ) as restarted:
            assert restarted_store.submit(policy, specs) == job_ids
            assert await restarted.scheduler.run_batch(max_jobs=8) == []
            assert dict(fixture.counts) == counts_before_restart
            assert len(restarted_store.surfaces(policy.engagement_id, limit=100)) == len(surfaces)
            assert len(restarted_store.findings(policy.engagement_id)) == 2
            fixture.fixed = True
            retest = JobSpec(
                header_spec.surface_id,
                header_spec.family,
                header_spec.capability,
                policy_revision=policy.revision,
                retest_revision="headers-fixed-1",
            )
            retest_id = restarted_store.submit(policy, [retest])[0]
            assert retest_id not in job_ids
            assert await restarted.scheduler.run_batch(max_jobs=2) == [retest_id]
            row = next(
                row for row in restarted_store.jobs(policy.engagement_id) if row["id"] == retest_id
            )
            assert row["execution_status"] == "succeeded"
            assert row["coverage_status"] == "completed"
            assert not row["result"]["findings"]
            evidence = restarted_store.evidence_get(
                policy.engagement_id,
                row["result"]["summary"]["evidence_refs"][0],
            )
            fixed_headers = json.loads(evidence["excerpt"])["headers"]
            assert fixed_headers["x-content-type-options"] == "nosniff"
            assert fixed_headers["content-security-policy"] == "default-src 'self'"
            final_requests = restarted_store.db.execute(
                "SELECT requests_used FROM rj_engagement WHERE id=?",
                (policy.engagement_id,),
            ).fetchone()[0]
            assert final_requests == persisted_requests + 1
            # Historical candidates are retained; automatic fixed reconciliation
            # is a separate, explicitly unimplemented finding lifecycle capability.
            assert len(restarted_store.findings(policy.engagement_id)) == 2
            assert restarted.governor.snapshot()["active"] == {}
            measurements = {
                "test": "real_chromium_http_persistent_pipeline",
                "duration_seconds": round(time.monotonic() - started, 6),
                "initial_jobs": len(job_ids),
                "retest_jobs": 1,
                "surfaces": len(surfaces),
                "header_candidates": len(findings),
                "nuclei_status": "blocked_missing_dependency_or_lock",
                "http_requests": sum(fixture.counts.values()),
                "model_calls": 0,
                "request_charges": final_requests,
                "restart_duplicate_requests": 0,
                "fixed_retest_candidates": len(row["result"]["findings"]),
            }
            print("PIPELINE_MEASUREMENTS=" + json.dumps(measurements, sort_keys=True))  # noqa: T201
        restarted_store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["missing", "raw_higher_revision", "mismatched_revision"])
async def test_named_browser_actor_requires_matching_state_before_network(tmp_path, case):
    pytest.importorskip("playwright.async_api")
    with FixtureServer() as fixture:
        policy = EngagementPolicy(
            "actor-state-guard",
            "operator",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("alice",),
        )
        actor_states = {}
        revision = "1"
        expected = "authentication_state_missing"
        if case == "raw_higher_revision":
            actor_states = {"alice": fixture.actor_state("alice")}
            revision = "2"
            expected = "authentication_state_revision_required"
        elif case == "mismatched_revision":
            actor_states = {
                "alice": {
                    "actor_id": "alice",
                    "session_revision": "1",
                    "tenant_id": "",
                    "storage_state": fixture.actor_state("alice"),
                }
            }
            revision = "2"
            expected = "authentication_state_revision_mismatch"
        store = AssessmentStore(tmp_path / ".state" / "agents.db")
        async with AssessmentRuntime(
            store,
            policy,
            caller="operator",
            actor_states=actor_states,
        ) as runtime:
            sid = store.upsert_surface(
                policy.engagement_id,
                Surface(
                    fixture.origin + "/",
                    actor_id="alice",
                    session_revision=revision,
                ),
            )
            store.submit(policy, [JobSpec(sid, "discovery", "browser_discover")])
            assert len(await runtime.scheduler.run_batch(max_jobs=1)) == 1
            row = store.jobs(policy.engagement_id)[0]
            assert row["execution_status"] == "failed"
            assert row["coverage_status"] == "blocked"
            assert row["result"]["error"]["code"] == expected
            assert not fixture.counts
            assert runtime.browser.healthcheck()["contexts_created"] == 0
            assert not runtime.browser.healthcheck()["ready"]
            assert runtime.governor.snapshot()["active"] == {}
        store.close()


@pytest.mark.asyncio
async def test_real_browser_expired_actor_is_blocked_without_anonymous_fallback(tmp_path):
    pytest.importorskip("playwright.async_api")
    with FixtureServer() as fixture:
        policy = EngagementPolicy(
            "expired-actor",
            "operator",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("alice",),
        )
        store = AssessmentStore(tmp_path / ".state" / "agents.db")
        states = {
            "alice": {
                "actor_id": "alice",
                "session_revision": "2",
                "tenant_id": "tenant-a",
                "storage_state": fixture.actor_state("alice"),
            }
        }
        async with AssessmentRuntime(
            store,
            policy,
            caller="operator",
            actor_states=states,
            envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
        ) as runtime:
            sid = store.upsert_surface(
                policy.engagement_id,
                Surface(
                    fixture.origin + "/expired",
                    actor_id="alice",
                    tenant_id="tenant-a",
                    session_revision="2",
                ),
            )
            store.submit(policy, [JobSpec(sid, "discovery", "browser_discover")])
            assert len(await runtime.scheduler.run_batch(max_jobs=2)) == 1
            row = store.jobs(policy.engagement_id)[0]
            assert row["execution_status"] == "failed"
            assert row["coverage_status"] == "blocked"
            assert row["result"]["error"]["code"] == "authentication_expired"
            assert fixture.counts == {"/expired": 1}
            assert row["attempt"] == 1
            evidence = store.evidence_get(
                policy.engagement_id,
                row["result"]["summary"]["evidence_refs"][0],
            )
            observation = json.loads(evidence["excerpt"])
            assert observation["actor_id"] == "alice"
            assert observation["session_revision"] == "2"
            assert observation["tenant_id"] == "tenant-a"
            assert observation["status"] == 401
            assert runtime.browser.healthcheck()["active_contexts"] == 0
        store.close()


@pytest.mark.asyncio
async def test_scheduler_cleanup_cancellation_stops_the_next_job_without_execution(tmp_path):
    """Fake adapter contract regression; this test does not execute a scanner."""
    policy = EngagementPolicy(
        "cancel-during-cleanup",
        "operator",
        ("http://127.0.0.1:12345",),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )
    store = AssessmentStore(tmp_path / ".state" / "agents.db")

    class CleanupWaitAdapter:
        def __init__(self):
            self.calls = 0
            self.cleaning = asyncio.Event()

        async def run(self, *_args):
            self.calls += 1
            return AdapterResult("succeeded", "completed")

        async def cancel(self):
            return None

        async def cleanup(self):
            self.cleaning.set()
            await asyncio.sleep(0.05)

    adapter = CleanupWaitAdapter()
    async with AssessmentRuntime(
        store,
        policy,
        caller="operator",
        envelope=ResourceEnvelope(total_memory_budget=2 * 1024**3),
    ) as runtime:
        runtime.scheduler.adapters["http_observe"] = adapter
        for index in range(2):
            sid = store.upsert_surface(
                policy.engagement_id,
                Surface(
                    f"http://127.0.0.1:12345/{index}",
                ),
            )
            store.submit(policy, [JobSpec(sid, "observation", "http_observe")])
        batch = asyncio.create_task(runtime.scheduler.run_batch(max_jobs=2))
        await asyncio.wait_for(adapter.cleaning.wait(), timeout=2)
        batch.cancel()
        await asyncio.wait_for(batch, timeout=2)
        assert adapter.calls == 1
        rows = store.jobs(policy.engagement_id)
        assert [row["execution_status"] for row in rows] == ["cancelled", "cancelled"]
        assert all(row["coverage_status"] == "partial" for row in rows)
        assert sorted(row["attempt"] for row in rows) == [0, 1]
        assert runtime.governor.snapshot()["active"] == {}
        stopped, requests = store.db.execute(
            "SELECT stopped,requests_used FROM rj_engagement WHERE id=?",
            (policy.engagement_id,),
        ).fetchone()
        assert stopped == 1 and requests == 0
    store.close()


@pytest.mark.asyncio
async def test_real_chromium_sequential_runtimes_release_browser_before_unlock(tmp_path):
    """Two actual Chromium batches cannot leave two idle browser processes alive."""
    pytest.importorskip("playwright.async_api")
    with FixtureServer() as fixture:
        policy = EngagementPolicy(
            "shared-browser-lifetime",
            "operator",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice"),
        )
        path = tmp_path / ".state" / "agents.db"
        first_store, second_store = AssessmentStore(path), AssessmentStore(path)
        envelope = ResourceEnvelope(total_memory_budget=2 * 1024**3, browser_concurrency=1)
        before = process_tree_memory()
        async with AssessmentRuntime(
            first_store,
            policy,
            caller="operator",
            envelope=envelope,
            actor_states={"alice": fixture.actor_state("alice")},
        ) as first:
            for actor in ("anonymous", "alice"):
                sid = first_store.upsert_surface(
                    policy.engagement_id,
                    Surface(
                        fixture.origin + "/",
                        actor_id=actor,
                    ),
                )
                first_store.submit(policy, [JobSpec(sid, "discovery", "browser_discover")])
            assert len(await first.scheduler.run_batch(max_jobs=2)) == 2
            first_health = first.browser.healthcheck()
            assert first_health["contexts_created"] == first_health["contexts_closed"] == 2
            assert not first_health["ready"]
            assert first_health["active_contexts"] == first_health["active_pages"] == 0
            assert first.governor.snapshot()["active"] == {}
            assert process_tree_memory().process_count <= before.process_count
            async with AssessmentRuntime(
                second_store,
                policy,
                caller="operator",
                envelope=envelope,
            ) as second:
                sid = second_store.upsert_surface(
                    policy.engagement_id,
                    Surface(
                        fixture.origin + "/api/dynamic",
                    ),
                )
                second_store.submit(policy, [JobSpec(sid, "discovery", "browser_discover")])
                assert len(await second.scheduler.run_batch(max_jobs=1)) == 1
                assert all(
                    row["execution_status"] == "succeeded"
                    for row in second_store.jobs(policy.engagement_id)
                )
                second_health = second.browser.healthcheck()
                assert second_health["contexts_created"] == second_health["contexts_closed"] == 1
                assert not first.browser.healthcheck()["ready"]
                assert not second_health["ready"]
                assert first.governor.snapshot()["active"] == {}
                assert second.governor.snapshot()["active"] == {}
                assert process_tree_memory().process_count <= before.process_count
        assert process_tree_memory().process_count <= before.process_count
        first_store.close()
        second_store.close()


def test_real_missing_chromium_is_blocked_and_cleaned_in_isolated_process(tmp_path):
    """Use a genuinely absent browser directory; do not change the installed cache."""
    pytest.importorskip("playwright.async_api")
    program = """
import asyncio, json, sys
from pathlib import Path
from redjohn.assessment.browser import BrowserUnavailableError
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.resources import process_tree_memory
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
async def main():
    policy = EngagementPolicy(
        'missing-browser-fixture', 'operator', ('http://127.0.0.1:12345',),
        profile='isolated-lab', egress_mode='local-fixture',
    )
    store = AssessmentStore(Path(sys.argv[1]))
    before = process_tree_memory().process_count
    async with AssessmentRuntime(store, policy, caller='operator') as runtime:
        sid = store.upsert_surface(policy.engagement_id, Surface('http://127.0.0.1:12345/'))
        store.submit(policy, [JobSpec(sid, 'discovery', 'browser_discover')])
        await runtime.scheduler.run_batch(max_jobs=1)
        row = store.jobs(policy.engagement_id)[0]
        launch_code = 'unexpected_launch_success'
        try:
            await runtime.browser.start()
        except BrowserUnavailableError as error:
            launch_code = str(error)
        print(json.dumps({
            'execution_status': row['execution_status'], 'coverage_status': row['coverage_status'],
            'error': row['result']['error'], 'resources': runtime.governor.snapshot()['active'],
            'browser': runtime.browser.healthcheck(), 'before_process_count': before,
            'after_process_count': process_tree_memory().process_count,
            'requests': store.db.execute('SELECT requests_used FROM rj_engagement').fetchone()[0],
            'launch_code': launch_code,
        }))
    store.close()
asyncio.run(main())
"""
    missing_cache = tmp_path / "intentionally-missing-chromium"
    assert not missing_cache.exists()
    completed = subprocess.run(  # noqa: S603 - fixed local Python and controlled fixture program
        [sys.executable, "-c", program, str(tmp_path / ".state" / "agents.db")],
        env={**os.environ, "PLAYWRIGHT_BROWSERS_PATH": str(missing_cache)},
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    result = json.loads(completed.stdout.splitlines()[-1])
    assert result["execution_status"] == "failed"
    assert result["coverage_status"] == "blocked"
    assert result["error"]["code"] == "blocked_missing_dependency"
    assert result["launch_code"] == "chromium_executable_missing"
    assert result["resources"] == {}
    assert result["browser"]["active_contexts"] == result["browser"]["active_pages"] == 0
    assert result["browser"]["active_proxy_connections"] == 0
    assert not result["browser"]["ready"]
    assert result["after_process_count"] <= result["before_process_count"]
    assert result["requests"] == 0
    assert "Executable doesn't exist" not in completed.stdout
    assert str(missing_cache) not in completed.stdout
