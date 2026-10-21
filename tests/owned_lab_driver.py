"""Native public owned header-regression driver, always inside memory_exec."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from redjohn.assessment.lab_contract import CAPABILITY, VERSION
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.proof_bound_correlation import ProofBoundCorrelation
from redjohn.assessment.report import build_report
from redjohn.assessment.resources import ResourceEnvelope
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from tests.lab_validation_support import (
    OwnedHeaderFixture,
    candidate,
)


async def run(root: Path, memory_config, scenario):  # noqa: PLR0912, PLR0915 - one owned E2E lifecycle
    root.mkdir(mode=0o700)
    mode = (
        "slow_after_capture"
        if scenario in {"slow", "cancel"}
        else "oversized_after_capture"
        if scenario == "oversized"
        else "normal"
    )
    store = None
    runtime = None

    def compose(store, policy):
        return AssessmentRuntime(
            store,
            policy,
            caller="operator",
            envelope=ResourceEnvelope(total_memory_budget=1024**3, max_workers=1),
            host_pool_path=root / "host.sqlite3",
            lab_validation_config={"version": VERSION},
            os_memory_config=memory_config,
        )

    try:
        async with OwnedHeaderFixture(mode=mode) as before:
            policy = EngagementPolicy(
                "actual-owned-lab",
                "operator",
                (before.url.rsplit("/", 1)[0],),
                profile="isolated-lab",
                egress_mode="local-fixture",
                request_budget=16,
            )
            store = AssessmentStore(root / "agents.db")
            policy = store.register(policy)
            runtime = compose(store, policy)
            component = runtime.lab_validation
            assert component is not None
            coordinator = runtime.scheduler
            adapter = coordinator.adapters[CAPABILITY]
            governor = runtime.governor
            finding_id, surface_id = await candidate(store, policy, coordinator, before)
            asset = store.db.execute(
                "SELECT asset_id FROM rj_inventory_surface WHERE surface_id=?", (surface_id,)
            ).fetchone()[0]
            before.bind_asset(asset)
            initial_key = runtime.bind_owned_lab_fixture(before.binding)
            plan = runtime.create_owned_lab_plan(finding_id, surface_id, initial_key)
            before_job = runtime.submit_owned_lab(plan.key, "candidate", initial_key)
            # Real database/controller-object close and reopen before dispatch.
            await runtime.close()
            store.close()
            store = AssessmentStore(root / "agents.db")
            runtime = compose(store, policy)
            component = runtime.lab_validation
            assert component is not None
            runtime.bind_owned_lab_fixture(before.binding)
            assert runtime.submit_owned_lab(plan.key, "candidate", initial_key) == before_job
            coordinator = runtime.scheduler
            adapter = coordinator.adapters[CAPABILITY]
            governor = runtime.governor
            if scenario == "cancel":
                task = asyncio.create_task(coordinator.run_batch(max_jobs=1))
                async with asyncio.timeout(15):
                    while True:
                        row = store.db.execute(
                            "SELECT stage FROM rj_lab_phase WHERE job_id=?", (before_job,)
                        ).fetchone()
                        if row is not None and row[0] == "admitted":
                            break
                        await asyncio.sleep(0.01)
                await before.wait_requests(2)
                await coordinator.cancel()
                await task
            else:
                await coordinator.run_batch(max_jobs=1)
            row = next(x for x in store.jobs(policy.engagement_id) if x["id"] == before_job)
            if scenario == "positive":
                assert (
                    row["execution_status"] == "succeeded" and row["coverage_status"] == "completed"
                ), row
            else:
                assert row["execution_status"] in {"failed", "timed_out", "cancelled"}, row
                assert row["coverage_status"] in {"blocked", "inconclusive", "partial"}, row
                assert row["result"]["summary"].get("evidence_refs"), row
                if _has_assertions(store):
                    assert not store.db.execute("SELECT 1 FROM rj_lab_assertion").fetchone()
            await adapter.cleanup()
            # An admitted incomplete/cancelled phase remains deduplicated after reopen.
            await runtime.close()
            store.close()
            store = AssessmentStore(root / "agents.db")
            runtime = compose(store, policy)
            component = runtime.lab_validation
            assert component is not None
            if scenario == "cancel":
                try:
                    runtime.bind_owned_lab_fixture(before.binding)
                except PolicyDenied:
                    pass
                else:
                    raise AssertionError("cancelled campaign reopened validation authority")
            else:
                runtime.bind_owned_lab_fixture(before.binding)
                assert runtime.submit_owned_lab(plan.key, "candidate", initial_key) == before_job
            coordinator = runtime.scheduler
            adapter = coordinator.adapters[CAPABILITY]
            governor = runtime.governor
            assert await coordinator.run_batch(max_jobs=1) == []
            assert governor.snapshot()["active"] == {}
            port = before.port
        assert len(before.requests) == 2, before.requests
        if scenario != "positive":
            measurements = {
                "scenario": scenario,
                "job": row,
                "requests": store.request_usage(policy),
                "target_requests": len(before.requests),
                "duplicate_resume_requests": 0,
                "model_calls": 0,
                "public_runtime_integrated": True,
                "original_rce_status": "not_reproduced_missing_fixture",
            }
        else:
            async with OwnedHeaderFixture(fixed=True, port=port) as fixed:
                fixed.bind_asset(plan.asset_ref)
                fixed_key = runtime.bind_owned_lab_fixture(fixed.binding)
                fixed_job = runtime.submit_owned_lab(plan.key, "fixed_control", fixed_key)
                await coordinator.run_batch(max_jobs=1)
                final = next(x for x in store.jobs(policy.engagement_id) if x["id"] == fixed_job)
                assert (
                    final["execution_status"] == "succeeded"
                    and final["coverage_status"] == "completed"
                ), final
                proof = ProofBoundCorrelation(component)
                assertion = runtime.validate_owned_lab(plan.key, before_job, fixed_job)
                assert runtime.validate_owned_lab(plan.key, before_job, fixed_job) == assertion
                edge = proof.edge(assertion["assertion_ref"])
                proof.authorize_edge(edge)
                graph = runtime.lab_correlator
                assert graph is not None
                chain = graph.query(policy.engagement_id, plan.asset_ref)
                assert chain.chain_status == "validated_in_lab" and not chain.truncated
                report = build_report(
                    store, policy.engagement_id, registry=runtime.registry, lab_validation=component
                )
                assert report["owned_lab"]["assertions"] == [assertion]
                assert report["rce_regression"] == "not_reproduced_missing_fixture"
                assert store.request_usage(policy) == 3
                assert governor.snapshot()["active"] == {}
                measurements = {
                    "scenario": scenario,
                    "assertion": assertion,
                    "report": report,
                    "requests": 3,
                    "model_calls": 0,
                    "duplicate_resume_requests": 0,
                    "public_runtime_integrated": True,
                }
            assert len(fixed.requests) == 1
        assert not list((store.path.parent / "owned-lab-workers").glob("lab-*"))
        (root / "result.json").write_text(json.dumps(measurements, indent=2))
    finally:
        if runtime is not None:
            await runtime.close()
        if store is not None:
            store.close()


def _has_assertions(store):
    return (
        store.db.execute("SELECT 1 FROM sqlite_master WHERE name='rj_lab_assertion'").fetchone()
        is not None
    )


if __name__ == "__main__":
    asyncio.run(run(Path(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3]))
