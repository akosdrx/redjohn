"""One live scheduler rotates a session, recaptures POSTs and replays Nuclei.

The oracle is an owned HTTPS server on an actual Linux interface. Chromium and
the pinned Nuclei binary run behind attested kernel egress boundaries. No mock
adapter, SDK capture, controller restart or post-refresh child submission is
used to advance the automatic chain.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import time
from base64 import b64decode, b64encode
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from redjohn.assessment.browser import BrowserLimits
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import JobSpec
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.request_body import HOST_REPLAY_MULTIPART_CONTENT_TYPE
from redjohn.assessment.resources import ResourceEnvelope, process_tree_memory
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from redjohn.tools.hunt.nuclei import bundle_digest
from tests.test_browser_token_pipeline import BrowserTokenHTTPSFixture, _token_binding
from tests.test_nuclei_post_live import post_fixture_lock
from tests.test_post_refresh_pipeline import _dependencies, _lock_document, _private_json
from tests.test_remote_authenticated_pipeline import _assert_attested


if TYPE_CHECKING:
    from redjohn.assessment.models import Surface
    from redjohn.tools.hunt.nuclei import NucleiLock


_MEDIA = {
    "json": "application/json",
    "form": "application/x-www-form-urlencoded",
    "multipart": "multipart/form-data",
}


def _reviewed_chain_lock(directory: Path, binary: NucleiLock) -> NucleiLock:
    """Merge three owned public templates, each with one explicit selector."""
    directory.mkdir(mode=0o700)
    files, templates = {}, []
    for kind, content_type in _MEDIA.items():
        item = post_fixture_lock(
            directory / (kind + "-source"),
            HOST_REPLAY_MULTIPART_CONTENT_TYPE if kind == "multipart" else content_type,
            "/replay/" + kind,
            binary_lock=binary,
        )
        document = yaml.safe_load((Path(item.bundle_root) / "post.yaml").read_bytes())
        template_id = "redjohn-fixture-post-" + kind
        document["id"] = template_id
        raw = yaml.safe_dump(document, sort_keys=False).encode()
        name = kind + ".yaml"
        (directory / name).write_bytes(raw)
        files[name] = hashlib.sha256(raw).hexdigest()
        templates.append(replace(item.templates[0], path=name, template_id=template_id))
    lock = replace(
        binary,
        bundle_root=str(directory),
        bundle_version="redjohn-owned-continuous-post-fixture-v1",
        bundle_sha256=bundle_digest(files),
        bundle_source="RedJohn owned harmless continuous POST fixture",
        bundle_license="Apache-2.0",
        files=files,
        templates=tuple(templates),
    )
    lock.validate()
    return lock


async def test_actual_single_runtime_refresh_recapture_and_reviewed_nuclei_chain(  # noqa: PLR0915 - actual continuous lifecycle and negative controls
    tmp_path: Path,
) -> None:
    host, binary = _dependencies()
    database = tmp_path / ".state" / "agents.db"
    private = tmp_path / "host-secrets"
    private.mkdir(mode=0o700)
    vault, provider, capture = (
        private / name for name in ("vault.json", "provider.json", "capture.json")
    )
    lock = _reviewed_chain_lock(tmp_path / "reviewed-templates", binary)
    pid, started = os.getpid(), time.monotonic()
    metrics = {
        "platform": platform.platform(),
        "controller_pid": pid,
        "binary_version": binary.binary_version,
        "binary_sha256": binary.binary_sha256,
        "bundle_sha256": lock.bundle_sha256,
        "model_calls": 0,
        "stages": [],
    }
    memory = {
        "target_interval_seconds": 0.025,
        "sample_count": 0,
        "available_sample_count": 0,
        "peak_rss_bytes": 0,
        "peak_process_count": 0,
        "max_observed_interval_seconds": 0.0,
    }
    resources = {
        "peak_active_workers": 0,
        "active_browser_samples": 0,
        "active_scanner_samples": 0,
        "overlapping_browser_scanner_samples": 0,
    }
    observed_runtime: AssessmentRuntime | None = None

    async def sample_memory() -> None:
        previous, deadline = None, time.monotonic()
        while True:
            now = time.monotonic()
            if previous is not None:
                memory["max_observed_interval_seconds"] = max(
                    memory["max_observed_interval_seconds"], now - previous
                )
            previous = now
            sample = await asyncio.to_thread(process_tree_memory, pid)
            memory["sample_count"] += 1
            if sample.available:
                memory["available_sample_count"] += 1
                memory["peak_rss_bytes"] = max(memory["peak_rss_bytes"], sample.rss_bytes)
                memory["peak_process_count"] = max(
                    memory["peak_process_count"], sample.process_count
                )
            if observed_runtime is not None:
                active = observed_runtime.governor.snapshot()["active"]
                resources["peak_active_workers"] = max(
                    resources["peak_active_workers"],
                    sum(active.get(kind, 0) for kind in ("browser", "scanner", "worker")),
                )
                resources["active_browser_samples"] += bool(active.get("browser"))
                resources["active_scanner_samples"] += bool(active.get("scanner"))
                resources["overlapping_browser_scanner_samples"] += bool(
                    active.get("browser") and active.get("scanner")
                )
            deadline += 0.025
            await asyncio.sleep(max(0.0, deadline - time.monotonic()))

    with BrowserTokenHTTPSFixture(host, tmp_path / "upstream-tls") as fixture:
        policy = EngagementPolicy(
            "continuous-refresh-e2e",
            "operator",
            (fixture.origin,),
            allowed_ips=(host + "/32",),
            profile="isolated-lab",
            egress_mode="enforced",
            actor_ids=("anonymous", "alice"),
            allowed_replay_urls=tuple(fixture.origin + "/replay/" + kind for kind in _MEDIA),
            allowed_refresh_urls=(fixture.origin + "/refresh",),
            request_budget=64,
            deadline=time.time() + 300,
        )
        identity = {
            "engagement_id": policy.engagement_id,
            "owner_id": policy.owner_id,
            "actor_id": "alice",
            "tenant_id": "tenant-a",
            "policy_revision": policy.revision,
        }
        _private_json(
            vault,
            {
                "version": 2,
                "entries": [
                    {
                        **identity,
                        "session_revision": "7",
                        "origin": fixture.origin,
                        "expires_at": time.time() + 600,
                        "headers": fixture.auth_headers("7"),
                        "cookies": [{"name": "fixture_session", "value": fixture.sessions["7"]}],
                        "allowed_requests": [
                            {
                                "url": fixture.origin + "/start",
                                "method": "GET",
                                "request_ref": "approved-start-anchor",
                            }
                        ],
                    }
                ],
            },
        )
        _private_json(
            provider,
            {
                "version": 1,
                "providers": [
                    {
                        **identity,
                        "refresh_url": fixture.origin + "/refresh",
                        "headers": {"Authorization": "Bearer " + fixture.refresh_secret},
                        "body_base64": b64encode(fixture.refresh_body).decode(),
                        "content_type": "application/json",
                    }
                ],
            },
        )
        _private_json(
            capture,
            {
                "version": 1,
                "rules": [
                    {
                        **identity,
                        "session_revision": "current",
                        "url": fixture.origin + "/replay/" + kind,
                        "content_type": content_type,
                        "expires_at": time.time() + 600,
                        "automatic_approval": True,
                        "start_url": fixture.origin + "/start",
                        "body_tokens": _token_binding(kind),
                    }
                    for kind, content_type in _MEDIA.items()
                ],
            },
        )
        session = NativeFixtureSession(policy, tmp_path / "nuclei-worker", lock)
        configuration = {
            "caller": "operator",
            "session": session,
            "envelope": ResourceEnvelope(total_memory_budget=3 * 1024**3, max_workers=1),
            "browser_limits": BrowserLimits(
                max_pages=1,
                max_requests=12,
                readiness_selector="body[data-ready='yes']",
                readiness_timeout_ms=8000,
                observation_window_ms=200,
                total_timeout_seconds=35,
            ),
            "browser_tls": BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            "nuclei_lock": _lock_document(lock),
            "auth_vault_file": vault,
            "refresh_provider_file": provider,
            "browser_capture_file": capture,
            "continuous_replay": {
                "version": 1,
                "rules": [
                    {
                        "actor_id": "alice",
                        "tenant_id": "tenant-a",
                        "url": fixture.origin + "/replay/" + kind,
                        "content_type": content_type,
                        "template_id": "redjohn-fixture-post-" + kind,
                    }
                    for kind, content_type in _MEDIA.items()
                ],
            },
        }
        store = AssessmentStore(database)

        def rows() -> list[dict]:
            return store.jobs(policy.engagement_id, limit=100)

        def assert_capture_result(row: dict) -> None:
            assert row["execution_status"] == "succeeded", row
            assert row["coverage_status"] in {"completed", "partial"}, row
            assert row["result"]["error"] is None, row
            # Chromium may attempt a background connection outside the owned
            # origin. Its denial remains a visible partial-coverage gap; only
            # separately verified completed POST observations can be replayed.
            assert all(
                failure["code"] == "browser_scope_denied"
                for failure in row["result"]["summary"]["failures"]
            ), row

        def captured(revision: str) -> dict[str, Surface]:
            result = {}
            for record in store.surfaces(policy.engagement_id, limit=100):
                if (
                    record["method"] != "POST"
                    or record["session_revision"] != revision
                    or record["source"] != "observed"
                ):
                    continue
                surface = store.surface(policy.engagement_id, record["id"])
                evidence = json.loads(
                    store.evidence_get(policy.engagement_id, surface.request_ref)["excerpt"]
                )
                assert evidence["sent"] and evidence["response_complete"]
                assert evidence["status"] == 200
                assert all(
                    evidence[key] == getattr(surface, key)
                    for key in (
                        "url",
                        "method",
                        "actor_id",
                        "tenant_id",
                        "session_revision",
                        "body_sha256",
                    )
                ), (surface, evidence)
                assert evidence["engagement_id"] == policy.engagement_id
                assert evidence["policy_revision"] == policy.revision
                assert evidence["request_content_type"] == surface.content_type
                kind = surface.url.rsplit("/", 1)[-1]
                assert kind not in result, (revision, kind)
                result[kind] = surface
            assert set(result) == set(_MEDIA), result
            return result

        async def run_batch(runtime: AssessmentRuntime, label: str, maximum: int) -> list[dict]:
            before, tick = len(fixture.observed), time.monotonic()
            completed = await runtime.scheduler.run_batch(max_jobs=maximum)
            completed_set = set(completed)
            actual = [row for row in rows() if row["id"] in completed_set]
            assert len(actual) == len(completed), (label, completed, actual)
            metrics["stages"].append(
                {
                    "case": label,
                    "controller_pid": os.getpid(),
                    "duration_seconds": time.monotonic() - tick,
                    "completed_jobs": [
                        {
                            "id": row["id"],
                            "capability": row["capability"],
                            "execution_status": row["execution_status"],
                            "coverage_status": row["coverage_status"],
                            "findings": len(row["result"].get("findings", [])),
                            "result": row["result"],
                        }
                        for row in actual
                    ],
                    "target_requests": fixture.observed[before:],
                    "governor_snapshot": runtime.governor.snapshot(),
                }
            )
            assert os.getpid() == pid
            return actual

        sampler = asyncio.create_task(sample_memory())
        try:
            async with AssessmentRuntime(store, policy, **configuration) as runtime:
                observed_runtime = runtime
                browser_identity = id(runtime.browser)
                first = await run_batch(runtime, "initial_capture_bounded_one_job", 1)
                assert len(first) == 1 and first[0]["capability"] == "browser_post_capture", first
                assert_capture_result(first[0])
                capture_summary = first[0]["result"]["summary"]
                assert capture_summary["metrics"]["captured_post_requests"] == 3
                _assert_attested(capture_summary["tool"]["egress_attestations"])
                metrics["chromium_version"] = capture_summary["tool"]["chromium_version"]
                metrics["playwright_version"] = capture_summary["tool"]["playwright_version"]
                first_surfaces = captured("7")
                queued = [row for row in rows() if row["execution_status"] == "queued"]
                assert len(queued) == 3 and all(
                    row["capability"] == "nuclei_scan" for row in queued
                ), queued
                # The job limit stops execution, while already-created children
                # remain durable rather than disappearing into callback state.
                independent = AssessmentStore(database)
                try:
                    assert {
                        row["id"]
                        for row in independent.jobs(policy.engagement_id, limit=100)
                        if row["execution_status"] == "queued"
                    } == {row["id"] for row in queued}
                finally:
                    independent.close()
                initial_replays = await run_batch(runtime, "initial_reviewed_replays", 3)
                assert len(initial_replays) == 3, initial_replays
                for row in initial_replays:
                    assert row["capability"] == "nuclei_scan"
                    assert row["coverage_status"] == "completed"
                    assert len(row["result"]["findings"]) == 1, row
                    _assert_attested(row["result"]["summary"]["network"]["egress_attestations"])
                refresh_surface = store.upsert_surface(policy.engagement_id, first_surfaces["json"])
                refresh_id = store.submit(
                    policy,
                    [
                        JobSpec(
                            refresh_surface,
                            "authentication",
                            "session_refresh",
                            policy_revision=policy.revision,
                            idempotent=False,
                            timeout_seconds=45,
                        )
                    ],
                )[0]
                before_refresh_ids = {row["id"] for row in rows()}
                # This is the only call that advances the entire refreshed
                # generation. It does not submit or execute children itself.
                refreshed = await run_batch(runtime, "continuous_refresh_capture_replay", 5)
                assert len(refreshed) == 5, refreshed
                assert {row["capability"] for row in refreshed} == {
                    "session_refresh",
                    "browser_post_capture",
                    "nuclei_scan",
                }
                assert sum(row["capability"] == "nuclei_scan" for row in refreshed) == 3
                assert (
                    next(row for row in refreshed if row["id"] == refresh_id)["coverage_status"]
                    == "completed"
                ), refreshed
                assert all(row["execution_status"] == "succeeded" for row in refreshed), refreshed
                assert len({row["id"] for row in rows()} - before_refresh_ids) == 4
                assert id(runtime.browser) == browser_identity and os.getpid() == pid
                assert fixture.revision == "8" and fixture.counts["/refresh"] == 1
                second_surfaces = captured("8")
                for kind in _MEDIA:
                    assert second_surfaces[kind].body_sha256 != first_surfaces[kind].body_sha256
                    assert second_surfaces[kind].request_ref != first_surfaces[kind].request_ref
                assert (
                    second_surfaces["multipart"].content_type
                    != first_surfaces["multipart"].content_type
                )
                replay_rows = [row for row in refreshed if row["capability"] == "nuclei_scan"]
                for row in replay_rows:
                    assert row["coverage_status"] == "completed"
                    assert len(row["result"]["findings"]) == 1, row
                    _assert_attested(row["result"]["summary"]["network"]["egress_attestations"])
                refreshed_capture = next(
                    row for row in refreshed if row["capability"] == "browser_post_capture"
                )
                assert_capture_result(refreshed_capture)
                assert (
                    refreshed_capture["result"]["summary"]["metrics"]["captured_post_requests"] == 3
                )
                _assert_attested(
                    refreshed_capture["result"]["summary"]["tool"]["egress_attestations"]
                )
                mapping = json.loads(vault.read_text())
                requests = [
                    request
                    for entry in mapping["entries"]
                    for request in entry["allowed_requests"]
                    if request["method"] == "POST"
                ]
                assert len(requests) == 3
                assert all(entry["session_revision"] == "8" for entry in mapping["entries"])
                for request in requests:
                    kind = request["url"].rsplit("/", 1)[-1]
                    assert request["request_ref"] == second_surfaces[kind].request_ref
                    assert request["replay_safety"] == "operator-approved"
                    assert request["body_tokens"] == _token_binding(kind)
                    assert fixture.body_matches(
                        "/replay/" + kind,
                        request["content_type"],
                        b64decode(request["body_base64"]),
                    )
                fixture.mode = "fixed"
                fixed_ids = []
                for row in replay_rows:
                    spec = JobSpec(**row["spec"])
                    fixed_ids.extend(
                        store.submit(policy, [replace(spec, retest_revision="fixed-control")])
                    )
                fixed = await run_batch(runtime, "fixed_controls_all_three_formats", 3)
                assert {row["id"] for row in fixed} == set(fixed_ids)
                for row in fixed:
                    assert row["coverage_status"] == "completed" and not row["result"]["findings"]
                    assert row["result"]["summary"]["no_finding_observed"] is True
                before = len(fixture.observed)
                assert await run_batch(runtime, "same_runtime_duplicate_reconciliation", 16) == []
                assert len(fixture.observed) == before
                assert runtime.scheduler.metrics["jobs"] == 12
                assert runtime.scheduler.metrics["model_calls"] == 0
            # A later controller observes completed stable jobs. Restarting is
            # deliberately tested only after the no-restart chain has finished.
            async with AssessmentRuntime(store, policy, **configuration) as reopened:
                observed_runtime = reopened
                assert await run_batch(reopened, "completed_chain_restart_deduplication", 16) == []
            assert len(fixture.observed) == before
            used = store.db.execute(
                "SELECT requests_used FROM rj_engagement WHERE id=?", (policy.engagement_id,)
            ).fetchone()[0]
            state = store.session_state(policy, second_surfaces["json"])
            assert state["revision"] == "8" and state["status"] == "ready"
            assert used == len(fixture.observed) == 18, (used, fixture.observed)
            assert fixture.counts["/start"] == 2
            assert fixture.counts["/refresh"] == 1 and fixture.counts["/credential-trap"] == 0
            assert all(row["private_values_valid"] for row in fixture.observed)
            assert all(row["status"] == 200 for row in fixture.observed)
        finally:
            sampler.cancel()
            await asyncio.gather(sampler, return_exceptions=True)
            await session.aclose()
            store.close()
        assert memory["available_sample_count"] > 0
        assert resources["active_browser_samples"] > 0
        assert resources["active_scanner_samples"] > 0
        assert resources["peak_active_workers"] == 1
        assert resources["overlapping_browser_scanner_samples"] == 0
        secrets = (
            *fixture.tokens.values(),
            *fixture.sessions.values(),
            fixture.refresh_secret,
            fixture.private_value,
        )
        for path in tmp_path.rglob("*"):
            if path.is_file() and private not in path.parents:
                contents = path.read_bytes()
                assert all(secret.encode() not in contents for secret in secrets), path
        metrics.update(
            duration_seconds=time.monotonic() - started,
            target_origin=fixture.origin,
            target_ip=host,
            http_requests=len(fixture.observed),
            persisted_requests_used=used,
            refresh_requests=fixture.counts["/refresh"],
            browser_capture_revisions=["7", "8"],
            body_formats=list(_MEDIA),
            positive_candidates=6,
            fixed_control_new_findings=0,
            automatic_refresh_chain_jobs=5,
            runtime_restart_required=False,
            controller_pid_changed=False,
            restart_duplicate_requests=0,
            credential_trap_requests=fixture.counts["/credential-trap"],
            body_tokens_rotated=True,
            browser_capture_coverage=[
                {
                    "session_revision": revision,
                    "coverage_status": row["coverage_status"],
                    "failure_codes": [
                        failure["code"] for failure in row["result"]["summary"]["failures"]
                    ],
                }
                for revision, row in (("7", first[0]), ("8", refreshed_capture))
            ],
            capture_source="actual_headless_chromium_post_via_host_proxy_no_sdk_capture",
            process_tree_memory_sampling=memory,
            resource_lease_sampling=resources,
            configured_max_workers=1,
            memory_measurement=(
                "25 ms target interval test controller and descendant summed RSS; "
                "shared pages may be counted more than once; sampled peak"
            ),
        )
        assert all(secret not in json.dumps(metrics) for secret in secrets)
        for path in (vault, provider, capture):
            path.unlink()
    if output := os.environ.get("REDJOHN_CONTINUOUS_REFRESH_MEASUREMENTS"):
        Path(output).write_text(json.dumps(metrics, indent=2) + "\n")
