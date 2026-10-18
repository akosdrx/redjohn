"""Real rejecting responses and separate CLI process recovery; no mocked I/O."""

import asyncio
import json
import os
import signal
import sys
import time
from contextlib import closing, nullcontext
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault
from redjohn.assessment.models import JobSpec
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from tests.test_authenticated_schema_oast_live import (
    CAPABILITIES,
    AuthenticatedInputFixture,
    OwnedReceiver,
    configuration,
    publish_measurement,
)
from tests.test_schema_oast_live import make_spec
from tests.test_specialists_live import host_for


@pytest.mark.parametrize("kind", ["json", "form", "multipart"])
async def test_actual_native_worker_hop_nomination_cannot_strip_host_post_type_or_credentials(
    tmp_path, kind, monkeypatch
):
    with (
        AuthenticatedInputFixture("127.0.0.1", tmp_path / "target", "tinja", kind) as fixture,
        closing(AssessmentStore(tmp_path / "state/agents.db")) as store,
    ):
        policy, settings = configuration(tmp_path, fixture, remote=False)
        async with AssessmentRuntime(store, policy, **settings) as app:
            await app.scheduler.run_batch(max_jobs=1)
            adapter = app.scheduler.adapters["tinja_validate"]
            argv = adapter.argv

            def hostile_real_cli_headers(*args):
                return [*argv(*args), "--header", "Connection: Content-Type, Cookie, Authorization"]

            # Fault injection changes only a real native CLI header. There is
            # no fake engine response, auth binding or proxy implementation.
            monkeypatch.setattr(adapter, "argv", hostile_real_cli_headers)
            await app.scheduler.run_batch(max_jobs=1)
            job = next(
                r for r in store.jobs(policy.engagement_id) if r["capability"] == "tinja_validate"
            )
            assert job["execution_status"] == "succeeded", job
            assert job["result"]["summary"]["scanner_verdict"]["candidate"] is True
            assert all(p["valid"] for p in fixture.posts)


@pytest.mark.parametrize("tool", ["tinja", "schemathesis"])
async def test_actual_worker_startup_outliving_credential_ttl_refreshes_without_old_post(
    tmp_path, tool, monkeypatch
):
    """Inject only startup latency; the scanner/HTTPS/provider I/O remains real."""
    with (
        AuthenticatedInputFixture("127.0.0.1", tmp_path / "target", tool, "json") as fixture,
        closing(AssessmentStore(tmp_path / "state/agents.db")) as store,
    ):
        policy, settings = configuration(tmp_path, fixture, remote=False, recovery=True)
        async with AssessmentRuntime(store, policy, **settings) as app:
            await app.scheduler.run_batch(max_jobs=1)
            adapter = app.scheduler.adapters[CAPABILITIES[tool]]
            prepare = adapter.runner.prepare
            calls = []

            async def delayed_real_prepare(*args, **kwargs):
                await prepare(*args, **kwargs)
                calls.append("real_prepare_completed")
                await asyncio.sleep(1.2)

            monkeypatch.setattr(adapter.runner, "prepare", delayed_real_prepare)
            vault = Path(settings["auth_vault_file"])
            data = json.loads(vault.read_text())
            for entry in data["entries"]:
                if any(r["method"] == "POST" for r in entry["allowed_requests"]):
                    entry["expires_at"] = time.time() + 1
            from tests.test_post_refresh_pipeline import _private_json  # noqa: PLC0415 - private fixture input

            _private_json(vault, data)
            await app.scheduler.run_until_idle(max_jobs=12, wait_seconds=3)
            rows = store.jobs(policy.engagement_id, limit=100)
            assert len(calls) == 2, rows
            old = [
                r
                for r in rows
                if r["capability"] == CAPABILITIES[tool]
                and store.surface(policy.engagement_id, r["surface_id"]).session_revision == "7"
            ]
            fresh = [
                r
                for r in rows
                if r["capability"] == CAPABILITIES[tool]
                and store.surface(policy.engagement_id, r["surface_id"]).session_revision == "8"
            ]
            assert len(old) == len(fresh) == 1
            assert (
                old[0]["execution_status"] == "failed"
                and old[0]["result"]["summary"]["requests"] == 0
            ), rows
            assert old[0]["result"]["summary"]["auth_recovery"]["signal"] == "credential_expired"
            assert fresh[0]["execution_status"] == "succeeded", rows
            assert (
                len([p for p in fixture.posts if p["path"] == "/input" and p["revision"] == "7"])
                == 1
            )  # original Chromium capture only


@pytest.mark.parametrize("kind", ["json", "form", "multipart"])
async def test_actual_late_post_callback_survives_target_session_rotation_without_redelivery(
    tmp_path, kind
):
    with (
        OwnedReceiver(tmp_path / "receiver", "127.0.0.1") as receiver,
        AuthenticatedInputFixture(
            "127.0.0.1", tmp_path / "target", "interactsh", kind, receiver=receiver
        ) as fixture,
        closing(AssessmentStore(tmp_path / "state/agents.db")) as store,
    ):
        policy, settings = configuration(tmp_path, fixture, remote=False)
        settings.pop("continuous_replay")  # this case explicitly selects a single allocation
        settings["interactsh_config"] = receiver.config(window_seconds=12, max_polls=16)
        fixture.late = True
        async with AssessmentRuntime(store, policy, **settings) as app:
            await app.scheduler.run_batch(max_jobs=1)
            capture = next(
                r
                for r in store.jobs(policy.engagement_id)
                if r["capability"] == "browser_post_capture"
            )
            record = next(
                r for r in store.surfaces(policy.engagement_id, limit=100) if r["method"] == "POST"
            )
            surface = replace(
                store.surface(policy.engagement_id, record["id"]),
                input_location=kind,
                input_name="/value" if kind == "json" else "value",
            )
            sid = store.upsert_surface(policy.engagement_id, surface)
            spec = make_spec(app, store, policy, sid, surface, "interactsh", idempotent=False)
            store.submit(policy, [spec])
            await app.scheduler.run_batch(max_jobs=1)
            assert len(fixture.callbacks) == 1
            store.submit(
                policy,
                [
                    JobSpec(
                        capture["surface_id"],
                        "authentication",
                        "session_refresh",
                        idempotent=False,
                        priority=10,
                    )
                ],
            )
            await app.scheduler.run_batch(max_jobs=1)
            assert fixture.revision == "8"
            with pytest.raises(AuthReplayDenied):
                AuthReplayVault.from_file_for_surface(settings["auth_vault_file"], policy, surface)
            await asyncio.to_thread(fixture.deliver_callback, fixture.callbacks[0])
            before = len(fixture.posts)
            await app.scheduler.run_until_idle(max_jobs=16, wait_seconds=8)
            rows = store.jobs(policy.engagement_id, limit=100)
            polls = [r for r in rows if r["capability"] == "oast_poll"]
            assert polls and any(
                r["result"]["summary"].get("outcome") == "callback_observed" for r in polls
            ), rows
            assert len(fixture.posts) == before and len(fixture.callbacks) == 1
            assert all(r["execution_status"] == "succeeded" for r in polls)
            publish_measurement(
                "late-post-after-refresh-" + kind,
                {
                    "target_redelivery": 0,
                    "old_target_credentials_no_longer_authorize": True,
                    "correlated_under_original_allocation": spec.key,
                    "jobs": rows,
                },
            )


@pytest.mark.parametrize("tool", list(CAPABILITIES))
@pytest.mark.parametrize("fault", ["truncated401", "403", "429"])
async def test_actual_partial_post_or_challenge_does_not_refresh_or_become_negative(
    tmp_path, tool, fault
):
    with (
        (
            OwnedReceiver(tmp_path / "receiver", "127.0.0.1")
            if tool == "interactsh"
            else nullcontext(None)
        ) as receiver,
        AuthenticatedInputFixture(
            "127.0.0.1", tmp_path / "target", tool, "json", receiver=receiver
        ) as fixture,
        closing(AssessmentStore(tmp_path / "state/agents.db")) as store,
    ):
        policy, config = configuration(tmp_path, fixture, remote=False, recovery=True)
        async with AssessmentRuntime(store, policy, **config) as app:
            await app.scheduler.run_batch(max_jobs=1)
            fixture.fault = fault
            await app.scheduler.run_until_idle(max_jobs=8, wait_seconds=3)
            rows = store.jobs(policy.engagement_id, limit=100)
            actual = [r for r in rows if r["capability"] == CAPABILITIES[tool]]
            assert len(actual) == 1 and actual[0]["execution_status"] == "failed", rows
            assert actual[0]["coverage_status"] in {"blocked", "inconclusive"}, actual
            assert actual[0]["result"]["summary"].get("outcome") not in {
                "no_finding_observed",
                "no_callback_observed_in_window",
            }
            assert not any(r["capability"] == "session_refresh" for r in rows), rows
            assert not store.findings(policy.engagement_id)
            assert not app.scheduler._active


@pytest.mark.parametrize("tool", list(CAPABILITIES))
@pytest.mark.parametrize("remote", [False, True], ids=["loopback", "remote"])
async def test_actual_four_cli_processes_refresh_multipart_and_resume_without_redelivery(
    tmp_path, tool, remote
):
    host, started = host_for(remote), time.monotonic()
    with (
        (
            OwnedReceiver(tmp_path / "receiver", host)
            if tool == "interactsh"
            else nullcontext(None)
        ) as receiver,
        AuthenticatedInputFixture(
            host, tmp_path / "target", tool, "multipart", receiver=receiver
        ) as fixture,
    ):
        policy, settings = configuration(tmp_path, fixture, remote, recovery=True)
        output = tmp_path / "engagement"
        document = {
            "policy": policy.to_dict(),
            "resources": asdict(settings["envelope"]),
            "browser": asdict(settings["browser_limits"]),
            "tls": {"upstream_ca_file": str(settings["browser_tls"].upstream_ca_file)},
            **{
                key: str(settings[key])
                for key in ("auth_vault_file", "refresh_provider_file", "browser_capture_file")
            },
            "continuous_replay": settings["continuous_replay"],
            tool: settings[tool + "_config"],
        }
        config_path = tmp_path / "approved-config.json"
        config_path.write_text(json.dumps(document))
        invocations = []

        async def cli(maximum, wait=0):
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "redjohn.assessment",
                "run",
                "--config",
                str(config_path),
                "--output",
                str(output),
                "--max-jobs",
                str(maximum),
                "--wait-ready-seconds",
                str(wait),
                env={
                    **os.environ,
                    "PYTHONPATH": str(Path(__file__).parents[1]),
                    "REDJOHN_TELEMETRY": "0",
                },
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=100)
                assert len(stdout) + len(stderr) < 1024 * 1024
                assert process.returncode in {0, 1}, stderr.decode()
                invocations.append({"pid": process.pid, "exit_code": process.returncode})
            finally:
                if process.returncode is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    await process.wait()

        await cli(1)
        fixture.fault = "401"
        await cli(1)
        await cli(16, 8)
        with closing(AssessmentStore(output / ".state/agents.db")) as store:
            rows = store.jobs(policy.engagement_id, limit=100)
            old = [
                r
                for r in rows
                if r["capability"] == CAPABILITIES[tool]
                and store.surface(policy.engagement_id, r["surface_id"]).session_revision == "7"
            ]
            fresh = [
                r
                for r in rows
                if r["capability"] == CAPABILITIES[tool]
                and store.surface(policy.engagement_id, r["surface_id"]).session_revision == "8"
            ]
            assert len(old) == len(fresh) == 1, rows
            assert old[0]["execution_status"] == "failed" and old[0]["attempt"] == 1
            assert fresh[0]["execution_status"] == "succeeded", rows
            assert len([r for r in rows if r["capability"] == "session_refresh"]) == 1
            assert all(p["valid"] for p in fixture.posts)
            before = len(fixture.posts)
            await cli(16)
            assert len(fixture.posts) == before
            assert len({c["pid"] for c in invocations}) == 4
            assert (
                store.db.execute("SELECT count(*) FROM rj_job WHERE owner IS NOT NULL").fetchone()[
                    0
                ]
                == 0
            )
            if remote and tool != "interactsh":
                assert fresh[0]["result"]["summary"]["egress_attestations"]
            publish_measurement(
                f"cli-refresh-{tool}-{'remote' if remote else 'loopback'}",
                {
                    "elapsed_seconds": time.monotonic() - started,
                    "cli_processes": invocations,
                    "duplicate_resume_requests": 0,
                    "refresh_count": 1,
                    "model_calls": 0,
                    "jobs": rows,
                },
            )
