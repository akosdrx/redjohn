"""Absolute deadlines remain enforced across real browser/scanner CLI restarts."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from pathlib import Path

import pytest

from redjohn.assessment import cli, specialists
from redjohn.assessment.policy import PolicyDenied
from tests import test_authenticated_schema_oast_live as adapters
from tests import test_browser_token_pipeline as pipeline


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        ("campaign_deadline_exceeded", "campaign_deadline_exceeded"),
        ("policy_change_requires_new_revision", "policy_change_requires_new_revision"),
        ("private-secret-must-never-be-published", "policy_denied"),
    ],
)
def test_cli_policy_reason_is_allowlisted(tmp_path, monkeypatch, capsys, message, reason):
    config = tmp_path / "config.json"
    config.write_text("{}")

    async def denied(*_args, **_kwargs):
        raise PolicyDenied(message)

    monkeypatch.setattr(cli, "configured_run", denied)
    assert cli.main(["run", "--config", str(config), "--output", str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "ok": False,
        "error": "policy_denied",
        "category": "PolicyDenied",
        "reason": reason,
    }


def job_snapshot(path):
    with sqlite3.connect(path) as db:
        return db.execute("SELECT id,execution_status,attempt FROM rj_job ORDER BY id").fetchall()


async def test_actual_chromium_nuclei_restart_after_wall_clock_step(tmp_path, monkeypatch):
    """Advance only one child clock; TLS, Chromium and Nuclei I/O stay real."""
    pipeline._dependencies()
    wrapper = tmp_path / "clock_step_cli.py"
    wrapper.write_text(
        "import runpy, time\n"
        "wall_time = time.time\n"
        "time.time = lambda: wall_time() + 600\n"
        "runpy.run_module('redjohn.assessment', run_name='__main__')\n"
    )
    original = asyncio.create_subprocess_exec
    instances = []
    base = pipeline.BrowserTokenHTTPSFixture

    class TrackedFixture(base):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)

    monkeypatch.setattr(pipeline, "BrowserTokenHTTPSFixture", TrackedFixture)
    calls = 0
    expiry = {}

    async def spawn(*args, **kwargs):
        nonlocal calls
        if len(args) > 3 and args[1:3] == ("-m", "redjohn.assessment"):
            calls += 1
            if calls == 5:
                before = job_snapshot(tmp_path / ".state/agents.db")
                requests = len(instances[0].observed)
                configuration = json.loads((tmp_path / "configured-browser-token.json").read_text())
                deadline = configuration["policy"]["deadline"]
                expired = await original(args[0], str(wrapper), *args[3:], **kwargs)
                stdout, stderr = await asyncio.wait_for(expired.communicate(), 20)
                assert expired.returncode == 2 and not stderr
                assert json.loads(stdout) == {
                    "ok": False,
                    "error": "policy_denied",
                    "category": "PolicyDenied",
                    "reason": "campaign_deadline_exceeded",
                }
                assert job_snapshot(tmp_path / ".state/agents.db") == before
                assert len(instances[0].observed) == requests
                assert (
                    json.loads((tmp_path / "configured-browser-token.json").read_text())["policy"][
                        "deadline"
                    ]
                    == deadline
                )
                expiry.update(
                    clock_step_seconds=600,
                    exit_code=expired.returncode,
                    reason="campaign_deadline_exceeded",
                    persisted_jobs_unchanged=len(before),
                    additional_requests=0,
                )
        return await original(*args, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    # The unmodified full lifecycle then continues under normal wall time,
    # including the zero-job restart, session refresh and fresh replay.
    await pipeline.test_actual_chromium_post_capture_body_token_refresh_and_nuclei_restart(tmp_path)
    assert calls > 5 and expiry["persisted_jobs_unchanged"] == 4
    if destination := os.environ.get("REDJOHN_MIME_RESTART_MEASUREMENTS"):
        path = Path(destination).parent / "restart-deadline.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"clock_injection": True, **expiry}, indent=2) + "\n")


async def test_actual_schemathesis_stops_admission_after_complete_401(tmp_path, monkeypatch):
    base = specialists.BrowserEgressProxy
    observations = {"complete_401": 0, "late_admissions": 0}

    class TrackedProxy(base):
        def __init__(self, *args, **kwargs):
            admit, complete = kwargs["request_admission"], kwargs["on_complete"]
            rejected = False

            def admission(url):
                admit(url)
                observations["late_admissions"] += int(rejected)

            def completion(url, method, status, headers):
                nonlocal rejected
                complete(url, method, status, headers)
                if status == 401:
                    rejected = True
                    observations["complete_401"] += 1

            kwargs.update(request_admission=admission, on_complete=completion)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(specialists, "BrowserEgressProxy", TrackedProxy)
    await adapters.test_actual_refresh_recapture_and_adapter_in_same_scheduler(
        tmp_path, "schemathesis", "json"
    )
    assert observations["complete_401"] > 0
    assert observations["late_admissions"] == 0
