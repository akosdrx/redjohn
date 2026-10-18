"""Actual verified HTTPS failure responses; no HTTP/client/worker mocks."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler

import pytest

from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.models import Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.scheduler import Scheduler
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.assessment.workflow_execution import WorkflowExecutionAdapter, WorkflowExecutionConfig
from redjohn.assessment.workflow_models import WorkflowDefinition, WorkflowStep


@pytest.mark.parametrize("mode", ["denied", "redirect", "oversize", "incomplete", "wrong_hash"])
async def test_real_https_bad_outcome_never_advances_or_replays(tmp_path, mode):
    token = secrets.token_urlsafe(24)
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            raw = b"actual owned response" if mode != "oversize" else b"x" * 2048
            self.send_response(403 if mode == "denied" else 302 if mode == "redirect" else 200)
            self.send_header("Location", "/must-not-follow")
            self.send_header("Content-Length", str(len(raw) + (10 if mode == "incomplete" else 0)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        store = AssessmentStore(tmp_path / "state.db")
        policy = store.register(
            EngagementPolicy(
                "workflow-fault",
                "owner",
                (fixture.origin,),
                actor_ids=("anonymous", "alice"),
                profile="isolated-lab",
                egress_mode="local-fixture",
            )
        )
        proof = store.evidence_put(policy.engagement_id, {"fixture_contract_input": True})
        surface = Surface(fixture.origin + "/check", actor_id="alice", request_ref=proof)
        surface_id = store.upsert_surface(policy.engagement_id, surface)
        definition = WorkflowDefinition(
            "single-read",
            "1",
            "initial",
            ("done",),
            (
                WorkflowStep(
                    "check",
                    "initial",
                    "done",
                    "GET",
                    surface.url,
                    response_sha256=hashlib.sha256(b"different reviewed body").hexdigest()
                    if mode == "wrong_hash"
                    else "",
                ),
            ),
        )
        definition_id = store.inventory.register_workflow(policy, definition)
        instance_id = store.inventory.start_workflow(
            policy, definition_id, instance_key="read", actor_id="alice"
        )
        vault = tmp_path / "vault.json"
        vault.write_text(
            json.dumps(
                {
                    "version": 1,
                    "entries": [
                        {
                            "engagement_id": policy.engagement_id,
                            "owner_id": policy.owner_id,
                            "actor_id": "alice",
                            "tenant_id": "",
                            "session_revision": "1",
                            "policy_revision": policy.revision,
                            "expires_at": time.time() + 300,
                            "origin": fixture.origin,
                            "allowed_requests": [
                                {"url": surface.url, "method": "GET", "request_ref": proof}
                            ],
                            "headers": {"Authorization": "Bearer " + token},
                            "cookies": [],
                        }
                    ],
                }
            )
        )
        vault.chmod(0o600)
        adapter = WorkflowExecutionAdapter(
            WorkflowExecutionConfig(enabled=True, max_response_bytes=1024),
            policy,
            store,
            auth_vault_file=vault,
            tls_config=BrowserTLSConfig(fixture.ca_file),
        )
        registry = CapabilityRegistry(workflow_execution_configured=True)
        governor = ResourceGovernor()
        scheduler = Scheduler(store, policy, governor, registry, {"workflow_execute": adapter})
        control = AssessmentControl(
            store, policy, caller=policy.owner_id, registry=registry, scheduler=scheduler
        )
        args = {
            "policy_revision": policy.revision,
            "instance_id": instance_id,
            "step_name": "check",
            "surface_id": surface_id,
            "expected_revision": 1,
        }
        try:
            submitted = await control.call("workflow_submit_step", args)
            assert submitted["ok"], submitted
            job_id = submitted["result"]["job_ids"][0]
            assert await scheduler.run_until_idle(max_jobs=1) == [job_id]
            job = store.jobs(policy.engagement_id)[0]
            assert job["execution_status"] == "failed"
            assert job["coverage_status"] == "inconclusive"
            assert job["result"]["summary"]["automatic_replay"] is False
            state = store.inventory.workflow(policy, instance_id)
            assert state["state"] == "initial" and state["revision"] == 1
            assert state["active_lease"]["phase"] == "inflight"
            assert seen == ["/check"]
            assert not adapter._proxies
            assert governor.snapshot()["active"] == {}
            # Repeated submission deduplicates the non-idempotent scheduler job.
            duplicate = await control.call("workflow_submit_step", args)
            assert duplicate["result"]["job_ids"] == [job_id]
            assert await scheduler.run_until_idle(max_jobs=1) == []
            assert seen == ["/check"]
            assert token not in "\n".join(store.db.iterdump())
        finally:
            control.close()
            await adapter.cleanup()
            store.close()
    assert not fixture.thread.is_alive()
    assert not fixture.certificate_directory.exists()
