"""Actual owned HTTPS capture -> private replay -> scheduled stateful workflow.

The fixture is an actual TLS application, with real scheduler, replay, refresh,
SQLite restart and cleanup. No transport or provider double is used. No LLM.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import ssl
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler

import httpx
import pytest

from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.control import AssessmentControl
from redjohn.assessment.inventory import InventoryConflictError
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.resources import ResourceGovernor
from redjohn.assessment.scheduler import Scheduler
from redjohn.assessment.session_refresh import SessionRefreshService
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.assessment.workflow_execution import WorkflowExecutionAdapter, WorkflowExecutionConfig
from redjohn.assessment.workflow_models import WorkflowDefinition, WorkflowStep


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


async def test_real_two_actor_crud_scheduled_refresh_restart_and_cleanup(  # noqa: PLR0915 - actual lifecycle
    tmp_path, record_testsuite_property
):
    started_at = time.monotonic()
    tokens = {"alice": secrets.token_urlsafe(24), "bob": secrets.token_urlsafe(24)}
    old_alice = tokens["alice"]
    refresh_token = secrets.token_urlsafe(24)
    objects = {}
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, payload=None):
            raw = json.dumps(payload).encode() if payload is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def identity(self):
            return next(
                (
                    actor
                    for actor, token in tokens.items()
                    if self.headers.get("Authorization") == "Bearer " + token
                ),
                None,
            )

        def do_GET(self):
            actor = self.identity()
            seen.append(("GET", self.path, actor))
            if self.path == "/read-alice" and actor == "bob":
                self.respond(403)
            elif self.path != "/read" or actor is None or (actor, "tenant-a") not in objects:
                self.respond(401 if actor is None else 404)
            else:
                self.respond(200, {"actor": actor, "value": objects[(actor, "tenant-a")]})

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path == "/refresh":
                valid = self.headers.get("Authorization") == "Bearer " + refresh_token
                seen.append(("POST", self.path, "refresh" if valid else None))
                if not valid or raw != b'{"grant_type":"refresh_token"}':
                    self.respond(403)
                    return
                tokens["alice"] = secrets.token_urlsafe(24)
                self.respond(
                    200,
                    {
                        "headers": {"Authorization": "Bearer " + tokens["alice"]},
                        "cookies": [],
                        "expires_at": time.time() + 300,
                    },
                )
                return
            actor = self.identity()
            seen.append(("POST", self.path, actor))
            if actor is None:
                self.respond(401)
                return
            key = (actor, "tenant-a")
            if self.path == "/create" and key not in objects:
                objects[key] = "created"
                self.respond(201, {"actor": actor, "value": "created"})
            elif self.path == "/update" and key in objects and raw == b'{"value":"updated"}':
                objects[key] = "updated"
                self.respond(200, {"actor": actor, "value": "updated"})
            elif self.path == "/cleanup" and key in objects:
                del objects[key]
                self.respond(204)
            else:
                self.respond(409)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        database = tmp_path / "state.db"
        store = AssessmentStore(database)
        origin = fixture.origin
        policy = store.register(
            EngagementPolicy(
                "workflow-live",
                "operator",
                (origin,),
                profile="isolated-lab",
                egress_mode="local-fixture",
                actor_ids=("anonymous", "alice", "bob"),
                allowed_replay_urls=tuple(
                    origin + path for path in ("/create", "/update", "/cleanup")
                ),
                allowed_refresh_urls=(origin + "/refresh",),
            )
        )
        definition = WorkflowDefinition(
            "owned-crud",
            "1",
            "empty",
            ("cleaned",),
            (
                WorkflowStep(
                    "create", "empty", "created", "POST", origin + "/create", "mutation", (201,)
                ),
                WorkflowStep("read", "created", "read", "GET", origin + "/read"),
                WorkflowStep("update", "read", "updated", "POST", origin + "/update", "mutation"),
                WorkflowStep(
                    "cleanup", "updated", "cleaned", "POST", origin + "/cleanup", "cleanup", (204,)
                ),
            ),
        )
        definition_id = store.inventory.register_workflow(policy, definition)
        instances = {
            actor: store.inventory.start_workflow(
                policy,
                definition_id,
                instance_key="owned-object",
                actor_id=actor,
                tenant_id="tenant-a",
                session_revision="7",
            )
            for actor in tokens
        }
        observed = {}
        tls = ssl.create_default_context(cafile=str(fixture.ca_file))
        async with httpx.AsyncClient(
            verify=tls, trust_env=False, follow_redirects=False, timeout=5
        ) as client:
            # Genuine observed baselines. Every POST is explicit fixture setup;
            # cleanup closes each baseline object before the assessed workflow.
            entries = []
            for actor, token in tokens.items():
                requests = []
                for step in definition.steps:
                    body = b'{"value":"updated"}' if step.name == "update" else b"{}"
                    response = await client.request(
                        step.method,
                        step.url,
                        headers={
                            "Authorization": "Bearer " + token,
                            "Content-Type": "application/json",
                        },
                        content=body if step.method == "POST" else b"",
                    )
                    assert response.status_code in step.expected_statuses
                    proof = store.evidence_put(
                        policy.engagement_id,
                        {
                            "producer": "actual-owned-https-baseline",
                            "actor_id": actor,
                            "url": step.url,
                            "method": step.method,
                            "response_complete": True,
                            "status": response.status_code,
                            "response_sha256": hashlib.sha256(response.content).hexdigest(),
                        },
                        kind="workflow_fixture_request",
                    )
                    request = {"url": step.url, "method": step.method, "request_ref": proof}
                    if step.method == "POST":
                        request.update(
                            content_type="application/json",
                            body_base64=base64.b64encode(body).decode(),
                            body_sha256=hashlib.sha256(body).hexdigest(),
                            replay_safety="operator-approved",
                        )
                    requests.append(request)
                    observed[(actor, step.name)] = store.upsert_surface(
                        policy.engagement_id,
                        Surface(
                            step.url,
                            method=step.method,
                            actor_id=actor,
                            tenant_id="tenant-a",
                            session_revision="7",
                            request_ref=proof,
                            content_type="application/json" if step.method == "POST" else "",
                            body_sha256=hashlib.sha256(body).hexdigest()
                            if step.method == "POST"
                            else "",
                        ),
                    )
                entries.append(
                    {
                        "engagement_id": policy.engagement_id,
                        "owner_id": policy.owner_id,
                        "actor_id": actor,
                        "tenant_id": "tenant-a",
                        "session_revision": "7",
                        "policy_revision": policy.revision,
                        "expires_at": time.time() + 300,
                        "origin": origin,
                        "allowed_requests": requests,
                        "headers": {"Authorization": "Bearer " + token},
                        "cookies": [],
                    }
                )
            assert objects == {}
            baseline_counts = {
                path: sum(item[1] == path for item in seen) for path in ("/create", "/cleanup")
            }
            vault = private_json(tmp_path / "vault.json", {"version": 2, "entries": entries})
            registry = CapabilityRegistry(
                session_refresh_configured=True, workflow_execution_configured=True
            )
            governor = ResourceGovernor()

            async def perform(actor, step_name):
                current = store.inventory.workflow(policy, instances[actor])
                adapter = WorkflowExecutionAdapter(
                    WorkflowExecutionConfig(enabled=True),
                    policy,
                    store,
                    tls_config=BrowserTLSConfig(fixture.ca_file),
                    auth_vault_file=vault,
                )
                scheduler = Scheduler(
                    store, policy, governor, registry, {"workflow_execute": adapter}
                )
                control = AssessmentControl(
                    store, policy, caller=policy.owner_id, registry=registry, scheduler=scheduler
                )
                try:
                    submitted = await control.call(
                        "workflow_submit_step",
                        {
                            "policy_revision": policy.revision,
                            "instance_id": instances[actor],
                            "step_name": step_name,
                            "surface_id": observed[(actor, step_name)],
                            "expected_revision": current["revision"],
                        },
                    )
                    assert submitted["ok"], submitted
                    job_id = submitted["result"]["job_ids"][0]
                    assert await scheduler.run_until_idle(max_jobs=1) == [job_id]
                    job = next(
                        row for row in store.jobs(policy.engagement_id) if row["id"] == job_id
                    )
                    assert job["execution_status"] == "succeeded", job
                    assert job["result"]["summary"]["requests"] == 1
                    return store.inventory.workflow(policy, instances[actor])
                finally:
                    control.close()
                    await adapter.cleanup()

            await perform("alice", "create")
            await perform("bob", "create")
            # Both actual server authorization and metadata identity deny crossing actors.
            forbidden = await client.get(
                origin + "/read-alice", headers={"Authorization": "Bearer " + tokens["bob"]}
            )
            assert forbidden.status_code == 403
            with pytest.raises(PolicyDenied, match="context_mismatch"):
                store.inventory.claim_step(
                    policy,
                    instances["alice"],
                    "read",
                    observed[("bob", "read")],
                    expected_revision=2,
                    owner="owned-fixture-driver",
                )
            assert store.inventory.workflow(policy, instances["alice"])["state"] == "created"

            refresh_surface = store.surface(policy.engagement_id, observed[("alice", "read")])
            providers = private_json(
                tmp_path / "providers.json",
                {
                    "version": 1,
                    "providers": [
                        {
                            "engagement_id": policy.engagement_id,
                            "owner_id": policy.owner_id,
                            "actor_id": "alice",
                            "tenant_id": "tenant-a",
                            "policy_revision": policy.revision,
                            "refresh_url": origin + "/refresh",
                            "headers": {"Authorization": "Bearer " + refresh_token},
                            "body_base64": base64.b64encode(
                                b'{"grant_type":"refresh_token"}'
                            ).decode(),
                            "content_type": "application/json",
                        }
                    ],
                },
            )
            service = SessionRefreshService(
                policy, store, vault, providers, tls_config=BrowserTLSConfig(fixture.ca_file)
            )
            spec = JobSpec(
                observed[("alice", "read")],
                "session",
                "session_refresh",
                policy_revision=policy.revision,
                idempotent=False,
                timeout_seconds=5,
                **registry.execution_versions("session_refresh"),
            )
            job_id = store.submit(policy, [spec])[0]
            governor = ResourceGovernor()
            scheduler = Scheduler(store, policy, governor, registry, {"session_refresh": service})
            assert await scheduler.run_until_idle(max_jobs=1) == [job_id]
            job = next(row for row in store.jobs(policy.engagement_id) if row["id"] == job_id)
            assert job["execution_status"] == "succeeded", job
            refresh_key = job["result"]["summary"]["refresh_key"]
            assert store.session_state(policy, refresh_surface)["revision"] == "8"
            with pytest.raises(InventoryConflictError, match="session_not_current"):
                store.inventory.claim_step(
                    policy,
                    instances["alice"],
                    "read",
                    observed[("alice", "read")],
                    expected_revision=2,
                    owner="owned-fixture-driver",
                )
            proof = store.inventory.record_session_refresh_outcome(
                policy, instances["alice"], refresh_key
            )
            refreshed = store.inventory.refresh_workflow_session(
                policy,
                instances["alice"],
                expected_revision=2,
                session_revision="8",
                evidence_ref=proof,
            )
            assert refreshed["state"] == "created" and refreshed["revision"] == 3
            with pytest.raises(AuthReplayDenied):
                AuthReplayVault.from_file(vault, policy).authorize(refresh_surface)
            for step in definition.steps:
                old = store.surface(policy.engagement_id, observed[("alice", step.name)])
                observed[("alice", step.name)] = store.upsert_surface(
                    policy.engagement_id, replace(old, session_revision="8")
                )
            # Real close/reopen loses all Python objects while durable state and identity remain.
            store.close()
            store = AssessmentStore(database)
            assert store.inventory.workflow(policy, instances["alice"])["state"] == "created"
            assert store.inventory.workflow(policy, instances["bob"])["session_revision"] == "7"
            alice_read = store.surface(policy.engagement_id, observed[("alice", "read")])
            binding = AuthReplayVault.from_file(vault, policy).authorize(alice_read)
            header = dict(binding.headers_for(alice_read.url, "GET"))["Authorization"]
            assert header == "Bearer " + tokens["alice"]
            assert (
                await client.get(alice_read.url, headers={"Authorization": "Bearer " + old_alice})
            ).status_code == 401
            await perform("alice", "read")
            await perform("bob", "read")
            for actor in tokens:
                await perform(actor, "update")
                state = await perform(actor, "cleanup")
                assert state["status"] == "completed" and state["state"] == "cleaned"
            assert objects == {}
            assert not store.db.execute("SELECT 1 FROM rj_workflow_lease").fetchone()
            assert len(store.inventory.assets(policy, source="observed")) == 1
            assert len(store.inventory.services(policy)) == 1
            assert (
                len(
                    store.surfaces(
                        policy.engagement_id, actor_id="alice", session_revision="8", method="POST"
                    )
                )
                == 3
            )
            assert store.submit(policy, [spec]) == [job_id]
            assert (
                await Scheduler(
                    store,
                    policy,
                    ResourceGovernor(),
                    registry,
                    {
                        "session_refresh": SessionRefreshService(
                            policy,
                            store,
                            vault,
                            providers,
                            tls_config=BrowserTLSConfig(fixture.ca_file),
                        )
                    },
                ).run_until_idle(max_jobs=1)
                == []
            )
            dump = "\n".join(store.db.iterdump())
            assert all(
                secret not in dump
                for secret in (old_alice, tokens["alice"], tokens["bob"], refresh_token)
            )
            assert len([entry for entry in seen if entry[1] == "/refresh"]) == 1
            assert (
                len([entry for entry in seen if entry[1] == "/create"]) - baseline_counts["/create"]
                == 2
            )
            assert (
                len([entry for entry in seen if entry[1] == "/cleanup"])
                - baseline_counts["/cleanup"]
                == 2
            )
            assert governor.snapshot()["active"] == {}
            assert store.request_usage(policy) == 9  # 8 workflow requests + 1 refresh.
            assert len(seen) == 19  # plus 8 actual capture baselines + 2 denials.
            for key, value in {
                "workflow_real_actors": 2,
                "workflow_real_completed_steps": 8,
                "workflow_real_refreshes": 1,
                "workflow_scheduler_admitted_requests": 9,
                "workflow_fixture_requests_including_baselines_and_denials": len(seen),
                "workflow_residual_objects": len(objects),
                "workflow_residual_leases": 0,
                "workflow_controller_active_resources": 0,
                "workflow_real_elapsed_seconds": round(time.monotonic() - started_at, 6),
            }.items():
                record_testsuite_property(key, value)
            store.close()
        assert not list(tmp_path.glob(".redjohn-session-*"))
    assert not fixture.thread.is_alive()
    assert not fixture.certificate_directory.exists()
