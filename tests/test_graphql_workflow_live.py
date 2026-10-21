"""Actual owned TLS/GraphQL execution, private captures and persistent scheduler.

The application runs graphql-core resolvers; no transport, provider or scanner
model double is used. Baseline captures are actual HTTPS requests and are
counted separately from scheduled workflow executions.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import ssl
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler
from importlib.metadata import version

import httpx
import pytest

from redjohn.assessment.configuration import ConfiguredAssessment
from redjohn.assessment.models import Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer


graphql = pytest.importorskip("graphql", reason="blocked optional GraphQL parser capability")
GraphQLError, build_schema, graphql_sync = (
    graphql.GraphQLError,
    graphql.build_schema,
    graphql.graphql_sync,
)


SDL = """
type Item { id: ID!, owner: String!, value: String! }
type Deleted { deleted: Boolean! }
type Query { read(id: ID!): Item }
type Mutation {
  create(value: String!): Item!
  update(id: ID!, value: String!): Item
  delete(id: ID!): Deleted
}
"""
DOCUMENTS = {
    "create": "mutation Create($value:String!){create(value:$value){id owner value}}",
    "read": "query Read($id:ID!){read(id:$id){id owner value}}",
    "update": (
        "mutation Update($id:ID!,$value:String!){update(id:$id,value:$value){id owner value}}"
    ),
    "delete": "mutation Delete($id:ID!){delete(id:$id){deleted}}",
}


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


async def test_actual_graphql_two_actor_crud_private_values_restart_errors_and_cleanup(  # noqa: PLR0915 - owned full lifecycle
    tmp_path, monkeypatch, record_testsuite_property
):
    monkeypatch.setenv("REDJOHN_HOST_RESOURCE_DB", str(tmp_path / "host-pool.db"))
    tokens = {actor: secrets.token_urlsafe(24) for actor in ("alice", "bob")}
    objects, seen = {}, Counter()
    schema = build_schema(SDL)

    def item(identity, actor):
        value = objects.get(identity)
        if value is None:
            raise GraphQLError("missing", extensions={"code": "NOT_FOUND"})
        if value["owner"] != actor:
            raise GraphQLError("denied", extensions={"code": "FORBIDDEN"})
        return value

    def create(_root, info, value):
        identity = secrets.token_urlsafe(20)
        objects[identity] = {"id": identity, "owner": info.context["actor"], "value": value}
        return objects[identity]

    def update(_root, info, **variables):
        result = item(variables["id"], info.context["actor"])
        result["value"] = variables["value"]
        return result

    def delete(_root, info, **variables):
        item(variables["id"], info.context["actor"])
        del objects[variables["id"]]
        return {"deleted": True}

    schema.type_map["Query"].fields["read"].resolve = lambda _root, info, **variables: item(
        variables["id"], info.context["actor"]
    )
    schema.type_map["Mutation"].fields["create"].resolve = create
    schema.type_map["Mutation"].fields["update"].resolve = update
    schema.type_map["Mutation"].fields["delete"].resolve = delete

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            actor = next(
                (
                    actor
                    for actor, token in tokens.items()
                    if self.headers.get("Authorization") == "Bearer " + token
                ),
                None,
            )
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            request = json.loads(raw)
            seen[(actor, request["operationName"])] += 1
            if self.path != "/graphql" or actor is None:
                self.send_error(403)
                return
            result = graphql_sync(
                schema,
                request["query"],
                variable_values=request["variables"],
                operation_name=request["operationName"],
                context_value={"actor": actor},
            )
            payload = json.dumps(result.formatted, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    fixture = TLSFixtureServer()
    try:
        with fixture:
            fixture.server.RequestHandlerClass = Handler
            origin, url = fixture.origin, fixture.origin + "/graphql"
            schema_file = private_json(tmp_path / "placeholder.json", {})
            schema_file.write_text(SDL)
            schema_pin = hashlib.sha256(SDL.encode()).hexdigest()
            contracts = []
            for operation, document in DOCUMENTS.items():
                contracts.append(
                    {
                        "name": operation,
                        "schema_file": str(schema_file),
                        "schema_sha256": schema_pin,
                        "document_sha256": hashlib.sha256(document.encode()).hexdigest(),
                        "operation_name": operation.title(),
                        "operation_type": "query" if operation == "read" else "mutation",
                        "variable_bindings": [["id", "object"]] if operation != "create" else [],
                        "extracts": [["object", "/data/create/id"]]
                        if operation == "create"
                        else [],
                        "actor_pointer": "/data/" + operation + "/owner"
                        if operation != "delete"
                        else "",
                        "expected_fields": [
                            [
                                "/data/" + operation + "/value",
                                "created" if operation != "update" else "updated",
                            ]
                        ]
                        if operation != "delete"
                        else [["/data/delete/deleted", True]],
                    }
                )
            base_read = {
                key: value
                for key, value in contracts[1].items()
                if key not in {"variable_bindings", "expected_fields", "actor_pointer"}
            }
            contracts.extend(
                [
                    {
                        **base_read,
                        "name": "denied",
                        "expected_error_code": "FORBIDDEN",
                        "denied_data_pointer": "/data/read",
                    },
                    {**base_read, "name": "errors-fail"},
                ]
            )
            identity = {
                "version": 1,
                "engagement_id": "graphql-workflow",
                "owner_id": "operator",
                "policy_revision": "1",
            }
            state = private_json(tmp_path / "graphql-private.json", {**identity, "flows": {}})
            vault_file = private_json(tmp_path / "replay-vault.json", {"version": 2, "entries": []})
            definitions = [
                {
                    "name": "graphql-crud",
                    "revision": "1",
                    "initial_state": "initial",
                    "terminal_states": ["clean"],
                    "steps": [
                        {
                            "name": operation,
                            "from_state": previous,
                            "to_state": following,
                            "url": url,
                            "method": "POST",
                            "effect": "read_only"
                            if operation == "read"
                            else "cleanup"
                            if operation == "delete"
                            else "mutation",
                            "graphql_contract": operation,
                        }
                        for operation, previous, following in (
                            ("create", "initial", "created"),
                            ("read", "created", "read"),
                            ("update", "read", "updated"),
                            ("delete", "updated", "clean"),
                        )
                    ],
                }
            ]
            for operation in ("denied", "errors-fail"):
                definitions.append(  # noqa: PERF401 - explicit reviewable test definitions
                    {
                        "name": operation,
                        "revision": "1",
                        "initial_state": "initial",
                        "terminal_states": ["done"],
                        "steps": [
                            {
                                "name": "check",
                                "from_state": "initial",
                                "to_state": "done",
                                "url": url,
                                "method": "POST",
                                "effect": "read_only",
                                "graphql_contract": operation,
                            }
                        ],
                    }
                )
            config = {
                "policy": {
                    "engagement_id": identity["engagement_id"],
                    "owner_id": "operator",
                    "revision": "1",
                    "allowed_origins": [origin],
                    "actor_ids": ["anonymous", "alice", "bob"],
                    "profile": "isolated-lab",
                    "egress_mode": "local-fixture",
                    "allowed_replay_urls": [url],
                },
                "tls": {"upstream_ca_file": str(fixture.ca_file)},
                "auth_vault_file": str(vault_file),
                "workflow_execution": {
                    "enabled": True,
                    "definitions": definitions,
                    "graphql_contracts": contracts,
                    "private_state_file": str(state),
                },
            }
            output = tmp_path / "assessment"
            surface_ids, instance_ids = {}, {}
            entries = []

            async def actual(client, actor, operation, variables):
                raw = json.dumps(
                    {
                        "query": DOCUMENTS[operation],
                        "operationName": operation.title(),
                        "variables": variables,
                    },
                    separators=(",", ":"),
                ).encode()
                response = await client.post(
                    url,
                    content=raw,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + tokens[actor],
                    },
                )
                assert response.status_code == 200
                return raw, response.json()

            def capture(store, actor, raw):
                digest = hashlib.sha256(raw).hexdigest()
                ref = store.evidence_put(
                    identity["engagement_id"],
                    {
                        "producer": "actual-owned-tls-capture",
                        "method": "POST",
                        "url": url,
                        "actor": actor,
                        "body_sha256": digest,
                    },
                    kind="graphql_capture",
                )
                surface = Surface(
                    url,
                    method="POST",
                    input_location="body_json",
                    input_name="variables",
                    actor_id=actor,
                    tenant_id="owned",
                    source="observed",
                    request_ref=ref,
                    content_type="application/json",
                    body_sha256=digest,
                )
                sid = store.upsert_surface(identity["engagement_id"], surface)
                entry = next((entry for entry in entries if entry["actor_id"] == actor), None)
                if entry is None:
                    entry = {
                        "engagement_id": identity["engagement_id"],
                        "owner_id": "operator",
                        "policy_revision": "1",
                        "actor_id": actor,
                        "tenant_id": "owned",
                        "session_revision": "1",
                        "expires_at": time.time() + 600,
                        "origin": origin,
                        "headers": {"Authorization": "Bearer " + tokens[actor]},
                        "cookies": [],
                        "allowed_requests": [],
                    }
                    entries.append(entry)
                entry["allowed_requests"].append(
                    {
                        "url": url,
                        "method": "POST",
                        "request_ref": ref,
                        "content_type": "application/json",
                        "body_base64": base64.b64encode(raw).decode(),
                        "body_sha256": digest,
                        "replay_safety": "operator-approved",
                    }
                )
                private_json(vault_file, {"version": 2, "entries": entries})
                return sid

            async def step(
                assessment, actor, operation, *, definition="graphql-crud", surface_id=None
            ):
                instance = instance_ids[(actor, definition)]
                before = assessment.store.inventory.workflow(assessment.policy, instance)
                result = await assessment.runtime.control.call(
                    "workflow_submit_step",
                    {
                        "policy_revision": "1",
                        "instance_id": instance,
                        "step_name": operation,
                        "surface_id": surface_id or surface_ids[(actor, operation)],
                        "expected_revision": before["revision"],
                    },
                )
                assert result["ok"], result
                job = result["result"]["job_ids"][0]
                assert await assessment.runtime.scheduler.run_until_idle(max_jobs=1) == [job]
                return next(
                    row
                    for row in assessment.store.jobs(identity["engagement_id"], limit=100)
                    if row["id"] == job
                )

            tls = ssl.create_default_context(cafile=str(fixture.ca_file))
            async with httpx.AsyncClient(verify=tls, trust_env=False) as client:
                store = AssessmentStore(output / ".state" / "agents.db")
                try:
                    store.register(EngagementPolicy.from_mapping(config["policy"]))
                    for actor in tokens:
                        raw, response = await actual(client, actor, "create", {"value": "created"})
                        baseline_id = response["data"]["create"]["id"]
                        surface_ids[(actor, "create")] = capture(store, actor, raw)
                        for operation, variables in (
                            ("read", {"id": baseline_id}),
                            ("update", {"id": baseline_id, "value": "updated"}),
                            ("delete", {"id": baseline_id}),
                        ):
                            raw, response = await actual(client, actor, operation, variables)
                            assert not response.get("errors"), response
                            surface_ids[(actor, operation)] = capture(store, actor, raw)
                finally:
                    store.close()
                assert not objects
                async with ConfiguredAssessment(config, output, caller="operator") as assessment:
                    definitions_by_name = {
                        item["name"]: item["id"]
                        for item in assessment.store.inventory.definitions(assessment.policy)
                    }
                    for actor in tokens:
                        instance_ids[(actor, "graphql-crud")] = (
                            assessment.store.inventory.start_workflow(
                                assessment.policy,
                                definitions_by_name["graphql-crud"],
                                instance_key="owned",
                                actor_id=actor,
                                tenant_id="owned",
                            )
                        )
                    assert (await step(assessment, "alice", "create"))[
                        "execution_status"
                    ] == "succeeded"
                    assert len(objects) == 1
                # The object ID is host-private. A real restart restores its
                # committed scalar, and never repeats the create request.
                async with ConfiguredAssessment(config, output, caller="operator") as assessment:
                    assert await assessment.runtime.scheduler.run_until_idle(max_jobs=1) == []
                    for operation in ("read", "update"):
                        result = await step(assessment, "alice", operation)
                        assert result["execution_status"] == "succeeded", result
                    for operation in DOCUMENTS:
                        result = await step(assessment, "bob", operation)
                        assert result["execution_status"] == "succeeded", result
                    alice_id = next(
                        identity for identity, value in objects.items() if value["owner"] == "alice"
                    )
                    raw, denied = await actual(client, "bob", "read", {"id": alice_id})
                    assert (
                        denied["data"]["read"] is None
                        and denied["errors"][0]["extensions"]["code"] == "FORBIDDEN"
                    )
                    denial_surface = capture(assessment.store, "bob", raw)
                    for name in ("denied", "errors-fail"):
                        instance_ids[("bob", name)] = assessment.store.inventory.start_workflow(
                            assessment.policy,
                            definitions_by_name[name],
                            instance_key="owned",
                            actor_id="bob",
                            tenant_id="owned",
                        )
                        result = await step(
                            assessment, "bob", "check", definition=name, surface_id=denial_surface
                        )
                        assert result["execution_status"] == (
                            "succeeded" if name == "denied" else "failed"
                        ), result
                    failed = assessment.store.inventory.workflow(
                        assessment.policy, instance_ids[("bob", "errors-fail")]
                    )
                    assert (
                        failed["state"] == "initial"
                        and failed["active_lease"]["phase"] == "inflight"
                    )
                    assert (await step(assessment, "alice", "delete"))[
                        "execution_status"
                    ] == "succeeded"
                    assert not objects
                    assert seen == Counter(
                        {
                            ("alice", "Create"): 2,
                            ("alice", "Read"): 2,
                            ("alice", "Update"): 2,
                            ("alice", "Delete"): 2,
                            ("bob", "Create"): 2,
                            ("bob", "Read"): 5,
                            ("bob", "Update"): 2,
                            ("bob", "Delete"): 2,
                        }
                    )
                    assert assessment.runtime.governor.snapshot()["active"] == {}
                    assert assessment.store.request_usage(assessment.policy) == 10
                    assert not assessment.runtime.scheduler.adapters["workflow_execute"]._proxies
                    dump = "\n".join(assessment.store.db.iterdump())
                    assert all(secret not in dump for secret in (*tokens.values(), alice_id))
                    record_testsuite_property("graphql_actual_baseline_https_requests", 9)
                    record_testsuite_property("graphql_actual_scheduled_crud_requests", 8)
                    record_testsuite_property(
                        "graphql_actual_scheduled_denial_and_error_requests", 2
                    )
                    record_testsuite_property("graphql_actual_residual_objects", len(objects))
                    record_testsuite_property("graphql_actual_actors", 2)
                    record_testsuite_property(
                        "graphql_actual_parser_version", version("graphql-core")
                    )
    finally:
        if fixture.thread is not None:
            assert not fixture.thread.is_alive()
        assert not fixture.certificate_directory.exists()
