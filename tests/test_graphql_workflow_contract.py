"""Pinned GraphQL parser/private-state contracts, not live transport evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from redjohn.assessment.auth_replay import AuthReplayBinding
from redjohn.assessment.body_tokens import BodyTokenBinding
from redjohn.assessment.graphql_workflow import GraphQLContract, GraphQLExecution, bounded_json
from redjohn.assessment.models import stable_key
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.request_body import ApprovedRequestBody
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.workflow_inputs import PrivateWorkflowState
from redjohn.assessment.workflow_models import WorkflowDefinition, WorkflowStep


pytest.importorskip("graphql", reason="blocked optional GraphQL parser capability")


SDL = "type Query { read(id: ID!): String }"
DOCUMENT = "query Read($id: ID!) { read(id: $id) }"


def contract(tmp_path, document=DOCUMENT, **fields):
    schema = tmp_path / "schema.graphql"
    schema.write_text(SDL)
    schema.chmod(0o600)
    return GraphQLContract(
        "read",
        schema,
        hashlib.sha256(SDL.encode()).hexdigest(),
        hashlib.sha256(document.encode()).hexdigest(),
        "Read",
        "query",
        **fields,
    )


def request(document=DOCUMENT):
    return {"query": document, "operationName": "Read", "variables": {"id": "reviewed"}}


@pytest.mark.parametrize(
    "document",
    [
        "query Read { __schema { types { name } } }",
        "query Read { __typename }",
        "query Read($id:ID!){read(id:$id)} query Other($id:ID!){read(id:$id)}",
        "query Read($id:ID!){...Fields} fragment Fields on Query{read(id:$id)}",
        "query Read($id:ID!){read(id:$id) second:read(id:$id)}",
        "query Read($id:ID!){missing(id:$id)}",
        "query Read($id:ID!){read(id:$id)",
    ],
)
def test_pinned_but_unreviewable_ast_is_denied(tmp_path, document):
    reviewed = contract(tmp_path, document)
    with pytest.raises(ValueError):
        reviewed.validate_request(request(document))


@pytest.mark.parametrize(
    "raw",
    [
        b'[{"query":"batch"}]',
        b'{"data":{},"data":{}}',
        b'{"variables":{"value":NaN}}',
        b'{"variables":{"value":1e999}}',
        b'{"nested":' + b"[" * 33 + b"0" + b"]" * 33 + b"}",
    ],
)
def test_bounded_single_envelope_json_rejects_ambiguity_and_nonfinite(raw):
    with pytest.raises(ValueError):
        bounded_json(raw)


def test_document_and_schema_pins_are_rechecked(tmp_path):
    reviewed = contract(tmp_path)
    reviewed.validate_request(request())
    with pytest.raises(ValueError, match="exact_operation"):
        reviewed.validate_request(request(DOCUMENT + " "))
    reviewed.schema_file.write_text(SDL + " ")
    with pytest.raises(ValueError, match="schema_pin"):
        reviewed.validate_request(request())


def test_actual_fifo_schema_is_rejected_before_configuration_can_block(tmp_path):
    """A real FIFO/subprocess, not a mocked file descriptor or timer."""
    fifo = tmp_path / "schema.fifo"
    os.mkfifo(fifo, 0o600)
    script = (
        "import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
        "from redjohn.assessment.graphql_workflow import GraphQLContract\n"
        "try:\n GraphQLContract('read',Path(sys.argv[2]),'0'*64,'1'*64,'Read','query')\n"
        "except ValueError as error:\n"
        " assert str(error)=='graphql_private_pinned_schema_required';print('fifo-denied')\n"
        "else:\n raise SystemExit('fifo-was-accepted')\n"
    )
    result = subprocess.run(  # noqa: S603 - fixed isolated interpreter; only owned FIFO paths vary.
        [sys.executable, "-I", "-c", script, str(Path(__file__).resolve().parents[1]), str(fifo)],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    assert result.returncode == 0 and result.stdout.strip() == "fifo-denied", result.stderr


def test_legacy_workflow_identity_and_serialized_definition_stay_exact(tmp_path):
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(
        EngagementPolicy(
            "legacy-graphql",
            "owner",
            ("https://127.0.0.1:41011",),
            profile="isolated-lab",
            egress_mode="local-fixture",
        )
    )
    definition = WorkflowDefinition(
        "read",
        "1",
        "initial",
        ("done",),
        (WorkflowStep("read", "initial", "done", "GET", policy.allowed_origins[0] + "/read"),),
    )
    legacy = asdict(definition)
    del legacy["steps"][0]["graphql_contract"]
    key = stable_key([policy.engagement_id, definition.name, definition.revision])
    store.db.execute(
        "INSERT INTO rj_workflow_definition VALUES(?,?,?,?,?,?)",
        (
            key,
            policy.engagement_id,
            policy.revision,
            definition.name,
            definition.revision,
            json.dumps(legacy, sort_keys=True, separators=(",", ":")),
        ),
    )
    assert store.inventory.register_workflow(policy, definition) == key
    assert definition.to_mapping() == legacy
    store.close()


def execution(tmp_path):
    policy = EngagementPolicy(
        "graphql-private",
        "owner",
        ("https://127.0.0.1:41011",),
        actor_ids=("anonymous", "alice", "bob"),
        profile="isolated-lab",
        egress_mode="local-fixture",
        allowed_replay_urls=("https://127.0.0.1:41011/graphql",),
    )
    raw = json.dumps(request(), separators=(",", ":")).encode()
    body = ApprovedRequestBody.from_mapping(
        {
            "content_type": "application/json",
            "body_base64": base64.b64encode(raw).decode(),
            "body_sha256": hashlib.sha256(raw).hexdigest(),
        }
    )
    binding = AuthReplayBinding(
        policy.engagement_id,
        "owner",
        "alice",
        "owned",
        "1",
        "1",
        "capture-proof",
        policy.allowed_origins[0] + "/graphql",
        "POST",
        time.time() + 60,
        (("Authorization", "Bearer private"),),
        ("private",),
        body,
    )
    state = tmp_path / "private.json"
    state.write_text(
        json.dumps(
            {
                "version": 1,
                "engagement_id": policy.engagement_id,
                "owner_id": "owner",
                "policy_revision": "1",
                "flows": {},
            }
        )
    )
    state.chmod(0o600)
    instance = {
        "id": "workflow",
        "actor": "alice",
        "tenant": "owned",
        "session_revision": "1",
        "policy_revision": "1",
        "definition_id": "definition",
        "revision": 2,
    }
    return policy, binding, state, instance


def test_private_scalar_requires_committed_exact_identity_and_unique_variable(tmp_path):
    policy, binding, state, instance = execution(tmp_path)
    reviewed = contract(tmp_path, variable_bindings=(("id", "object"),))
    private = PrivateWorkflowState(state, policy)
    checkpoint = {
        "actor_id": "alice",
        "tenant_id": "owned",
        "policy_revision": "1",
        "definition_id": "definition",
        "produced_revision": 2,
        "values": {"object": "server-owned-id"},
    }
    private.put(instance["id"], checkpoint)
    actual = GraphQLExecution(reviewed, binding, policy, instance, state)
    assert json.loads(actual.body)["variables"]["id"] == "server-owned-id"
    with pytest.raises(ValueError, match="capture_identity"):
        GraphQLExecution(reviewed, replace(binding, actor_id="bob"), policy, instance, state)
    protected = replace(
        binding, _body_tokens=(BodyTokenBinding("json", "/variables/id", 0, "cookie", "csrf"),)
    )
    with pytest.raises(ValueError, match="token_variable_protected"):
        GraphQLExecution(reviewed, protected, policy, instance, state)
    private = PrivateWorkflowState(state, policy)
    private.put(instance["id"], {**checkpoint, "produced_revision": 3})
    with pytest.raises(ValueError, match="not_committed"):
        GraphQLExecution(reviewed, binding, policy, instance, state)


@pytest.mark.parametrize("errors", [None, {}, [], [{"message": "actual API error"}]])
def test_http200_errors_or_malformed_errors_never_become_success(tmp_path, errors):
    policy, binding, state, instance = execution(tmp_path)
    actual = GraphQLExecution(contract(tmp_path), binding, policy, instance, state)
    assert (
        actual.observe(json.dumps({"data": {"read": "value"}, "errors": errors}).encode()) is False
    )


@pytest.mark.parametrize("content_type", ["text/html", "", "application/xml"])
def test_graphql_response_requires_declared_json_mime(tmp_path, content_type):
    policy, binding, state, instance = execution(tmp_path)
    actual = GraphQLExecution(contract(tmp_path), binding, policy, instance, state)
    with pytest.raises(ValueError):
        actual.observe(b'{"data":{"read":"value"}}', content_type=content_type)
