"""Typed/configuration/parser controls; distinct from actual CLI/receiver E2Es."""

import base64
import hashlib
import json
import os
import time
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.oast import OASTAdapter, OASTConfig, OASTDenied, reconcile_oast
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.schema_tools import CAPABILITIES, SchemaToolAdapter, SchemaToolConfig
from redjohn.assessment.store import AssessmentStore
from tests.test_schema_oast_live import reviewed_schema


def config(tool, tmp_path):
    value = {
        "binary": {
            "path": str(tmp_path / "payload"),
            "sha256": "1" * 64,
            "version": {"tinja": "1.2.0", "schemathesis": "4.31.1"}[tool],
        }
    }
    if tool == "schemathesis":
        value.update(reviewed_schema(tmp_path))
    return value


def policy():
    return EngagementPolicy(
        "schema-contract",
        "operator",
        ("https://127.0.0.1:4443",),
        allowed_ips=("127.0.0.1",),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )


@pytest.mark.parametrize("tool", ["tinja", "schemathesis"])
@pytest.mark.parametrize(
    "option,value",
    [
        ("rate_limit", 0),
        ("rate_limit", 11),
        ("request_timeout", 0),
        ("max_requests", 129),
        ("max_requests", True),
        ("extra_args", ["--shell"]),
        ("plugins", "x.py"),
    ],
)
def test_schema_tool_typed_bounds_and_no_arbitrary_cli(tmp_path, tool, option, value):
    with pytest.raises(ValueError):
        SchemaToolConfig.from_mapping(tool, config(tool, tmp_path) | {option: value})


@pytest.mark.parametrize("tool", ["tinja", "schemathesis"])
@pytest.mark.parametrize(
    "change",
    [
        {"method": "POST"},
        {"actor_id": "alice"},
        {"source": "imported"},
        {"url": "https://127.0.0.1:4443/api?id=1&id=2"},
        {"content_type": "application/json"},
        {"request_ref": ""},
    ],
)
def test_schema_tools_refuse_unsupported_captured_inputs(tmp_path, tool, change):
    c = SchemaToolConfig.from_mapping(tool, config(tool, tmp_path))
    surface = replace(
        Surface(
            "https://127.0.0.1:4443/api?id=1",
            input_location="query",
            input_name="id",
            request_ref="a" * 32,
        ),
        **change,
    )
    spec = JobSpec(
        "surface",
        "ssti",
        CAPABILITIES[tool],
        tool_version=c.version,
        template_version=c.revision,
        options={"hint_ref": "b" * 32},
    )
    with pytest.raises(ValueError):
        c.validate_input(policy(), surface, spec)


@pytest.mark.parametrize(
    "mutation",
    ["external_ref", "local_ref", "post", "servers", "links", "security", "oversize_input"],
)
def test_schema_snapshot_cannot_expand_operations_or_load_code(tmp_path, mutation):
    raw = config("schemathesis", tmp_path)
    file = Path(raw["schema_file"])
    data = json.loads(file.read_text())
    operation = data["paths"]["/api"]["get"]
    if mutation == "external_ref":
        operation["parameters"][0]["schema"] = {"$ref": "https://outside.invalid/schema"}
    elif mutation == "local_ref":
        operation["parameters"][0]["schema"] = {"$ref": "file:///etc/passwd"}
    elif mutation == "post":
        data["paths"]["/api"]["post"] = operation
    elif mutation == "servers":
        data["servers"] = [{"url": "https://outside.invalid"}]
    elif mutation == "links":
        operation["responses"]["200"]["links"] = {"follow": {"operationId": "delete"}}
    elif mutation == "security":
        data["security"] = [{"oauth": []}]
    else:
        operation["parameters"][0]["schema"]["maximum"] = 100000
    file.write_text(json.dumps(data))
    raw["schema_sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
    c = SchemaToolConfig.from_mapping("schemathesis", raw)
    with pytest.raises(ValueError):
        c.schema(Surface("https://127.0.0.1:4443/api?id=1", input_name="id"))


@pytest.mark.parametrize("tool", ["tinja", "schemathesis"])
def test_host_mutation_gate_never_accepts_unreviewed_payloads(tmp_path, tool):
    p = policy()
    with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
        store.register(p)
        c = SchemaToolConfig.from_mapping(tool, config(tool, tmp_path))
        adapter = SchemaToolAdapter(c, p, store, rate_limits=None)
        surface = Surface(
            "https://127.0.0.1:4443/api?id=1", input_location="query", input_name="id"
        )
        assert adapter.mutation_allowed(surface, surface.url)
        for query in [
            "id=1&extra=2",
            "id=1&id=2",
            "id=__import__",
            "id=1%00",
            "id=%7B%7Bos.system(1)%7D%7D",
        ]:
            assert not adapter.mutation_allowed(surface, "https://127.0.0.1:4443/api?" + query)


def oast_config(**changes):
    return {
        "receiver_url": "https://127.0.0.1:9443",
        "receiver_ips": ["127.0.0.1"],
        "callback_domain": "owned-oast.test",
        **changes,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"receiver_url": "http://127.0.0.1:9443"},
        {"receiver_url": "https://127.0.0.1:9443/x"},
        {"receiver_ips": []},
        {"callback_domain": "*.oast.test"},
        {"callback_domain": "a..test"},
        {"callback_domain": "outside.test/"},
        {"callback_port": 0},
        {"max_polls": 100},
        {"poll_interval": True},
        {"window_seconds": 600},
        {"window_seconds": 60, "max_polls": 2},
        {"token_file": "relative"},
        {"extra_args": []},
    ],
)
def test_owned_receiver_configuration_is_bounded_and_separate(changes):
    with pytest.raises(ValueError):
        OASTConfig.from_mapping(oast_config(**changes))


def test_receiver_policy_cannot_expand_target_scope():
    p = policy()
    c = OASTConfig.from_mapping(oast_config())
    service = c.service_policy(p)
    assert p.allowed_origins == ("https://127.0.0.1:4443",)
    assert service.allowed_origins == ("https://127.0.0.1:9443",)
    with pytest.raises(ValueError):
        p.check_scope_url(c.receiver_url)


@pytest.mark.parametrize(
    "name", ["tinja_validate", "schemathesis_validate", "oast_correlate", "oast_poll"]
)
async def test_optional_jobs_are_lazy_and_unconfigured_jobs_are_blocked(tmp_path, name):
    p = policy()
    with (
        closing(AssessmentStore(tmp_path / "state/agents.db")) as store,
        patch("asyncio.create_subprocess_exec", side_effect=AssertionError("eager startup")),
    ):
        async with AssessmentRuntime(store, p, caller="operator") as app:
            health = {r["id"]: r for r in app.registry.health()}
            assert health[name]["adapter_implemented"] is True
            assert health[name]["live_verified"] is False
            assert health[name]["status"] in {
                "blocked_configuration",
                "blocked_missing_dependency",
            }
            surface_id = store.upsert_surface(
                p.engagement_id, Surface("https://127.0.0.1:4443/api?id=1")
            )
            spec = JobSpec(surface_id, "oast", name)
            job_id = store.submit(p, [spec])[0]
            await app.scheduler.run_batch(max_jobs=1)
            row = next(r for r in store.jobs(p.engagement_id) if r["id"] == job_id)
            assert row["coverage_status"] == "blocked"
            assert row["result"]["error"]["code"] == name + "_configuration_missing"


def test_fresh_hint_reference_does_not_authorize_repeat_network_probe():
    for name in ["tinja_validate", "schemathesis_validate", "oast_correlate"]:
        a = JobSpec("surface", "test", name, options={"hint_ref": "a" * 32})
        b = replace(a, options={"hint_ref": "b" * 32})
        assert a.key == b.key
        assert replace(a, retest_revision="approved-retest-2").key != a.key


def test_oast_outbox_releases_only_committed_successful_parent_and_deduplicates(tmp_path):
    p, c = policy(), OASTConfig.from_mapping(oast_config())
    with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
        store.register(p)
        OASTAdapter(c, p, store, rate_limits=None)
        surface_id = store.upsert_surface(
            p.engagement_id, Surface("https://127.0.0.1:4443/api?id=1")
        )
        parent = store.submit(p, [JobSpec(surface_id, "oast", "oast_correlate")])[0]
        with store.transaction() as db:
            db.execute(
                "INSERT INTO rj_oast_followup VALUES(?,?,?,?,?,?,0,?)",
                ("a" * 64, p.engagement_id, surface_id, parent, 1, time.time() + 5, c.revision),
            )
        reconcile_oast(store, p, c)
        assert len(store.jobs(p.engagement_id)) == 1
        with store.transaction() as db:
            db.execute("UPDATE rj_job SET execution_status='succeeded' WHERE id=?", (parent,))
        reconcile_oast(store, p, c)
        reconcile_oast(store, p, c)
        rows = store.jobs(p.engagement_id)
        assert len(rows) == 2
        child = next(row for row in rows if row["id"] != parent)
        assert child["ready_at"] > time.time()
        assert child["spec"]["options"] == {"allocation": "a" * 64, "poll_index": 1}


def test_interactsh_private_state_and_correlation_reject_invalid_events(tmp_path):
    p, c = policy(), OASTConfig.from_mapping(oast_config())
    with closing(AssessmentStore(tmp_path / "state/agents.db")) as store:
        store.register(p)
        adapter = OASTAdapter(c, p, store, rate_limits=None)
        with pytest.raises(OASTDenied):
            adapter._file("../escape")
        with pytest.raises(OASTDenied):
            adapter._events({"data": ["invalid-encryption"] * 17}, {})
        with pytest.raises((ValueError, KeyError)):
            adapter._events({"data": None, "extra": [], "tlddata": None}, {})


def test_no_mock_result_is_live_verified():
    assert all(not row["live_verified"] for row in CapabilityRegistry().health())


@pytest.mark.parametrize("budget", [-1, 121, float("inf"), float("nan"), True])
async def test_scheduler_wait_budget_is_real_bounded_and_does_not_submit_jobs(tmp_path, budget):
    p = policy()
    with closing(AssessmentStore(tmp_path / "state/db")) as store:
        async with AssessmentRuntime(store, p, caller="operator") as app:
            with pytest.raises(ValueError, match="invalid_scheduler_drain_budget"):
                await app.scheduler.run_until_idle(wait_seconds=budget)
            assert store.jobs(p.engagement_id) == []


async def test_all_three_configured_adapters_still_do_not_start_together(tmp_path):
    p = policy()
    with (
        closing(AssessmentStore(tmp_path / "state/db")) as store,
        patch(
            "asyncio.create_subprocess_exec", side_effect=AssertionError("eager optional process")
        ),
        patch("socket.create_connection", side_effect=AssertionError("eager network")),
    ):
        async with AssessmentRuntime(
            store,
            p,
            caller="operator",
            tinja_config=config("tinja", tmp_path),
            schemathesis_config=config("schemathesis", tmp_path),
            interactsh_config=oast_config(),
        ) as app:
            assert {
                "tinja_validate",
                "schemathesis_validate",
                "oast_correlate",
                "oast_poll",
            } <= app.scheduler.adapters.keys()
            assert app.governor.snapshot()["reserved_bytes"] == 0


@pytest.mark.parametrize(
    "field,value",
    [("content", None), ("required", None), ("properties", []), ("description", "changed")],
)
def test_malformed_reviewed_schema_is_an_explicit_input_error(tmp_path, field, value):
    raw = config("schemathesis", tmp_path)
    file = Path(raw["schema_file"])
    data = json.loads(file.read_text())
    response = data["paths"]["/api"]["get"]["responses"]["200"]
    if field in {"required", "properties"}:
        response["content"]["application/json"]["schema"][field] = value
    else:
        response[field] = value
    file.write_text(json.dumps(data))
    raw["schema_sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
    c = SchemaToolConfig.from_mapping("schemathesis", raw)
    with pytest.raises(ValueError):
        c.schema(Surface("https://127.0.0.1:4443/api?id=1", input_name="id"))


@pytest.mark.parametrize(
    "fault",
    ["valid", "empty", "wrong-id", "wrong-path", "expired", "other-protocol", "wrong-aes-key"],
)
def test_synthetic_protocol_crypto_controls_are_separate_from_real_receiver_e2e(tmp_path, fault):
    p, c = policy(), OASTConfig.from_mapping(oast_config())
    with closing(AssessmentStore(tmp_path / "state/db")) as store:
        store.register(p)
        adapter = OASTAdapter(c, p, store, rate_limits=None)
        surface = Surface("https://127.0.0.1:4443/api?id=1")
        spec = JobSpec("surface", "oast", "oast_correlate")
        adapter._file(spec.key)
        state = adapter._new(spec.key, surface, spec)
        state["dispatch_at"] = time.time() - 0.1
        key = serialization.load_pem_private_key(state["private"].encode(), password=None)
        aes, iv = os.urandom(32), os.urandom(16)
        item = {
            "unique-id": state["full_id"],
            "full-id": state["full_id"],
            "protocol": "http",
            "timestamp": datetime.now(UTC).isoformat(),
            "raw-request": "GET /rj/" + state["nonce"] + " HTTP/1.1\r\nHost: fixture\r\n\r\n",
        }
        if fault == "wrong-id":
            item["unique-id"] = "another-identifier"
        elif fault == "wrong-path":
            item["raw-request"] = "GET /not-the-nonce HTTP/1.1\r\n"
        elif fault == "expired":
            item["timestamp"] = "2000-01-01T00:00:00Z"
        elif fault == "other-protocol":
            item["protocol"] = "dns"
        encryptor = Cipher(algorithms.AES(aes), modes.CTR(iv)).encryptor()
        encrypted = iv + encryptor.update(json.dumps(item).encode()) + encryptor.finalize()
        encrypted_key = key.public_key().encrypt(
            aes if fault != "wrong-aes-key" else b"bad-key",
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        payload = {
            "data": None if fault == "empty" else [base64.b64encode(encrypted).decode()],
            "aes_key": base64.b64encode(encrypted_key).decode(),
            "extra": [],
            "tlddata": None,
        }
        if fault in {"valid", "empty"}:
            events = adapter._events(payload, state)
            assert len(events) == (1 if fault == "valid" else 0)
            assert all(event["impact"] == "callback_only_execution_unproven" for event in events)
        else:
            with pytest.raises(ValueError):
                adapter._events(payload, state)
