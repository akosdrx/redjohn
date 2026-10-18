"""Real broker/TCP/SQLite contracts and synthetic Nmap parser/proof contracts.

No synthetic engine reply is claimed as native Nmap integration evidence.
"""

import asyncio
import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment
from redjohn.assessment.models import AdapterResult, JobSpec
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.service_broker import HTTP_SERVICE_PROBE, ObservedServiceBroker
from redjohn.assessment.service_tools import (
    NMAP_LICENSE_SHA256,
    NMAP_VERSION,
    PROBE_SHA256,
    SERVICE_PROBES,
    NmapServiceAdapter,
    NmapServiceConfig,
    NmapServiceRunner,
    require_open_observation,
)
from tests.test_network_broker_contract import close_stream, owned_job


def service_config(tmp_path):
    binary = tmp_path / "nmap"
    binary.write_bytes(b"synthetic-contract-binary-never-executed")
    return {
        "binary": {
            "path": str(binary),
            "version": NMAP_VERSION,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        },
        "external_operator_install": True,
        "license_sha256": NMAP_LICENSE_SHA256,
    }


async def test_optional_service_runtime_does_not_launch_external_engine_or_browser(tmp_path):
    selected = service_config(tmp_path)
    document = {
        "policy": {
            "engagement_id": "optional-service",
            "owner_id": "owner",
            "allowed_origins": [],
            "target_domains": ["network"],
            "profile": "isolated-lab",
            "allowed_networks": ["127.0.0.1/32"],
            "allowed_tcp_ports": ["9000"],
            "network_request_budget": 16,
            "egress_mode": "unavailable",
        },
        "nmap": selected,
    }
    async with ConfiguredAssessment(document, tmp_path / "run", caller="owner") as assessment:
        adapter = assessment.runtime.scheduler.adapters["nmap_services"]
        assert adapter.runner.process is None and adapter.runner.broker is None
        assert assessment.runtime.governor.snapshot()["active"] == {}
        assert assessment.store.jobs(assessment.policy.engagement_id) == []
        assert (
            assessment.runtime.registry.execution_versions("nmap_services")["tool_version"]
            == NMAP_VERSION
        )


async def test_service_health_rejects_lua_build_even_without_explicit_nse_cli(
    tmp_path, monkeypatch
):
    """Synthetic native version reply; does not claim engine execution."""
    config = NmapServiceConfig.from_mapping(service_config(tmp_path))
    runner = NmapServiceRunner(config, tmp_path / "workers")

    async def version_reply(_argv, _timeout):
        return {
            "exit_code": 0,
            "stdout": "Nmap version 7.992\nCompiled with: liblua\nCompiled without: openssl\n",
        }

    monkeypatch.setattr(runner, "execute", version_reply)
    with pytest.raises(ValueError, match="nse_exclusion"):
        await runner.healthcheck()


@pytest.mark.parametrize("kind", ["ssh", "http", "forbidden"])
async def test_actual_service_broker_fences_exact_probe_and_records_upstream_bytes(  # noqa: PLR0915 - owned target and cancellation lifecycle
    tmp_path, kind
):
    requests = []

    async def target(reader, writer):
        try:
            if kind == "ssh":
                writer.write(b"SSH-2.0-OwnedFixture\r\n")
                await writer.drain()
                await reader.read()
            else:
                try:
                    data = await reader.readexactly(len(HTTP_SERVICE_PROBE))
                except asyncio.IncompleteReadError as exc:
                    data = exc.partial
                requests.append(data)
                if data == HTTP_SERVICE_PROBE:
                    writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
        finally:
            await close_stream(writer)

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    store, policy, surface, job = owned_job(tmp_path, port)
    broker = ObservedServiceBroker(policy, store, surface, job)
    address = await broker.start()
    reader, writer = await asyncio.open_connection(*address.rsplit(":", 1))
    try:
        writer.write(broker.preamble)
        if kind == "http":
            # Split input also tests exact prefix assembly across TCP chunks.
            writer.write(HTTP_SERVICE_PROBE[:4])
            await writer.drain()
            writer.write(HTTP_SERVICE_PROBE[4:])
            await writer.drain()
        elif kind == "forbidden":
            writer.write(b"POST /private HTTP/1.0\r\n\r\n")
        await writer.drain()
        if kind == "ssh":
            assert await asyncio.wait_for(reader.readuntil(b"\n"), 1) == b"SSH-2.0-OwnedFixture\r\n"
        elif kind == "forbidden":
            assert await asyncio.wait_for(reader.read(), 1) == b""
        else:
            assert (await asyncio.wait_for(reader.read(), 1)).startswith(b"HTTP/1.0 200 OK")
        await close_stream(writer)
        await broker.close()
        if kind == "forbidden":
            assert broker.denied == 1 and not broker.response_bytes
            assert requests == [b""]
        else:
            assert broker.denied == 0
            assert kind in broker.banner_types and broker.response_bytes > 0
            assert len(broker.response_digests) == 1
        assert store.network_request_usage(policy) == (2 if kind == "http" else 1)
        assert broker.closed and not broker.tasks and not broker.writers
    finally:
        await close_stream(writer)
        await broker.close()
        server.close()
        await server.wait_closed()
        store.close()


async def test_service_nonce_denial_cannot_create_real_upstream_or_proof(tmp_path):
    accepted = []

    async def target(_reader, writer):
        accepted.append(True)
        await close_stream(writer)

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    store, policy, surface, job = owned_job(tmp_path, server.sockets[0].getsockname()[1])
    broker = ObservedServiceBroker(policy, store, surface, job)
    address = await broker.start()
    reader, writer = await asyncio.open_connection(*address.rsplit(":", 1))
    try:
        writer.write(b"x" * len(broker.preamble))
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 1) == b""
        assert not accepted and broker.attempted == broker.response_bytes == 0
        assert store.network_request_usage(policy) == 0
    finally:
        await close_stream(writer)
        await broker.close()
        server.close()
        await server.wait_closed()
        store.close()


def test_service_profile_uses_only_fixed_reviewed_probes_and_no_discovery_claim(tmp_path):
    config = NmapServiceConfig.from_mapping(service_config(tmp_path))
    runner = NmapServiceRunner(config, tmp_path / "workers")
    runner.data_root, runner.proxy_address = tmp_path / "data", "127.0.0.1:23456"
    argv = runner.argv()
    assert argv[-1] == "127.0.0.1"
    assert argv[argv.index("-p") + 1] == "23456"
    assert "-sT" in argv and "-sV" in argv and "--unprivileged" in argv
    assert argv[argv.index("--versiondb") + 1] == str(runner.data_root / "nmap-service-probes")
    assert argv[argv.index("--version-intensity") + 1] == "1"
    assert not any(flag in argv for flag in ("--script", "-sC", "-sU", "-O", "--proxies"))
    assert hashlib.sha256(SERVICE_PROBES).hexdigest() == PROBE_SHA256
    assert SERVICE_PROBES.count(b"Probe TCP ") == 2
    with pytest.raises(ValueError, match="license"):
        NmapServiceConfig.from_mapping({**service_config(tmp_path), "license_sha256": "a" * 64})


def nmap_xml(service="ssh", version="2.0"):
    return (
        '<!DOCTYPE nmaprun><nmaprun><host><ports><port protocol="tcp" portid="23456">'
        '<state state="open"/><service name="'
        + service
        + '" method="probed" product="SSH service" version="'
        + version
        + '"/>'
        '</port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
    )


def test_service_parser_requires_real_matching_upstream_and_never_uses_local_port_state(tmp_path):
    store, policy, _surface, _job = owned_job(tmp_path, 9000)
    config = NmapServiceConfig.from_mapping(service_config(tmp_path))
    adapter = NmapServiceAdapter(config, policy, store)
    adapter.runner.proxy_address = "127.0.0.1:23456"
    broker = SimpleNamespace(denied=0, response_bytes=0, response_digests=[], banner_types=set())
    raw = {"stdout": nmap_xml(), "exit_code": 0}
    try:
        assert adapter.normalize(raw, broker).coverage_status == "inconclusive"
        broker.response_bytes, broker.response_digests = 24, ["a" * 64]
        broker.banner_types = {"http"}
        result = adapter.normalize(raw, broker)
        assert result.coverage_status == "partial" and not result.summary["service_observed"]
        broker.banner_types = {"ssh"}
        result = adapter.normalize(raw, broker)
        assert result.coverage_status == "partial" and result.summary["service_observed"]
        assert "state" not in result.summary["service"] and not result.findings
        with pytest.raises(ValueError, match="xml_extension"):
            adapter.normalize({**raw, "stdout": '<!DOCTYPE nmaprun [<!ENTITY x "boom">]>'}, broker)
        with pytest.raises(ValueError, match="invalid_xml"):
            adapter.normalize({**raw, "stdout": "<nmaprun><broken>"}, broker)
    finally:
        store.close()


def test_open_observation_must_be_same_current_completed_native_job_and_exact_endpoint(tmp_path):
    """Synthetic producer result checks immutable SQL authority; not native E2E."""
    store, policy, surface, job = owned_job(tmp_path, 9000)
    try:
        with pytest.raises(PolicyDenied):
            require_open_observation(store, policy, surface, "not-present")
        proof = {
            "tool": "naabu",
            "tool_version": "2.6.1",
            "connected": 1,
            "refused": 0,
            "observation": {
                "address": surface.network_address,
                "port": surface.network_port,
                "state": "open",
            },
        }
        ref = store.evidence_put(
            policy.engagement_id, proof, job_id=job["id"], kind="naabu_network"
        )
        with pytest.raises(PolicyDenied):
            require_open_observation(store, policy, surface, ref)  # producer still running
        store.finish(job, AdapterResult("succeeded", "completed", summary={"evidence_refs": [ref]}))
        require_open_observation(store, policy, surface, ref)
        with pytest.raises(PolicyDenied):
            require_open_observation(
                store, policy, replace(surface, network_address="127.0.0.2"), ref
            )
        with store.transaction() as db:
            db.execute("UPDATE rj_evidence SET created_at=created_at-301 WHERE id=?", (ref,))
        with pytest.raises(PolicyDenied):
            require_open_observation(store, policy, surface, ref)
    finally:
        store.close()


async def test_service_health_failure_is_blocked_capability_not_closed_port_control(tmp_path):
    """Synthetic producer/health only; actual SQL prerequisite and cleanup."""
    store, policy, surface, producer = owned_job(tmp_path, 9000)
    config = NmapServiceConfig.from_mapping(service_config(tmp_path))
    proof = {
        "tool": "naabu",
        "tool_version": "2.6.1",
        "connected": 1,
        "refused": 0,
        "observation": {
            "address": surface.network_address,
            "port": surface.network_port,
            "state": "open",
        },
    }
    ref = store.evidence_put(
        policy.engagement_id, proof, job_id=producer["id"], kind="naabu_network"
    )
    store.finish(
        producer, AdapterResult("succeeded", "completed", summary={"evidence_refs": [ref]})
    )
    adapter = NmapServiceAdapter(config, policy, store)

    class FailingHealth:
        async def prepare_service(self, broker):
            self.broker = broker

        async def healthcheck(self):
            raise ValueError("synthetic_wrong_nse_build")

        async def cleanup(self):
            await self.broker.close()

    adapter.runner = FailingHealth()
    surface = replace(surface, input_name=config.revision)
    spec = JobSpec(
        "synthetic-source",
        "service_identification",
        "nmap_services",
        tool_version=config.version,
        template_version=config.revision,
        options={"open_evidence_ref": ref},
    )
    try:
        result = await adapter.run({"id": "synthetic-health"}, surface, spec)
        assert result.coverage_status == "blocked" and result.execution_status == "failed"
        assert result.error["coverage_effect"] == "blocked"
        assert adapter.runner.broker.attempted == 0 and adapter.runner.broker.closed
    finally:
        store.close()
