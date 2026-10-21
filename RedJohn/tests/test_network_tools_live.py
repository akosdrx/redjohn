"""Real pinned native scanners, owned TCP/DNS targets, namespace and SQLite E2E.

Required CI mode turns missing Linux engines/isolation into failures, never passes.
"""

import asyncio
import hashlib
import ipaddress
import json
import os
import platform
import struct
import sys
from pathlib import Path

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment, enqueue_configured_jobs
from redjohn.assessment.network_broker import ScopedTCPBroker, question
from redjohn.assessment.network_observation import service_observations
from redjohn.assessment.network_scope import endpoint
from redjohn.assessment.network_tools import VERSIONS, NetworkToolConfig, NetworkToolRunner
from tests.test_network_broker_contract import close_stream, owned_job


def installed_pin(tool):
    root = Path(__file__).resolve().parents[1] / ".tools" / tool / VERSIONS[tool]
    binary = root / tool
    if (
        platform.system() != "Linux"
        or not binary.is_file()
        or not (root / "receipt.json").is_file()
    ):
        message = "blocked_missing_dependency: reviewed Linux network scanner installation required"
        if os.environ.get("REDJOHN_REQUIRE_NETWORK_SCANNER_E2E") == "1":
            pytest.fail(message)
        pytest.skip(message)
    receipt = json.loads((root / "receipt.json").read_text())
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert receipt["binary_sha256"] == digest
    assert receipt["version"] == VERSIONS[tool]
    return {"path": str(binary), "sha256": digest, "version": VERSIONS[tool]}


def assessment_config(tool, binary, port, *, query_type="A"):
    dns = tool == "dnsx"
    policy = {
        "engagement_id": "owned-native-" + tool,
        "owner_id": "owner",
        "allowed_origins": [],
        "target_domains": ["network"],
        "profile": "isolated-lab",
        "network_request_budget": 64,
        "egress_mode": "unavailable",
    }
    if dns:
        policy.update(
            allowed_dns_zones=["owned.test"],
            allowed_dns_resolvers=[endpoint("127.0.0.1", str(port))],
        )
    else:
        policy.update(allowed_networks=["127.0.0.1/32"], allowed_tcp_ports=[str(port)])
    job = {
        "capability": "dnsx_resolve" if dns else "naabu_ports",
        "address": "127.0.0.1",
        "port": str(port),
        "timeout_seconds": 20,
    }
    if dns:
        job.update(name="owned.test", query_type=query_type)
    return {
        "policy": policy,
        "resources": {"total_memory_budget": 2 * 1024**3, "max_workers": 1},
        tool: {"binary": binary},
        "network_jobs": [job],
    }


async def scheduled_result(config, output):
    async with ConfiguredAssessment(config, output, caller="owner") as assessment:
        enqueue_configured_jobs(assessment.runtime, assessment.store, assessment.policy, config)
        rows = assessment.store.jobs(assessment.policy.engagement_id)
        assert len(rows) == 1
        job_id = rows[0]["id"]
        surface = assessment.store.surface(assessment.policy.engagement_id, rows[0]["surface_id"])
        assert surface.url == ""
        assert await assessment.runtime.scheduler.run_batch(max_jobs=1) == [job_id]
        row = assessment.store.jobs(assessment.policy.engagement_id)[0]
        assert row["execution_status"] == "succeeded", row
        assert row["coverage_status"] == "completed", row
        result = row["result"] if isinstance(row["result"], dict) else json.loads(row["result"])
        assert result["summary"]["requests"] == 0
        assert assessment.store.request_usage(assessment.policy) == 0
        used = assessment.store.network_request_usage(assessment.policy)
        assert used >= 1
        assert assessment.runtime.governor.snapshot()["active"] == {}
        for adapter in assessment.runtime.scheduler.adapters.values():
            if isinstance(getattr(adapter, "runner", None), NetworkToolRunner):
                assert adapter.runner.process is None
                assert adapter.runner.broker is None
                assert not list(adapter.runner.root.glob("job-*"))
                assert not list(adapter.runner.root.glob("payload-*"))
    async with ConfiguredAssessment(config, output, caller="owner") as reopened:
        enqueue_configured_jobs(reopened.runtime, reopened.store, reopened.policy, config)
        assert await reopened.runtime.scheduler.run_batch(max_jobs=1) == []
        rows = reopened.store.jobs(reopened.policy.engagement_id)
        assert len(rows) == 1 and rows[0]["id"] == job_id and rows[0]["attempt"] == 1
        assert reopened.store.network_request_usage(reopened.policy) == used
    return result["summary"]


@pytest.mark.parametrize("open_port", [True, False], ids=["open", "closed"])
async def test_real_naabu_tcp_connect_owned_target_and_durable_restart(tmp_path, open_port):
    binary = installed_pin("naabu")
    accepted = []

    async def target(reader, writer):
        accepted.append(True)
        await reader.read()
        await close_stream(writer)

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    if not open_port:
        server.close()
        await server.wait_closed()
    try:
        config = assessment_config("naabu", binary, port)
        summary = await scheduled_result(config, tmp_path / "run")
        assert summary["observation"]["state"] == ("open" if open_port else "closed_or_unreachable")
        assert summary["connected"] == (1 if open_port else 0)
        assert summary["refused"] == (0 if open_port else 1)
        assert len(accepted) == (1 if open_port else 0)
        async with ConfiguredAssessment(config, tmp_path / "run", caller="owner") as verify:
            services = verify.store.inventory.services(verify.policy)
            assert len(services) == 1
            assert services[0]["source"] == ("observed" if open_port else "imported")
            obs = service_observations(verify.store, verify.policy)
            assert len(obs) == (1 if open_port else 0)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("kind", ["A", "AAAA", "CNAME", "NXDOMAIN"])
async def test_real_dnsx_scoped_tcp_dns_and_durable_restart(tmp_path, kind):
    binary = installed_pin("dnsx")
    observed = []
    qtype = "A" if kind == "NXDOMAIN" else kind

    async def resolver(reader, writer):
        try:
            size = struct.unpack("!H", await reader.readexactly(2))[0]
            name, query_type, clean = question(await reader.readexactly(size))
            observed.append((name, query_type))
            flags = 0x8183 if kind == "NXDOMAIN" else 0x8180
            reply = (
                clean[:2]
                + struct.pack("!5H", flags, 1, 0 if kind == "NXDOMAIN" else 1, 0, 0)
                + clean[12:]
            )
            if kind != "NXDOMAIN":
                rtype, payload = (
                    (1, ipaddress.ip_address("127.0.0.42").packed)
                    if kind == "A"
                    else (
                        (28, ipaddress.ip_address("::1").packed)
                        if kind == "AAAA"
                        else (5, b"\x05alias\x05owned\x04test\0")
                    )
                )
                reply += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(payload)) + payload
            writer.write(struct.pack("!H", len(reply)) + reply)
            await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            await close_stream(writer)

    server = await asyncio.start_server(resolver, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        summary = await scheduled_result(
            assessment_config("dnsx", binary, port, query_type=qtype), tmp_path / "run"
        )
        assert observed == [("owned.test", qtype)]
        expected = {
            "A": ["127.0.0.42"],
            "AAAA": ["::1"],
            "CNAME": ["alias.owned.test"],
            "NXDOMAIN": [],
        }[kind]
        assert [value.rstrip(".") for value in summary["observation"]["answers"]] == expected
        assert summary["observation"]["execution_grant"] is False
        assert summary["observation"]["rcodes"] == ([3] if kind == "NXDOMAIN" else [0])
    finally:
        server.close()
        await server.wait_closed()


async def test_real_dnsx_cancel_cleans_owned_broker_namespace_and_process(tmp_path):
    binary = installed_pin("dnsx")
    received, disconnected = asyncio.Event(), asyncio.Event()

    async def resolver(reader, writer):
        try:
            size = struct.unpack("!H", await reader.readexactly(2))[0]
            await reader.readexactly(size)
            received.set()
            await reader.read()
        except asyncio.IncompleteReadError:
            pass
        finally:
            await close_stream(writer)
            disconnected.set()

    server = await asyncio.start_server(resolver, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    config = assessment_config("dnsx", binary, port)
    try:
        async with ConfiguredAssessment(config, tmp_path / "run", caller="owner") as assessment:
            assessment.runtime.scheduler.lease_seconds = 0.3
            enqueue_configured_jobs(assessment.runtime, assessment.store, assessment.policy, config)
            row = assessment.store.jobs(assessment.policy.engagement_id)[0]
            task = asyncio.create_task(assessment.runtime.scheduler.run_batch(max_jobs=1))
            try:
                await asyncio.wait_for(received.wait(), 15)
                assessment.store.cancel(assessment.policy.engagement_id, row["id"])
                await asyncio.wait_for(task, 10)
                final = assessment.store.jobs(assessment.policy.engagement_id)[0]
                assert final["execution_status"] == "cancelled", final
                await asyncio.wait_for(disconnected.wait(), 3)
                assert assessment.runtime.governor.snapshot()["active"] == {}
                runner = assessment.runtime.scheduler.adapters["dnsx_resolve"].runner
                assert runner.process is None and runner.broker is None
                assert not list(runner.root.glob("job-*"))
                assert not list(runner.root.glob("payload-*"))
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    finally:
        server.close()
        await server.wait_closed()


class BoundaryProbeRunner(NetworkToolRunner):
    probe_port = 0

    def _worker_argv(self, argv):
        if argv[1:] != ["__owned_boundary_probe__"]:
            return argv
        program = """import json,socket,sys
blocked=False
try:
 socket.create_connection(('127.0.0.1',int(sys.argv[1])),1).close()
except OSError:
 blocked=True
raw=False
try:
 socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP).close()
except PermissionError:
 raw=True
print(json.dumps({'direct_connect_blocked':blocked,'raw_socket_blocked':raw}))
"""
        return [sys.executable, "-I", "-S", "-c", program, str(self.probe_port)]


async def test_real_namespace_blocks_direct_target_and_raw_socket_bypass(tmp_path):
    binary = installed_pin("naabu")
    accepted = []

    async def target(_reader, writer):
        accepted.append(True)
        await close_stream(writer)

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    store, policy, surface, job = owned_job(tmp_path, port)
    config = NetworkToolConfig.from_mapping("naabu", {"binary": binary})
    runner = BoundaryProbeRunner(config, tmp_path / "workers")

    # Trusted fixed test code, never a public tool's argv or script input.
    runner.probe_port = port
    try:
        await runner.prepare_network(ScopedTCPBroker(policy, store, surface, job))
        result = await runner.execute([str(runner.binary.path), "__owned_boundary_probe__"], 5)
        assert result.get("exit_code") == 0, result
        assert json.loads(result["stdout"]) == {
            "direct_connect_blocked": True,
            "raw_socket_blocked": True,
        }
        assert accepted == []
        assert store.network_request_usage(policy) == 0
    finally:
        await runner.cleanup()
        server.close()
        await server.wait_closed()
        store.close()
