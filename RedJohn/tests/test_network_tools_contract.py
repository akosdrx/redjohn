"""Native argument/config/output contracts; no scanner is impersonated as live."""

import asyncio
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from redjohn.assessment.configuration import ConfiguredAssessment, enqueue_configured_jobs
from redjohn.assessment.models import AdapterResult, JobSpec, Surface
from redjohn.assessment.network_tools import (
    VERSIONS,
    NetworkToolAdapter,
    NetworkToolConfig,
    NetworkToolRunner,
)
from redjohn.assessment.store import EvidenceWriteError
from tests.test_network_broker_contract import close_stream, owned_job, socks_connect


def binary_config(tmp_path, tool):
    binary = tmp_path / tool
    binary.write_bytes(b"contract-only-never-executed")
    return {
        "binary": {
            "path": str(binary),
            "version": VERSIONS[tool],
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
    }


@pytest.mark.parametrize("tool", ["naabu", "dnsx"])
def test_network_configuration_requires_exact_reviewed_version_and_no_extra_flags(tmp_path, tool):
    value = binary_config(tmp_path, tool)
    config = NetworkToolConfig.from_mapping(tool, value)
    assert config.version == VERSIONS[tool]
    with pytest.raises(ValueError):
        NetworkToolConfig.from_mapping(tool, {**value, "flags": ["--unsafe"]})
    value["binary"]["version"] = "unreviewed"
    with pytest.raises(ValueError):
        NetworkToolConfig.from_mapping(tool, value)


@pytest.mark.parametrize("tool", ["naabu", "dnsx"])
def test_network_fixed_arguments_use_explicit_single_tuple_and_scoped_socks(tmp_path, tool):
    config = NetworkToolConfig.from_mapping(tool, binary_config(tmp_path, tool))
    runner = NetworkToolRunner(config, tmp_path / "workers")
    store, _policy, surface, _job = owned_job(tmp_path, 9000, dns=tool == "dnsx")
    try:
        runner.broker = SimpleNamespace(nonce="owned-nonce")
        runner.workspace = tmp_path
        runner.proxy_address = "127.0.0.1:9001"
        argv = runner.argv(surface)
        assert argv[0] == str(config.binary.path)
        assert "-duc" in argv
        for excluded in [
            "-nmap",
            "-nmap-cli",
            "-passive",
            "-ping",
            "-sU",
            "-trace",
            "-auto-wildcard",
            "-all",
            "-asn",
            "-update",
        ]:
            assert excluded not in argv
        if tool == "naabu":
            assert argv[argv.index("-s") + 1] == "c"
            assert argv[argv.index("-p") + 1] == "9000"
            assert argv[argv.index("-host") + 1] == "127.0.0.1"
            assert "-stream" in argv and "-Pn" in argv
        else:
            assert argv[argv.index("-proxy") + 1].startswith("socks5://redjohn:owned-nonce@")
            assert argv[argv.index("-r") + 1] == "127.0.0.1:9000"
            assert Path(argv[argv.index("-l") + 1]).read_text() == "owned.test\n"
    finally:
        store.close()


def test_no_network_budget_or_partial_scan_cannot_be_reported_clean(tmp_path):
    config = NetworkToolConfig.from_mapping("naabu", binary_config(tmp_path, "naabu"))
    store, policy, surface, _job = owned_job(tmp_path, 9000)
    try:
        adapter = NetworkToolAdapter(config, policy, store)
        broker = SimpleNamespace(denied=0, attempted=0, connected=0, refused=0)
        result = adapter.normalize(
            {"id": "test"}, surface, {"exit_code": 0, "stdout": ""}, broker, 0.1
        )
        assert result.coverage_status == "inconclusive"
        broker.attempted = broker.connected = 1
        with pytest.raises(ValueError, match="result_mismatch"):
            adapter.normalize({"id": "test"}, surface, {"exit_code": 0, "stdout": ""}, broker, 0.1)
        denied = adapter.normalize({"id": "test"}, surface, {}, SimpleNamespace(denied=1), 0.1)
        assert denied.coverage_status == "blocked"
    finally:
        store.close()


def test_network_surface_never_accepts_http_or_implicit_port_identity():
    for fields in [
        {"url": "https://owned.test", "network_port": "443"},
        {"url": "", "network_port": "0443"},
        {"url": "", "network_port": "0"},
    ]:
        with pytest.raises(ValueError):
            Surface(
                resource_kind="network_endpoint",
                asset_ref="a" * 64,
                network_address="127.0.0.1",
                input_location="network_endpoint",
                **fields,
            )


async def test_configured_network_queue_uses_real_assets_and_preserves_restart_identity(tmp_path):
    config = {
        "policy": {
            "engagement_id": "config-network",
            "owner_id": "owner",
            "allowed_origins": [],
            "target_domains": ["network"],
            "profile": "isolated-lab",
            "allowed_networks": ["127.0.0.1/32"],
            "allowed_tcp_ports": ["9000"],
            "network_request_budget": 8,
        },
        "naabu": binary_config(tmp_path, "naabu"),
        "network_jobs": [{"capability": "naabu_ports", "address": "127.0.0.1", "port": "9000"}],
    }
    output = tmp_path / "assessment"
    async with ConfiguredAssessment(config, output, caller="owner") as first:
        enqueue_configured_jobs(first.runtime, first.store, first.policy, config)
        rows = first.store.jobs(first.policy.engagement_id)
        assert len(rows) == 1 and rows[0]["execution_status"] == "queued"
        job_id = rows[0]["id"]
        surface = first.store.surface(first.policy.engagement_id, rows[0]["surface_id"])
        assert surface.url == "" and surface.resource_kind == "network_endpoint"
        asset = first.store.inventory.asset(first.policy, surface.asset_ref)
        assert asset["kind"] == "ip_address" and asset["locator"] == "127.0.0.1"
        assert first.runtime.scheduler.adapters["naabu_ports"].runner.process is None
        assert first.store.network_request_usage(first.policy) == 0
    async with ConfiguredAssessment(config, output, caller="owner") as restarted:
        enqueue_configured_jobs(restarted.runtime, restarted.store, restarted.policy, config)
        rows = restarted.store.jobs(restarted.policy.engagement_id)
        assert len(rows) == 1 and rows[0]["id"] == job_id
        invalid = {**config, "jobs": [{"capability": "not-reviewed"}]}
        with pytest.raises(ValueError):
            enqueue_configured_jobs(restarted.runtime, restarted.store, restarted.policy, invalid)
        assert len(restarted.store.jobs(restarted.policy.engagement_id)) == 1


@pytest.mark.parametrize("fault", ["parser", "cancel", "evidence-quota"])
async def test_fault_driver_preserves_actual_transport_proof_or_surfaces_storage_failure(  # noqa: PLR0915 - fault lifecycle with real socket cleanup
    tmp_path, fault
):
    """Synthetic engine output only; real broker/TCP/SQLite and cancellation."""

    async def target(reader, writer):
        await reader.read()
        await close_stream(writer)

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    config = NetworkToolConfig.from_mapping("naabu", binary_config(tmp_path, "naabu"))
    store, policy, surface, old_job = owned_job(tmp_path, port)
    store.finish(old_job, AdapterResult("failed", "blocked"))
    surface = replace(surface, input_name=config.revision)
    sid = store.upsert_surface(policy.engagement_id, surface)
    spec = JobSpec(
        sid,
        "network_test",
        "naabu_ports",
        tool_version=config.version,
        template_version=config.revision,
        policy_revision=policy.revision,
    )
    store.submit(policy, [spec])
    job = store.claim(policy, "fault-driver", lease_seconds=30)
    adapter = NetworkToolAdapter(config, policy, store)
    connected = asyncio.Event()

    class FaultEngineRunner:
        async def prepare_network(self, broker):
            self.broker = broker
            self.address = await broker.start()

        async def healthcheck(self):
            return {"synthetic": "not-an-engine-health-proof"}

        def argv(self, _surface):
            return []

        async def execute(self, _argv, _timeout):
            _reader, writer, reply = await socks_connect(self.address, self.broker)
            await close_stream(writer)
            assert reply[1] == 0
            connected.set()
            if fault == "cancel":
                await asyncio.sleep(10)
            return {"exit_code": 0, "stdout": "synthetic-invalid-json"}

        async def cleanup(self):
            await self.broker.close()

    driver = FaultEngineRunner()
    adapter.runner = driver
    if fault == "evidence-quota":
        store.evidence_quota_bytes = 1
    task = asyncio.create_task(adapter.run(job, surface, spec))
    try:
        if fault == "cancel":
            await asyncio.wait_for(connected.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif fault == "evidence-quota":
            with pytest.raises(EvidenceWriteError):
                await task
        else:
            result = await task
            assert result.coverage_status == "inconclusive"
            assert result.error["partial_evidence_refs"] == list(adapter.partial_evidence_refs)
        assert driver.broker.closed and not driver.broker.tasks
        assert store.network_request_usage(policy) == 1
        if fault != "evidence-quota":
            assert len(adapter.partial_evidence_refs) == 1
            preview = store.evidence_get(policy.engagement_id, adapter.partial_evidence_refs[0])
            proof = json.loads(preview["excerpt"])
            assert proof["connect_attempts"] == proof["connected"] == 1
            assert proof["admission_closed"] is True
            assert driver.broker.nonce not in preview["excerpt"]
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await driver.cleanup()
        server.close()
        await server.wait_closed()
        store.close()
