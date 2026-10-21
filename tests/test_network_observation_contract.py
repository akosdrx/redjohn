"""Real SQLite/broker/inventory contracts for native network/service observation promotion.

Synthetic native outputs test proof validation, sealing and atomic completion
without claiming live native binary execution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from redjohn.assessment.egress import LinuxEgressBoundary
from redjohn.assessment.models import AdapterResult, JobSpec
from redjohn.assessment.network_broker import ScopedTCPBroker
from redjohn.assessment.network_observation import (
    NativeObservationCollector,
    NetworkProofDenied,
    parse_native,
    service_observations,
)
from redjohn.assessment.network_tools import NetworkToolConfig, NetworkToolRunner
from redjohn.assessment.service_broker import HTTP_SERVICE_PROBE, ObservedServiceBroker
from redjohn.assessment.service_tools import (
    NMAP_LICENSE_SHA256,
    NMAP_VERSION,
    PROBE_SHA256,
    NmapServiceConfig,
    NmapServiceRunner,
)
from tests.test_network_broker_contract import owned_job


def _attested_boundary(tmp_path):
    boundary = LinuxEgressBoundary("http://127.0.0.1:9", tmp_path)
    boundary._verified = True
    boundary._attestations.append(
        {
            "interfaces": ["lo"],
            "effective_capabilities": "0",
            "no_new_privileges": True,
            "namespaces": {
                "net": "net:[1]",
                "mnt": "mnt:[1]",
                "pid": "pid:[1]",
                "user": "user:[1]",
            },
        }
    )
    return boundary


def _naabu_runner(tmp_path):
    binary = tmp_path / "naabu"
    binary.write_bytes(b"synthetic-naabu-contract-binary")
    config = NetworkToolConfig.from_mapping(
        "naabu",
        {
            "binary": {
                "path": str(binary),
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "version": "2.6.1",
            }
        },
    )
    return NetworkToolRunner(config, tmp_path / "naabu-workers")


def _nmap_runner(tmp_path):
    binary = tmp_path / "nmap"
    binary.write_bytes(b"synthetic-nmap-contract-binary")
    config = NmapServiceConfig.from_mapping(
        {
            "binary": {
                "path": str(binary),
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "version": NMAP_VERSION,
            },
            "external_operator_install": True,
            "license_sha256": NMAP_LICENSE_SHA256,
        }
    )
    return NmapServiceRunner(config, tmp_path / "nmap-workers")


def _claim_job(store, policy, surface, capability, tool_version, revision, options=None):
    surface = replace(surface, input_name=revision)
    sid = store.upsert_surface(policy.engagement_id, surface)
    spec = JobSpec(
        sid,
        "network_test",
        capability,
        tool_version=tool_version,
        template_version=revision,
        policy_revision=policy.revision,
        options=options or {},
    )
    store.submit(policy, [spec])
    job = store.claim(policy, "contract-worker", lease_seconds=30)
    assert job is not None
    return job, surface, spec


def test_synthetic_summary_without_sealed_proof_never_promotes_imported_service(tmp_path):
    store, policy, surface, initial_job = owned_job(tmp_path, 9000)
    try:
        services = store.inventory.services(policy)
        assert len(services) == 1 and services[0]["source"] == "imported"
        ref = store.evidence_put(
            policy.engagement_id,
            {
                "tool": "naabu",
                "tool_version": "2.6.1",
                "connected": 1,
                "refused": 0,
                "observation": {
                    "address": surface.network_address,
                    "port": surface.network_port,
                    "state": "open",
                },
            },
            job_id=initial_job["id"],
            kind="naabu_network",
        )
        assert store.finish(
            initial_job,
            AdapterResult(
                "succeeded",
                "completed",
                summary={
                    "observation": {
                        "address": surface.network_address,
                        "port": surface.network_port,
                        "state": "open",
                    },
                    "evidence_refs": [ref],
                },
            ),
        )
        assert store.inventory.services(policy)[0]["source"] == "imported"
        assert service_observations(store, policy) == []
    finally:
        store.close()


@pytest.mark.parametrize("open_port", [True, False], ids=["open", "closed"])
def test_sealed_naabu_and_nmap_proof_promotes_only_verified_open_service(  # noqa: PLR0915
    tmp_path, open_port
):
    store, policy, surface, initial_job = owned_job(tmp_path, 9000)
    store.finish(initial_job, AdapterResult("failed", "blocked"))
    try:
        runner = _naabu_runner(tmp_path)
        job, surface, spec = _claim_job(
            store,
            policy,
            surface,
            "naabu_ports",
            runner.config.version,
            runner.config.revision,
        )
        broker = ScopedTCPBroker(policy, store, surface, job)
        broker.attempted = 1
        broker.connected = 1 if open_port else 0
        broker.refused = 0 if open_port else 1
        runner.broker = broker
        runner._broker_cleanup_proof = broker
        runner.boundary = _attested_boundary(tmp_path)
        collector = NativeObservationCollector(store, policy, runner)
        stdout = (
            json.dumps({"ip": surface.network_address, "port": int(surface.network_port)}) + "\n"
            if open_port
            else ""
        )
        native_ref = collector.capture(
            job, surface, spec, {"exit_code": 0, "stdout": stdout}, broker
        )
        broker.closed = True
        runner.broker = None
        runner.boundary = None
        naabu_ref = store.evidence_put(
            policy.engagement_id,
            {
                "tool": "naabu",
                "tool_version": runner.config.version,
                "binary_sha256": runner.config.binary.sha256,
                "connect_attempts": broker.attempted,
                "connected": broker.connected,
                "refused": broker.refused,
                "observation": {
                    "address": surface.network_address,
                    "port": surface.network_port,
                    "state": "open" if open_port else "closed_or_unreachable",
                },
            },
            job_id=job["id"],
            kind="naabu_network",
        )
        transport_ref = store.evidence_put(
            policy.engagement_id,
            {
                "tool": "naabu",
                "tool_version": runner.config.version,
                "binary_sha256": runner.config.binary.sha256,
                "connect_attempts": broker.attempted,
                "connected": broker.connected,
                "refused": broker.refused,
                "denied": 0,
                "dns_queries": 0,
                "dns_rcodes": [],
                "response_bytes": 0,
                "admission_closed": True,
            },
            job_id=job["id"],
            kind="naabu_network_transport",
        )
        sealed_native, seal_ref = collector.seal(job, spec, transport_ref)
        assert sealed_native == native_ref
        assert store.finish(
            job,
            AdapterResult(
                "succeeded",
                "completed",
                summary={"evidence_refs": [naabu_ref, transport_ref, native_ref, seal_ref]},
            ),
        )
        services = store.inventory.services(policy)
        assert len(services) == 1
        if not open_port:
            assert services[0]["source"] == "imported"
            assert service_observations(store, policy) == []
            return
        assert services[0]["source"] == "observed"
        obs = service_observations(store, policy)
        assert len(obs) == 1 and obs[0]["payload"]["engine"] == "naabu"

        nmap_runner = _nmap_runner(tmp_path)
        nmap_job, nmap_surface, nmap_spec = _claim_job(
            store,
            policy,
            surface,
            "nmap_services",
            nmap_runner.config.version,
            nmap_runner.config.revision,
            options={"open_evidence_ref": naabu_ref},
        )
        nmap_broker = ObservedServiceBroker(policy, store, nmap_surface, nmap_job)
        nmap_broker.attempted = 2
        nmap_broker.connected = 2
        nmap_broker.response_bytes = 38
        nmap_broker.response_digests = ["a" * 64]
        nmap_broker.banner_types = {"http"}
        nmap_broker.sent_probe_count = 1
        nmap_broker.probe_bytes_received = len(HTTP_SERVICE_PROBE)
        nmap_runner.broker = nmap_broker
        nmap_runner._broker_cleanup_proof = nmap_broker
        nmap_runner.proxy_address = "127.0.0.1:23456"
        nmap_runner.boundary = _attested_boundary(tmp_path)
        nmap_collector = NativeObservationCollector(store, policy, nmap_runner)
        xml = (
            '<!DOCTYPE nmaprun><nmaprun><host><ports><port protocol="tcp" portid="23456">'
            '<state state="open"/><service name="http" method="probed" product="HTTP service"/>'
            '</port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
        )
        nmap_native = nmap_collector.capture(
            nmap_job, nmap_surface, nmap_spec, {"exit_code": 0, "stdout": xml}, nmap_broker
        )
        nmap_broker.closed = True
        nmap_runner.broker = None
        nmap_runner.boundary = None
        nmap_transport = store.evidence_put(
            policy.engagement_id,
            {
                "tool": "nmap",
                "tool_version": nmap_runner.config.version,
                "binary_sha256": nmap_runner.config.binary.sha256,
                "probe_sha256": PROBE_SHA256,
                "license_sha256": NMAP_LICENSE_SHA256,
                "open_evidence_ref": naabu_ref,
                "connect_attempts": 2,
                "connected": 2,
                "refused": 0,
                "denied": 0,
                "response_bytes": 38,
                "response_digests": ["a" * 64],
                "banner_types": ["http"],
                "sent_probe_count": 1,
                "probe_bytes_received": len(HTTP_SERVICE_PROBE),
                "transport_errors": {},
                "admission_closed": True,
            },
            job_id=nmap_job["id"],
            kind="nmap_service_transport",
        )
        _, nmap_seal = nmap_collector.seal(nmap_job, nmap_spec, nmap_transport)
        assert store.finish(
            nmap_job,
            AdapterResult(
                "succeeded",
                "partial",
                summary={
                    "service_observed": True,
                    "service": {"name": "http", "service_label": "HTTP service"},
                    "evidence_refs": [nmap_transport, nmap_native, nmap_seal],
                },
            ),
        )
        obs = service_observations(store, policy, service_id=services[0]["id"])
        assert len(obs) == 2
        nmap_obs = next(item["payload"] for item in obs if item["payload"]["engine"] == "nmap")
        assert nmap_obs["protocol_name"] == "http"
        assert nmap_obs["product_version_status"] == "not_determined_by_narrow_profile"
    finally:
        store.close()


def test_unsealed_or_uncleaned_capture_cannot_seal_or_promote(tmp_path):
    store, policy, surface, initial_job = owned_job(tmp_path, 9000)
    store.finish(initial_job, AdapterResult("failed", "blocked"))
    try:
        runner = _naabu_runner(tmp_path)
        job, surface, spec = _claim_job(
            store,
            policy,
            surface,
            "naabu_ports",
            runner.config.version,
            runner.config.revision,
        )
        broker = ScopedTCPBroker(policy, store, surface, job)
        broker.attempted = broker.connected = 1
        runner.broker = broker
        runner._broker_cleanup_proof = broker
        runner.boundary = _attested_boundary(tmp_path)
        collector = NativeObservationCollector(store, policy, runner)
        stdout = json.dumps({"ip": surface.network_address, "port": int(surface.network_port)})
        collector.capture(job, surface, spec, {"exit_code": 0, "stdout": stdout}, broker)
        transport_ref = store.evidence_put(
            policy.engagement_id,
            {
                "tool": "naabu",
                "tool_version": runner.config.version,
                "binary_sha256": runner.config.binary.sha256,
                "connect_attempts": 1,
                "connected": 1,
                "refused": 0,
                "denied": 0,
                "response_bytes": 0,
                "admission_closed": True,
            },
            job_id=job["id"],
            kind="naabu_network_transport",
        )
        with pytest.raises(NetworkProofDenied, match="verified_cleanup_required"):
            collector.seal(job, spec, transport_ref)
        naabu_ref = store.evidence_put(
            policy.engagement_id,
            {
                "tool": "naabu",
                "tool_version": "2.6.1",
                "connected": 1,
                "refused": 0,
                "observation": {
                    "address": surface.network_address,
                    "port": surface.network_port,
                    "state": "open",
                },
            },
            job_id=job["id"],
            kind="naabu_network",
        )
        assert store.finish(
            job,
            AdapterResult("succeeded", "completed", summary={"evidence_refs": [naabu_ref]}),
        )
        assert store.inventory.services(policy)[0]["source"] == "imported"
        assert service_observations(store, policy) == []
    finally:
        store.close()


def test_parse_native_rejects_mismatched_probes_banners_and_declarations(tmp_path):
    store, _policy, surface, _job = owned_job(tmp_path, 9000)
    try:
        with pytest.raises(NetworkProofDenied, match="http_probe_required"):
            parse_native(
                "nmap",
                '<!DOCTYPE nmaprun><nmaprun><host><ports><port protocol="tcp" portid="23456">'
                '<state state="open"/><service name="http" method="probed" product="HTTP service"/>'
                '</port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>',
                surface,
                {
                    "connect_attempts": 1,
                    "connected": 1,
                    "refused": 0,
                    "denied": 0,
                    "response_bytes": 32,
                    "response_digests": ["a" * 64],
                    "banner_types": ["http"],
                    "sent_probe_count": 0,
                    "probe_bytes_received": 0,
                },
                "23456",
            )
    finally:
        store.close()
