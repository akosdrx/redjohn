"""Optional Nmap service observations on an explicitly approved observed-open port.

The external engine and its license identity are operator configured. A tiny
RedJohn-authored, content-pinned probe profile replaces the system probe DB;
there is no NSE, OS/UDP scan, arbitrary payload or port-discovery capability.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary
from redjohn.assessment.models import AdapterResult, error_record, stable_key
from redjohn.assessment.pinned_tools import BinaryPin, PinnedToolRunner
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.service_broker import ObservedServiceBroker
from redjohn.assessment.source_tools import read_source_file
from redjohn.assessment.store import EvidenceWriteError


if TYPE_CHECKING:
    from redjohn.assessment.models import CoverageStatus, JobSpec, Surface
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore

NMAP_VERSION = "7.992"
NMAP_LICENSE_SHA256 = "9d9a9a763c0e6145172cfe7d8483e23b38ce60b6c79a82e4894242917bdae6d3"
# RedJohn's own deliberately narrow initial profile. These bytes are copied
# into a read-only private payload; no upstream/system probe DB is read.
SERVICE_PROBES = rb"""# RedJohn observed-service profile 1; no upstream probe database
Probe TCP NULL q||
totalwaitms 1200
tcpwrappedms 200
match ssh m|^SSH-([0-9.]+)-[^\r\n]+\r?\n| p/SSH service/ i/SSH protocol $1/
match http m|^HTTP/1\.[01] [0-9]{3}[^\r\n]*\r?\n| p/HTTP service/
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
totalwaitms 1200
match http m|^HTTP/1\.[01] [0-9]{3}[^\r\n]*\r?\n| p/HTTP service/
"""
PROBE_SHA256 = hashlib.sha256(SERVICE_PROBES).hexdigest()


@dataclass(frozen=True)
class NmapServiceConfig:
    binary: BinaryPin

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> NmapServiceConfig:
        if (
            not isinstance(value, dict)
            or set(value) != {"binary", "external_operator_install", "license_sha256"}
            or value["external_operator_install"] is not True
            or value["license_sha256"] != NMAP_LICENSE_SHA256
        ):
            raise ValueError("nmap_external_install_and_reviewed_license_required")
        raw = value["binary"]
        if (
            not isinstance(raw, dict)
            or set(raw) != {"path", "sha256", "version"}
            or not all(isinstance(item, str) for item in raw.values())
            or not Path(raw["path"]).is_absolute()
            or re.fullmatch(r"[a-f0-9]{64}", raw["sha256"]) is None
            or raw["version"] != NMAP_VERSION
        ):
            raise ValueError("invalid_nmap_service_binary_pin")
        return cls(BinaryPin(Path(raw["path"]), raw["sha256"], raw["version"]))

    @property
    def version(self) -> str:
        return self.binary.version

    @property
    def revision(self) -> str:
        return stable_key(
            [
                "observed-service-v1",
                self.binary.sha256,
                self.version,
                PROBE_SHA256,
                NMAP_LICENSE_SHA256,
            ]
        )


class NmapServiceRunner(PinnedToolRunner):
    def __init__(self, config: NmapServiceConfig, root: Path) -> None:
        super().__init__("nmap", config.binary, root)
        self.config = config
        self.payload: tempfile.TemporaryDirectory[str] | None = None
        self.broker: ObservedServiceBroker | None = None
        self._broker_cleanup_proof: ObservedServiceBroker | None = None
        self.proxy_address = ""
        self.data_root: Path | None = None

    async def prepare_service(self, broker: ObservedServiceBroker) -> None:
        self.broker = broker
        self._broker_cleanup_proof = broker
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._temporary = tempfile.TemporaryDirectory(prefix="job-", dir=self.root)
        self.workspace = Path(self._temporary.name).resolve()
        self.payload = tempfile.TemporaryDirectory(prefix="payload-", dir=self.root)
        payload = Path(self.payload.name).resolve()
        binary = payload / "nmap"
        binary.write_bytes(
            read_source_file(
                self.config.binary.path.parent,
                self.config.binary.path.name,
                self.config.binary.sha256,
                64 * 1024**2,
            )
        )
        binary.chmod(0o500)
        self.binary = BinaryPin(binary, self.config.binary.sha256, self.config.version)
        self.data_root = payload / "data"
        self.data_root.mkdir(mode=0o700)
        for name, content in {
            "nmap-service-probes": SERVICE_PROBES,
            "nmap-services": b"redjohn 1/tcp 0.0\n",
            "nmap-protocols": b"tcp 6 TCP\n",
        }.items():
            (self.data_root / name).write_bytes(content)
            (self.data_root / name).chmod(0o400)
        self._ca_file = self.workspace / "proxy-ca.pem"
        self._ca_file.write_text("")
        (self.workspace / "empty-ca-directory").mkdir(mode=0o700)
        self.proxy_address = await broker.start()
        self.boundary = LinuxEgressBoundary(
            "http://" + self.proxy_address,
            self.workspace,
            read_only_paths=(payload,),
            max_connections=8,
            max_stream_bytes=128 * 1024,
            timeout_seconds=5,
            controller_preamble=broker.preamble,
        )
        await self.boundary.start()
        await self.boundary.attest()

    async def healthcheck(self) -> dict[str, str]:
        raw = await self.execute([str(self.binary.path), "--version"], 5)
        text = raw.get("stdout", "") + raw.get("stderr", "")
        if (
            raw.get("error")
            or raw.get("exit_code") != 0
            or raw.get("truncated")
            or re.search(r"Nmap version " + re.escape(NMAP_VERSION) + r"(?:\s|$)", text) is None
            or re.search(r"Compiled without:.*liblua", text) is None
        ):
            raise ValueError("nmap_service_version_digest_or_nse_exclusion_mismatch")
        return {"tool_version": self.config.version, "binary_sha256": self.binary.sha256}

    def argv(self) -> list[str]:
        assert self.data_root is not None and self.proxy_address
        port = self.proxy_address.rsplit(":", 1)[1]
        return [
            str(self.binary.path),
            "--unprivileged",
            "-sT",
            "-sV",
            "-Pn",
            "-n",
            "--version-intensity",
            "1",
            "--versiondb",
            str(self.data_root / "nmap-service-probes"),
            "--datadir",
            str(self.data_root),
            "--max-parallelism",
            "1",
            "--max-retries",
            "0",
            "--max-rate",
            "1",
            "--scan-delay",
            "100ms",
            "--host-timeout",
            "10s",
            "--no-stylesheet",
            "-oX",
            "-",
            "-p",
            port,
            "127.0.0.1",
        ]

    def resource_cleanup_verified(self) -> bool:
        broker = self._broker_cleanup_proof
        return (
            super().resource_cleanup_verified()
            and self.broker is None
            and self.payload is None
            and self.data_root is None
            and (
                broker is None
                or (
                    broker.closed
                    and broker.server is None
                    and not broker.tasks
                    and not broker.writers
                )
            )
        )

    async def cleanup(self) -> None:
        try:
            await super().cleanup()
        finally:
            if self.broker is not None:
                await self.broker.close()
                self.broker = None
            if self.payload is not None:
                self.payload.cleanup()
                self.payload = None
            self.data_root = None


def require_open_observation(
    store: AssessmentStore,
    policy: EngagementPolicy,
    surface: Surface,
    evidence_ref: str,
) -> None:
    """Require this engagement's recent completed native Naabu observation."""
    if not isinstance(evidence_ref, str) or not 1 <= len(evidence_ref) <= 128:
        raise PolicyDenied("nmap_current_open_observation_required")
    with store._lock:
        row = store.db.execute(
            "SELECT e.payload,e.created_at,j.spec,j.result,j.surface_id FROM rj_evidence e "
            "JOIN rj_job j ON j.id=e.job_id AND j.engagement=e.engagement "
            "WHERE e.id=? AND e.engagement=? AND e.kind='naabu_network' "
            "AND j.execution_status='succeeded' AND j.coverage_status='completed'",
            (evidence_ref, policy.engagement_id),
        ).fetchone()
        if row is None or not time.time() - 300 <= row[1] <= time.time():
            raise PolicyDenied("nmap_current_open_observation_required")
        producer = json.loads(row[2])
        result = json.loads(row[3])
        proof = json.loads(row[0])
        prior = store.surface(policy.engagement_id, row[4])
        observation = proof.get("observation", {})
        if (
            producer.get("capability") != "naabu_ports"
            or producer.get("policy_revision") != policy.revision
            or evidence_ref not in result.get("summary", {}).get("evidence_refs", [])
            or prior.resource_kind != "network_endpoint"
            or prior.asset_ref != surface.asset_ref
            or (prior.network_address, prior.network_port)
            != (surface.network_address, surface.network_port)
            or proof.get("tool") != "naabu"
            or proof.get("tool_version") != "2.6.1"
            or proof.get("connected", 0) < 1
            or proof.get("refused", 0) != 0
            or observation
            != {"address": surface.network_address, "port": surface.network_port, "state": "open"}
        ):
            raise PolicyDenied("nmap_open_observation_identity_mismatch")
        store.inventory.require_surface_active(store.db, policy, row[4])


class NmapServiceAdapter:
    resource_class = "scanner"

    def __init__(
        self, config: NmapServiceConfig, policy: EngagementPolicy, store: AssessmentStore
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        self.runner = NmapServiceRunner(config, store.path.parent / "nmap-service-workers")
        self.partial_evidence_refs: tuple[str, ...] = ()

    async def run(  # noqa: PLR0912, PLR0915 - bounded capability and proof lifecycle
        self, job: dict[str, Any], surface: Surface, spec: JobSpec
    ) -> AdapterResult:
        self.partial_evidence_refs = ()
        self.policy.check_capability(
            domains=("network",), profiles=("active-staging", "isolated-lab")
        )
        self.policy.check_surface(surface)
        if (
            spec.capability != "nmap_services"
            or surface.resource_kind != "network_endpoint"
            or set(spec.options) != {"open_evidence_ref"}
            or not spec.idempotent
            or spec.tool_version != self.config.version
            or spec.template_version != self.config.revision
            or surface.input_name != self.config.revision
        ):
            return AdapterResult(
                "failed", "unsupported", error=error_record("nmap_service_input_unsupported")
            )
        require_open_observation(
            self.store, self.policy, surface, spec.options["open_evidence_ref"]
        )
        broker = ObservedServiceBroker(self.policy, self.store, surface, job)
        outcome: AdapterResult | None = None
        collector: Any = None
        started = time.monotonic()
        stage = "prepare"
        try:
            if not self.config.binary.path.is_file():
                return AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record("nmap_binary_missing", coverage_effect="blocked"),
                )
            await self.runner.prepare_service(broker)
            stage = "health"
            await self.runner.healthcheck()
            stage = "scan"
            raw = await self.runner.execute(self.runner.argv(), min(spec.timeout_seconds, 15))
            for task in tuple(broker.tasks):
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(asyncio.shield(task), 5)
            outcome = self.normalize(raw, broker)
            if (
                outcome.execution_status == "succeeded"
                and outcome.summary.get("service_observed") is True
            ):
                from redjohn.assessment.network_observation import (  # noqa: PLC0415
                    NativeObservationCollector,
                )

                collector = NativeObservationCollector(self.store, self.policy, self.runner)
                collector.capture(job, surface, spec, raw, broker)
        except EvidenceWriteError:
            raise
        except EgressUnavailable as exc:
            outcome = AdapterResult(
                "failed",
                "blocked",
                error=error_record(str(exc).split(":")[0], coverage_effect="blocked"),
            )
        except (ValueError, RuntimeError, OSError, TypeError, KeyError):
            coverage: CoverageStatus = "inconclusive" if stage == "scan" else "blocked"
            outcome = AdapterResult(
                "failed",
                coverage,
                error=error_record(
                    "nmap_service_engine_or_parser_unavailable", coverage_effect=coverage
                ),
            )
        finally:
            try:
                await asyncio.shield(self.cleanup())
            finally:
                if broker.attempted or broker.denied:
                    ref = self.store.evidence_put(
                        self.policy.engagement_id,
                        {
                            "tool": "nmap",
                            "tool_version": self.config.version,
                            "binary_sha256": self.config.binary.sha256,
                            "probe_sha256": PROBE_SHA256,
                            "license_sha256": NMAP_LICENSE_SHA256,
                            "open_evidence_ref": spec.options["open_evidence_ref"],
                            "connect_attempts": broker.attempted,
                            "connected": broker.connected,
                            "refused": broker.refused,
                            "denied": broker.denied,
                            "response_bytes": broker.response_bytes,
                            "response_digests": broker.response_digests,
                            "banner_types": sorted(broker.banner_types),
                            "sent_probe_count": broker.sent_probe_count,
                            "probe_bytes_received": broker.probe_bytes_received,
                            "transport_errors": dict(broker.transport_errors),
                            "admission_closed": broker.closed,
                            "duration_seconds": time.monotonic() - started,
                        },
                        job_id=job["id"],
                        kind="nmap_service_transport",
                    )
                    self.partial_evidence_refs = (ref,)
                    if outcome is not None:
                        outcome.summary["evidence_refs"] = [ref]
                        if outcome.error:
                            outcome.error["partial_evidence_refs"] = [ref]
                        elif collector is not None and collector.pending is not None:
                            try:
                                native_ref, seal_ref = collector.seal(job, spec, ref)
                                outcome.summary["evidence_refs"].extend([native_ref, seal_ref])
                            except (ValueError, RuntimeError):
                                outcome = AdapterResult(
                                    "failed",
                                    "inconclusive",
                                    summary={"evidence_refs": [ref]},
                                    error={
                                        **error_record(
                                            "nmap_service_engine_or_parser_unavailable",
                                            coverage_effect="inconclusive",
                                        ),
                                        "partial_evidence_refs": [ref],
                                    },
                                )
        assert outcome is not None
        return outcome

    def normalize(self, raw: dict[str, Any], broker: ObservedServiceBroker) -> AdapterResult:
        if broker.denied:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record("nmap_service_broker_denied", coverage_effect="blocked"),
            )
        if (
            raw.get("error")
            or raw.get("timed_out")
            or raw.get("truncated")
            or raw.get("exit_code") != 0
            or not broker.response_bytes
            or not broker.response_digests
        ):
            return AdapterResult(
                "failed",
                "inconclusive",
                error=error_record("nmap_service_upstream_response_not_proven"),
            )
        text = raw.get("stdout", "")
        if not isinstance(text, str) or len(text.encode()) > 512 * 1024:
            raise ValueError("nmap_service_output_limit")
        safe = text.replace("<!DOCTYPE nmaprun>", "")
        if "<!DOCTYPE" in safe.upper() or "<!ENTITY" in safe.upper():
            raise ValueError("nmap_service_xml_extension_denied")
        # All DTD/entity declarations are rejected above, before the bounded
        # parser; Nmap's exact empty doctype was removed, without loading it.
        try:
            document = ET.fromstring(safe)  # noqa: S314 - declaration-free, size-bounded XML
        except ET.ParseError:
            raise ValueError("nmap_service_invalid_xml") from None
        ports = document.findall("./host/ports/port")
        finished = document.find("./runstats/finished")
        if (
            document.tag != "nmaprun"
            or len(list(document.iter())) > 128
            or len(ports) != 1
            or finished is None
            or finished.get("exit") != "success"
        ):
            raise ValueError("nmap_service_incomplete_xml")
        port = ports[0]
        service = port.find("service")
        local_port = self.runner.proxy_address.rsplit(":", 1)[1]
        if (
            port.get("protocol") != "tcp"
            or port.get("portid") != local_port
            or service is None
            or service.get("method") != "probed"
            or service.get("name") not in broker.banner_types
        ):
            return AdapterResult(
                "succeeded",
                "partial",
                summary={
                    "service_observed": False,
                    "coverage_lost": "narrow_profile_service_not_identified",
                    "requests": 0,
                },
            )
        fields = {
            "name": service.get("name", ""),
            "service_label": service.get("product", ""),
            "protocol_details": service.get("extrainfo", ""),
        }
        if any(
            len(value) > 128 or any(ord(char) < 32 for char in value) for value in fields.values()
        ):
            raise ValueError("nmap_service_field_limit")
        return AdapterResult(
            "succeeded",
            "partial",
            summary={
                "service_observed": True,
                "service": fields,
                "port_state_claim": "not_derived_from_local_relay",
                "coverage_lost": "narrow_ssh_http_profile_no_nse_no_general_probe_database",
                "requests": 0,
                "tool_version": self.config.version,
                "probe_sha256": PROBE_SHA256,
                "product_version_status": "not_determined_by_narrow_profile",
            },
        )

    async def cancel(self) -> None:
        await self.runner.cancel()
        if self.runner.broker is not None:
            await self.runner.broker.close()

    async def cleanup(self) -> None:
        await self.runner.cleanup()
