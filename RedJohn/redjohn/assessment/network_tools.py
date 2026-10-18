"""Explicit pinned Naabu/dnsx jobs over an attested namespace and scoped TCP broker."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary
from redjohn.assessment.models import AdapterResult, error_record, stable_key
from redjohn.assessment.network_broker import ScopedTCPBroker
from redjohn.assessment.pinned_tools import BinaryPin, PinnedToolRunner
from redjohn.assessment.source_tools import read_source_file
from redjohn.assessment.store import EvidenceWriteError


if TYPE_CHECKING:
    from redjohn.assessment.models import CoverageStatus, JobSpec, Surface
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore

VERSIONS = {"naabu": "2.6.1", "dnsx": "1.3.1"}
CAPABILITIES = {"naabu": "naabu_ports", "dnsx": "dnsx_resolve"}


@dataclass(frozen=True)
class NetworkToolConfig:
    tool: str
    binary: BinaryPin

    @classmethod
    def from_mapping(cls, tool: str, value: dict[str, Any]) -> NetworkToolConfig:
        if tool not in VERSIONS or not isinstance(value, dict) or set(value) != {"binary"}:
            raise ValueError("invalid_network_tool_configuration")
        pin = value["binary"]
        if (
            not isinstance(pin, dict)
            or set(pin) != {"path", "sha256", "version"}
            or not all(isinstance(item, str) for item in pin.values())
            or not Path(pin["path"]).is_absolute()
            or re.fullmatch(r"[a-f0-9]{64}", pin["sha256"]) is None
            or pin["version"] != VERSIONS[tool]
        ):
            raise ValueError("invalid_network_binary_pin")
        return cls(tool, BinaryPin(Path(pin["path"]), pin["sha256"], pin["version"]))

    @property
    def version(self) -> str:
        return self.binary.version

    @property
    def revision(self) -> str:
        return stable_key(["network-broker-v1", self.tool, self.binary.sha256, self.version])


class NetworkToolRunner(PinnedToolRunner):
    def __init__(self, config: NetworkToolConfig, root: Path) -> None:
        super().__init__(config.tool, config.binary, root)
        self.config = config
        self.broker: ScopedTCPBroker | None = None
        self.proxy_address = ""
        self.payload: tempfile.TemporaryDirectory[str] | None = None

    async def prepare_network(self, broker: ScopedTCPBroker) -> None:
        self.broker = broker
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._temporary = tempfile.TemporaryDirectory(prefix="job-", dir=self.root)
        self.workspace = Path(self._temporary.name).resolve()
        self.payload = tempfile.TemporaryDirectory(prefix="payload-", dir=self.root)
        payload_root = Path(self.payload.name).resolve()
        binary = payload_root / self.config.binary.path.name
        binary.write_bytes(
            read_source_file(
                self.config.binary.path.parent,
                self.config.binary.path.name,
                self.config.binary.sha256,
                64 * 1024**2,
            )
        )
        binary.chmod(0o500)
        self.binary = BinaryPin(binary, self.config.binary.sha256, self.config.binary.version)
        self._ca_file = self.workspace / "proxy-ca.pem"
        self._ca_file.write_text("")
        (self.workspace / "empty-ca-directory").mkdir(mode=0o700)
        self.proxy_address = await broker.start()
        # Transport is a byte relay to a distinct SOCKS5 controller, not HTTP
        # authorization or BrowserEgressProxy. Workers have no other network.
        self.boundary = LinuxEgressBoundary(
            "http://" + self.proxy_address, self.workspace, read_only_paths=(self.binary.path,)
        )
        await self.boundary.start()
        await self.boundary.attest()

    async def healthcheck(self) -> dict[str, str]:
        raw = await self.execute([str(self.binary.path), "-version", "-duc"], 5)
        text = raw.get("stdout", "") + raw.get("stderr", "")
        if (
            raw.get("error")
            or raw.get("exit_code") != 0
            or raw.get("truncated")
            or re.search(r"(?<![\d.])" + re.escape(self.binary.version) + r"(?![\d.])", text)
            is None
        ):
            raise ValueError("network_binary_version_or_digest_mismatch")
        return {"tool_version": self.binary.version, "binary_sha256": self.binary.sha256}

    def argv(self, surface: Surface) -> list[str]:
        assert self.broker is not None and self.workspace is not None
        if self.tool == "naabu":
            return [
                str(self.binary.path),
                "-host",
                surface.network_address,
                "-p",
                surface.network_port,
                "-s",
                "c",
                "-Pn",
                "-stream",
                "-no-stdin",
                "-proxy",
                self.proxy_address,
                "-proxy-auth",
                "redjohn:" + self.broker.nonce,
                "-c",
                "1",
                "-rate",
                "1",
                "-timeout",
                "1000ms",
                "-json",
                "-silent",
                "-duc",
            ]
        target = self.workspace / "names.txt"
        target.write_text(surface.dns_name + "\n")
        return [
            str(self.binary.path),
            "-l",
            str(target),
            "-" + surface.dns_type.lower(),
            "-r",
            (
                "[" + surface.network_address + "]"
                if ":" in surface.network_address
                else surface.network_address
            )
            + ":"
            + surface.network_port,
            "-proxy",
            "socks5://redjohn:" + self.broker.nonce + "@" + self.proxy_address,
            "-t",
            "1",
            "-rl",
            "1",
            "-retry",
            "1",
            "-timeout",
            "2s",
            "-json",
            "-omit-raw",
            "-silent",
            "-duc",
        ]

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


class NetworkToolAdapter:
    resource_class = "scanner"

    def __init__(
        self, config: NetworkToolConfig, policy: EngagementPolicy, store: AssessmentStore
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        self.runner = NetworkToolRunner(
            config, store.path.parent / (config.tool + "-network-workers")
        )
        self.partial_evidence_refs: tuple[str, ...] = ()

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:
        self.partial_evidence_refs = ()
        self.policy.check_capability(
            domains=("network",), profiles=("active-staging", "isolated-lab")
        )
        self.policy.check_surface(surface)
        kind = "network_endpoint" if self.config.tool == "naabu" else "dns_name"
        if (
            spec.capability != CAPABILITIES[self.config.tool]
            or spec.options
            or surface.resource_kind != kind
            or not spec.idempotent
            or spec.tool_version != self.config.version
            or spec.template_version != self.config.revision
            or surface.input_name != self.config.revision
        ):
            return AdapterResult(
                "failed",
                "unsupported",
                error=error_record("network_input_not_supported", coverage_effect="unsupported"),
            )
        broker = ScopedTCPBroker(self.policy, self.store, surface, job)
        stage = "prepare"
        start = time.monotonic()
        outcome: AdapterResult | None = None
        try:
            if not self.config.binary.path.is_file():
                return AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record(
                        "network_binary_missing", category="capability", coverage_effect="blocked"
                    ),
                )
            await self.runner.prepare_network(broker)
            await self.runner.healthcheck()
            stage = "scan"
            raw = await self.runner.execute(self.runner.argv(surface), spec.timeout_seconds)
            # Drain accepted controller tasks so evidence includes final refusal,
            # query outcome and cleanup, rather than a partial counter snapshot.
            for task in tuple(broker.tasks):
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(asyncio.shield(task), 3)
            outcome = self.normalize(job, surface, raw, broker, time.monotonic() - start)
        except EvidenceWriteError:
            raise
        except EgressUnavailable as exc:
            outcome = AdapterResult(
                "failed",
                "blocked",
                error=error_record(str(exc).split(":")[0], coverage_effect="blocked"),
            )
        except (ValueError, RuntimeError, OSError, KeyError, TypeError):
            coverage: CoverageStatus = "blocked" if stage == "prepare" else "inconclusive"
            outcome = AdapterResult(
                "failed",
                coverage,
                error=error_record(
                    "network_engine_or_broker_unavailable", coverage_effect=coverage
                ),
            )
        finally:
            try:
                await asyncio.shield(self.cleanup())
            finally:
                if broker.attempted or broker.denied:
                    ref = self._record_transport(job, broker, time.monotonic() - start)
                    self.partial_evidence_refs = (ref,)
                    if outcome is not None:
                        outcome.summary.setdefault("evidence_refs", []).append(ref)
                        if outcome.error:
                            outcome.error["partial_evidence_refs"] = [ref]
        assert outcome is not None
        return outcome

    def _record_transport(
        self, job: dict[str, Any], broker: ScopedTCPBroker, duration: float
    ) -> str:
        return self.store.evidence_put(
            self.policy.engagement_id,
            {
                "tool": self.config.tool,
                "tool_version": self.config.version,
                "binary_sha256": self.config.binary.sha256,
                "connect_attempts": broker.attempted,
                "connected": broker.connected,
                "refused": broker.refused,
                "denied": broker.denied,
                "dns_queries": broker.dns_queries,
                "dns_rcodes": broker.dns_rcodes,
                "response_bytes": broker.response_bytes,
                "admission_closed": broker.closed,
                "duration_seconds": duration,
            },
            job_id=job["id"],
            kind=self.config.tool + "_network_transport",
        )

    def normalize(  # noqa: PLR0912 - explicit native/broker completeness gates
        self,
        job: dict[str, Any],
        surface: Surface,
        raw: dict[str, Any],
        broker: ScopedTCPBroker,
        duration: float,
    ) -> AdapterResult:
        if broker.denied:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record("network_broker_denied", coverage_effect="blocked"),
            )
        if (
            raw.get("error")
            or raw.get("timed_out")
            or raw.get("truncated")
            or raw.get("exit_code") != 0
            or not broker.attempted
        ):
            return AdapterResult(
                "failed", "inconclusive", error=error_record("network_scan_incomplete")
            )
        rows = [json.loads(line) for line in raw.get("stdout", "").splitlines() if line.strip()]
        if len(rows) > 16 or any(not isinstance(row, dict) for row in rows):
            raise ValueError("network_output_row_limit")
        observation: dict[str, Any]
        if self.config.tool == "naabu":
            for row in rows:
                if (
                    (row.get("ip"), str(row.get("port")))
                    != (surface.network_address, surface.network_port)
                    or row.get("protocol", "tcp") != "tcp"
                    or not broker.connected
                ):
                    raise ValueError("network_unproven_open_port")
            if (
                bool(rows) != bool(broker.connected)
                or broker.attempted != broker.connected + broker.refused
            ):
                raise ValueError("network_connect_result_mismatch")
            observation = {
                "address": surface.network_address,
                "port": surface.network_port,
                "state": "open" if broker.connected else "closed_or_unreachable",
            }
        else:
            if (
                not broker.dns_queries
                or not broker.response_bytes
                or len(broker.dns_rcodes) != broker.dns_queries
                or any(code not in {0, 3} for code in broker.dns_rcodes)
            ):
                raise ValueError("dns_complete_response_not_observed")
            answers = []
            field = surface.dns_type.lower()
            for row in rows:
                if row.get("host", "").rstrip(".").lower() != surface.dns_name:
                    raise ValueError("dns_output_name_mismatch")
                values = row.get(field, [])
                if (
                    not isinstance(values, list)
                    or len(values) > 64
                    or not all(isinstance(v, str) and len(v) <= 253 for v in values)
                ):
                    raise ValueError("dns_answer_limit")
                answers.extend(values)
            if len(answers) > 64 or (any(broker.dns_answer_counts) and not answers):
                raise ValueError("dns_scanner_missing_or_excessive_answer_output")
            observation = {
                "name": surface.dns_name,
                "query_type": surface.dns_type,
                "answers": answers,
                "rcodes": broker.dns_rcodes,
                "execution_grant": False,
            }
        evidence = self.store.evidence_put(
            self.policy.engagement_id,
            {
                "tool": self.config.tool,
                "tool_version": self.config.version,
                "binary_sha256": self.config.binary.sha256,
                "duration_seconds": duration,
                "connect_attempts": broker.attempted,
                "connected": broker.connected,
                "refused": broker.refused,
                "dns_queries": broker.dns_queries,
                "response_bytes": broker.response_bytes,
                "observation": observation,
            },
            job_id=job["id"],
            kind=self.config.tool + "_network",
        )
        return AdapterResult(
            "succeeded",
            "completed",
            summary={
                "observation": observation,
                "connect_attempts": broker.attempted,
                "connected": broker.connected,
                "refused": broker.refused,
                "dns_queries": broker.dns_queries,
                "requests": 0,
                "evidence_refs": [evidence],
                "tool_version": self.config.version,
                "binary_sha256": self.config.binary.sha256,
            },
        )

    async def cancel(self) -> None:
        await self.runner.cancel()
        if self.runner.broker is not None:
            await self.runner.broker.close()

    async def cleanup(self) -> None:
        await self.runner.cleanup()
