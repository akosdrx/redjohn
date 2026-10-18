"""Explicit immutable local source scans in a deny-all network namespace.

Only the operator's exact file manifest is read. No repository checkout, build,
package install, plugin, registry rule download or scanner startup occurs while
the runtime is composed. Static matches remain candidates, not dynamic proof.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary
from redjohn.assessment.models import AdapterResult, error_record, stable_key
from redjohn.assessment.pinned_tools import BinaryPin, PinnedToolRunner
from redjohn.assessment.policy import PolicyDenied


if TYPE_CHECKING:
    from redjohn.assessment.models import CoverageStatus, JobSpec, Surface
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


VERSIONS = {"semgrep": "1.181.0", "trivy": "0.76.0"}
CAPABILITIES = {"semgrep": "semgrep_source", "trivy": "trivy_source"}
MAX_FILES, MAX_FILE_BYTES, MAX_SOURCE_BYTES = 1024, 1024**2, 16 * 1024**2
_DIGEST = re.compile(r"[a-f0-9]{64}")
_RULE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}")
_UNSAFE_NAMES = frozenset(
    {".git", ".semgrepignore", ".trivyignore", ".trivyignore.yaml", "trivy.yaml"}
)


def offline_trust_anchor() -> bytes:
    """Let native TLS libraries initialize without importing host trust.

    The signing key exists only while creating this unrelated ephemeral root;
    no server certificate or key is exported. The worker still has deny-all
    kernel egress and a controller which rejects every network connection.
    """
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RedJohn offline source root")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def relative_source_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > 512:
        raise ValueError("source_relative_path_required")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} | _UNSAFE_NAMES for part in path.parts)
        or str(path) != value
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("unsafe_source_path")
    return value


@dataclass(frozen=True)
class SourceToolConfig:
    tool: str
    binary: BinaryPin
    source_root: Path
    files: tuple[tuple[str, str], ...]
    rules_file: Path | None = None
    rules_sha256: str = ""
    native_libraries: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_mapping(cls, tool: str, value: dict[str, Any]) -> SourceToolConfig:
        allowed = {"binary", "source_root", "files"}
        if tool == "semgrep":
            allowed |= {"rules_file", "rules_sha256", "native_libraries"}
        if tool not in VERSIONS or not isinstance(value, dict) or set(value) - allowed:
            raise ValueError("invalid_source_tool_configuration")
        pin = value.get("binary")
        if (
            not isinstance(pin, dict)
            or set(pin) != {"path", "sha256", "version"}
            or not all(isinstance(item, str) for item in pin.values())
            or not Path(pin["path"]).is_absolute()
            or _DIGEST.fullmatch(pin["sha256"]) is None
            or pin["version"] != VERSIONS[tool]
            or (tool == "semgrep" and Path(pin["path"]).name != "osemgrep")
        ):
            raise ValueError("invalid_source_binary_pin")
        root, files = value.get("source_root"), value.get("files")
        if (
            not isinstance(root, str)
            or not Path(root).is_absolute()
            or len(root.encode()) > 2048
            or not isinstance(files, list)
            or not 1 <= len(files) <= MAX_FILES
        ):
            raise ValueError("explicit_source_manifest_required")
        entries = []
        for item in files:
            if (
                not isinstance(item, dict)
                or set(item) != {"path", "sha256"}
                or not isinstance(item["sha256"], str)
                or _DIGEST.fullmatch(item["sha256"]) is None
            ):
                raise ValueError("source_file_digest_required")
            entries.append((relative_source_path(item["path"]), item["sha256"]))
        if len({entry[0] for entry in entries}) != len(entries):
            raise ValueError("duplicate_source_file")
        rules, digest = value.get("rules_file"), value.get("rules_sha256", "")
        if tool == "semgrep" and (
            not isinstance(rules, str)
            or not Path(rules).is_absolute()
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
        ):
            raise ValueError("explicit_local_semgrep_rules_pin_required")
        libraries = value.get("native_libraries", [])
        if tool == "semgrep" and (not isinstance(libraries, list) or not 1 <= len(libraries) <= 32):
            raise ValueError("explicit_semgrep_native_library_pins_required")
        library_pins = []
        for entry in libraries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"name", "sha256"}
                or not isinstance(entry["name"], str)
                or re.fullmatch(r"lib[A-Za-z0-9_.+-]{1,80}\.so(?:\.[0-9]+)*", entry["name"]) is None
                or not isinstance(entry["sha256"], str)
                or _DIGEST.fullmatch(entry["sha256"]) is None
            ):
                raise ValueError("invalid_source_native_library_pin")
            library_pins.append((entry["name"], entry["sha256"]))
        if len({name for name, _ in library_pins}) != len(library_pins):
            raise ValueError("duplicate_source_native_library")
        return cls(
            tool,
            BinaryPin(Path(pin["path"]), pin["sha256"], pin["version"]),
            Path(root),
            tuple(sorted(entries)),
            Path(rules) if rules is not None else None,
            digest,
            tuple(sorted(library_pins)),
        )

    @property
    def version(self) -> str:
        return self.binary.version

    @property
    def artifact_sha256(self) -> str:
        return stable_key(["redjohn-source-manifest-v1", self.files])

    @property
    def revision(self) -> str:
        return stable_key(
            [
                "offline-source-v1",
                self.tool,
                self.binary.sha256,
                self.files,
                self.rules_sha256,
                self.native_libraries,
            ]
        )

    def validate_input(self, policy: EngagementPolicy, surface: Surface, spec: JobSpec) -> None:
        policy.check_capability(
            domains=("source",), profiles=("safe-production", "active-staging", "isolated-lab")
        )
        if (
            spec.options
            or surface.resource_kind != "source_artifact"
            or surface.artifact_sha256 != self.artifact_sha256
            or surface.method != "GET"
            or surface.body_sha256
            or surface.actor_id != "anonymous"
            or surface.input_location != "source_artifact"
            or surface.input_name != self.revision
            or spec.tool_version != self.version
            or spec.template_version != self.revision
        ):
            raise ValueError("source_manifest_current_revision_required")
        policy.check_surface(surface)


def _source_directory(root: Path) -> int:
    if not root.is_absolute():
        raise ValueError("source_root_absolute_path_required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in root.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    else:
        return descriptor


def read_source_file(root: Path, relative: str, expected: str, maximum: int) -> bytes:
    """Use directory descriptors and O_NOFOLLOW for every manifest component."""
    relative_source_path(relative)
    descriptor = _source_directory(root)
    try:
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor
        )
        with os.fdopen(file_descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= maximum:
                raise ValueError("source_file_size_or_type_denied")
            data = stream.read(maximum + 1)
        if len(data) > maximum or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("source_file_digest_or_size_mismatch")
        return data
    finally:
        os.close(descriptor)


class OfflineSourceRunner(PinnedToolRunner):
    def __init__(self, config: SourceToolConfig, root: Path) -> None:
        super().__init__(config.tool, config.binary, root)
        self.config = config
        self.snapshot: Path | None = None
        self._snapshot_temporary: tempfile.TemporaryDirectory[str] | None = None
        self._deny_server: asyncio.Server | None = None
        self._deny_tasks: set[asyncio.Task[None]] = set()
        self.denied_connections = 0
        self.snapshot_readonly_attested = False

    def _worker_argv(self, argv: list[str]) -> list[str]:
        if argv[1:] != ["__redjohn_verify_snapshot__"]:
            return argv
        assert self.workspace is not None and self.snapshot is not None
        # Trusted fixed probe, not a model-supplied command. The supervisor
        # still verifies the selected engine's pin before admitting this job.
        probe = r"""import json,re,sys
from pathlib import Path
snapshot,workspace=map(Path,sys.argv[1:])
rows=Path('/proc/self/mountinfo').read_text().splitlines()
def decoded(text):
 return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),text)
matches=[r.split() for r in rows if decoded(r.split()[4])==str(snapshot)]
if len(matches)!=1 or 'ro' not in matches[0][5].split(','):
 raise RuntimeError('snapshot_mount_not_readonly')
control=workspace/'readonly-control'
control.write_text('owned-control');control.unlink()
print(json.dumps({'readonly':True,'writable_workspace':True}))
"""
        return [sys.executable, "-I", "-S", "-c", probe, str(self.snapshot), str(self.workspace)]

    async def _deny(self, _reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._deny_tasks.add(task)
        self.denied_connections += 1
        try:
            async with asyncio.timeout(1):
                writer.write(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            self._deny_tasks.discard(task)

    def _snapshot_engine(self) -> None:
        assert self.snapshot is not None
        # Pin and snapshot the executable and every dynamic payload before
        # namespace admission; the host install cannot race a running scan.
        engine = self.snapshot / "engine"
        engine.mkdir(mode=0o700)
        binary_data = read_source_file(
            self.config.binary.path.parent,
            self.config.binary.path.name,
            self.config.binary.sha256,
            256 * 1024**2,
        )
        executable = engine / self.config.binary.path.name
        executable.write_bytes(binary_data)
        executable.chmod(0o500)
        del binary_data
        self.binary = BinaryPin(executable, self.config.binary.sha256, self.config.binary.version)
        if self.config.native_libraries:
            (engine / "libs").mkdir(mode=0o700)
            library_bytes = 0
            for name, digest in self.config.native_libraries:
                data = read_source_file(
                    self.config.binary.path.parent / "libs", name, digest, 16 * 1024**2
                )
                library_bytes += len(data)
                if library_bytes > 32 * 1024**2:
                    raise ValueError("source_native_library_total_limit")
                (engine / "libs" / name).write_bytes(data)
                (engine / "libs" / name).chmod(0o400)

    async def prepare_offline(self) -> None:
        self.denied_connections = 0
        self.snapshot_readonly_attested = False
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(prefix="job-", dir=self.root)
        self.workspace = Path(self._temporary.name).resolve()
        self._snapshot_temporary = tempfile.TemporaryDirectory(prefix="snapshot-", dir=self.root)
        self.snapshot = Path(self._snapshot_temporary.name).resolve()
        (self.snapshot / "source").mkdir(mode=0o700)
        self._snapshot_engine()
        total = 0
        for relative, digest in self.config.files:
            data = read_source_file(self.config.source_root, relative, digest, MAX_FILE_BYTES)
            total += len(data)
            if total > MAX_SOURCE_BYTES:
                raise ValueError("source_snapshot_byte_limit_exceeded")
            target = self.snapshot / "source" / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o400)
        if self.config.rules_file is not None:
            rules = read_source_file(
                self.config.rules_file.parent,
                self.config.rules_file.name,
                self.config.rules_sha256,
                65536,
            )
            # JSON is also valid YAML, but avoids tags/aliases/Jsonnet/imports.
            document = json.loads(rules)
            if not isinstance(document, dict) or set(document) != {"rules"}:
                raise ValueError("semgrep_json_rules_required")
            if not isinstance(document["rules"], list) or not 1 <= len(document["rules"]) <= 32:
                raise ValueError("semgrep_rule_count_limit")
            for rule in document["rules"]:
                if not isinstance(rule, dict) or set(rule) - {
                    "id",
                    "languages",
                    "message",
                    "severity",
                    "pattern",
                    "patterns",
                    "pattern-either",
                    "metadata",
                    "mode",
                    "pattern-sources",
                    "pattern-sinks",
                    "pattern-sanitizers",
                    "options",
                }:
                    raise ValueError("semgrep_rule_extensions_denied")
            (self.snapshot / "rules.json").write_bytes(rules)
        (self.snapshot / "empty-ignore").write_text("")
        self._ca_file = self.workspace / "proxy-ca.pem"
        self._ca_file.write_bytes(offline_trust_anchor())
        self._ca_file.chmod(0o600)
        (self.workspace / "empty-ca-directory").mkdir(mode=0o700)
        self._deny_server = await asyncio.start_server(self._deny, "127.0.0.1", 0)
        port = self._deny_server.sockets[0].getsockname()[1]
        # Snapshot is a sibling of the writable workspace, so the latter bind
        # cannot hide its read-only mount. There is no local-fixture bypass.
        self.boundary = LinuxEgressBoundary(
            f"http://127.0.0.1:{port}",
            self.workspace,
            read_only_paths=(self.snapshot,),
            max_connections=4,
            max_stream_bytes=4096,
        )
        await self.boundary.start()
        await self.boundary.attest()
        attestation = await self.execute([str(self.binary.path), "__redjohn_verify_snapshot__"], 5)
        if (
            attestation.get("error")
            or attestation.get("exit_code") != 0
            or attestation.get("truncated")
            or json.loads(attestation.get("stdout", "{}"))
            != {"readonly": True, "writable_workspace": True}
        ):
            raise EgressUnavailable("source_snapshot_readonly_attestation_failed")
        self.snapshot_readonly_attested = True

    async def healthcheck(self) -> dict[str, str]:
        args = (
            ["scan", "--experimental", "--disable-version-check", "--metrics", "off", "--version"]
            if self.tool == "semgrep"
            else ["--version"]
        )
        result = await self.execute([str(self.binary.path), *args], 10)
        text = result.get("stdout", "") + result.get("stderr", "")
        if (
            result.get("error")
            or result.get("exit_code") != 0
            or result.get("truncated")
            or re.search(r"(?<![\d.])" + re.escape(self.binary.version) + r"(?![\d.])", text)
            is None
        ):
            raise ValueError("source_binary_version_or_digest_mismatch")
        return {"tool_version": self.binary.version, "binary_sha256": self.binary.sha256}

    def argv(self) -> list[str]:
        assert self.workspace is not None and self.snapshot is not None
        if self.tool == "semgrep":
            return [
                str(self.binary.path),
                "scan",
                # The pinned standalone native CLI otherwise asks for its
                # uninstalled Python frontend. This selects native dispatch;
                # namespace, rule and resource restrictions are unchanged.
                "--experimental",
                "--oss-only",
                "--config",
                str(self.snapshot / "rules.json"),
                "--json",
                "--metrics",
                "off",
                "--disable-version-check",
                "--no-git-ignore",
                "--no-secrets-validation",
                "--disable-nosem",
                "--no-rewrite-rule-ids",
                "--strict",
                "--jobs",
                "1",
                "--timeout",
                "5",
                "--max-memory",
                "128",
                "--max-target-bytes",
                str(MAX_FILE_BYTES),
                "--max-match-context-size",
                "128",
                "--max-log-list-entries",
                "20",
                str(self.snapshot / "source"),
            ]
        return [
            str(self.binary.path),
            "filesystem",
            "--scanners",
            "misconfig",
            "--format",
            "json",
            "--quiet",
            "--no-progress",
            "--offline-scan",
            "--disable-telemetry",
            "--skip-version-check",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--skip-vex-repo-update",
            "--parallel",
            "1",
            "--cache-backend",
            "memory",
            "--cache-dir",
            str(self.workspace / "cache"),
            "--ignorefile",
            str(self.snapshot / "empty-ignore"),
            "--timeout",
            "60s",
            "--misconfig-scanners",
            "terraform,dockerfile,kubernetes,cloudformation,azure-arm",
            str(self.snapshot / "source"),
        ]

    async def cleanup(self) -> None:
        try:
            await super().cleanup()
        finally:
            if self._deny_server is not None:
                self._deny_server.close()
                await self._deny_server.wait_closed()
                self._deny_server = None
            for task in tuple(self._deny_tasks):
                task.cancel()
            await asyncio.gather(*self._deny_tasks, return_exceptions=True)
            if self._snapshot_temporary is not None:
                self._snapshot_temporary.cleanup()
                self._snapshot_temporary = None
            self.snapshot = None


class SourceToolAdapter:
    resource_class = "scanner"

    def __init__(
        self, config: SourceToolConfig, policy: EngagementPolicy, store: AssessmentStore
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        self.runner = OfflineSourceRunner(
            config, store.path.parent / (config.tool + "-source-workers")
        )
        self.partial_evidence_refs: tuple[str, ...] = ()

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:
        self.partial_evidence_refs = ()
        started = time.monotonic()
        try:
            self.config.validate_input(self.policy, surface, spec)
        except PolicyDenied:
            raise
        except ValueError:
            return AdapterResult(
                "failed",
                "unsupported",
                error=error_record("source_input_not_supported", coverage_effect="unsupported"),
            )
        stage = "prepare"
        try:
            if not self.config.binary.path.is_file():
                return AdapterResult(
                    "failed",
                    "blocked",
                    error=error_record("source_binary_missing", coverage_effect="blocked"),
                )
            await self.runner.prepare_offline()
            stage = "health"
            health = await self.runner.healthcheck()
            stage = "scan"
            raw = await self.runner.execute(self.runner.argv(), spec.timeout_seconds)
            return self.normalize(job, raw, health, time.monotonic() - started)
        except EgressUnavailable as exc:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(str(exc).split(":")[0], coverage_effect="blocked"),
            )
        except (ValueError, TypeError, OSError, KeyError, AttributeError) as exc:
            coverage: CoverageStatus = "inconclusive" if stage == "scan" else "blocked"
            cause = str(exc)
            if re.fullmatch(r"[a-z][a-z0-9_]{0,95}", cause) is None:
                cause = type(exc).__name__
            return AdapterResult(
                "failed",
                coverage,
                error=error_record(
                    "source_scanner_output_or_parser_unavailable"
                    if stage == "scan"
                    else "source_snapshot_or_pinned_engine_unavailable",
                    coverage_effect=coverage,
                    cause_ref=f"{stage}:{cause}",
                ),
            )
        finally:
            await asyncio.shield(self.cleanup())

    def normalize(
        self, job: dict[str, Any], raw: dict[str, Any], health: dict[str, str], duration: float
    ) -> AdapterResult:
        if raw.get("timed_out"):
            return AdapterResult(
                "timed_out", "inconclusive", error=error_record("source_scanner_timeout")
            )
        if raw.get("error") or raw.get("truncated") or raw.get("exit_code") != 0:
            return AdapterResult(
                "failed",
                "inconclusive",
                error=error_record("source_scanner_failed_or_output_limited"),
            )
        document = json.loads(raw.get("stdout", ""))
        if not isinstance(document, dict):
            raise TypeError("source_scanner_output_schema_error")
        matches, scanned = self._matches(document)
        if not scanned or len(matches) > 128:
            raise ValueError("source_scan_empty_or_finding_limit")
        if self.runner.denied_connections:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    "source_offline_dependency_network_denied", coverage_effect="blocked"
                ),
            )
        findings = []
        assert self.runner.snapshot is not None
        root = self.runner.snapshot / "source"
        for rule, path, line, severity in matches:
            if (
                not isinstance(rule, str)
                or _RULE_ID.fullmatch(rule) is None
                or type(line) is not int
                or line < 1
            ):
                raise ValueError("source_finding_schema_error")
            source_path = str(path)
            relative = (
                str(Path(source_path).relative_to(root))
                if Path(source_path).is_absolute()
                else source_path
            )
            relative_source_path(relative)
            if relative not in {entry[0] for entry in self.config.files}:
                raise ValueError("source_finding_outside_manifest")
            findings.append(
                {
                    "template_id": rule,
                    "source_path": relative,
                    "line": line,
                    "severity": str(severity).lower(),
                    "finding_status": "candidate",
                    "finding_claim": "static_source_match_requires_validation",
                }
            )
        evidence = self.store.evidence_put(
            self.policy.engagement_id,
            {
                "tool": self.config.tool,
                **health,
                "configuration_revision": self.config.revision,
                "source_files": len(self.config.files),
                "scanned_units": scanned,
                "duration_seconds": duration,
                "denied_network_connections": self.runner.denied_connections,
                "snapshot_readonly_attested": self.runner.snapshot_readonly_attested,
                "results": findings,
                "finding_claim": "static_source_match_requires_validation",
            },
            job_id=job["id"],
            kind=self.config.tool + "_source",
        )
        return AdapterResult(
            "succeeded",
            "completed",
            summary={
                "source_files": len(self.config.files),
                "scanned_units": scanned,
                "requests": 0,
                "snapshot_readonly_attested": self.runner.snapshot_readonly_attested,
                "finding_count": len(findings),
                "evidence_refs": [evidence],
                **health,
            },
            findings=tuple({**finding, "evidence_refs": [evidence]} for finding in findings),
        )

    def _matches(self, document: dict[str, Any]) -> tuple[list[tuple[Any, Any, Any, Any]], int]:
        matches: list[tuple[Any, Any, Any, Any]] = []
        if self.config.tool == "semgrep":
            if document.get("errors"):
                raise ValueError("semgrep_partial_scan")
            rows = document.get("results")
            if not isinstance(rows, list) or not isinstance(document.get("paths"), dict):
                raise TypeError("semgrep_result_collection_missing")
            scanned = len(document["paths"].get("scanned", []))
            matches.extend(
                (
                    row["check_id"],
                    row["path"],
                    row["start"]["line"],
                    row.get("extra", {}).get("severity", "WARNING"),
                )
                for row in rows
            )
        else:
            rows = document.get("Results")
            if not isinstance(rows, list):
                raise TypeError("trivy_result_collection_missing")
            scanned = len(rows)
            for row in rows:
                for match in row.get("Misconfigurations", []):
                    if match.get("Status") not in {"FAIL", "FAILURE"}:
                        continue
                    matches.append(
                        (
                            match["ID"],
                            row["Target"],
                            match.get("CauseMetadata", {}).get("StartLine", 1),
                            match.get("Severity", "UNKNOWN"),
                        )
                    )
        return matches, scanned

    async def cancel(self) -> None:
        await self.runner.cancel()

    async def cleanup(self) -> None:
        await self.runner.cleanup()
