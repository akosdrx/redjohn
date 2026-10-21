"""Manual bounded CycloneDX advisory matching with an operator-pinned offline DB.

This optional adapter never proves package installation, exploitability or an
official database publisher. Existing Trivy misconfiguration behavior is separate.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary
from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record, stable_key
from redjohn.assessment.pinned_tools import BinaryPin
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.source_tools import (
    OfflineSourceRunner,
    SourceToolConfig,
    offline_trust_anchor,
    read_source_file,
)
from redjohn.assessment.trivy_copy import OwnedDatabaseCopier, TrivyCopyUnavailable
from redjohn.assessment.trivy_database import DatabaseSnapshot, bounded_document


if TYPE_CHECKING:
    from pathlib import Path

    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


CAPABILITY = "trivy_sbom"
MAX_SBOM_BYTES = 256 * 1024
_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+!-]{0,95}\Z")
_RULE = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")


@dataclass(frozen=True)
class DeclaredPackage:
    ecosystem: str
    name: str
    version: str
    purl: str
    reference: str


def parse_cyclonedx(raw: bytes) -> tuple[DeclaredPackage, ...]:
    """A strict supported subset: JSON1.5, declared unscoped npm/PyPI libraries.

    No external references, VEX/attestations, nested components, Java lookup,
    license claims, arbitrary properties, embedded tools or executable content.
    """
    document = bounded_document(raw, MAX_SBOM_BYTES)
    if (
        set(document) - {"bomFormat", "specVersion", "version", "components", "dependencies"}
        or document.get("bomFormat") != "CycloneDX"
        or document.get("specVersion") != "1.5"
        or type(document.get("version")) is not int
        or document["version"] != 1
    ):
        raise ValueError("trivy_supported_cyclonedx_json_1_5_required")
    rows = document.get("components")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128:
        raise ValueError("trivy_sbom_component_budget")
    packages = []
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"type", "name", "version", "purl", "bom-ref"}
            or row["type"] != "library"
            or not isinstance(row["name"], str)
            or _NAME.fullmatch(row["name"]) is None
            or not isinstance(row["version"], str)
            or _VERSION.fullmatch(row["version"]) is None
        ):
            raise ValueError("trivy_explicit_simple_library_component_required")
        purl, reference = row["purl"], row["bom-ref"]
        if (
            not isinstance(purl, str)
            or not isinstance(reference, str)
            or re.fullmatch(r"[A-Za-z0-9_.:@/+-]{1,256}", reference) is None
        ):
            raise ValueError("trivy_bounded_component_identity_required")
        ecosystem = next(
            (
                kind
                for kind in ("pypi", "npm")
                if purl == f"pkg:{kind}/{row['name']}@{row['version']}"
            ),
            "",
        )
        if not ecosystem or (ecosystem == "pypi" and re.search(r"[_.]", row["name"])):
            raise ValueError("trivy_exact_supported_package_purl_required")
        packages.append(DeclaredPackage(ecosystem, row["name"], row["version"], purl, reference))
    if (
        len({package.purl for package in packages}) != len(packages)
        or len({package.reference for package in packages}) != len(packages)
        or len({(package.name, package.version) for package in packages}) != len(packages)
    ):
        raise ValueError("trivy_ambiguous_or_duplicate_component")
    dependencies = document.get("dependencies", [])
    if not isinstance(dependencies, list) or len(dependencies) > 128:
        raise ValueError("trivy_sbom_dependency_budget")
    references = {package.reference for package in packages}
    seen = set()
    for dependency in dependencies:
        if (
            not isinstance(dependency, dict)
            or set(dependency) != {"ref", "dependsOn"}
            or not isinstance(dependency["ref"], str)
            or dependency["ref"] not in references
            or dependency["ref"] in seen
            or not isinstance(dependency["dependsOn"], list)
            or len(dependency["dependsOn"]) > 128
            or any(
                not isinstance(item, str) or item not in references
                for item in dependency["dependsOn"]
            )
            or len(set(dependency["dependsOn"])) != len(dependency["dependsOn"])
        ):
            raise ValueError("trivy_sbom_dependency_reference_denied")
        seen.add(dependency["ref"])
    return tuple(packages)


@dataclass(frozen=True)
class TrivySBOMConfig:
    source: SourceToolConfig
    database: DatabaseSnapshot

    @classmethod
    def from_mapping(cls, value: object) -> TrivySBOMConfig:
        if not isinstance(value, dict) or set(value) != {
            "binary",
            "source_root",
            "files",
            "database",
        }:
            raise ValueError("trivy_exact_sbom_configuration_required")
        source = SourceToolConfig.from_mapping(
            "trivy", {key: item for key, item in value.items() if key != "database"}
        )
        if len(str(source.binary.path).encode()) > 2048 or any(
            ord(char) < 32 or ord(char) == 127 for char in str(source.binary.path)
        ):
            raise ValueError("trivy_bounded_binary_path_required")
        if len(source.files) != 1 or not source.files[0][0].endswith(".json"):
            raise ValueError("trivy_one_explicit_json_sbom_required")
        return cls(source, DatabaseSnapshot.from_mapping(value["database"]))

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": {
                "path": str(self.source.binary.path),
                "sha256": self.source.binary.sha256,
                "version": self.source.binary.version,
            },
            "source_root": str(self.source.source_root),
            "files": [{"path": name, "sha256": digest} for name, digest in self.source.files],
            "database": self.database.to_dict(),
        }

    @property
    def capability(self) -> str:
        return CAPABILITY

    @property
    def binary(self) -> BinaryPin:
        return self.source.binary

    @property
    def version(self) -> str:
        return self.source.version

    @property
    def artifact_sha256(self) -> str:
        return self.source.artifact_sha256

    @property
    def revision(self) -> str:
        return stable_key(["redjohn-trivy-sbom-v1", self.source.revision, self.database.revision])

    def read_packages(self) -> tuple[DeclaredPackage, ...]:
        """Worker/local-contract IO; never called by the composed controller."""
        relative, digest = self.source.files[0]
        return parse_cyclonedx(
            read_source_file(self.source.source_root, relative, digest, MAX_SBOM_BYTES)
        )

    def validate(self, policy: EngagementPolicy) -> None:
        policy.check_capability(
            domains=("source",), profiles=("safe-production", "active-staging", "isolated-lab")
        )
        if self.artifact_sha256 not in policy.allowed_source_artifacts:
            raise PolicyDenied("trivy_sbom_artifact_not_explicitly_approved")
        if self.database.origin == "controlled_ghsa_fixture" and policy.profile != "isolated-lab":
            raise PolicyDenied("trivy_controlled_fixture_requires_isolated_lab")
        self.database.validate()


def trivy_sbom_job(
    config: TrivySBOMConfig,
    policy: EngagementPolicy,
    store: AssessmentStore,
    *,
    timeout_seconds: float = 60,
    retest_revision: str = "",
) -> JobSpec:
    config.validate(policy)
    if type(timeout_seconds) not in {int, float} or not 1 <= timeout_seconds <= 120:
        raise ValueError("trivy_sbom_timeout_budget_required")
    with store._lock:
        store.inventory._fence(store.db, policy)
    ref = store.evidence_put(
        policy.engagement_id,
        {
            "format": "redjohn-source-manifest-v1",
            "artifact_sha256": config.artifact_sha256,
            "files": [{"path": name, "sha256": digest} for name, digest in config.source.files],
        },
        kind="approved_source_manifest",
        deduplicate=True,
    )
    asset = store.inventory.record_asset(
        policy,
        kind="source_artifact",
        locator=config.artifact_sha256,
        source="imported",
        evidence_refs=(ref,),
    )
    surface = Surface(
        "",
        resource_kind="source_artifact",
        asset_ref=asset,
        artifact_sha256=config.artifact_sha256,
        input_location="source_artifact",
        input_name=config.revision,
        source="imported",
        workflow_state="approved_seed",
    )
    policy.check_surface(surface)
    sid = store.upsert_surface(policy.engagement_id, surface)
    return JobSpec(
        sid,
        "source_dependency",
        CAPABILITY,
        tool_version=config.version,
        template_version=config.revision,
        policy_revision=policy.revision,
        timeout_seconds=timeout_seconds,
        retest_revision=retest_revision,
    )


class TrivySBOMRunner(OfflineSourceRunner):
    def __init__(self, config: TrivySBOMConfig, root: Path) -> None:
        super().__init__(config.source, root)
        self.sbom_config = config
        self.data_sources: tuple[str, ...] = ()
        self.declared_packages: tuple[DeclaredPackage, ...] = ()
        self.valid_until = 0.0
        self._owned_root: Path | None = None
        self.copier = OwnedDatabaseCopier()

    async def prepare_offline(self) -> None:
        self.denied_connections = 0
        self.snapshot_readonly_attested = False
        self._owned_root = self.root / ("owned-" + uuid.uuid4().hex)
        report = await self.copier.prepare(
            self.sbom_config, self._owned_root, offline_trust_anchor()
        )
        if (
            report["artifact_sha256"] != self.sbom_config.artifact_sha256
            or not report["engine_bytes"]
        ):
            raise ValueError("trivy_prepared_artifact_or_engine_unbound")
        rows = report["packages"]
        if not rows or any(
            not isinstance(row, dict)
            or set(row) != {"ecosystem", "name", "version", "purl", "reference"}
            for row in rows
        ):
            raise ValueError("trivy_prepared_package_report_required")
        self.declared_packages = parse_cyclonedx(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "version": 1,
                    "components": [
                        {
                            "type": "library",
                            "name": row["name"],
                            "version": row["version"],
                            "purl": row["purl"],
                            "bom-ref": row["reference"],
                        }
                        for row in rows
                    ],
                }
            ).encode()
        )
        if any(
            row["ecosystem"] != package.ecosystem
            for row, package in zip(rows, self.declared_packages, strict=True)
        ):
            raise ValueError("trivy_prepared_ecosystem_unbound")
        self.data_sources, self.valid_until = tuple(report["data_sources"]), report["valid_until"]
        self.workspace, self.snapshot = (
            self._owned_root / "workspace",
            self._owned_root / "snapshot",
        )
        self.binary = BinaryPin(
            self.snapshot / "engine" / "trivy",
            self.config.binary.sha256,
            self.config.binary.version,
        )
        self._ca_file = self.workspace / "proxy-ca.pem"
        self._deny_server = await asyncio.start_server(self._deny, "127.0.0.1", 0)
        port = self._deny_server.sockets[0].getsockname()[1]
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

    def assert_fresh(self) -> None:
        if not time.time() < self.valid_until:
            raise ValueError("trivy_prepared_database_expired")

    def resource_cleanup_verified(self) -> bool:
        return (
            super().resource_cleanup_verified()
            and self.copier.resource_cleanup_verified()
            and self._owned_root is None
        )

    async def cleanup(self) -> None:
        # Never delete a snapshot while either its preparer or native reader lives.
        await self.copier.stop()
        await super().cleanup()
        await self.copier.cleanup()
        self._owned_root = None

    async def cancel(self) -> None:
        await self.copier.cancel()
        await super().cancel()

    def argv(self) -> list[str]:
        assert self.snapshot is not None
        # SBOM0.76 explicitly has no --parallel / misconfiguration flags.
        return [
            str(self.binary.path),
            "sbom",
            "--config",
            "",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--list-all-pkgs",
            "--quiet",
            "--no-progress",
            "--offline-scan",
            "--disable-telemetry",
            "--skip-version-check",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-vex-repo-update",
            "--cache-backend",
            "memory",
            "--cache-dir",
            str(self.snapshot / "cache"),
            "--ignorefile",
            str(self.snapshot / "empty-ignore"),
            "--timeout",
            "60s",
            str(self.snapshot / "source" / self.config.files[0][0]),
        ]


class TrivySBOMAdapter:
    resource_class = "scanner"

    def __init__(
        self, config: TrivySBOMConfig, policy: EngagementPolicy, store: AssessmentStore
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        config.validate(policy)
        self.runner = TrivySBOMRunner(config, store.path.parent / "trivy-sbom-workers")
        self.partial_evidence_refs: tuple[str, ...] = ()
        self._run_lock = asyncio.Lock()

    @property
    def cleanup_unverified(self) -> bool:
        """The later shared scheduler must retain its existing lease when true."""
        return self.runner.copier.cleanup_unverified

    def resource_cleanup_verified(self) -> bool:
        """Synchronous guard for the scheduler's existing logical scanner lease."""
        return self.runner.resource_cleanup_verified()

    def _fence(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> None:
        with self.store._lock:
            self.store.inventory._fence(self.store.db, self.policy)
            current = self.store.db.execute(
                "SELECT spec FROM rj_job WHERE id=? AND engagement=? AND owner=? AND attempt=? "
                "AND capability=? AND execution_status='running' "
                "AND cancel_requested=0 AND lease_until>?",
                (
                    job["id"],
                    self.policy.engagement_id,
                    job["owner"],
                    job["attempt"],
                    CAPABILITY,
                    time.time(),
                ),
            ).fetchone()
            if current is None or JobSpec(**json.loads(current[0])).key != spec.key:
                raise PolicyDenied("trivy_sbom_current_job_lease_required")
            self.store.inventory.require_surface_active(self.store.db, self.policy, spec.surface_id)
            self.store.inventory.require_source_asset(
                self.policy, surface.asset_ref, self.config.artifact_sha256
            )
        if (
            spec.options
            or spec.capability != CAPABILITY
            or spec.tool_version != self.config.version
            or spec.template_version != self.config.revision
            or spec.policy_revision != self.policy.revision
            or surface.resource_kind != "source_artifact"
            or surface.artifact_sha256 != self.config.artifact_sha256
            or surface.input_name != self.config.revision
        ):
            raise PolicyDenied("trivy_sbom_exact_current_input_required")
        self.policy.check_surface(surface)

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:
        # One optional engine instance owns one workspace/copy/namespace at a time.
        async with self._run_lock:
            return await self._run(job, surface, spec)

    async def _run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:
        stage = "prepare"
        started = time.monotonic()
        try:
            self._fence(job, surface, spec)
            self.config.validate(self.policy)
            await self.runner.prepare_offline()
            self._fence(job, surface, spec)
            health = await self.runner.healthcheck()
            self._fence(job, surface, spec)
            stage = "scan"
            raw = await self.runner.execute(self.runner.argv(), spec.timeout_seconds)
            self._fence(job, surface, spec)
            stage = "database_fence"
            self.runner.assert_fresh()
            stage = "output"
            return self.normalize(job, raw, health, time.monotonic() - started)
        except EgressUnavailable:
            return self._blocked("trivy_sbom_deny_all_namespace_unavailable")
        except TrivyCopyUnavailable:
            return self._blocked("trivy_sbom_attested_owner_or_copy_unavailable")
        except PolicyDenied:
            raise
        except (OSError, ValueError, TypeError, KeyError):
            if stage in {"prepare", "database_fence"}:
                return self._blocked("trivy_sbom_input_database_or_engine_unavailable")
            return AdapterResult(
                "failed", "inconclusive", error=error_record("trivy_sbom_output_unavailable")
            )
        finally:
            await asyncio.shield(self.cleanup())

    @staticmethod
    def _blocked(code: str) -> AdapterResult:
        return AdapterResult(
            "failed", "blocked", error=error_record(code, coverage_effect="blocked")
        )

    def normalize(  # noqa: PLR0912 - bounded exact result contract
        self, job: dict[str, Any], raw: dict[str, Any], health: dict[str, str], duration: float
    ) -> AdapterResult:
        if raw.get("timed_out"):
            return AdapterResult(
                "timed_out", "inconclusive", error=error_record("trivy_sbom_timeout")
            )
        if raw.get("error") or raw.get("truncated") or raw.get("exit_code") != 0:
            return AdapterResult(
                "failed", "inconclusive", error=error_record("trivy_sbom_failed_or_output_limited")
            )
        if self.runner.denied_connections or not self.runner.snapshot_readonly_attested:
            return self._blocked("trivy_sbom_offline_or_readonly_attestation_failed")
        self.runner.assert_fresh()
        expected = {(p.name, p.version): p for p in self.runner.declared_packages}
        if not expected:
            raise ValueError("trivy_owned_prepared_package_inventory_required")
        output = raw.get("stdout", "")
        if not isinstance(output, str):
            raise TypeError("trivy_sbom_text_output_required")
        document = bounded_document(output.encode(), 512 * 1024)
        rows = document.get("Results")
        if (
            type(document.get("SchemaVersion")) is not int
            or document["SchemaVersion"] != 2
            or not isinstance(rows, list)
            or not 1 <= len(rows) <= 2
        ):
            raise ValueError("trivy_sbom_result_schema_required")
        seen, findings = set(), []
        for row in rows:
            if (
                not isinstance(row, dict)
                or row.get("Class") != "lang-pkgs"
                or row.get("Type") not in {"python-pkg", "node-pkg"}
                or not isinstance(row.get("Packages"), list)
            ):
                raise ValueError("trivy_sbom_complete_package_inventory_required")
            kind = "pypi" if row["Type"] == "python-pkg" else "npm"
            for package in row["Packages"]:
                if (
                    not isinstance(package, dict)
                    or not isinstance(package.get("Name"), str)
                    or not isinstance(package.get("Version"), str)
                ):
                    raise TypeError("trivy_sbom_package_inventory_invalid")
                key = package["Name"], package["Version"]
                if key not in expected or key in seen or expected[key].ecosystem != kind:
                    raise ValueError("trivy_sbom_package_inventory_mismatch")
                seen.add(key)
            matches = row.get("Vulnerabilities", [])
            if not isinstance(matches, list) or len(matches) > 128:
                raise ValueError("trivy_sbom_advisory_budget")
            for match in matches:
                if (
                    not isinstance(match, dict)
                    or not isinstance(match.get("PkgName"), str)
                    or not isinstance(match.get("InstalledVersion"), str)
                ):
                    raise TypeError("trivy_sbom_advisory_package_required")
                key = match["PkgName"], match["InstalledVersion"]
                rule, source = match.get("VulnerabilityID"), match.get("DataSource")
                if (
                    key not in expected
                    or expected[key].ecosystem != kind
                    or not isinstance(rule, str)
                    or _RULE.fullmatch(rule) is None
                    or not isinstance(source, dict)
                    or source.get("ID") not in self.runner.data_sources
                ):
                    raise ValueError("trivy_sbom_advisory_identity_or_terms_mismatch")
                severity = match.get("Severity")
                if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                    raise ValueError("trivy_sbom_advisory_severity_invalid")
                findings.append(
                    {
                        "template_id": rule,
                        "source_path": self.config.source.files[0][0],
                        "component_ref": expected[key].reference,
                        "package_name": key[0],
                        "installed_version": key[1],
                        "data_source_id": source["ID"],
                        "severity": severity.lower(),
                        "finding_status": "candidate",
                        "finding_claim": "declared_sbom_advisory_match_requires_validation",
                    }
                )
        if seen != set(expected) or len(findings) > 128:
            raise ValueError("trivy_sbom_incomplete_inventory_or_finding_budget")
        if len(
            {(f["template_id"], f["package_name"], f["installed_version"]) for f in findings}
        ) != len(findings):
            raise ValueError("trivy_sbom_duplicate_advisory")
        summary = {
            "sbom_scan_completed": True,
            "scope": "declared_supported_sbom_packages",
            "packages": len(seen),
            "finding_count": len(findings),
            "requests": 0,
            "publisher_provenance_verified": False,
            "database_origin": self.config.database.origin,
            "official_aggregate_database": False,
            "package_installation_verified": False,
            "image_or_source_tree_scan": False,
            "database_revision": self.config.database.revision,
            "database_sha256": self.config.database.database_sha256,
            "metadata_sha256": self.config.database.metadata_sha256,
            "provenance_sha256": self.config.database.provenance_sha256,
            "database_schema": 2,
            "database_freshness_checked_at": time.time(),
            "artifact_sha256": self.config.artifact_sha256,
            "snapshot_readonly_attested": True,
            "duration_seconds": duration,
            **health,
        }
        ref = self.store.evidence_put(
            self.policy.engagement_id,
            {**summary, "results": findings},
            job_id=job["id"],
            kind="trivy_sbom",
        )
        return AdapterResult(
            "succeeded",
            "partial",
            summary={**summary, "evidence_refs": [ref]},
            findings=tuple({**finding, "evidence_refs": [ref]} for finding in findings),
        )

    async def cancel(self) -> None:
        await self.runner.cancel()

    async def cleanup(self) -> None:
        await self.runner.cleanup()
