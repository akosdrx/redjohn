"""Explicitly pinned private Ruby/Nokogiri/Racc runtime for offline observation.

No gem discovery, installer or version process runs at import/configuration time.
All execution uses RedJohn's existing supervised deny-all source namespace.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import re
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary
from redjohn.assessment.pinned_tools import BinaryPin
from redjohn.assessment.source_tools import (
    OfflineSourceRunner,
    SourceToolConfig,
    offline_trust_anchor,
    read_source_file,
    relative_source_path,
)
from redjohn.assessment.wpscan_component import (
    BOOTSTRAP_SHA256,
    COMPONENT_SHA256,
    NOKOGIRI_VERSION,
    RACC_VERSION,
    RUBY_VERSION,
    WPScanComponentSource,
    WPScanHTMLArtifact,
)


if TYPE_CHECKING:
    from collections.abc import Callable


MAX_RUNTIME_FILES = 4096
MAX_RUNTIME_BYTES = 128 * 1024 * 1024
MAX_RUNTIME_FILE_BYTES = 32 * 1024 * 1024
RUBY_SOURCE_COMMIT = "0581089df9f0af0fe6b64cb8167987c211100947"
RUBY_ARCHIVE_SHAS = {
    "aarch64": "72fbd769aca07528cbcfb093f4d00b63740096b5fbe51e6b324db0812fc11245",
    "x86_64": "3fa2d6242e105a65f694fae86e9f68d9617c827fc14d1fcf611035b9ae2cbdb8",
}
GEM_ARCHIVE_SHAS = {
    "nokogiri": "50c951611c92bca05c51411aef45f1cbc50f2821c4802758c5c6d34696533ab5",
    "racc": "4a7f6929691dbec8b5209a0b373bc2614882b55fc5d2e447a21aaa691303d62f",
}
REQUIRED_LICENSE_SHAS = {
    "licenses/ruby/COPYING": "967586d538a28955ec2541910cf63c5ac345fcdea94bfb1f1705a1f6eb36bcbb",
    "licenses/ruby/BSDL": "36a9a6e7347214bbba599a412617204e65bff065dcbe5c46f5cb454c80de9eb0",
    "licenses/ruby/LEGAL": "e849b28d324423e636a3e6bc5d583cdaf4bd046c2b20872c53886b612d01a4a1",
    "licenses/nokogiri/LICENSE.md": (
        "fdc2068b104e269be2946e21d271d340dfd003f0c8f964308cba4404f75db1aa"
    ),
    "licenses/nokogiri/LICENSE-DEPENDENCIES.md": (
        "ec46d18d39ebe8c6c89b9c2cc5e9e0745ead6a80e3caf4496c8ded89c638102d"
    ),
    "licenses/racc/COPYING": "967586d538a28955ec2541910cf63c5ac345fcdea94bfb1f1705a1f6eb36bcbb",
}

EXPECTED_RUNTIME = {
    "ruby": RUBY_VERSION,
    "nokogiri": NOKOGIRI_VERSION,
    "racc": RACC_VERSION,
    "network": "offline",
}
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_FORBIDDEN = re.compile(
    r"(?:^|/)(?:ferrum|typhoeus|active_support|get_process_mem|mini_portile2|wpscan)(?:/|\.rb$)"
)
# Fixed host-authored launcher: file protection applies before Ruby or extension
# initialization. All inherited credentials remain filtered by bounded_worker.
_LAUNCH = """import os,resource,sys
resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
env=dict(os.environ)
env['LD_LIBRARY_PATH']=sys.argv[1]
os.execve(sys.argv[2],sys.argv[2:],env)
"""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("wpscan_runtime_duplicate_json_key")
        result[key] = value
    return result


def runtime_document(data: bytes) -> dict[str, Any]:
    if len(data) > 1024 * 1024:
        raise ValueError("wpscan_runtime_manifest_byte_budget")
    try:
        value = json.loads(data, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("wpscan_runtime_manifest_invalid") from exc
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > 40000 or depth > 8:
            raise ValueError("wpscan_runtime_manifest_node_budget")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in {str, int, bool}:
            raise ValueError("wpscan_runtime_manifest_scalar_schema")
    if not isinstance(value, dict):
        raise TypeError("wpscan_runtime_manifest_object_required")
    return value


@dataclass(frozen=True)
class RuntimeFile:
    path: str
    sha256: str
    executable: bool


@dataclass(frozen=True)
class WPScanRuntime:
    root: Path
    manifest_file: Path
    manifest_sha256: str
    architecture: str
    files: tuple[RuntimeFile, ...]
    load_paths: tuple[str, ...]
    expected_features: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: object) -> WPScanRuntime:
        if (
            not isinstance(value, dict)
            or set(value) != {"root", "manifest_file", "manifest_sha256"}
            or not all(isinstance(item, str) for item in value.values())
            or not Path(value["root"]).is_absolute()
            or len(value["root"]) > 1024
            or not Path(value["manifest_file"]).is_absolute()
            or _DIGEST.fullmatch(value["manifest_sha256"]) is None
        ):
            raise ValueError("wpscan_explicit_runtime_manifest_required")
        return WPScanRuntime(
            Path(value["root"]),
            Path(value["manifest_file"]),
            value["manifest_sha256"],
            "",
            (),
            (),
            (),
        )

    def load_manifest(self) -> WPScanRuntime:  # noqa: PLR0912 - fixed IO worker only
        """Read a pinned operator manifest only inside the deadline-owned helper."""
        value = {
            "root": str(self.root),
            "manifest_file": str(self.manifest_file),
            "manifest_sha256": self.manifest_sha256,
        }
        manifest = Path(value["manifest_file"])
        document = runtime_document(
            read_source_file(manifest.parent, manifest.name, value["manifest_sha256"], 1024 * 1024)
        )
        if (
            set(document)
            != {
                "schema_version",
                "architecture",
                "ruby_source_commit",
                "ruby_archive_sha256",
                "gem_archive_sha256",
                "runtime",
                "files",
                "load_paths",
                "expected_features",
                "license_files",
                "linked_libraries",
            }
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or not isinstance(document["architecture"], str)
            or document["architecture"] not in RUBY_ARCHIVE_SHAS
            or document["ruby_source_commit"] != RUBY_SOURCE_COMMIT
            or document["ruby_archive_sha256"] != RUBY_ARCHIVE_SHAS[document["architecture"]]
            or document["gem_archive_sha256"] != GEM_ARCHIVE_SHAS
            or document["runtime"] != EXPECTED_RUNTIME
        ):
            raise ValueError("wpscan_runtime_provenance_or_version_mismatch")
        rows = document["files"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_RUNTIME_FILES:
            raise ValueError("wpscan_runtime_file_count_budget")
        entries = []
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"path", "sha256", "executable"}
                or not isinstance(row["sha256"], str)
                or _DIGEST.fullmatch(row["sha256"]) is None
                or type(row["executable"]) is not bool
            ):
                raise ValueError("wpscan_runtime_file_schema")
            path = relative_source_path(row["path"])
            if not path.startswith(
                ("ruby/", "packages/nokogiri/", "packages/racc/", "native/", "licenses/")
            ) or _FORBIDDEN.search(path):
                raise ValueError("wpscan_unreviewed_runtime_component")
            if "/gems/" in path:
                raise ValueError("wpscan_ambient_gem_tree_denied")
            entries.append(RuntimeFile(path, row["sha256"], row["executable"]))
        by_path = {entry.path: entry for entry in entries}
        if (
            len(by_path) != len(entries)
            or "ruby/bin/ruby" not in by_path
            or not by_path["ruby/bin/ruby"].executable
        ):
            raise ValueError("wpscan_duplicate_or_missing_ruby_executable")
        load_paths, features = document["load_paths"], document["expected_features"]
        if (
            not isinstance(load_paths, list)
            or not 2 <= len(load_paths) <= 8
            or not isinstance(features, list)
            or not 1 <= len(features) <= 512
            or any(not isinstance(path, str) for path in load_paths + features)
            or len(set(load_paths)) != len(load_paths)
            or len(set(features)) != len(features)
        ):
            raise ValueError("wpscan_runtime_load_closure_budget")
        for path in load_paths:
            relative_source_path(path)
            if not any(entry.path.startswith(path + "/") for entry in entries):
                raise ValueError("wpscan_runtime_load_path_not_in_manifest")
        for feature in features:
            relative_source_path(feature)
            if feature not in by_path:
                raise ValueError("wpscan_runtime_feature_not_in_manifest")
        if any(
            path != "ruby/bin/ruby"
            and path not in features
            and not path.startswith(("native/", "licenses/"))
            for path in by_path
        ):
            raise ValueError("wpscan_runtime_contains_unused_component_code")
        licenses = document["license_files"]
        if (
            not isinstance(licenses, list)
            or not 6 <= len(licenses) <= 32
            or any(
                not isinstance(path, str) or path not in by_path or not path.startswith("licenses/")
                for path in licenses
            )
        ):
            raise ValueError("wpscan_runtime_license_payload_required")
        if any(
            path not in licenses or path not in by_path or by_path[path].sha256 != expected
            for path, expected in REQUIRED_LICENSE_SHAS.items()
        ):
            raise ValueError("wpscan_runtime_original_license_digest_mismatch")
        if len(set(licenses)) != len(licenses):
            raise ValueError("wpscan_duplicate_license_receipt")
        libraries = document["linked_libraries"]
        if not isinstance(libraries, list) or not 1 <= len(libraries) <= 32:
            raise ValueError("wpscan_os_library_receipts_required")
        for row in libraries:
            if (
                not isinstance(row, dict)
                or set(row) != {"path", "package", "version", "copyright_file", "source_kind"}
                or not all(isinstance(item, str) for item in row.values())
                or row["path"] not in by_path
                or not row["path"].startswith("native/")
                or row["copyright_file"] not in licenses
                or row["source_kind"] not in {"ruby_archive", "os_package"}
                or any(
                    not isinstance(row[k], str) or not 1 <= len(row[k]) <= 256
                    for k in ["package", "version"]
                )
            ):
                raise ValueError("wpscan_os_library_receipt_invalid")
        if len({row["path"] for row in libraries}) != len(libraries):
            raise ValueError("wpscan_duplicate_library_receipt")
        if {row["path"] for row in libraries} != {
            path for path in by_path if path.startswith("native/")
        }:
            raise ValueError("wpscan_native_library_receipt_missing")
        return WPScanRuntime(
            Path(value["root"]),
            manifest,
            value["manifest_sha256"],
            document["architecture"],
            tuple(sorted(entries, key=lambda entry: entry.path)),
            tuple(load_paths),
            tuple(sorted(features)),
        )

    @property
    def binary(self) -> BinaryPin:
        entry = next(entry for entry in self.files if entry.path == "ruby/bin/ruby")
        return BinaryPin(self.root / entry.path, entry.sha256, RUBY_VERSION)


class WPScanObservationRunner(OfflineSourceRunner):
    """Selected-job only; actual pinned native output or an explicit blocked gap."""

    def __init__(
        self,
        runtime: WPScanRuntime,
        source: WPScanComponentSource,
        artifact: WPScanHTMLArtifact,
        root: Path,
        guard: Callable[[], None],
    ) -> None:
        super().__init__(
            SourceToolConfig(
                "wordpress_observe",
                BinaryPin(Path("/unprepared/ruby"), "0" * 64, RUBY_VERSION),
                artifact.html_file.parent,
                (),
            ),
            root,
        )
        self.runtime, self.source, self.artifact, self.guard = runtime, source, artifact, guard
        self.engine: Path | None = None
        self.expected_runtime_files: set[str] = set()
        self.io: Any = None
        self._wp_cleanup_task: asyncio.Task[None] | None = None

    async def prepare_offline(self) -> None:
        from redjohn.assessment.wpscan_io import WPScanIO  # noqa: PLC0415
        from redjohn.assessment.wpscan_observe import WPScanObserveConfig  # noqa: PLC0415

        self.guard()
        if platform.system() != "Linux":
            raise EgressUnavailable("wpscan_reviewed_linux_runtime_required")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(prefix="job-", dir=self.root)
        self.workspace = Path(self._temporary.name).resolve()
        self.snapshot = self.root.resolve() / ("snapshot-" + uuid.uuid4().hex)
        self.io = WPScanIO(self.root / "io-workers", self.guard)
        config = WPScanObserveConfig(self.source, self.artifact, self.runtime)
        report = await self.io.prepare_bundle(config.to_mapping(), self.snapshot, 15)
        if (
            set(report)
            != {
                "prepared",
                "nonce",
                "configuration_revision",
                "manifest_sha256",
                "architecture",
                "binary_sha256",
                "load_paths",
                "expected_features",
                "runtime_files",
                "runtime_bytes",
            }
            or report["prepared"] is not True
            or report["nonce"] != self.io.nonce
            or report["configuration_revision"] != config.revision
            or report["manifest_sha256"] != self.runtime.manifest_sha256
            or report["architecture"] != platform.machine()
            or not isinstance(report["binary_sha256"], str)
            or _DIGEST.fullmatch(report["binary_sha256"]) is None
            or type(report["runtime_files"]) is not int
            or not 1 <= report["runtime_files"] <= MAX_RUNTIME_FILES
            or type(report["runtime_bytes"]) is not int
            or not 1 <= report["runtime_bytes"] <= MAX_RUNTIME_BYTES
        ):
            raise ValueError("wpscan_owned_prepare_report_unbound")
        paths, features = report["load_paths"], report["expected_features"]
        if (
            not isinstance(paths, list)
            or not 2 <= len(paths) <= 8
            or not isinstance(features, list)
            or not 1 <= len(features) <= 512
            or any(not isinstance(path, str) for path in paths + features)
        ):
            raise ValueError("wpscan_owned_prepare_closure_unbound")
        for path in paths + features:
            relative_source_path(path)
        self.engine = self.snapshot / "engine"
        self.runtime = WPScanRuntime(
            self.runtime.root,
            self.runtime.manifest_file,
            self.runtime.manifest_sha256,
            report["architecture"],
            (RuntimeFile("ruby/bin/ruby", report["binary_sha256"], executable=True),),
            tuple(paths),
            tuple(features),
        )
        self.binary = BinaryPin(
            self.engine / "ruby/bin/ruby", report["binary_sha256"], RUBY_VERSION
        )
        self.expected_runtime_files = {str(self.engine / feature) for feature in features}
        self.guard()
        self._ca_file = self.workspace / "proxy-ca.pem"
        self._ca_file.write_bytes(offline_trust_anchor())
        self._ca_file.chmod(0o600)
        (self.workspace / "empty-ca-directory").mkdir(mode=0o700)
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
            raise EgressUnavailable("wpscan_snapshot_readonly_attestation_failed")
        self.snapshot_readonly_attested = True

    def _snapshot_engine(self) -> None:
        raise RuntimeError("wpscan_operator_io_requires_owned_async_prepare")

    def resource_cleanup_verified(self) -> bool:
        return (
            getattr(super(), "resource_cleanup_verified", lambda: False)() is True
            and (self.io is None or self.io.resource_cleanup_verified())
            and self.snapshot is None
            and (self._wp_cleanup_task is None or self._wp_cleanup_task.done())
        )

    async def _cleanup_wp_bundle(self) -> None:
        await super().cleanup()
        if self.io is not None:
            await self.io.cleanup()
            if not self.io.resource_cleanup_verified():
                raise RuntimeError("wpscan_owned_io_cleanup_unverified")
            self.io = None

    async def cleanup(self) -> None:
        from redjohn.assessment.wpscan_io import WPScanIO  # noqa: PLC0415

        if self._wp_cleanup_task is None or self._wp_cleanup_task.done():
            self._wp_cleanup_task = asyncio.create_task(self._cleanup_wp_bundle())
        await WPScanIO._join(self._wp_cleanup_task)

    def _worker_argv(self, argv: list[str]) -> list[str]:
        self.guard()
        if argv[1:] == ["__redjohn_verify_snapshot__"]:
            return super()._worker_argv(argv)
        assert self.engine is not None
        return [sys.executable, "-I", "-S", "-c", _LAUNCH, str(self.engine / "native"), *argv]

    def argv(self, *, health: bool = False) -> list[str]:
        assert self.engine is not None
        paths = ":".join(str(self.engine / path) for path in self.runtime.load_paths)
        args = [
            str(self.binary.path),
            "--disable-gems",
            "--disable-did_you_mean",
            "--disable-error_highlight",
            "-I",
            paths,
            str(self.engine / "wpscan_observe_bootstrap.rb"),
        ]
        return args + (
            ["--health"]
            if health
            else [str(self.engine / "request.json"), str(self.engine / "component.rb")]
        )

    def validate_runtime_files(self, document: dict[str, Any]) -> None:
        features = document.pop("_runtime_files", None)
        if (
            not isinstance(features, list)
            or len(features) > 512
            or any(not isinstance(feature, str) for feature in features)
            or len(set(features)) != len(features)
            or set(features) != self.expected_runtime_files
            or document.get("runtime") != EXPECTED_RUNTIME
        ):
            raise ValueError("wpscan_native_runtime_load_closure_mismatch")

    async def healthcheck(self) -> dict[str, str]:
        self.guard()
        raw = await self.execute(self.argv(health=True), 5)
        if (
            raw.get("error")
            or raw.get("timed_out")
            or raw.get("truncated")
            or raw.get("exit_code") != 0
        ):
            raise ValueError("wpscan_pinned_native_runtime_unavailable")
        document = runtime_document(raw.get("stdout", "").encode())
        self.validate_runtime_files(document)
        if (
            set(document) != {"schema_version", "runtime", "ruby_revision"}
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or document["ruby_revision"] not in {RUBY_SOURCE_COMMIT, RUBY_SOURCE_COMMIT[:10]}
        ):
            raise ValueError("wpscan_ruby_source_revision_mismatch")
        self.guard()
        return {
            "ruby_version": RUBY_VERSION,
            "nokogiri_version": NOKOGIRI_VERSION,
            "racc_version": RACC_VERSION,
            "runtime_manifest_sha256": self.runtime.manifest_sha256,
            "bootstrap_sha256": BOOTSTRAP_SHA256,
            "component_sha256": COMPONENT_SHA256,
            "runtime_features_sha256": hashlib.sha256(
                json.dumps(sorted(self.runtime.expected_features)).encode()
            ).hexdigest(),
        }
