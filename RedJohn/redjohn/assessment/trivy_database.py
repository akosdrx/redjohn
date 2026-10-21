"""Operator-pinned offline Trivy DB bytes, freshness and declared data terms.

Content pins prove selected bytes, never an official publisher's authenticity.
No download, scanner, archive extraction or implicit database refresh exists here.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from redjohn.assessment.models import stable_key
from redjohn.assessment.source_tools import _source_directory, read_source_file


MAX_DATABASE_BYTES = 2 * 1024**3
MAX_PROVENANCE_BYTES = 65536
LICENSE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
NOTICE_SHA256 = "33886b726b32f94ae3ac2d1adf4f5bfb3911f774807b271d27256e4fdc2f77f3"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,96}\Z")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("trivy_duplicate_json_key")
        result[key] = value
    return result


def _constant(_value: str) -> Any:
    raise ValueError("trivy_nonfinite_json_number")


def bounded_document(raw: bytes, maximum: int) -> dict[str, Any]:
    if len(raw) > maximum:
        raise ValueError("trivy_json_byte_limit")
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (ValueError, RecursionError):
        raise ValueError("trivy_invalid_bounded_json") from None
    if not isinstance(value, dict):
        raise ValueError("trivy_json_object_required")  # noqa: TRY004 - hostile serialized input
    pending: list[tuple[Any, int]] = [(value, 0)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if depth > 32 or count > 8192:
            raise ValueError("trivy_json_structure_limit")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("trivy_nonfinite_json_number")
    return value


def timestamp(value: object) -> float:
    if not isinstance(value, str) or len(value) > 48:
        raise ValueError("trivy_utc_timestamp_required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("trivy_utc_timestamp_required")
    return parsed.timestamp()


def _https(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise ValueError("trivy_terms_https_reference_required")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
    ):
        raise ValueError("trivy_terms_https_reference_required")
    return value


@dataclass(frozen=True)
class DatabaseSnapshot:
    root: Path
    database_sha256: str
    database_bytes: int
    metadata_sha256: str
    provenance_file: Path
    provenance_sha256: str
    max_age_seconds: int = 86400
    origin: str = "operator_oci"

    @classmethod
    def from_mapping(cls, value: object) -> DatabaseSnapshot:
        fields = {
            "root",
            "database_sha256",
            "database_bytes",
            "metadata_sha256",
            "provenance_file",
            "provenance_sha256",
            "max_age_seconds",
            "origin",
        }
        if (
            not isinstance(value, dict)
            or set(value) - fields
            or fields - {"max_age_seconds", "origin"} - set(value)
        ):
            raise ValueError("trivy_exact_database_snapshot_required")
        for field in ("database_sha256", "metadata_sha256", "provenance_sha256"):
            if not isinstance(value[field], str) or _SHA.fullmatch(value[field]) is None:
                raise ValueError("trivy_database_content_pin_required")
        if any(
            not isinstance(value[key], str)
            or not Path(value[key]).is_absolute()
            or len(value[key].encode()) > 2048
            or any(ord(char) < 32 or ord(char) == 127 for char in value[key])
            for key in ("root", "provenance_file")
        ):
            raise ValueError("trivy_database_absolute_paths_required")
        if value.get("origin", "operator_oci") not in {"operator_oci", "controlled_ghsa_fixture"}:
            raise ValueError("trivy_database_origin_invalid")
        size, age = value["database_bytes"], value.get("max_age_seconds", 86400)
        if type(size) is not int or not 1 <= size <= MAX_DATABASE_BYTES:
            raise ValueError("trivy_database_disk_budget_exceeded")
        if type(age) is not int or not 60 <= age <= 7 * 86400:
            raise ValueError("trivy_database_freshness_budget_required")
        return cls(
            Path(value["root"]),
            value["database_sha256"],
            size,
            value["metadata_sha256"],
            Path(value["provenance_file"]),
            value["provenance_sha256"],
            age,
            value.get("origin", "operator_oci"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "database_sha256": self.database_sha256,
            "database_bytes": self.database_bytes,
            "metadata_sha256": self.metadata_sha256,
            "provenance_file": str(self.provenance_file),
            "provenance_sha256": self.provenance_sha256,
            "max_age_seconds": self.max_age_seconds,
            "origin": self.origin,
        }

    def validate(self) -> None:
        """Validate pinned identity only; never open an operator path here."""
        self.from_mapping(self.to_dict())

    @property
    def revision(self) -> str:
        return stable_key(
            [
                "redjohn-trivy-database-v1",
                self.database_sha256,
                self.database_bytes,
                self.metadata_sha256,
                self.provenance_sha256,
                self.max_age_seconds,
                self.origin,
            ]
        )

    def read_metadata(self) -> tuple[bytes, bytes, tuple[str, ...]]:  # noqa: PLR0912 - independent mandatory provenance/freshness gates
        """Worker/local-contract IO; production callers require the owned helper."""
        self.validate()
        descriptor, _info = _open_database(self)
        os.close(descriptor)
        metadata_raw = read_source_file(self.root, "metadata.json", self.metadata_sha256, 2048)
        metadata = bounded_document(metadata_raw, 2048)
        if (
            set(metadata) - {"Version", "NextUpdate", "UpdatedAt", "DownloadedAt"}
            or type(metadata.get("Version")) is not int
            or metadata["Version"] != 2
        ):
            raise ValueError("trivy_database_schema_2_required")
        updated, expires = (
            timestamp(metadata.get("UpdatedAt")),
            timestamp(metadata.get("NextUpdate")),
        )
        provenance_raw = read_source_file(
            self.provenance_file.parent,
            self.provenance_file.name,
            self.provenance_sha256,
            MAX_PROVENANCE_BYTES,
        )
        provenance = bounded_document(provenance_raw, MAX_PROVENANCE_BYTES)
        if (
            type(provenance.get("database_bytes")) is not int
            or set(provenance)
            != {
                "format",
                "publisher",
                "oci_reference",
                "builder_revision",
                "database_sha256",
                "database_bytes",
                "metadata_sha256",
                "acquired_at",
                "license_review",
                "data_sources",
            }
            or any(
                provenance.get(key) != expected
                for key, expected in (
                    (
                        "format",
                        "redjohn-trivy-db-controlled-fixture-v1"
                        if self.origin == "controlled_ghsa_fixture"
                        else "redjohn-trivy-db-provenance-v1",
                    ),
                    (
                        "publisher",
                        "redjohn-local-controlled-fixture"
                        if self.origin == "controlled_ghsa_fixture"
                        else "aquasecurity/trivy-db",
                    ),
                    ("database_sha256", self.database_sha256),
                    ("database_bytes", self.database_bytes),
                    ("metadata_sha256", self.metadata_sha256),
                )
            )
        ):
            raise ValueError("trivy_database_provenance_binding_required")
        if self.origin == "controlled_ghsa_fixture":
            if (
                provenance["oci_reference"] != ""
                or provenance["builder_revision"] != "cbebf2ecd6df42d36463844a45e689afee51c70f"
            ):
                raise ValueError("trivy_controlled_fixture_builder_required")
        elif (
            not isinstance(provenance["oci_reference"], str)
            or re.fullmatch(
                r"ghcr\.io/aquasecurity/trivy-db@sha256:[a-f0-9]{64}", provenance["oci_reference"]
            )
            is None
            or not isinstance(provenance["builder_revision"], str)
            or re.fullmatch(r"[a-f0-9]{40}", provenance["builder_revision"]) is None
        ):
            raise ValueError("trivy_immutable_declared_publisher_reference_required")
        review = provenance["license_review"]
        if (
            not isinstance(review, dict)
            or review.get("operator_terms_reviewed") is not True
            or review
            != {
                "engine_license_sha256": LICENSE_SHA256,
                "database_builder_license_sha256": LICENSE_SHA256,
                "database_builder_notice_sha256": NOTICE_SHA256,
                "operator_terms_reviewed": True,
            }
        ):
            raise ValueError("trivy_explicit_operator_terms_review_required")
        sources = provenance["data_sources"]
        if not isinstance(sources, list) or not 1 <= len(sources) <= 16:
            raise ValueError("trivy_advisory_data_terms_required")
        if self.origin == "controlled_ghsa_fixture" and (
            len(sources) != 1
            or not isinstance(sources[0], dict)
            or sources[0].get("id") != "ghsa"
            or sources[0].get("terms_sha256")
            != "9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94"
        ):
            raise ValueError("trivy_controlled_fixture_exact_ghsa_terms_required")
        names = []
        terms_bytes = 0
        for source in sources:
            if (
                not isinstance(source, dict)
                or set(source) != {"id", "url", "terms_url", "terms_file", "terms_sha256"}
                or not isinstance(source["id"], str)
                or _NAME.fullmatch(source["id"]) is None
                or not isinstance(source["terms_sha256"], str)
                or _SHA.fullmatch(source["terms_sha256"]) is None
            ):
                raise ValueError("trivy_advisory_data_terms_required")
            _https(source["url"])
            _https(source["terms_url"])
            terms = read_source_file(
                self.provenance_file.parent, source["terms_file"], source["terms_sha256"], 65536
            )
            terms_bytes += len(terms)
            if terms_bytes > 256 * 1024:
                raise ValueError("trivy_advisory_terms_byte_budget")
            names.append(source["id"])
        if len(set(names)) != len(names):
            raise ValueError("trivy_duplicate_advisory_data_source")
        acquired, now = timestamp(provenance["acquired_at"]), time.time()
        if "DownloadedAt" in metadata and timestamp(metadata["DownloadedAt"]) > now + 300:
            raise ValueError("trivy_database_stale_or_future")
        if (
            updated > now + 300
            or acquired > now + 300
            or expires <= updated
            or expires <= now
            or now - updated > self.max_age_seconds
            or now - acquired > self.max_age_seconds
        ):
            raise ValueError("trivy_database_stale_or_future")
        return metadata_raw, provenance_raw, tuple(sorted(names))

    def snapshot(self, destination: Path) -> tuple[str, ...]:
        """Copy each byte once into a fresh owned snapshot; never import a host cache."""
        metadata, provenance, sources = self.read_metadata()
        destination.mkdir(mode=0o700)
        try:
            _stream_database(self, destination / "trivy.db", time.monotonic() + 30)
            self.write_metadata(destination, metadata, provenance)
            self.read_metadata()  # Freshness/terms are checked again inside the helper.
        except BaseException:
            shutil.rmtree(destination)
            raise
        return sources

    def write_metadata(self, destination: Path, metadata: bytes, provenance: bytes) -> None:
        """Small bounded metadata only; scheduled DB bytes use the owned copier."""
        (destination / "metadata.json").write_bytes(metadata)
        (destination / "provenance.json").write_bytes(provenance)
        (destination / "terms").mkdir(mode=0o700)
        for index, source in enumerate(
            bounded_document(provenance, MAX_PROVENANCE_BYTES)["data_sources"]
        ):
            terms = read_source_file(
                self.provenance_file.parent, source["terms_file"], source["terms_sha256"], 65536
            )
            path = destination / "terms" / (str(index) + ".txt")
            path.write_bytes(terms)
            path.chmod(0o400)
        for name in ("trivy.db", "metadata.json", "provenance.json"):
            (destination / name).chmod(0o400)


def _open_database(config: DatabaseSnapshot) -> tuple[int, os.stat_result]:
    directory = _source_directory(config.root)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            "trivy.db", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != config.database_bytes:
            raise ValueError("trivy_database_type_or_size_mismatch")  # noqa: TRY301 - close the owned descriptor on this explicit type fence
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(directory)
    return descriptor, before


def _stream_database(config: DatabaseSnapshot, target: Path, deadline: float) -> None:
    descriptor, before = _open_database(config)
    try:
        digest, count = hashlib.sha256(), 0
        output = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(output, "wb") as handle:
            while block := os.read(descriptor, min(65536, config.database_bytes + 1 - count)):
                if time.monotonic() >= deadline:
                    raise ValueError("trivy_database_copy_deadline")
                count += len(block)
                if count > config.database_bytes:
                    raise ValueError("trivy_database_disk_budget_exceeded")
                digest.update(block)
                handle.write(block)
            handle.flush()
            os.fsync(handle.fileno())
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or count != config.database_bytes
            or digest.hexdigest() != config.database_sha256
        ):
            raise ValueError("trivy_database_changed_or_digest_mismatch")
    finally:
        os.close(descriptor)
