"""Synthetic DB/terms fixtures and actual bounded local file IO contracts.

The bytes below are not a bbolt database or official advisory feed. No Trivy,
download, namespace or vulnerability scan is run by these tests.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime, timedelta

import pytest

from redjohn.assessment import trivy_database
from redjohn.assessment.trivy_database import (
    LICENSE_SHA256,
    NOTICE_SHA256,
    DatabaseSnapshot,
    bounded_document,
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def synthetic_database(tmp_path, *, metadata_change=None, provenance_change=None, data=None):
    root = tmp_path / "synthetic-db"
    root.mkdir()
    data = data if data is not None else b"SYNTHETIC_NOT_A_TRIVY_DATABASE\n" * 4000
    (root / "trivy.db").write_bytes(data)
    now = datetime.now(UTC)
    metadata = {
        "Version": 2,
        "UpdatedAt": (now - timedelta(minutes=5)).isoformat(),
        "NextUpdate": (now + timedelta(hours=1)).isoformat(),
    }
    if metadata_change:
        metadata_change(metadata)
    raw = json.dumps(metadata).encode()
    (root / "metadata.json").write_bytes(raw)
    terms = b"SYNTHETIC TERMS FIXTURE; NOT AN UPSTREAM LICENSE\n"
    (tmp_path / "synthetic-terms.txt").write_bytes(terms)
    provenance = {
        "format": "redjohn-trivy-db-provenance-v1",
        "publisher": "aquasecurity/trivy-db",
        "oci_reference": "ghcr.io/aquasecurity/trivy-db@sha256:" + "1" * 64,
        "builder_revision": "2" * 40,
        "database_sha256": digest(data),
        "database_bytes": len(data),
        "metadata_sha256": digest(raw),
        "acquired_at": now.isoformat(),
        "license_review": {
            "engine_license_sha256": LICENSE_SHA256,
            "database_builder_license_sha256": LICENSE_SHA256,
            "database_builder_notice_sha256": NOTICE_SHA256,
            "operator_terms_reviewed": True,
        },
        "data_sources": [
            {
                "id": "synthetic-advisory",
                "url": "https://example.invalid/advisories",
                "terms_url": "https://example.invalid/LICENSE",
                "terms_file": "synthetic-terms.txt",
                "terms_sha256": digest(terms),
            }
        ],
    }
    if provenance_change:
        provenance_change(provenance)
    encoded = json.dumps(provenance).encode()
    path = tmp_path / "synthetic-provenance.json"
    path.write_bytes(encoded)
    return {
        "root": str(root),
        "database_sha256": digest(data),
        "database_bytes": len(data),
        "metadata_sha256": digest(raw),
        "provenance_file": str(path),
        "provenance_sha256": digest(encoded),
    }, data


def test_actual_bounded_stream_copy_hashes_all_synthetic_bytes_and_terms(tmp_path, monkeypatch):
    raw, data = synthetic_database(tmp_path)
    selected = DatabaseSnapshot.from_mapping(raw)
    actual_read, requests = os.read, []

    def observed_read(descriptor, count):
        requests.append(count)
        return actual_read(descriptor, count)

    monkeypatch.setattr(trivy_database.os, "read", observed_read)
    target = tmp_path / "snapshot"
    assert selected.snapshot(target) == ("synthetic-advisory",)
    assert (target / "trivy.db").read_bytes() == data
    assert max(requests) <= 65536 and len(requests) > 2
    assert (target / "trivy.db").stat().st_mode & 0o777 == 0o400
    assert digest((target / "terms/0.txt").read_bytes()) == digest(
        (tmp_path / "synthetic-terms.txt").read_bytes()
    )


@pytest.mark.parametrize(
    "defect",
    [
        "schema",
        "expired",
        "old",
        "future",
        "future_download",
        "age_bool",
        "unbounded",
        "terms_unapproved",
        "terms_integer",
        "mutable_ref",
        "terms_changed",
    ],
)
def test_missing_or_invalid_database_authority_never_becomes_a_negative_scan(tmp_path, defect):
    def metadata(value):
        now = datetime.now(UTC)
        if defect == "schema":
            value["Version"] = 3
        elif defect == "expired":
            value["NextUpdate"] = (now - timedelta(seconds=1)).isoformat()
        elif defect == "old":
            value["UpdatedAt"] = (now - timedelta(days=2)).isoformat()
        elif defect == "future":
            value["UpdatedAt"] = (now + timedelta(hours=2)).isoformat()
        elif defect == "future_download":
            value["DownloadedAt"] = (now + timedelta(hours=2)).isoformat()

    def provenance(value):
        if defect in {"terms_unapproved", "terms_integer"}:
            value["license_review"]["operator_terms_reviewed"] = (
                False if defect == "terms_unapproved" else 1
            )
        elif defect == "mutable_ref":
            value["oci_reference"] = "ghcr.io/aquasecurity/trivy-db:2"

    raw, _ = synthetic_database(tmp_path, metadata_change=metadata, provenance_change=provenance)
    if defect == "age_bool":
        raw["max_age_seconds"] = True
    elif defect == "unbounded":
        raw["database_bytes"] = 2**40
    elif defect == "terms_changed":
        (tmp_path / "synthetic-terms.txt").write_text("changed")
    with pytest.raises(ValueError):
        DatabaseSnapshot.from_mapping(raw).read_metadata()


@pytest.mark.parametrize("defect", ["digest", "missing", "fifo", "symlink", "metadata"])
def test_actual_snapshot_denies_missing_changed_and_nonregular_files(tmp_path, defect):
    raw, _ = synthetic_database(tmp_path)
    selected = DatabaseSnapshot.from_mapping(raw)
    root = selected.root
    if defect in {"missing", "fifo", "symlink"}:
        (root / "trivy.db").unlink()
    if defect == "digest":
        (root / "trivy.db").write_bytes(b"x" * raw["database_bytes"])
    elif defect == "fifo":
        os.mkfifo(root / "trivy.db", 0o600)
    elif defect == "symlink":
        (root / "trivy.db").symlink_to(tmp_path / "synthetic-terms.txt")
    elif defect == "metadata":
        (root / "metadata.json").write_text("{}")
    target = tmp_path / "snapshot"
    with pytest.raises((ValueError, OSError)):
        selected.snapshot(target)
    assert not target.exists()


def test_database_revision_changes_with_any_pinned_database_or_terms_bytes(tmp_path):
    raw, _ = synthetic_database(tmp_path)
    first = DatabaseSnapshot.from_mapping(raw)
    raw["max_age_seconds"] = 3600
    assert DatabaseSnapshot.from_mapping(raw).revision != first.revision


def test_actual_copy_deadline_is_enforced_between_bounded_file_reads(tmp_path):
    raw, _ = synthetic_database(tmp_path)
    selected = DatabaseSnapshot.from_mapping(raw)
    with pytest.raises(ValueError, match="copy_deadline"):
        trivy_database._stream_database(selected, tmp_path / "partial", time.monotonic() - 1)


def test_existing_snapshot_directory_is_preserved_without_adoption(tmp_path):
    raw, _ = synthetic_database(tmp_path)
    selected = DatabaseSnapshot.from_mapping(raw)
    target = tmp_path / "snapshot"
    target.mkdir()
    (target / "preserve").write_text("existing-data")
    with pytest.raises(FileExistsError):
        selected.snapshot(target)
    assert (target / "preserve").read_text() == "existing-data"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b"[]",
        b'{"x":' + b"[" * 34 + b"0" + b"]" * 34 + b"}",
    ],
)
def test_bounded_json_rejects_duplicate_nonfinite_and_deep_synthetic_input(raw):
    with pytest.raises(ValueError):
        bounded_document(raw, 65536)
