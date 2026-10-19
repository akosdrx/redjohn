"""Synthetic supply-chain parser contracts; these are not WPScan engine E2Es."""

import copy
import gzip
import importlib.util
import io
import json
import os
import tarfile
import time
import urllib.request
from pathlib import Path

import pytest
import yaml


MODULE = Path(__file__).resolve().parents[1] / "scripts/audit-wpscan-gems.py"
spec = importlib.util.spec_from_file_location("redjohn_wpscan_audit", MODULE)
assert spec is not None and spec.loader is not None
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def requirement(operator=">=", version="0"):
    return {"requirements": [[operator, {"version": version}]]}


def fixture_gem(tmp_path, *, payload=None, metadata=None, outer_extra=None, bad_checksum=False):
    metadata = metadata or {
        "name": "wpscan",
        "version": {"version": "4.1.0"},
        "platform": "ruby",
        "licenses": ["Dual"],
        "dependencies": [],
        "extensions": [],
        "required_ruby_version": requirement(">=", "3.3"),
        "required_rubygems_version": requirement(),
    }
    if payload is None:
        payload = [("LICENSE", b"fixture license", tarfile.REGTYPE)]
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:") as archive:
        for name, content, kind in payload:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(content) if kind == tarfile.REGTYPE else 0
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = "/outside"
            archive.addfile(member, io.BytesIO(content) if member.size else None)
    parts = {
        "metadata.gz": gzip.compress(yaml.safe_dump(metadata).encode()),
        "data.tar.gz": gzip.compress(data.getvalue()),
    }
    hashes = {name: review.digest(value) for name, value in parts.items()}
    if bad_checksum:
        hashes["data.tar.gz"] = "0" * 64
    parts["checksums.yaml.gz"] = gzip.compress(yaml.safe_dump({"SHA256": hashes}).encode())
    if outer_extra:
        parts.update(outer_extra)
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:") as archive:
        for name, content in parts.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    body = out.getvalue()
    path = tmp_path / "wpscan-4.1.0.gem"
    path.write_bytes(body)
    pin = {
        "name": "wpscan",
        "version": "4.1.0",
        "platform": "ruby",
        "gem_uri": "https://rubygems.org/gems/wpscan-4.1.0.gem",
        "sha256": review.digest(body),
        "licenses": ["Dual"],
        "dependencies": [],
        "ruby_version": ">= 3.3",
    }
    return path, pin


def test_published_pins_have_complete_numeric_ruby_dependency_closure():
    pins = json.loads(MODULE.with_name("wpscan-component-pins.json").read_text())
    packages = review.validate_pins(pins)
    assert len(packages) == 35
    assert all(
        package["platform"] == "ruby" and "-java.gem" not in package["gem_uri"]
        for package in packages
    )
    assert next(p for p in packages if p["name"] == "wpscan")["version"] == "4.1.0"
    assert pins["target_ruby"] == "3.3.12"


@pytest.mark.parametrize("change", ["java", "url", "digest", "duplicate", "closure", "ruby"])
def test_pins_reject_platform_url_digest_duplicates_missing_dependency_and_old_ruby(change):
    pins = json.loads(MODULE.with_name("wpscan-component-pins.json").read_text())
    if change == "java":
        pins["packages"][0]["platform"] = "java"
    elif change == "url":
        pins["packages"][0]["gem_uri"] = "https://outside.invalid/a.gem"
    elif change == "digest":
        pins["packages"][0]["sha256"] = "latest"
    elif change == "duplicate":
        pins["packages"].append(copy.deepcopy(pins["packages"][0]))
    elif change == "closure":
        pins["packages"] = [p for p in pins["packages"] if p["name"] != "ffi"]
    else:
        pins["target_ruby"] = "3.2.3"
    with pytest.raises(ValueError):
        review.validate_pins(pins)


@pytest.mark.parametrize(
    "version, constraint, expected",
    [
        ("1.4.99", "~> 1.4.1", True),
        ("1.5", "~> 1.4.1", False),
        ("1.99", "~> 1.4", True),
        ("2.0", "~> 1.4", False),
        ("3.3.12", ">= 3.3, < 4", True),
        ("3.3", "!= 3.3.0", False),
    ],
)
def test_numeric_requirement_semantics_match_gem_pessimistic_and_normalized_bounds(
    version, constraint, expected
):
    assert review.satisfies(version, constraint) is expected


def test_actual_regular_fixture_and_signed_container_are_read_without_execution(tmp_path):
    path, pin = fixture_gem(tmp_path, outer_extra={"metadata.gz.sig": b"signature"})
    result = review.audit_archive(pin, path)
    assert result["runtime_dependencies"] == []
    assert result["license_notice_status"] == "packaged_notice_reviewed"
    assert result["signature_payload_sha256"] == {"metadata.gz.sig": review.digest(b"signature")}
    assert result["signature_trust_status"] == "not_chain_verified"
    assert result["extensions"] == []


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../../escape", tarfile.REGTYPE),
        ("/escape", tarfile.REGTYPE),
        ("alias", tarfile.SYMTYPE),
        ("hard", tarfile.LNKTYPE),
        ("fifo", tarfile.FIFOTYPE),
    ],
)
def test_payload_rejects_path_escape_and_nonregular_entries_without_extraction(
    tmp_path, name, kind
):
    path, pin = fixture_gem(tmp_path, payload=[(name, b"x", kind)])
    with pytest.raises(ValueError, match=r"archive_path|payload_schema"):
        review.audit_archive(pin, path)
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]


def test_duplicate_payload_and_unknown_outer_member_are_denied(tmp_path):
    path, pin = fixture_gem(tmp_path, payload=[("x", b"x", tarfile.REGTYPE)] * 2)
    with pytest.raises(ValueError, match="payload_schema"):
        review.audit_archive(pin, path)
    path, pin = fixture_gem(tmp_path, outer_extra={"unreviewed.rb": b"raise 'never evaluate'"})
    with pytest.raises(ValueError, match="container_schema"):
        review.audit_archive(pin, path)


def test_internal_and_external_archive_digests_are_both_enforced(tmp_path):
    path, pin = fixture_gem(tmp_path, bad_checksum=True)
    with pytest.raises(ValueError, match="internal_digest"):
        review.audit_archive(pin, path)
    pin["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="archive_digest"):
        review.audit_archive(pin, path)


def test_missing_full_notice_remains_a_blocker_in_completed_preparation(tmp_path):
    path, pin = fixture_gem(
        tmp_path, payload=[("README.md", b"## License\nMIT\n", tarfile.REGTYPE)]
    )
    pins = {"schema_version": 1, "target_ruby": "3.3.12", "packages": [pin]}
    result = review.audit(pins, path.parent)
    assert result["audit_status"] == "completed"
    assert result["engine_status"] == "not_installed_or_executed"
    assert result["coverage_status"] == "blocked"
    assert result["blockers"] == [{"package": "wpscan", "reason": "missing_full_license_notice"}]


@pytest.mark.parametrize(
    "text", [b"a: x\na: y\n", b"a: &a [*a]", b"a: " + b"[" * 40 + b"x" + b"]" * 40]
)
def test_yaml_rejects_duplicate_keys_alias_cycles_and_excessive_depth(text):
    with pytest.raises(ValueError):
        review.yaml_metadata(text)


def test_ruby_and_python_object_tags_are_metadata_only_and_cannot_create_files(tmp_path):
    marker = tmp_path / "must-not-exist"
    tagged = f"!!python/object/apply:os.system ['touch {marker}']\n".encode()
    assert review.yaml_metadata(tagged) == [f"touch {marker}"]
    assert review.yaml_metadata(b"--- !ruby/object:Gem::Version\nversion: 4.1.0\n") == {
        "version": "4.1.0"
    }
    assert not marker.exists()


def test_gzip_budget_stops_large_inflation_and_fifo_never_waits_for_a_writer(tmp_path):
    with pytest.raises(ValueError, match="inflated_bytes_over_budget"):
        review.gunzip(gzip.compress(b"x" * 10000), 100)
    fifo = tmp_path / "fifo.gem"
    os.mkfifo(fifo)
    started = time.monotonic()
    with pytest.raises(ValueError, match="not_regular"):
        review.read_regular(fifo, 100)
    assert time.monotonic() - started < 0.5


def test_official_archive_redirect_cannot_contact_another_origin():
    request = urllib.request.Request("https://rubygems.org/gems/wpscan-4.1.0.gem")
    with pytest.raises(ValueError, match="redirect_denied"):
        review.OfficialRedirects().redirect_request(
            request, None, 302, "Found", {}, "https://outside.invalid/evil"
        )


def test_pinned_reviewed_component_source_and_missing_files_cannot_silently_change(tmp_path):
    path, pin = fixture_gem(tmp_path)
    pin["reviewed_files"] = {"LICENSE": "0" * 64}
    with pytest.raises(ValueError, match="reviewed_source_file_digest"):
        review.audit_archive(pin, path)
    pin["reviewed_files"] = {"absent.rb": review.digest(b"x")}
    with pytest.raises(ValueError, match="reviewed_source_file_digest"):
        review.audit_archive(pin, path)


def test_declared_native_extension_must_exist_but_is_never_evaluated(tmp_path):
    metadata = {
        "name": "wpscan",
        "version": {"version": "4.1.0"},
        "platform": "ruby",
        "licenses": ["Dual"],
        "dependencies": [],
        "extensions": ["ext/install.rb"],
        "required_ruby_version": requirement(">=", "3.3"),
        "required_rubygems_version": requirement(),
    }
    path, pin = fixture_gem(tmp_path, metadata=metadata)
    with pytest.raises(ValueError, match="extension_not_packaged"):
        review.audit_archive(pin, path)
    marker = tmp_path / "must-not-exist"
    path, pin = fixture_gem(
        tmp_path,
        metadata=metadata,
        payload=[
            ("LICENSE", b"fixture", tarfile.REGTYPE),
            ("ext/install.rb", f"File.write('{marker}', 'bad')".encode(), tarfile.REGTYPE),
        ],
    )
    assert review.audit_archive(pin, path)["extensions"] == ["ext/install.rb"]
    assert not marker.exists()
