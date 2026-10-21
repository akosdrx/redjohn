#!/usr/bin/env python3
"""Audit pinned WPScan .gem bytes without installing or evaluating Ruby code.

This is a supply-chain preparation command, not a scanner or execution grant.
It only downloads the exact official RubyGems archives when --download is given.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any
import urllib.request

import yaml


MAX_GEM_BYTES = 8 * 1024 * 1024
MAX_METADATA_BYTES = 256 * 1024
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_FILES = 1024
MAX_PACKAGES = 64
MAX_TOTAL_BYTES = 64 * 1024 * 1024
HEX = re.compile(r"[a-f0-9]{64}\Z")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,5}\Z")
REQUIREMENT = re.compile(r"(>=|<=|~>|!=|=|>|<)\s*([0-9]+(?:\.[0-9]+){0,5})\Z")
LICENSE_PATH = re.compile(r"(?:licen[cs]e|copying|copyright|notice)", re.I)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_regular(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= limit:
            raise ValueError("wpscan_archive_not_regular_or_over_budget")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("wpscan_archive_over_budget")
        return data
    finally:
        os.close(fd)


def yaml_metadata(data: bytes) -> Any:
    """Read scalar/sequence/mapping nodes; never instantiate tagged Ruby objects."""
    if len(data) > MAX_METADATA_BYTES:
        raise ValueError("wpscan_metadata_over_budget")
    try:
        text = data.decode("utf-8", errors="strict")
        depth = 0
        for count, event in enumerate(yaml.parse(text, Loader=yaml.BaseLoader), start=1):
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
            if count > 20000 or depth > 32:
                raise ValueError("wpscan_metadata_node_budget")
        node = yaml.compose(text, Loader=yaml.BaseLoader)
        remaining = [20000]

        def plain(current: yaml.nodes.Node, active: frozenset[int]) -> Any:
            remaining[0] -= 1
            if remaining[0] < 0 or id(current) in active or len(active) > 32:
                raise ValueError("wpscan_metadata_alias_or_node_budget")
            next_active = active | {id(current)}
            if isinstance(current, yaml.nodes.ScalarNode):
                return current.value
            if isinstance(current, yaml.nodes.SequenceNode):
                return [plain(child, next_active) for child in current.value]
            if isinstance(current, yaml.nodes.MappingNode):
                result: dict[str, Any] = {}
                for key, value in current.value:
                    if not isinstance(key, yaml.nodes.ScalarNode) or key.value in result:
                        raise ValueError("wpscan_metadata_duplicate_or_complex_key")
                    result[key.value] = plain(value, next_active)
                return result
            raise ValueError("wpscan_metadata_node_schema")

        if node is None:
            raise ValueError("wpscan_metadata_empty")
        return plain(node, frozenset())
    except (UnicodeError, yaml.YAMLError, RecursionError) as exc:
        raise ValueError("wpscan_metadata_invalid") from exc


def gunzip(data: bytes, limit: int) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        decoded = stream.read(limit + 1)
    if len(decoded) > limit:
        raise ValueError("wpscan_inflated_bytes_over_budget")
    return decoded


def numeric_version(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError("wpscan_unreviewed_version_syntax")
    parts = tuple(map(int, value.split(".")))
    return parts + (0,) * (6 - len(parts))


def requirements(text: str) -> list[tuple[str, str]]:
    result = []
    for part in text.split(","):
        match = REQUIREMENT.fullmatch(part.strip())
        if match is None:
            raise ValueError("wpscan_unreviewed_requirement_syntax")
        result.append((match[1], match[2]))
    if not 1 <= len(result) <= 8:
        raise ValueError("wpscan_requirement_count")
    return result


def satisfies(version: str, text: str) -> bool:
    value = numeric_version(version)
    for operator, required in requirements(text):
        target = numeric_version(required)
        if operator == "~>":
            parts = list(map(int, required.split(".")))
            pivot = max(0, len(parts) - 2)
            upper = parts[: pivot + 1]
            upper[pivot] += 1
            ok = target <= value < numeric_version(".".join(map(str, upper)))
        else:
            ok = {
                ">=": value >= target,
                "<=": value <= target,
                ">": value > target,
                "<": value < target,
                "=": value == target,
                "!=": value != target,
            }[operator]
        if not ok:
            return False
    return True


def metadata_requirements(value: Any) -> str:
    if not isinstance(value, dict) or set(value) != {"requirements"}:
        raise ValueError("wpscan_metadata_requirement_schema")
    rows = value["requirements"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 8:
        raise ValueError("wpscan_metadata_requirement_schema")
    parts = []
    for row in rows:
        if (
            not isinstance(row, list)
            or len(row) != 2
            or not isinstance(row[1], dict)
            or set(row[1]) != {"version"}
        ):
            raise ValueError("wpscan_metadata_requirement_schema")
        parts.append(f"{row[0]} {row[1]['version']}")
    text = ", ".join(parts)
    requirements(text)
    return text


def requirement_identity(text: str) -> set[tuple[str, tuple[int, ...]]]:
    # Preserve ~> segment count: ~>1.4 and ~>1.4.0 have different upper bounds.
    return {
        (
            operator + (":" + str(len(version.split("."))) if operator == "~>" else ""),
            numeric_version(version),
        )
        for operator, version in requirements(text)
    }


def validate_pins(pins: Any) -> list[dict[str, Any]]:
    if not isinstance(pins, dict) or pins.get("schema_version") != 1:
        raise ValueError("wpscan_pin_schema")
    numeric_version(pins["target_ruby"])
    packages = pins.get("packages")
    if not isinstance(packages, list) or not 1 <= len(packages) <= MAX_PACKAGES:
        raise ValueError("wpscan_package_budget")
    names = set()
    for package in packages:
        if not isinstance(package, dict) or not NAME.fullmatch(package.get("name", "")):
            raise ValueError("wpscan_package_schema")
        name, version = package["name"], package["version"]
        numeric_version(version)
        expected = f"https://rubygems.org/gems/{name}-{version}.gem"
        if (
            name in names
            or package.get("platform") != "ruby"
            or package.get("gem_uri") != expected
            or not HEX.fullmatch(package.get("sha256", ""))
        ):
            raise ValueError("wpscan_package_identity")
        names.add(name)
        if not satisfies(pins["target_ruby"], package["ruby_version"]):
            raise ValueError("wpscan_required_ruby_unsatisfied")
    selected = {package["name"]: package["version"] for package in packages}
    for package in packages:
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list) or len(dependencies) > MAX_PACKAGES:
            raise ValueError("wpscan_dependency_schema")
        seen = set()
        for dependency in dependencies:
            name = dependency["name"]
            if (
                name in seen
                or name not in selected
                or not satisfies(selected[name], dependency["requirements"])
            ):
                raise ValueError("wpscan_dependency_not_pinned_or_unsatisfied")
            seen.add(name)
    return packages


class OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        if newurl != req.full_url:
            raise ValueError("wpscan_archive_redirect_denied")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(package: dict[str, Any], destination: Path) -> None:
    opener = urllib.request.build_opener(OfficialRedirects())
    with opener.open(package["gem_uri"], timeout=20) as response:
        data = response.read(MAX_GEM_BYTES + 1)
    if len(data) > MAX_GEM_BYTES or digest(data) != package["sha256"]:
        raise ValueError("wpscan_download_digest_or_budget")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(data)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(fd)


def safe_path(name: str) -> None:
    path = PurePosixPath(name)
    if (
        len(name) > 256
        or path.is_absolute()
        or ".." in path.parts
        or not name
        or "\\" in name
        or "\x00" in name
        or str(path) != name
    ):
        raise ValueError("wpscan_archive_path")


def audit_archive(package: dict[str, Any], path: Path) -> dict[str, Any]:
    data = read_regular(path, MAX_GEM_BYTES)
    if digest(data) != package["sha256"]:
        raise ValueError("wpscan_archive_digest")
    members: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as outer:
        for count, member in enumerate(outer, start=1):
            if (
                count > 6
                or not member.isfile()
                or member.name in members
                or member.name
                not in {
                    "metadata.gz",
                    "data.tar.gz",
                    "checksums.yaml.gz",
                    "metadata.gz.sig",
                    "data.tar.gz.sig",
                    "checksums.yaml.gz.sig",
                }
                or not 0 <= member.size <= (1024 if member.name.endswith(".sig") else MAX_GEM_BYTES)
            ):
                raise ValueError("wpscan_gem_container_schema")
            stream = outer.extractfile(member)
            assert stream is not None
            members[member.name] = stream.read(MAX_GEM_BYTES + 1)
    if not {"metadata.gz", "data.tar.gz", "checksums.yaml.gz"} <= set(members):
        raise ValueError("wpscan_gem_container_missing")
    metadata_bytes = gunzip(members["metadata.gz"], MAX_METADATA_BYTES)
    metadata = yaml_metadata(metadata_bytes)
    if (
        not isinstance(metadata, dict)
        or metadata.get("name") != package["name"]
        or metadata.get("version") != {"version": package["version"]}
        or metadata.get("platform") != "ruby"
        or sorted(metadata.get("licenses", [])) != sorted(package["licenses"])
    ):
        raise ValueError("wpscan_actual_metadata_identity")
    ruby_requirement = metadata_requirements(metadata["required_ruby_version"])
    if requirement_identity(ruby_requirement) != requirement_identity(package["ruby_version"]):
        raise ValueError("wpscan_actual_ruby_requirement_mismatch")
    dependencies = metadata.get("dependencies", [])
    if (
        not isinstance(dependencies, list)
        or len(dependencies) > MAX_PACKAGES
        or any(not isinstance(d, dict) for d in dependencies)
    ):
        raise ValueError("wpscan_actual_dependency_schema")
    actual_dependencies = [
        {
            "name": dependency["name"],
            "requirements": metadata_requirements(dependency["requirement"]),
        }
        for dependency in dependencies
        if dependency["type"] == ":runtime"
    ]
    wanted = {d["name"]: requirement_identity(d["requirements"]) for d in package["dependencies"]}
    actual = {d["name"]: requirement_identity(d["requirements"]) for d in actual_dependencies}
    if actual != wanted or len(actual) != len(actual_dependencies):
        raise ValueError("wpscan_actual_runtime_dependencies_mismatch")
    checksums = yaml_metadata(gunzip(members["checksums.yaml.gz"], MAX_METADATA_BYTES))
    if not isinstance(checksums, dict) or checksums.get("SHA256") != {
        name: digest(body)
        for name, body in members.items()
        if name in {"metadata.gz", "data.tar.gz"}
    }:
        raise ValueError("wpscan_internal_digest_mismatch")
    reviewed = package.get("reviewed_files", {})
    if (
        not isinstance(reviewed, dict)
        or len(reviewed) > 64
        or any(not isinstance(k, str) or not HEX.fullmatch(v) for k, v in reviewed.items())
    ):
        raise ValueError("wpscan_reviewed_file_pin_schema")
    actual_reviewed = {}
    files = set()
    total = maximum = 0
    notices = []
    embedded_archives = []
    with tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"]), mode="r|gz") as payload:
        for count, member in enumerate(payload, start=1):
            safe_path(member.name)
            if (
                count > MAX_FILES
                or not member.isfile()
                or member.name in files
                or not 0 <= member.size <= MAX_FILE_BYTES
            ):
                raise ValueError("wpscan_payload_schema_or_budget")
            files.add(member.name)
            total += member.size
            maximum = max(maximum, member.size)
            if total > MAX_PAYLOAD_BYTES:
                raise ValueError("wpscan_payload_total_budget")
            basename = PurePosixPath(member.name).name
            if (
                LICENSE_PATH.search(basename)
                or basename.lower().startswith("readme")
                or basename.endswith((".tar.gz", ".tar.xz", ".zip", ".tar.bz2"))
                or member.name in reviewed
            ):
                stream = payload.extractfile(member)
                assert stream is not None
                content = stream.read(MAX_FILE_BYTES + 1)
                if member.name in reviewed:
                    actual_reviewed[member.name] = digest(content)
                if basename.endswith((".tar.gz", ".tar.xz", ".zip", ".tar.bz2")):
                    embedded_archives.append(
                        {
                            "path": member.name,
                            "bytes": len(content),
                            "sha256": digest(content),
                            "nested_content_status": "not_recursively_reviewed",
                        }
                    )
                if LICENSE_PATH.search(basename) or b"license" in content.lower():
                    # Record the actual entire public notice file digest, not an SPDX guess.
                    notices.append(
                        {
                            "path": member.name,
                            "bytes": len(content),
                            "sha256": digest(content),
                            "dedicated_notice": bool(LICENSE_PATH.search(basename)),
                            "permission_notice_marker": b"permission is hereby granted"
                            in content.lower(),
                        }
                    )
    if actual_reviewed != reviewed:
        raise ValueError("wpscan_reviewed_source_file_digest")
    extensions = metadata.get("extensions", [])
    if not isinstance(extensions, list) or len(extensions) > 16:
        raise ValueError("wpscan_extension_schema")
    for extension in extensions:
        if extension not in files:
            raise ValueError("wpscan_extension_not_packaged")
    notice_available = any(n["dedicated_notice"] or n["permission_notice_marker"] for n in notices)
    return {
        "name": package["name"],
        "version": package["version"],
        "platform": "ruby",
        "archive_sha256": digest(data),
        "archive_bytes": len(data),
        "signature_payload_sha256": {
            name: digest(body) for name, body in members.items() if name.endswith(".sig")
        },
        "signature_trust_status": "not_chain_verified",
        "metadata_sha256": digest(metadata_bytes),
        "metadata_bytes": len(metadata_bytes),
        "payload_files": len(files),
        "payload_bytes": total,
        "max_file_bytes": maximum,
        "licenses": metadata["licenses"],
        "license_payloads": notices,
        "license_notice_status": "packaged_notice_reviewed"
        if notice_available
        else "missing_full_notice",
        "reviewed_source_file_sha256": actual_reviewed,
        "extensions": extensions,
        "embedded_archives": embedded_archives,
        "runtime_dependencies": actual_dependencies,
        "required_ruby_version": ruby_requirement,
        "required_rubygems_version": metadata_requirements(metadata["required_rubygems_version"]),
    }


def audit(pins: dict[str, Any], cache: Path, *, fetch: bool = False) -> dict[str, Any]:
    packages = validate_pins(pins)
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    results = []
    total = 0
    for package in packages:
        path = cache / f"{package['name']}-{package['version']}.gem"
        if fetch and not path.exists():
            download(package, path)
        result = audit_archive(package, path)
        total += result["payload_bytes"]
        if total > MAX_TOTAL_BYTES:
            raise ValueError("wpscan_all_payloads_budget")
        results.append(result)
    blockers = [
        {"package": row["name"], "reason": "missing_full_license_notice"}
        for row in results
        if row["license_notice_status"] != "packaged_notice_reviewed"
    ]
    return {
        "schema_version": 1,
        "audit_status": "completed",
        "engine_status": "not_installed_or_executed",
        "coverage_status": "blocked" if blockers else "preparation_only",
        "target_ruby": pins["target_ruby"],
        "pins_sha256": digest(json.dumps(pins, sort_keys=True, separators=(",", ":")).encode()),
        "packages": results,
        "package_count": len(results),
        "archive_bytes": sum(r["archive_bytes"] for r in results),
        "payload_bytes": total,
        "blockers": blockers,
        "limits": {
            "gem_bytes": MAX_GEM_BYTES,
            "metadata_bytes": MAX_METADATA_BYTES,
            "payload_bytes_per_gem": MAX_PAYLOAD_BYTES,
            "file_bytes": MAX_FILE_BYTES,
            "files_per_gem": MAX_FILES,
            "all_payload_bytes": MAX_TOTAL_BYTES,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pins", type=Path, default=Path(__file__).with_name("wpscan-component-pins.json")
    )
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument(
        "--download",
        action="store_true",
        help="Fetch exact official archives; never install/execute",
    )
    args = parser.parse_args()
    pins = json.loads(read_regular(args.pins, 256 * 1024))
    result = audit(pins, args.cache, fetch=args.download)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
