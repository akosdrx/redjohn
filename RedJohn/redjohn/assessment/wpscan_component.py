"""Offline WPScan passive-component payload preparation, not a live scan grant.

Only an operator-supplied, content-pinned upstream method is extracted. No WPScan
source/third-party runtime is redistributed by this module. Native execution and
scheduler registration require a separately verified, confined Linux backend.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from redjohn.assessment.models import stable_key
from redjohn.assessment.source_tools import read_source_file


UPSTREAM_VERSION = "4.1.0"
UPSTREAM_COMMIT = "f6169f00652c07feb45f57ff2a10e38949c28d56"
SOURCE_SHA256 = "9f612c9148ff3fa3213361e5e08306f6cd7a449c8946eb88cb15adf94c7e5f88"
LICENSE_SHA256 = "72eaecf9c3497bb34fb5722eba38a4b3b0ae39235c17378547101b8329b51008"
FRAGMENT_SHA256 = "db80f7cc572d58e2f27e70b0783615146ddf69d803ff60ea79feb83b2a1c330c"
# One-based inclusive ranges in the exact upstream source file. These exclude
# require/include hooks, HTTP/browser logic, cookies, login and other methods.
FRAGMENTS = (
    (14, 14, "e16e1e36a99527490354197ac6a64ef37c48599f1e9d3dee36e8b4141d2733eb"),
    (16, 17, "6e17a934ed8fa76dbbcb7f9ee6224299cbc267308ace92bee4e8691e2f7bdafb"),
    (51, 67, "5e69a78748bf307c6bff64b2acfdb9f7fa50e138101283e4cb2664da1d9d768e"),
)
COMPONENT_SHA256 = "002dae6850a08ecfe5abc1afcb694642b9d9132fd8406193d2987be6e4ecf70b"
RUBY_VERSION = "3.3.12"
NOKOGIRI_VERSION = "1.19.4"
RACC_VERSION = "1.8.1"
MAX_HTML_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 64 * 1024
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
BOOTSTRAP_SHA256 = "4aee6996b6801ee51b9d3677296e2c01bd73eed262081534d35296634bbbfbfb"
BOOTSTRAP = Path(__file__).with_name("wpscan_observe_bootstrap.rb")


def _absolute_file(value: object) -> Path:
    if not isinstance(value, str) or len(value) > 4096 or not Path(value).is_absolute():
        raise ValueError("wpscan_operator_absolute_file_required")
    return Path(value)


def _page_url(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("wpscan_artifact_page_url_invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
        if hostname is not None:
            hostname.encode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("wpscan_artifact_page_url_invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port == 0
        or any(ord(c) < 33 for c in value)
    ):
        raise ValueError("wpscan_artifact_page_url_invalid")
    return value


@dataclass(frozen=True)
class WPScanComponentSource:
    source_file: Path
    license_file: Path
    operator_use: str

    def __post_init__(self) -> None:
        _absolute_file(str(self.source_file))
        _absolute_file(str(self.license_file))
        if self.operator_use not in {"own-systems", "pentest-toolkit"}:
            raise ValueError("wpscan_external_component_license_context_required")

    @classmethod
    def from_mapping(cls, value: object) -> WPScanComponentSource:
        if (
            not isinstance(value, dict)
            or set(value)
            != {"source_file", "license_file", "external_operator_component", "operator_use"}
            or value["external_operator_component"] is not True
            or not isinstance(value["operator_use"], str)
            or value["operator_use"] not in {"own-systems", "pentest-toolkit"}
        ):
            raise ValueError("wpscan_external_component_license_context_required")
        return cls(
            _absolute_file(value["source_file"]),
            _absolute_file(value["license_file"]),
            value["operator_use"],
        )

    def reviewed_fragment(self) -> bytes:
        # The original public-source license must exist as the exact upstream
        # bytes; a host's context declaration does not grant commercial rights.
        read_source_file(self.license_file.parent, self.license_file.name, LICENSE_SHA256, 4096)
        original = read_source_file(
            self.source_file.parent, self.source_file.name, SOURCE_SHA256, MAX_SOURCE_BYTES
        )
        lines = original.splitlines(keepends=True)
        chunks = []
        for first, last, expected in FRAGMENTS:
            selected = b"".join(lines[first - 1 : last])
            if hashlib.sha256(selected).hexdigest() != expected:
                raise ValueError("wpscan_reviewed_source_range_mismatch")
            chunks.append(selected)
        component = b"".join(chunks)
        if hashlib.sha256(component).hexdigest() != FRAGMENT_SHA256:
            raise ValueError("wpscan_reviewed_source_fragment_mismatch")
        return component


@dataclass(frozen=True)
class WPScanHTMLArtifact:
    html_file: Path
    html_sha256: str
    page_url: str

    def __post_init__(self) -> None:
        _absolute_file(str(self.html_file))
        _page_url(self.page_url)
        if not isinstance(self.html_sha256, str) or SHA256.fullmatch(self.html_sha256) is None:
            raise ValueError("wpscan_html_artifact_digest_required")

    @classmethod
    def from_mapping(cls, value: object) -> WPScanHTMLArtifact:
        # Initial input is an explicitly supplied immutable operator artifact.
        # A future browser producer needs its own committed capture proof; no
        # producer name or arbitrary evidence ref can impersonate that proof.
        if (
            not isinstance(value, dict)
            or set(value) != {"html_file", "html_sha256", "page_url", "producer"}
            or value["producer"] != "operator"
            or not isinstance(value["html_sha256"], str)
            or SHA256.fullmatch(value["html_sha256"]) is None
        ):
            raise ValueError("wpscan_reviewed_operator_html_artifact_required")
        return cls(
            _absolute_file(value["html_file"]), value["html_sha256"], _page_url(value["page_url"])
        )

    def html_bytes(self) -> bytes:
        data = read_source_file(
            self.html_file.parent, self.html_file.name, self.html_sha256, MAX_HTML_BYTES
        )
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ValueError("wpscan_html_artifact_encoding_unsupported") from exc
        if "\x00" in text:
            raise ValueError("wpscan_html_artifact_nul_unsupported")
        return data

    @property
    def revision(self) -> str:
        return stable_key(["operator-html-observation-v1", self.html_sha256, self.page_url])


def component_payload(
    source: WPScanComponentSource, artifact: WPScanHTMLArtifact
) -> dict[str, bytes]:
    """Prepare bounded data/code bytes; does not spawn, install, fetch or scan."""
    component = b"class RedJohnWPObservation\n" + source.reviewed_fragment() + b"end\n"
    if hashlib.sha256(component).hexdigest() != COMPONENT_SHA256:
        raise ValueError("wpscan_component_wrapper_digest")
    license_bytes = read_source_file(
        source.license_file.parent, source.license_file.name, LICENSE_SHA256, 4096
    )
    html = artifact.html_bytes()
    bootstrap = read_source_file(BOOTSTRAP.parent, BOOTSTRAP.name, BOOTSTRAP_SHA256, 16384)
    if len(bootstrap) > 16384:
        raise ValueError("wpscan_bootstrap_byte_budget")
    request = json.dumps(
        {
            "schema_version": 1,
            "page_url": artifact.page_url,
            "html": html.decode("utf-8"),
            "html_sha256": artifact.html_sha256,
            "component_sha256": hashlib.sha256(component).hexdigest(),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    if len(request) > 2 * MAX_HTML_BYTES:
        raise ValueError("wpscan_request_frame_byte_budget")
    # Kept private by the caller: HTML and license/source payload are not public
    # evidence, job options, a model context or an outbound telemetry message.
    return {
        "component.rb": component,
        "WPScan-LICENSE": license_bytes,
        "request.json": request,
        "wpscan_observe_bootstrap.rb": bootstrap,
    }


def normalize_observation(
    raw: object, artifact: WPScanHTMLArtifact, component_sha256: str
) -> dict[str, Any]:
    """Only complete matching native output may become a partial observation."""
    if (
        component_sha256 != COMPONENT_SHA256
        or not isinstance(raw, dict)
        or set(raw)
        != {
            "schema_version",
            "wordpress_signature",
            "generator_observations",
            "html_sha256",
            "component_sha256",
            "runtime",
            "requests",
            "coverage_status",
        }
        or raw["schema_version"] != 1
        or isinstance(raw["schema_version"], bool)
        or not isinstance(raw["wordpress_signature"], bool)
        or raw["html_sha256"] != artifact.html_sha256
        or raw["component_sha256"] != component_sha256
        or raw["runtime"]
        != {
            "ruby": RUBY_VERSION,
            "nokogiri": NOKOGIRI_VERSION,
            "racc": RACC_VERSION,
            "network": "offline",
        }
        or raw["requests"] != 0
        or isinstance(raw["requests"], bool)
        or raw["coverage_status"] != "partial"
    ):
        raise ValueError("wpscan_observation_output_identity_or_schema")
    generators = raw["generator_observations"]
    if not isinstance(generators, list) or len(generators) > 16:
        raise ValueError("wpscan_observation_generator_budget")
    for row in generators:
        if (
            not isinstance(row, dict)
            or set(row) != {"value", "version", "version_status"}
            or not isinstance(row["value"], str)
            or not 1 <= len(row["value"]) <= 128
            or re.fullmatch(r"WordPress(?:\s+[0-9]+\.[0-9]+(?:\.[0-9]+)?)?", row["value"], re.I)
            is None
            or not isinstance(row["version"], str)
            or (
                row["version"]
                and re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", row["version"]) is None
            )
            or row["version_status"] != "unverified_generator_observation"
        ):
            raise ValueError("wpscan_observation_generator_schema")
    if generators and raw["wordpress_signature"] is not True:
        raise ValueError("wpscan_observation_inconsistent_generator_signature")
    for row in generators:
        expected_version = (
            row["value"].split(maxsplit=1)[1] if len(row["value"].split(maxsplit=1)) == 2 else ""
        )
        if row["version"] != expected_version:
            raise ValueError("wpscan_observation_inconsistent_generator_version")
    return {
        "wordpress_signature_observed": raw["wordpress_signature"],
        "generator_observations": generators,
        "coverage_status": "partial",
        "requests": 0,
        "artifact_sha256": artifact.html_sha256,
        "artifact_revision": artifact.revision,
        "upstream_version": UPSTREAM_VERSION,
        "upstream_commit": UPSTREAM_COMMIT,
        "source_sha256": SOURCE_SHA256,
        "fragment_sha256": FRAGMENT_SHA256,
        "component_sha256": COMPONENT_SHA256,
        "runtime": raw["runtime"],
        "findings": [],
        "coverage_gaps": [
            "deployment_not_verified",
            "version_not_verified_against_database",
            "vulnerability_api_not_used",
            "authenticated_replay_unsupported",
        ],
    }
