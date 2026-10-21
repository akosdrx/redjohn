"""Offline payload/protocol contracts, not Ruby/Nokogiri engine integrations."""

import hashlib
import json
import os
import time

import pytest

from redjohn.assessment.wpscan_component import (
    BOOTSTRAP,
    BOOTSTRAP_SHA256,
    COMPONENT_SHA256,
    NOKOGIRI_VERSION,
    RACC_VERSION,
    RUBY_VERSION,
    WPScanComponentSource,
    WPScanHTMLArtifact,
    normalize_observation,
)


def artifact(tmp_path, body=b'<html><meta name="generator" content="WordPress 6.4.3"></html>'):
    path = tmp_path / "page.html"
    path.write_bytes(body)
    return WPScanHTMLArtifact.from_mapping(
        {
            "html_file": str(path),
            "html_sha256": hashlib.sha256(body).hexdigest(),
            "page_url": "https://owned.example/app/",
            "producer": "operator",
        }
    )


def synthetic_output(value):
    # Synthetic parser output exercises validation; no engine was invoked.
    return {
        "schema_version": 1,
        "wordpress_signature": True,
        "generator_observations": [
            {
                "value": "WordPress 6.4.3",
                "version": "6.4.3",
                "version_status": "unverified_generator_observation",
            }
        ],
        "html_sha256": value.html_sha256,
        "component_sha256": COMPONENT_SHA256,
        "runtime": {
            "ruby": RUBY_VERSION,
            "nokogiri": NOKOGIRI_VERSION,
            "racc": RACC_VERSION,
            "network": "offline",
        },
        "requests": 0,
        "coverage_status": "partial",
    }


def test_operator_artifact_bytes_and_url_are_bound_and_observations_never_become_findings(tmp_path):
    value = artifact(tmp_path)
    assert b"WordPress" in value.html_bytes()
    output = normalize_observation(synthetic_output(value), value, COMPONENT_SHA256)
    assert output["coverage_status"] == "partial" and output["findings"] == []
    assert "version_not_verified_against_database" in output["coverage_gaps"]
    altered = WPScanHTMLArtifact(value.html_file, value.html_sha256, "https://other.example/")
    assert altered.revision != value.revision
    assert "page.html" not in json.dumps(output)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:secret@owned.example/",
        "https://owned.example/#fragment",
        "https://owned.example:0/",
        "https://owned.example:99999/",
        "https://owned.example/a\nb",
    ],
)
def test_artifact_page_metadata_never_accepts_file_credentials_controls_or_bad_ports(tmp_path, url):
    value = artifact(tmp_path)
    with pytest.raises(ValueError, match="page_url_invalid"):
        WPScanHTMLArtifact.from_mapping(
            {
                "html_file": str(value.html_file),
                "html_sha256": value.html_sha256,
                "page_url": url,
                "producer": "operator",
            }
        )


def test_operator_input_cannot_impersonate_an_authorized_browser_producer(tmp_path):
    value = artifact(tmp_path)
    with pytest.raises(ValueError, match="reviewed_operator_html"):
        WPScanHTMLArtifact.from_mapping(
            {
                "html_file": str(value.html_file),
                "html_sha256": value.html_sha256,
                "page_url": value.page_url,
                "producer": "browser",
                "evidence_ref": "unverified",
            }
        )


@pytest.mark.parametrize("body", [b"\xff", b"<html>\x00</html>", b"x" * (256 * 1024 + 1)])
def test_input_encoding_nul_and_size_fail_before_any_native_execution(tmp_path, body):
    with pytest.raises(ValueError):
        artifact(tmp_path, body).html_bytes()


def test_input_digest_symlink_and_fifo_are_rejected_without_waiting(tmp_path):
    value = artifact(tmp_path)
    value.html_file.write_bytes(b"altered")
    with pytest.raises(ValueError, match="digest"):
        value.html_bytes()
    value.html_file.unlink()
    value.html_file.symlink_to(tmp_path / "missing")
    with pytest.raises(OSError):
        value.html_bytes()
    value.html_file.unlink()
    os.mkfifo(value.html_file)
    started = time.monotonic()
    with pytest.raises(ValueError, match="size_or_type"):
        value.html_bytes()
    assert time.monotonic() - started < 0.5


@pytest.mark.parametrize("operator_use", ["commercial", "unknown", [], None])
def test_external_component_declaration_does_not_grant_commercial_licensing(tmp_path, operator_use):
    with pytest.raises(ValueError, match="license_context"):
        WPScanComponentSource.from_mapping(
            {
                "source_file": str(tmp_path / "source.rb"),
                "license_file": str(tmp_path / "LICENSE"),
                "external_operator_component": True,
                "operator_use": operator_use,
            }
        )


def test_missing_or_bogus_license_notice_blocks_component_extraction(tmp_path):
    source = tmp_path / "source.rb"
    source.write_text("do_not_execute\n")
    license_file = tmp_path / "LICENSE"
    config = WPScanComponentSource.from_mapping(
        {
            "source_file": str(source),
            "license_file": str(license_file),
            "external_operator_component": True,
            "operator_use": "pentest-toolkit",
        }
    )
    with pytest.raises(FileNotFoundError):
        config.reviewed_fragment()
    license_file.write_text("MIT substitute is not the upstream license")
    with pytest.raises(ValueError, match="digest"):
        config.reviewed_fragment()


@pytest.mark.parametrize(
    "change",
    [
        "runtime",
        "html",
        "component",
        "schema",
        "request",
        "status",
        "generator_version",
        "generator_claim",
        "signature",
        "missing",
    ],
)
def test_incomplete_or_contradictory_protocol_output_never_becomes_negative_or_confirmed(
    tmp_path, change
):
    value = artifact(tmp_path)
    output = synthetic_output(value)
    if change == "runtime":
        output["runtime"]["nokogiri"] = "other"
    elif change == "html":
        output["html_sha256"] = "0" * 64
    elif change == "component":
        output["component_sha256"] = "0" * 64
    elif change == "schema":
        output["schema_version"] = True
    elif change == "request":
        output["requests"] = True
    elif change == "status":
        output["coverage_status"] = "completed"
    elif change == "generator_version":
        output["generator_observations"][0]["version"] = "1.2"
    elif change == "generator_claim":
        output["generator_observations"][0]["version_status"] = "confirmed"
    elif change == "signature":
        output["wordpress_signature"] = False
    else:
        output.pop("runtime")
    with pytest.raises(ValueError, match="wpscan_observation"):
        normalize_observation(output, value, COMPONENT_SHA256)


def test_complete_empty_signature_protocol_is_only_partial_observation(tmp_path):
    value = artifact(tmp_path, b"<html>generic page</html>")
    output = synthetic_output(value)
    output.update(wordpress_signature=False, generator_observations=[])
    result = normalize_observation(output, value, COMPONENT_SHA256)
    assert result["wordpress_signature_observed"] is False
    assert result["coverage_status"] == "partial" and result["findings"] == []


def test_packaged_bootstrap_is_pinned_and_does_not_require_the_complete_platform():
    payload = BOOTSTRAP.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == BOOTSTRAP_SHA256
    assert b"require 'wpscan'" not in payload
    assert b"require 'ferrum'" not in payload
    assert b"require 'get_process_mem'" not in payload
    assert b"Process.setrlimit" in payload
    # This static check is not a namespace attestation or native parser E2E.
    assert b"Nokogiri::XML::ParseOptions::NONET" in payload
