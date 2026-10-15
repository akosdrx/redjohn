"""Tests for Strix Docker-free local runtime backend, lookup_cve tool, and anti-hallucination gate."""

from __future__ import annotations

import json
from pathlib import Path

from agents.sandbox.manifest import Manifest
import pytest

from strix.runtime.backends import get_backend, supported_backends
from strix.runtime.local_backend import StrixLocalSandboxClient, StrixLocalSandboxSession, local_backend
from strix.tools.cve.tool import (
    classify_vulnerability,
    compute_composite_risk_score,
    compute_ssvc_decision,
    lookup_cve_json,
)
from strix.tools.reporting.tool import _validate_anti_hallucination


def test_get_backend_supports_local_without_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_RUNTIME_BACKEND", "local")
    assert "local" in supported_backends()
    backend_fn = get_backend("local")
    assert callable(backend_fn)


@pytest.mark.asyncio
async def test_local_sandbox_session_executes_commands_without_docker(tmp_path: Path) -> None:
    manifest = Manifest(root="/workspace")
    client, session = await local_backend(
        image="local",
        manifest=manifest,
        exposed_ports=(),
        bind_mounts=[{"source": str(tmp_path), "target": "/workspace/target_src", "read_only": True}],
    )
    assert isinstance(client, StrixLocalSandboxClient)
    assert isinstance(session._inner, StrixLocalSandboxSession)
    try:
        result = await session.exec("echo strix-local-ok && pwd", shell="/bin/bash", timeout=10)
        assert result.exit_code == 0
        stdout = result.stdout.decode("utf-8") if isinstance(result.stdout, bytes) else str(result.stdout)
        assert "strix-local-ok" in stdout
    finally:
        await client.delete(session)


def test_cve_composite_risk_and_ssvc_v2_act_for_kev_rce() -> None:
    vuln_class, skill, impact_w, _ = classify_vulnerability(
        "Unauthenticated Remote Code Execution via command injection", ["CWE-78"]
    )
    assert vuln_class == "rce"
    assert skill == "45-rce-exploitation"
    score, level = compute_composite_risk_score(
        base_score=9.8,
        impact_weight=impact_w,
        epss_score=0.85,
        in_kev=True,
        has_poc=True,
        cve_id="CVE-2024-12345",
    )
    assert score >= 85.0
    assert level == "CRITICAL"
    ssvc = compute_ssvc_decision(
        in_kev=True,
        epss_score=0.85,
        has_poc=True,
        vuln_class=vuln_class,
        base_score=9.8,
    )
    assert ssvc == "Act"


def test_cve_ssvc_v2_track_for_low_risk() -> None:
    vuln_class, _, impact_w, _ = classify_vulnerability(
        "Minor information disclosure in debug header", ["CWE-200"]
    )
    assert vuln_class == "other"
    score, level = compute_composite_risk_score(
        base_score=4.3,
        impact_weight=impact_w,
        epss_score=0.001,
        in_kev=False,
        has_poc=False,
        cve_id="CVE-2018-9999",
    )
    assert score < 30.0
    assert level in ("LOW", "MEDIUM")
    ssvc = compute_ssvc_decision(
        in_kev=False,
        epss_score=0.001,
        has_poc=False,
        vuln_class=vuln_class,
        base_score=4.3,
    )
    assert ssvc == "Track"


@pytest.mark.asyncio
async def test_lookup_cve_rejects_empty_arguments() -> None:
    raw = await lookup_cve_json()
    data = json.loads(raw)
    assert data["success"] is False
    assert "Provide either" in data["error"]


def test_anti_hallucination_rejects_placeholder_poc_and_speculative_high_confidence() -> None:
    errors = _validate_anti_hallucination(
        confidence="high",
        poc_script_code="curl -X POST https://example.com -d 'INSERT_PAYLOAD'",
        evidence="untested hypothesis based on version banner only",
    )
    assert any("placeholder" in err.lower() for err in errors)
    assert any("speculative" in err.lower() or "untested" in err.lower() for err in errors)

    clean_errors = _validate_anti_hallucination(
        confidence="high",
        poc_script_code="curl -s -i 'https://target.local/api/ping?host=127.0.0.1'",
        evidence="Verified HTTP 200 response with deterministic differential output.",
    )
    assert clean_errors == []


def test_kali_httpx_shim_and_tui_candidates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from strix.interface.tui.sidecar import tui_executable_candidates
    from strix.runtime.local_backend import _ensure_kali_tool_shims, _is_python_httpx_wrapper

    fake_bin = tmp_path / "usr_bin"
    fake_bin.mkdir()
    py_httpx = fake_bin / "httpx"
    py_httpx.write_text("#!/usr/bin/python3\nfrom httpx import main\nmain()\n")
    py_httpx.chmod(0o755)
    pd_httpx = fake_bin / "httpx-toolkit"
    pd_httpx.write_text("#!/bin/sh\necho projectdiscovery-httpx\n")
    pd_httpx.chmod(0o755)

    assert _is_python_httpx_wrapper(py_httpx) is True
    assert _is_python_httpx_wrapper(pd_httpx) is False

    monkeypatch.setenv("PATH", str(fake_bin))
    shim_dir = _ensure_kali_tool_shims(tmp_path)
    assert shim_dir is not None
    assert (shim_dir / "httpx").is_symlink()
    assert (shim_dir / "httpx").resolve() == pd_httpx.resolve()

    candidates = tui_executable_candidates()
    assert len(candidates) >= 1
    assert candidates[-1] in ("strix-tui", "strix-tui.exe")


