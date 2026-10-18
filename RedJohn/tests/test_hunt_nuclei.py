"""Contract/fault tests use an explicitly fake scanner, never claim live Nuclei."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from redjohn.assessment.policy import EngagementPolicy
from redjohn.tools.hunt.nuclei import (
    BoundedScannerRunner,
    NucleiAdapter,
    NucleiContractError,
    NucleiLock,
    NucleiOptions,
    TemplateSelection,
    bundle_digest,
    normalize_nuclei,
    nuclei_argv,
    validate_template,
)
from redjohn.tools.hunt.tool import _run, hunt_argv


TEMPLATE = b"""id: fixture-marker
info:
  name: Harmless marker fixture
  author: RedJohn
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/marker"
    matchers:
      - type: word
        words: [redjohn-fixture-marker]
"""
SELECTION = TemplateSelection("marker.yaml", "fixture-marker", ("isolated-lab",))


def policy() -> EngagementPolicy:
    return EngagementPolicy(
        "test",
        "test-owner",
        ("http://127.0.0.1:8123",),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )


class FixtureSession:
    """Sandbox transport double; child commands are real local subprocesses."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.processes = []

    async def read(self, path: Path):
        return path.open("rb")

    async def exec(self, *argv: str, timeout: float, shell: bool):
        assert shell is False
        if argv[0] == "python3":
            argv = (sys.executable, *argv[1:])
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.root,
        )
        self.processes.append(process)
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
        return SimpleNamespace(stdout=stdout, stderr=stderr, exit_code=process.returncode)


@pytest.fixture
def locked_adapter(tmp_path: Path):
    binary = tmp_path / "fake-nuclei"
    binary.write_text(f"""#!{sys.executable}
import json, sys
if '-version' in sys.argv:
    print('Nuclei Engine Version: v3.5.1', file=sys.stderr)
else:
    print(json.dumps({{"template-id":"fixture-marker","type":"http","matched-at":"http://127.0.0.1:8123/marker","info":{{"name":"fixture","severity":"info"}}}}))
""")
    binary.chmod(0o700)
    templates = tmp_path / "bundle"
    templates.mkdir()
    (templates / "marker.yaml").write_bytes(TEMPLATE)
    files = {"marker.yaml": hashlib.sha256(TEMPLATE).hexdigest()}
    lock = NucleiLock(
        str(binary),
        "3.5.1",
        hashlib.sha256(binary.read_bytes()).hexdigest(),
        "local-test-double",
        "test-fixture-only",
        str(templates),
        "fixture-1",
        bundle_digest(files),
        "local-test-fixture",
        "Apache-2.0",
        files,
        (SELECTION,),
    )
    return NucleiAdapter(FixtureSession(tmp_path), lock)


def test_lock_requires_binary_and_complete_template_digest(locked_adapter):
    lock = locked_adapter.lock
    lock.validate()
    lock.files["unreviewed.yaml"] = "0" * 64
    with pytest.raises(NucleiContractError, match="bundle digest"):
        lock.validate()


@pytest.mark.parametrize(
    "replacement",
    [
        (b"method: GET", b"method: POST"),
        (b"http:", b"code:"),
        (b"{{BaseURL}}/marker", b"http://outside.invalid/"),
        (b"{{BaseURL}}/marker", b"{{BaseURL}}/{{interactsh-url}}"),
        (b"type: word", b"type: dsl"),
        (b"words: [redjohn-fixture-marker]", b"words: ['{{read_file(1)}}']"),
        (b"method: GET", b"method: GET\n    redirects: true"),
    ],
)
def test_template_capability_filter_rejects_dynamic_or_higher_effect(replacement):
    assert validate_template(TEMPLATE, SELECTION) == 1
    with pytest.raises(NucleiContractError):
        validate_template(TEMPLATE.replace(*replacement), SELECTION)


def test_options_argv_and_no_global_fallback(locked_adapter):
    argv = nuclei_argv("http://127.0.0.1:8123", locked_adapter.lock, NucleiOptions(), (SELECTION,))
    assert "-duc" in argv and "-jsonl" in argv and "-ni" in argv and "-dr" in argv
    assert "-tags" not in argv and "-severity" not in argv
    assert "-code" not in argv and "-headless" not in argv
    assert argv[argv.index("-t") + 1].endswith("bundle/marker.yaml")
    with pytest.raises(NucleiContractError, match="explicit"):
        hunt_argv("cve", "http://127.0.0.1:8123")
    with pytest.raises(NucleiContractError):
        NucleiOptions(rate_limit=999).validate()
    with pytest.raises(NucleiContractError):
        NucleiOptions(timeout_seconds=True).validate()


@pytest.mark.parametrize(
    "url",
    ["--config=/etc/passwd", "https://user:pass@127.0.0.1", "http://[bad", "http://127.0.0.1:abc"],
)
def test_flag_like_or_credential_target_rejected(url):
    with pytest.raises(NucleiContractError):
        hunt_argv("sqli", url)


def test_no_finding_requires_proven_executed_request():
    no_evidence = normalize_nuclei({"exit_code": 0}, (SELECTION,), policy())
    assert no_evidence["coverage_status"] == "inconclusive"
    assert no_evidence["no_finding_observed"] is False
    result = normalize_nuclei(
        {"exit_code": 0, "stderr": '{"requests":"1"}'}, (SELECTION,), policy()
    )
    assert result["coverage_status"] == "inconclusive"
    assert result["error"]["code"] == "response_status_unverified"
    assert result["no_finding_observed"] is False


@pytest.mark.parametrize(
    "stdout", ['{"template-id":', '{"other":"schema"}', "[INF] banner\n{broken"]
)
def test_parser_error_is_not_a_negative_scan(stdout):
    result = normalize_nuclei({"exit_code": 0, "stdout": stdout}, (SELECTION,), policy())
    assert result["error"]["code"] == "parser_error"
    assert result["no_finding_observed"] is False


def test_banner_mixed_json_and_out_of_scope_candidate():
    item = {
        "template-id": "fixture-marker",
        "type": "http",
        "info": {},
        "matched-at": "https://outside.invalid/",
    }
    result = normalize_nuclei(
        {"exit_code": 0, "stdout": "[INF] banner\n" + json.dumps(item)}, (SELECTION,), policy()
    )
    assert result["findings"] == [] and result["coverage_status"] == "inconclusive"


@pytest.mark.parametrize(
    "flag,status,coverage",
    [
        ("truncated", "resource_exhausted", "partial"),
        ("timed_out", "timed_out", "partial"),
        ("cancelled", "cancelled", "partial"),
    ],
)
def test_fault_status_dimensions(flag, status, coverage):
    result = normalize_nuclei({"exit_code": 0, flag: True}, (SELECTION,), policy())
    assert (result["execution_status"], result["coverage_status"]) == (status, coverage)
    assert result["no_finding_observed"] is False


async def test_mock_engine_candidate_and_provenance(locked_adapter):
    result = await locked_adapter.run("http://127.0.0.1:8123", policy=policy())
    assert result["execution_status"] == "succeeded", result
    assert result["coverage_status"] == "completed"
    assert result["findings"][0]["finding_status"] == "candidate"
    assert result["tool"]["bundle_sha256"] == locked_adapter.lock.bundle_sha256
    assert not list(locked_adapter.session.root.glob(".redjohn-nuclei-*"))
    assert not list(locked_adapter.session.root.glob(".redjohn-hunt/*.pid"))


async def test_mock_template_tampering_is_blocked(locked_adapter):
    Path(locked_adapter.lock.bundle_root, "marker.yaml").write_text("id: changed")
    result = await locked_adapter.run("http://127.0.0.1:8123", policy=policy())
    assert result["error"]["code"] == "template_contract_error"
    assert result["coverage_status"] == "blocked"


async def test_missing_binary_is_blocked_not_negative(locked_adapter):
    Path(locked_adapter.lock.binary_path).unlink()
    result = await locked_adapter.run("http://127.0.0.1:8123", policy=policy())
    assert result["error"]["code"] == "tool_missing"
    assert result["coverage_status"] == "blocked" and not result["no_finding_observed"]


async def test_worker_streams_and_stops_at_output_limit(tmp_path):
    runner = BoundedScannerRunner(FixtureSession(tmp_path))
    result = await runner._execute(
        [sys.executable, "-c", "import sys;sys.stdout.write('a'*1000000)"],
        NucleiOptions(max_output_bytes=1024),
        scan=False,
        digests={},
    )
    assert result["truncated"] is True
    assert len(result["stdout"].encode()) == 1024
    assert result["stdout_bytes"] <= 16384
    assert not list(tmp_path.glob(".redjohn-hunt/*.pid"))


async def test_worker_timeout_retains_partial_output_and_cleans_descendants(tmp_path):
    session = FixtureSession(tmp_path)
    runner = BoundedScannerRunner(session)
    script = (
        "import subprocess,sys,time; "
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        "print('partial',flush=True);time.sleep(30)"
    )
    result = await runner._execute(
        [sys.executable, "-c", script], NucleiOptions(timeout_seconds=1), scan=False, digests={}
    )
    assert result["timed_out"] is True and "partial" in result["stdout"]
    assert result["duration_seconds"] < 3
    assert not list(tmp_path.glob(".redjohn-hunt/*.pid"))


async def test_worker_cancellation_acknowledges_cleanup(tmp_path):
    session = FixtureSession(tmp_path)
    runner = BoundedScannerRunner(session)
    task = asyncio.create_task(
        runner._execute(
            [sys.executable, "-c", "import time;time.sleep(30)"],
            NucleiOptions(),
            scan=False,
            digests={},
        )
    )
    for _ in range(100):
        if list(tmp_path.glob(".redjohn-hunt/*.pid")):
            break
        await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not list(tmp_path.glob(".redjohn-hunt/*.pid"))
    for process in session.processes:
        await asyncio.wait_for(process.wait(), 2)
    assert runner._tokens == set()


async def test_hunt_never_suggests_unconfined_manual_fallback():
    context = SimpleNamespace(context={})
    for kind in ("sqli", "xss", "rce", "cve"):
        result = await _run(context, kind, "http://127.0.0.1:8123", "")
        assert result["error"]["code"] == "policy_required"
        assert result["coverage_status"] == "blocked" and "command" not in result


async def test_unreviewed_profile_cannot_start_scanner(locked_adapter):
    restricted = EngagementPolicy(
        "test",
        "owner",
        ("http://127.0.0.1:8123",),
        profile="safe-production",
        egress_mode="unavailable",
    )
    result = await locked_adapter.run("http://127.0.0.1:8123", policy=restricted)
    assert result["error"]["code"] == "blocked_by_policy"
    assert locked_adapter.session.processes == []


async def test_wrong_locked_version_blocks_before_scan(locked_adapter):
    adapter = NucleiAdapter(
        locked_adapter.session, replace(locked_adapter.lock, binary_version="3.5.2")
    )
    result = await adapter.run("http://127.0.0.1:8123", policy=policy())
    assert result["error"]["code"] == "tool_version_mismatch"
    assert len(locked_adapter.session.processes) == 1


async def test_request_admission_reserves_exact_bounded_template_count(locked_adapter):
    counts = []
    locked_adapter.request_admission = counts.append
    result = await locked_adapter.run("http://127.0.0.1:8123", policy=policy())
    assert result["coverage_status"] == "completed"
    assert counts == [1]


async def test_request_admission_denial_never_starts_scan(locked_adapter):
    def deny(_count):
        raise RuntimeError("shared request budget exhausted")

    locked_adapter.request_admission = deny
    with pytest.raises(RuntimeError, match="request budget"):
        await locked_adapter.run("http://127.0.0.1:8123", policy=policy())
    assert len(locked_adapter.session.processes) == 1  # version only, no network scan


async def test_partial_raw_evidence_is_referenced_and_diagnostics_are_not_reflected(locked_adapter):
    evidence = []

    def persist(raw):
        evidence.append(raw)
        return "evidence-fixture-ref"

    locked_adapter.evidence_sink = persist
    result = await locked_adapter.run("http://127.0.0.1:8123", policy=policy())
    assert result["evidence_refs"] == ["evidence-fixture-ref"]
    assert evidence and "stdout" in evidence[0]
    assert "stdout" not in result and "stderr" not in result


async def test_evidence_storage_failure_does_not_confirm_or_discard_failure(locked_adapter):
    def fail(_raw):
        raise OSError("/private/path/session-secret-token")

    locked_adapter.evidence_sink = fail
    result = await locked_adapter.run("http://127.0.0.1:8123", policy=policy())
    assert result["error"]["code"] == "evidence_write_failed"
    assert result["coverage_status"] == "inconclusive" and result["findings"] == []
    assert "/private/path" not in json.dumps(result)
    for field in (
        "job_id",
        "attempt_id",
        "tool_id",
        "cause_ref",
        "retry_after",
        "partial_evidence_refs",
        "coverage_effect",
        "recovery_action",
    ):
        assert field in result["error"]


def test_request_stats_including_failures_cannot_be_completed_negative():
    result = normalize_nuclei(
        {"exit_code": 0, "stderr": '{"requests":1,"errors":1}'}, (SELECTION,), policy()
    )
    assert result["error"]["code"] == "parser_error"
    assert result["coverage_status"] == "inconclusive" and not result["no_finding_observed"]


def test_failed_matcher_event_is_not_a_candidate():
    item = {
        "template-id": "fixture-marker",
        "type": "http",
        "info": {},
        "matched-at": "http://127.0.0.1:8123/marker",
        "matcher-status": False,
    }
    result = normalize_nuclei({"exit_code": 0, "stdout": json.dumps(item)}, (SELECTION,), policy())
    assert result["findings"] == [] and result["coverage_status"] == "inconclusive"


def test_yaml_alias_expansion_cannot_bypass_template_byte_budget():
    raw = TEMPLATE.replace(
        b"words: [redjohn-fixture-marker]",
        b"words: &shared [redjohn-fixture-marker]\n        negative: *shared",
    )
    with pytest.raises(NucleiContractError, match="aliases"):
        validate_template(raw, SELECTION)


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_captured_blocking_response_never_becomes_negative(status):
    result = normalize_nuclei(
        {
            "exit_code": 0,
            "response_observations": [{"url": "http://127.0.0.1:8123/marker", "status": status}],
        },
        (SELECTION,),
        policy(),
        expected_requests=1,
    )
    assert result["coverage_status"] == "blocked"
    assert result["no_finding_observed"] is False


def test_negative_requires_all_expected_complete_response_urls():
    raw = {
        "exit_code": 0,
        "response_observations": [{"url": "http://127.0.0.1:8123/other", "status": 200}],
    }
    result = normalize_nuclei(
        raw,
        (SELECTION,),
        policy(),
        expected_requests=1,
        expected_request_urls=("http://127.0.0.1:8123/marker",),
    )
    assert result["coverage_status"] == "inconclusive"
    assert result["no_finding_observed"] is False
    raw["response_observations"][0]["url"] = "http://127.0.0.1:8123/marker"
    result = normalize_nuclei(
        raw,
        (SELECTION,),
        policy(),
        expected_requests=1,
        expected_request_urls=("http://127.0.0.1:8123/marker",),
    )
    assert result["coverage_status"] == "completed"
    assert result["no_finding_observed"] is True


async def test_readonly_logout_target_is_blocked_before_engine(locked_adapter):
    result = await locked_adapter.run("http://127.0.0.1:8123/logout", policy=policy())
    assert result["error"]["code"] == "blocked_by_policy"
    assert not locked_adapter.session.processes


async def test_https_cannot_silently_use_unverified_native_engine_tls(locked_adapter):
    tls_policy = EngagementPolicy(
        "https-test",
        "owner",
        ("https://127.0.0.1:8123",),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )
    result = await locked_adapter.run("https://127.0.0.1:8123", policy=tls_policy)
    assert result["error"]["code"] == "https_requires_verified_egress_proxy"
    assert not locked_adapter.session.processes
