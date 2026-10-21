#!/usr/bin/env python3
"""Opt-in real provider -> actual CLI/Go TUI -> persistent browser/Nuclei E2E.

No supplied target, synthetic model, alternate dispatch, or scanner stub exists
here. Provider absence is retained as a blocked result with nonzero exit.
Raw run state (approval key, local gateway token and ephemeral TLS files) stays
in RUNNER_TEMP; only redacted terminal output and bounded proof are artifacts.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.util
import json
import os
import platform
import signal
import sqlite3
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def identity() -> dict:
    return {"commit_sha": os.environ.get("GITHUB_SHA", "local-uncommitted"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "architecture": platform.machine(), "python": platform.python_version()}


def junit(output: Path, result: dict, *, preflight_only: bool = False) -> None:
    suite = ET.Element("testsuite", name="redjohn_live_model", tests="0", failures="0", errors="0", skipped="0")
    properties = ET.SubElement(suite, "properties")
    for key in ("commit_sha", "run_id", "run_attempt", "architecture", "status"):
        ET.SubElement(properties, "property", name=key, value=str(result.get(key, "")))
    errors = 0
    if preflight_only:
        case = ET.SubElement(suite, "testcase", classname="capability_preflight_no_model_call", name="explicit_model_and_credential")
        if result["status"] != "ready":
            ET.SubElement(case, "error", type="blocked_missing_capability",
                          message="No model or interface test was executed; see preflight.json")
            errors = 1
        count = 1
    else:
        proofs = {item["interface"]: item for item in result.get("interfaces", [])}
        for interface in ("cli", "tui"):
            proven = interface in proofs and result.get("provider_verified") is True
            case = ET.SubElement(suite, "testcase", classname=("real_model_interface_e2e" if proven else "model_interface_unverified"), name=interface)
            if not proven:
                attempted = result.get("active_interface") == interface or interface in proofs
                ET.SubElement(case, "error", type=("real_model_attempt_unverified" if attempted else "blocked_not_executed"),
                              message="Actual model/interface proof incomplete; see result.json and owner/terminal evidence")
                errors += 1
        count = 2
        if result.get("status") != "passed" and not errors:
            case = ET.SubElement(suite, "testcase", classname="model_harness_unverified", name="final_cleanup_and_evidence")
            ET.SubElement(case, "error", type="harness_cleanup_or_evidence_failed", message="See result.json")
            count += 1
            errors += 1
    suite.set("tests", str(count))
    suite.set("errors", str(errors))
    path = output / ("preflight.junit.xml" if preflight_only else "live-model.junit.xml")
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def preflight(output: Path) -> bool:
    missing = []
    if not os.environ.get("REDJOHN_LIVE_MODEL"):
        missing.append("REDJOHN_LIVE_MODEL: explicit bare OpenAI model identifier")
    if not os.environ.get("REDJOHN_LIVE_MODEL_API_KEY"):
        missing.append("repository/environment secret REDJOHN_LIVE_MODEL_API_KEY")
    model = os.environ.get("REDJOHN_LIVE_MODEL", "")
    if model and (len(model) > 128 or "/" in model or any(c.isspace() for c in model)):
        missing.append("supported model route: bare OpenAI identifier only")
    result = {
        **identity(), "evidence_kind": "capability_preflight_no_model_call",
        "status": "blocked" if missing else "ready", "missing": missing,
        "model": model, "live_model_verified": False,
    }
    write(output / "preflight.json", result)
    junit(output, result, preflight_only=True)
    return not missing


def module(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def database(run: Path) -> dict:
    path = run / ".state/agents.db"
    if not path.is_file():
        return {"jobs": [], "tools": [], "messages": 0}
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=0.1) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        jobs = []
        if "rj_job" in tables:
            jobs = [dict(zip(("id", "capability", "execution_status", "coverage_status"), row[:4], strict=True),
                         findings=len(json.loads(row[4] or "{}").get("findings", [])))
                    for row in db.execute("SELECT id,capability,execution_status,coverage_status,result FROM rj_job")]
        messages = [json.loads(row[0]) for row in db.execute("SELECT message_data FROM agent_messages ORDER BY id")] if "agent_messages" in tables else []
    return {"jobs": jobs, "messages": len(messages), "tools": [
        item["name"] for item in messages if item.get("type") == "function_call"
    ]}


def current_run(workspace: Path) -> Path | None:
    candidates = list((workspace / "redjohn_runs").glob("*/run.json"))
    if len(candidates) > 1:
        raise RuntimeError("owned_workspace_has_multiple_runs")
    return candidates[0].parent if candidates else None


def status(run: Path) -> dict:
    path = run / ".state/agents.json"
    return json.loads(path.read_text()).get("statuses", {}) if path.is_file() else {}


def complete_jobs(proof: dict) -> set:
    return {job["capability"] for job in proof["jobs"]
            if job["execution_status"] == "succeeded" and job["coverage_status"] == "completed"}


def validate(proof: dict, report: dict, owner: dict) -> None:
    if not {"browser_discover", "nuclei_scan"} <= complete_jobs(proof):
        raise RuntimeError("real_browser_nuclei_scheduler_evidence_incomplete")
    if not {"assessment_control", "finish_scan"} <= set(proof["tools"]):
        raise RuntimeError("real_model_tool_dispatch_or_finish_missing")
    if not report.get("llm_usage", {}).get("requests", 0):
        raise RuntimeError("no_recorded_real_model_usage")
    if "REDJOHN_LIVE_COMPLETE" not in report.get("scan_results", {}).get("executive_summary", ""):
        raise RuntimeError("actual_model_completion_report_missing")
    if not any(job["capability"] == "nuclei_scan" and job["findings"] >= 1 for job in proof["jobs"]):
        raise RuntimeError("owned_fixture_positive_scanner_oracle_missing")
    resources = json.loads((Path(proof["run_directory"]) / "assessment-report.json").read_text())["metrics"]["resources"]
    if resources.get("active") or (resources.get("host") or {}).get("owners", 0):
        raise RuntimeError("runtime_resources_remain_active")
    if (owner.get("owner_returncode") not in {0, 2} or owner.get("outcome") != "owner_exited"
            or owner.get("process_cleanup_verified") is not True or owner.get("owner_cgroup_removed") is not True
            or owner.get("os_memory", {}).get("enforced") is not True
            or owner.get("os_memory", {}).get("owner_namespace", {}).get("verified") is not True
            or owner.get("os_memory", {}).get("memory_max_bytes") != 2048 * 1024**2
            or owner.get("os_memory", {}).get("aggregate", {}).get("memory_max_bytes") != 4096 * 1024**2
            or owner.get("os_memory", {}).get("oom_kills", 0)):
        raise RuntimeError("owner_cleanup_or_exit_not_verified")


async def execute(interface: str, fixture, gateway, args, output: Path) -> dict:
    # Heavy RedJohn imports occur only after the credential preflight succeeds.
    from redjohn.assessment.policy import EngagementPolicy

    import fcntl
    import pty
    import struct
    import termios

    workspace = Path(args.work) / interface
    workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
    private = workspace / "private"
    private.mkdir(mode=0o700)
    policy = EngagementPolicy(
        "live-model-" + interface, "ci-operator", (fixture.origin,),
        allowed_ips=("127.0.0.1/32",), profile="isolated-lab", egress_mode="local-fixture",
        request_budget=100, deadline=time.time() + 900,
    )
    config = {"policy": policy.to_dict(),
              "os_memory": {"delegated_root": str(Path(os.environ["REDJOHN_TEST_CGROUP_ROOT"]).resolve())},
              "tls": {"upstream_ca_file": str(fixture.ca_file)},
              "nuclei_lock": json.loads(Path(os.environ["REDJOHN_NUCLEI_LOCK"]).read_text()),
              "seeds": [{"url": fixture.origin + suffix, "capabilities": []} for suffix in ("/", "/api/items")]}
    approved = private / "assessment.json"
    write(approved, config)
    approved.chmod(0o600)
    instruction = (
        "This is the approved, owned RedJohn local HTTPS CI fixture. Use ONLY assessment_control "
        "and finish_scan (and wait_for_user when requested); do not spawn agents, shell, file or network tools. "
        'Call assessment_control surface_search with policy_revision "1" (a string) to obtain the two imported surfaces. '
        'Using jobs_submit_batch, submit browser_discover for / with family discovery and policy_revision "1". '
        "Poll jobs_get_status until it succeeds. "
    )
    finish = (
        'Then submit nuclei_scan for /api/items with family known_vulnerability and policy_revision "1". '
        "Use jobs_get_status until both jobs are succeeded with coverage completed, then findings_get. "
        "Call finish_scan with every required summary field nonempty and include REDJOHN_LIVE_COMPLETE in the executive summary. "
        'Every control arguments_json includes policy_revision "1". No other target is authorized.'
    )
    instruction += finish if interface == "cli" else (
        "After the browser job succeeds, write REDJOHN_LIVE_PAUSED and call wait_for_user. "
        "Do not finish before the human resumes the run."
    )
    command = [sys.executable, "-c", "from redjohn.interface.main import main; main()",
               "--target", fixture.origin, "--assessment-config", str(approved),
               "--scan-mode", "quick", "--max-turns", "12", "--max-budget-usd", "2",
               "--instruction", instruction]
    if interface == "cli":
        command.append("--non-interactive")
    owner_path = output / f"{interface}-owner.json"
    command = [sys.executable, "-m", "redjohn.assessment.memory_exec", "--delegated-root",
               os.environ["REDJOHN_TEST_CGROUP_ROOT"], "--memory-budget-mib", "2048",
               "--aggregate-budget-mib", "4096", "--pool-state-directory", str(Path(args.work) / "owner-pool"),
               "--receipt", str(owner_path), "--timeout-seconds", "900", "--", *command]
    # Start from process/runtime paths only; do not inherit arbitrary provider
    # keys, cloud identities, proxy settings or the user's RedJohn settings.
    preserved = {"PATH", "LANG", "LC_ALL", "LD_LIBRARY_PATH", "GOMAXPROCS", "GOTOOLCHAIN",
                 "GOCACHE", "GOMODCACHE", "RUNNER_TEMP", "REDJOHN_TEST_CGROUP_ROOT",
                 "REDJOHN_CI_APPARMOR_PROFILE", "PLAYWRIGHT_BROWSERS_PATH"}
    environment = {key: value for key, value in os.environ.items() if key in preserved}
    environment.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(Path.home() / ".cache/ms-playwright"))
    environment.setdefault("GOCACHE", str(Path.home() / ".cache/go-build"))
    environment.setdefault("GOMODCACHE", str(Path.home() / "go/pkg/mod"))
    environment.update({"HOME": str(private), "TERM": "xterm-256color", "CI": "true",
        "PYTHONPATH": str(ROOT / "RedJohn"), "REDJOHN_NO_UPDATE_CHECK": "1", "REDJOHN_TELEMETRY": "0",
        "OPENAI_AGENTS_DISABLE_TRACING": "1", "REDJOHN_RUNTIME_BACKEND": "local",
        "REDJOHN_ASSESSMENT_APPROVAL_KEY": str(private / "keys/host.key"),
        "REDJOHN_MCP_CONFIG": str(private / "empty-mcp.json"),
        "REDJOHN_RESOURCE_POOL_PATH": str(private / "resources.sqlite3"),
        "REDJOHN_LLM": gateway.model, "LLM_API_KEY": gateway.local_token,
        "LLM_API_BASE": gateway.base_url, "OPENAI_BASE_URL": gateway.base_url,
        "REDJOHN_API_TYPE": "responses", "LLM_MAX_OUTPUT_TOKENS": "2048",
        "LLM_TIMEOUT": "120", "LLM_STREAM_TOTAL_TIMEOUT": "120", "LLM_MAX_TOOL_CALLS_PER_TURN": "1",
        "REDJOHN_REASONING_EFFORT": "none", "REDJOHN_REQUIRE_OWNED_MEMORY": "1"})
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 160, 0, 0))
    os.set_blocking(master, False)
    captured = bytearray()
    overflow = False
    process = await asyncio.create_subprocess_exec(*command, cwd=workspace, env=environment,
        stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    loop = asyncio.get_running_loop()

    def read():
        nonlocal overflow
        with contextlib.suppress(OSError):
            chunk = os.read(master, 65536)
            if chunk:
                captured.extend(chunk)
                if len(captured) > 4 * 1024**2:
                    overflow = True
                    del captured[:len(captured) - 4 * 1024**2]

    loop.add_reader(master, read)
    stopped = resumed = quit_sent = False
    try:
        async with asyncio.timeout(930):
            while process.returncode is None:
                run = current_run(workspace)
                if interface == "tui" and run:
                    proof = database(run)
                    if not stopped and b"REDJOHN_LIVE_PAUSED" in captured and "waiting" in status(run).values():
                        os.write(master, b"\x1b")
                        await asyncio.sleep(0.2)
                        os.write(master, b"\x1b[D\r")
                        stopped = True
                    elif stopped and not resumed and "stopped" in status(run).values():
                        os.write(master, ("Resume the approved owned fixture. " + finish + "\r").encode())
                        resumed = True
                    elif resumed and not quit_sent and {"browser_discover", "nuclei_scan"} <= complete_jobs(proof) and "completed" in status(run).values():
                        if b"REDJOHN_LIVE_COMPLETE" not in captured:
                            await asyncio.sleep(0.1)
                            continue
                        os.write(master, b"\x11")
                        await asyncio.sleep(0.2)
                        os.write(master, b"\x1b[D\r")
                        quit_sent = True
                await asyncio.sleep(0.1)
            await process.wait()
        read()
        if overflow:
            raise RuntimeError("terminal_transcript_budget_exhausted")
        run = current_run(workspace)
        if run is None:
            raise RuntimeError("no_durable_run")
        proof = {**database(run), "run_directory": str(run), "interface": interface,
                 "exit_code": process.returncode, "stopped": stopped, "resumed": resumed,
                 "terminal_redjohn_displayed": b"REDJOHN" in captured.upper(),
                 "terminal_completion_displayed": b"REDJOHN_LIVE_COMPLETE" in captured}
        validate(proof, json.loads((run / "run.json").read_text()), json.loads(owner_path.read_text()))
        if interface == "tui" and not all((stopped, resumed, quit_sent, proof["terminal_completion_displayed"])):
            raise RuntimeError("actual_tui_stop_resume_display_not_proven")
        return proof
    finally:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(process.wait(), 25)
            except TimeoutError:
                process.kill()
                await process.wait()
                raise RuntimeError("owner_supervisor_emergency_kill_required") from None
        loop.remove_reader(master)
        os.close(master)
        transcript = captured.decode("utf-8", errors="replace").replace(gateway.local_token, "[REDACTED]")
        credential = os.environ.get("REDJOHN_LIVE_MODEL_API_KEY", "")
        if credential:
            transcript = transcript.replace(credential, "[REDACTED]")
        (output / f"{interface}-terminal.log").write_text(transcript)


async def run(args, output: Path, progress: dict) -> dict:
    from redjohn.assessment.tls_fixture import TLSFixtureServer

    gateway_class = module("redjohn_live_gateway", "live-model-gateway.py").Gateway
    with TLSFixtureServer() as fixture, gateway_class(
        os.environ["REDJOHN_LIVE_MODEL"], os.environ["REDJOHN_LIVE_MODEL_API_KEY"]
    ) as gateway:
        try:
            proofs = progress["interfaces"] = []
            for interface in ("cli", "tui"):
                progress["active_interface"] = interface
                proof = await execute(interface, fixture, gateway, args, output)
                proof.pop("run_directory", None)
                proofs.append(proof)
                write(output / f"{interface}-proof.json", {**identity(), **proof})
            measured = gateway.snapshot()
            if (measured["completed_calls"] < 2 or measured["rejected_calls"]
                    or measured["provider_errors"] or measured["accepted_calls"] != measured["completed_calls"]):
                raise RuntimeError("actual_provider_transport_provenance_incomplete")
            progress["provider_verified"] = True
            progress.pop("active_interface", None)
            return {"interfaces": proofs, "fixture_requests": sum(fixture.counts.values())}
        finally:
            write(output / "provider.json", {**identity(), **gateway.snapshot()})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/live-model")
    parser.add_argument("--work", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not preflight(output):
        write(output / "result.json", {**identity(), "status": "blocked", "live_model_verified": False,
            "reason": "explicit_model_and_dedicated_repository_secret_required"})
        return 2
    if args.preflight:
        return 0
    result = {**identity(), "status": "failed", "live_model_verified": False}
    try:
        if not args.work or not args.work.is_absolute() or args.work.exists():
            raise ValueError("a_new_absolute_owned_work_directory_required")
        args.work.mkdir(mode=0o700, parents=True)
        result.update(asyncio.run(run(args, output, result)), status="passed", live_model_verified=True)
        return 0
    except Exception as error:
        # Exception text/provider payloads may contain credentials or model
        # output. Store only the exception class; redacted PTY logs are separate.
        result["error_type"] = type(error).__name__
        reason = str(error)
        if 1 <= len(reason) <= 120 and all(character in "abcdefghijklmnopqrstuvwxyz_" for character in reason):
            result["reason"] = reason
        return 1
    finally:
        write(output / "result.json", result)
        junit(output, result)


if __name__ == "__main__":
    raise SystemExit(main())
