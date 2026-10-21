"""Real public CLI -> durable scheduler -> pinned Nuclei -> owned TLS target.

No model/provider is used or simulated. The separate TUI tests cover actual
terminal/IPC interaction and do not stand in for an authenticated LLM service.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from redjohn.assessment.tls_fixture import TLSFixtureServer
from tests.test_nuclei_live import DEFAULT_LOCK, existing_live_lock


async def test_actual_public_cli_nuclei_resume_retest_and_report(tmp_path: Path) -> None:
    existing_live_lock()
    lock = json.loads(Path(os.environ.get("REDJOHN_NUCLEI_LOCK", str(DEFAULT_LOCK))).read_text())
    with TLSFixtureServer() as fixture:
        config = {
            "policy": {
                "engagement_id": "owned-cli-retest",
                "owner_id": "operator",
                "allowed_origins": [fixture.origin],
                "profile": "isolated-lab",
                "egress_mode": "local-fixture",
                "request_budget": 16,
            },
            "nuclei_lock": lock,
            "tls": {"upstream_ca_file": str(fixture.ca_file)},
            "seeds": [{"url": fixture.origin + "/", "capabilities": ["nuclei_scan"]}],
        }
        configuration, output = tmp_path / "config.json", tmp_path / "run"
        for attempt in range(3):
            if attempt == 2:
                fixture.fixed = True
                config["seeds"][0]["retest_revision"] = "explicit-owned-fixed-control"
            configuration.write_text(json.dumps(config))
            environment = {
                **os.environ,
                "REDJOHN_TELEMETRY": "0",
                "OPENAI_AGENTS_DISABLE_TRACING": "1",
                "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
            }
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                "from redjohn.interface.main import main; main()",
                "assess",
                "run",
                "--config",
                str(configuration),
                "--output",
                str(output),
                env=environment,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), 45)
            except BaseException:
                if process.returncode is None:
                    process.kill()
                await process.wait()
                raise
            assert process.returncode == 0, (stdout, stderr)
            payload = json.loads(stdout)
            assert payload["product"] == "RedJohn"
            assert all(row["coverage_status"] == "completed" for row in payload["coverage"])
            report = json.loads((output / "assessment-report.json").read_text())
            assert report["metrics"]["model_calls"] == 0
            assert len(report["jobs_page"]) == (2 if attempt == 2 else 1)
            assert fixture.counts["/"] == (2 if attempt == 2 else 1)
            assert len(report["findings_page"]) == 1  # Historical candidate stays evidence.
            assert (output / "assessment-report.html").is_file()
            assert "RedJohn" in (output / "assessment-report.html").read_text()
            if attempt == 2:
                fixed = next(job for job in report["jobs_page"] if job["spec"]["retest_revision"])
                assert fixed["execution_status"] == "succeeded"
                assert fixed["coverage_status"] == "completed"
                assert fixed["result"]["summary"]["no_finding_observed"] is True
                assert fixed["result"]["findings"] == []
