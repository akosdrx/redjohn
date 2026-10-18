"""Actual CLI subprocesses resume one ffuf assessment without duplicate traffic."""

import asyncio
import json
import os
import sys
from pathlib import Path

from tests.test_ffuf_live import installed, owned_fixture


async def test_actual_ffuf_cli_resume_and_explicit_retest(tmp_path):
    document = installed()
    document["paths"] = ["hidden", "absent"]
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        config = {
            "policy": {
                "engagement_id": "ffuf-cli",
                "owner_id": "operator",
                "allowed_origins": [fixture.origin],
                "profile": "isolated-lab",
                "egress_mode": "local-fixture",
                "request_budget": 8,
            },
            "ffuf": document,
            "tls": {"upstream_ca_file": str(fixture.ca_file)},
            "seeds": [{"url": fixture.origin + "/", "capabilities": ["ffuf_discover"]}],
        }
        path, output = tmp_path / "config.json", tmp_path / "run"
        for attempt in range(3):
            if attempt == 1:
                document["rate_limit"] = 1  # QoS change must not repeat completed requests.
            if attempt == 2:
                config["seeds"][0]["retest_revision"] = "explicit-control"
            path.write_text(json.dumps(config))
            env = {
                **os.environ,
                "REDJOHN_TELEMETRY": "0",
                "OPENAI_AGENTS_DISABLE_TRACING": "1",
                "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
            }
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "redjohn.assessment",
                "run",
                "--config",
                str(path),
                "--output",
                str(output),
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode == 0, (stdout, stderr)
            payload = json.loads(stdout)
            assert payload["product"] == "RedJohn"
            assert all(row["coverage_status"] == "completed" for row in payload["coverage"])
            report = json.loads((output / "assessment-report.json").read_text())
            assert report["metrics"]["model_calls"] == 0
            assert len(report["jobs_page"]) == (2 if attempt == 2 else 1)
            health = next(row for row in report["capabilities"] if row["id"] == "ffuf_discover")
            assert health["status"] == "implemented_fixture_tested"
            assert fixture.request_counts["/hidden"] == (2 if attempt == 2 else 1)
            assert fixture.request_counts["/absent"] == (2 if attempt == 2 else 1)
