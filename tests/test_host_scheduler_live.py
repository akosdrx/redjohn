"""Actual Chromium and independent CLI controllers sharing one host ledger."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from redjohn.assessment.host_resources import HostResourcePool
from redjohn.assessment.policy import EngagementPolicy


def _save(name, value):
    if output := os.environ.get("REDJOHN_OS_MEMORY_MEASUREMENTS"):
        directory = Path(output)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        (directory / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


@pytest.mark.parametrize("automatic", [False, True])
async def test_real_browser_campaigns_share_capacity_and_retest_after_release(tmp_path, automatic):  # noqa: PLR0915 - actual independent-controller lifecycle and controls
    ready, release = threading.Event(), threading.Event()
    requests = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests[self.server.server_port].append(self.path)
            if self.path == "/ready":
                ready.set()
                release.wait(20)
                body = b"ok"
            else:
                body = (
                    b"<!doctype html><body><script>fetch('/ready').then(()=>{"
                    b"document.body.dataset.ready='yes'})</script></body>"
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    servers = [ThreadingHTTPServer(("127.0.0.1", 0), Handler) for _ in range(2)]
    threads = []
    for server in servers:
        requests[server.server_port] = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        threads.append(thread)
        thread.start()
    origins = {
        name: f"http://127.0.0.1:{server.server_port}"
        for name, server in zip(("first", "second"), servers, strict=True)
    }
    pool = HostResourcePool(tmp_path / "pool" / "host.sqlite3")
    children = []

    async def start(name, *, retest=""):
        origin = origins[name]
        policy = EngagementPolicy(
            name,
            "operator",
            (origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            deadline=deadline,
            request_budget=32,
            max_attempts=2 if automatic else 1,
        )
        directory = tmp_path / name
        config = {
            "policy": policy.to_dict(),
            "resources": {"total_memory_budget": 2 * 1024**3},
            "browser": {
                "max_pages": 1,
                "max_requests": 8,
                "readiness_selector": "body[data-ready='yes']",
                "readiness_timeout_ms": 15000,
                "total_timeout_seconds": 25,
            },
            "seeds": [
                {
                    "url": origin + "/",
                    "capabilities": ["browser_discover"],
                    "retest_revision": retest,
                }
            ],
        }
        path = tmp_path / (name + ".json")
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "redjohn.assessment",
            "run",
            "--config",
            str(path),
            "--output",
            str(directory),
            "--max-jobs",
            "2" if automatic and name == "second" else "1",
            "--wait-ready-seconds",
            "10" if automatic and name == "second" else "0",
            env={**os.environ, "REDJOHN_RESOURCE_POOL_PATH": str(pool.path)},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        children.append(process)
        return process, directory

    async def report(process, directory, exit_code):
        stdout, stderr = await asyncio.wait_for(process.communicate(), 40)
        assert process.returncode == exit_code, (stdout, stderr)
        return json.loads((directory / "assessment-report.json").read_text())

    deadline = time.time() + 120
    try:
        first, first_dir = await start("first")
        assert await asyncio.to_thread(ready.wait, 10), "First Chromium never reached the server"
        assert pool.snapshot()["active"].get("browser") == 1
        second, second_dir = await start("second")
        if automatic:
            limit = time.monotonic() + 10
            waiting = False
            while time.monotonic() < limit:
                database = second_dir / ".state/agents.db"
                if database.is_file():
                    with sqlite3.connect(database) as db:
                        try:
                            row = db.execute(
                                "SELECT execution_status FROM rj_job LIMIT 1"
                            ).fetchone()
                        except sqlite3.OperationalError:
                            row = None  # Schema initialization is still in progress.
                    if row is not None and row[0] == "retry_wait":
                        waiting = True
                        break
                await asyncio.sleep(0.02)
            assert waiting, "Occupied host capacity was not durably parked"
            assert requests[servers[1].server_port] == []
            assert pool.snapshot()["active"].get("browser") == 1
            release.set()
            await report(first, first_dir, 0)
            resumed = await report(second, second_dir, 0)
            assert resumed["jobs_page"][0]["execution_status"] == "succeeded"
            assert resumed["metrics"]["retries"] == 1
            with sqlite3.connect(second_dir / ".state/agents.db") as db:
                attempts = db.execute(
                    "SELECT execution_status,error FROM rj_attempt ORDER BY number"
                ).fetchall()
            assert [row[0] for row in attempts] == ["resource_exhausted", "succeeded"]
            assert json.loads(attempts[0][1])["code"] == "host_resource_busy"
            assert requests[servers[1].server_port]
            assert pool.snapshot()["active"] == {}
            _save(
                "cross-campaign-automatic-resume",
                {
                    "controllers": 2,
                    "real_browser_successes": 2,
                    "automatic_resume": True,
                    "blocked_controller_requests_before_release": 0,
                    "retries": 1,
                    "durable_attempt_states": [row[0] for row in attempts],
                    "requests": sum(map(len, requests.values())),
                    "resources_after_close": pool.snapshot(),
                },
            )
            return
        blocked = await report(second, second_dir, 1)
        assert requests[servers[1].server_port] == [], "Denied controller contacted its target"
        failed = blocked["jobs_page"][0]
        assert failed["execution_status"] == "resource_exhausted"
        assert failed["coverage_status"] == "blocked"
        assert not blocked["findings_page"]
        release.set()
        successful = await report(first, first_dir, 0)
        assert successful["jobs_page"][0]["execution_status"] == "succeeded"
        assert pool.snapshot()["active"] == {}
        third, directory = await start("second", retest="capacity-released")
        # Aggregate coverage still includes the historical blocked job. The
        # fresh retest succeeds without rewriting that earlier measurement.
        resumed = await report(third, directory, 1)
        assert resumed["metrics"]["jobs"] == 1
        rows = {row["id"]: row for row in resumed["jobs_page"]}
        assert rows[failed["id"]]["execution_status"] == "resource_exhausted"
        assert sum(row["execution_status"] == "succeeded" for row in rows.values()) == 1
        assert requests[servers[1].server_port]
        assert pool.snapshot()["active"] == {}
        _save(
            "cross-campaign-browser-scheduler",
            {
                "controllers": 3,
                "real_browser_successes": 2,
                "blocked_controller_requests": 0,
                "historical_blocked_job_preserved": True,
                "requests": sum(map(len, requests.values())),
                "resources_after_close": pool.snapshot(),
            },
        )
    finally:
        release.set()
        for process in children:
            if process.returncode is None:
                process.send_signal(signal.SIGINT)
                try:
                    await asyncio.wait_for(process.wait(), 10)
                except TimeoutError:
                    process.kill()
                    await process.wait()
        for server, thread in zip(servers, threads, strict=True):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
