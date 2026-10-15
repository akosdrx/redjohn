"""Native desktop memory boot with isolated HTTP and real-process boundaries."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import sys
from pathlib import Path

import httpx
import pytest
from redjohn_core import managed_memory as memory
from redjohn_core.errors import RJError
from redjohn_core.integrations import IntegrationStore, atomic_private_json
from redjohn_core.memory_config import generate_server_config, memory_proxy_url, memory_public, save_memory
from redjohn_core.models import ServiceState
from redjohn_core.settings import Settings

from .conftest import wait_for
from .test_integration_settings import server_values


class ProcessFixture:
    next_pid = 13000

    def __init__(self):
        self.pid = ProcessFixture.next_pid
        ProcessFixture.next_pid += 1
        self.returncode = None
        self.terminated = False

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    async def wait(self):
        return self.returncode


def fixture_boundaries(monkeypatch):
    """Mock the OpenViking admin HTTP surface and the native spawn. No model
    runtime exists anymore (language + embeddings are external endpoints)."""
    calls, requests, users = [], [], set()
    original_client = httpx.AsyncClient

    def respond(request):
        requests.append(request)
        if request.url.path.endswith("/users"):
            if request.url.path in users:
                return httpx.Response(409, json={"error": {"code": "CONFLICT"}})
            users.add(request.url.path)
            return httpx.Response(200, json={"status": "success", "result": {"user_key": "fixture-user-key"}})
        return httpx.Response(200, json={"status": "success", "result": {}})

    def client(*args, **kwargs):
        return original_client(*args, **kwargs, transport=httpx.MockTransport(respond))

    async def spawn(runtime, service, argv, port, config_hash=""):
        calls.append((service, argv))
        child = memory.NativeProcess(ProcessFixture(), port, config_hash)
        runtime.processes[service] = child
        return child

    monkeypatch.setattr(
        memory, "native_program", lambda service="openviking": Path("/native-fixture/" + service)
    )
    monkeypatch.setattr(memory.ManagedMemoryRuntime, "_spawn", spawn)
    monkeypatch.setattr(memory.httpx, "AsyncClient", client)
    return calls, requests


async def test_start_runs_openviking_with_external_models_and_separates_credentials(tmp_path, monkeypatch):
    calls, _ = fixture_boundaries(monkeypatch)
    settings = Settings(redjohn_home=tmp_path)
    store = IntegrationStore(settings)
    # Provider-routed language (via the in-engine proxy) + external embeddings.
    data = store.read()
    data["memory"] = {
        "provider_connection_id": "prov-1",
        "selected_model": "selected-model",
        "model_proxy_secret": store.encrypt("proxy-private"),
    }
    atomic_private_json(store.path, data)
    generate_server_config(
        settings,
        {
            "language_base_url": memory_proxy_url(settings),
            "language_model": "selected-model",
            "language_api_key": "proxy-private",
            "embedding_base_url": "https://embeddings.example/v1",
            "embedding_model": "embed-model",
            "embedding_api_key": "embed-private",
            "embedding_dimension": 37,
        },
    )
    source_path = settings.profile_dir / "openviking" / "ov.conf"
    source = source_path.read_bytes()
    runtime = memory.ManagedMemoryRuntime(settings, lambda _: None)
    assert await runtime.start() is True
    config = json.loads(source)
    assert config["embedding"]["dense"]["api_key"] == "embed-private"
    assert config["embedding"]["dense"]["dimension"] == 37
    assert config["vlm"]["api_key"] == "proxy-private"
    assert settings.openviking_api_key == "fixture-user-key"
    assert memory_public(settings)["model_config_applied"] is True
    assert memory_public(settings)["managed_process"] == runtime.processes["openviking"].process.pid
    assert "embed-private" not in repr(calls)
    # Only OpenViking is spawned — there is no local model runtime.
    assert [service for service, _ in calls] == ["openviking"]
    native = json.loads((source_path.parent / "ov.native.conf").read_text())
    assert native["server"]["host"] == "127.0.0.1"
    assert native["storage"]["workspace"] == str(source_path.parent / "data")
    assert native["encryption"]["local"]["key_file"] == str(source_path.parent / "master.key")
    assert native["vlm"]["api_base"] == memory_proxy_url(settings)
    # A restart reuses the existing config without respawning or rewriting ov.conf.
    assert await runtime.start() is True
    assert len(calls) == 1
    assert source_path.read_bytes() == source
    children = list(runtime.processes.values())
    await runtime.stop()
    assert all(child.process.terminated for child in children)
    assert memory_public(settings)["managed_process"] is None
    assert source_path.exists()


async def test_existing_external_memory_is_preserved_when_native_helpers_are_missing(tmp_path, monkeypatch):
    settings = Settings(redjohn_home=tmp_path)
    save_memory(settings, {"openviking_url": "https://memory.example", "service_api_key": "external-private"})
    before = IntegrationStore(settings).path.read_bytes()
    monkeypatch.setattr(
        memory, "native_program", lambda _: pytest.fail("External services need no local helper")
    )
    runtime = memory.ManagedMemoryRuntime(settings, lambda _: None)
    assert await runtime.start() is False
    assert IntegrationStore(settings).path.read_bytes() == before
    assert settings.openviking_api_key == "external-private"


async def test_saved_pid_never_authorizes_killing_or_attaching_to_an_unowned_service(tmp_path, monkeypatch):
    calls, _ = fixture_boundaries(monkeypatch)
    settings = Settings(redjohn_home=tmp_path)
    generate_server_config(settings, server_values())
    store = IntegrationStore(settings)
    data = store.read()
    with socket.socket() as unrelated:
        unrelated.bind(("127.0.0.1", 0))
        data["memory"].update({"managed_port": unrelated.getsockname()[1], "managed_process": os.getpid()})
        atomic_private_json(store.path, data)
        runtime = memory.ManagedMemoryRuntime(settings, lambda _: None)
        with pytest.raises(RJError, match="occupied by another process"):
            await runtime.start()
        await runtime.stop()
    assert not calls
    assert store.read()["memory"]["managed_process"] == os.getpid()


async def test_native_start_failure_is_visible_while_engine_remains_available(engine, api, monkeypatch):
    # With a configured server, a missing native OpenViking runtime must surface
    # as a visible DOWN status while the rest of the engine keeps serving.
    from .test_integration_settings import server_values

    generate_server_config(engine.settings, server_values())

    def missing(service="openviking"):
        raise RJError("native_memory_runtime_unavailable", "Native memory helper is missing", status=503)

    monkeypatch.setattr(memory, "native_program", missing)
    engine.start_memory_bootstrap()
    await wait_for(
        lambda: engine._memory_startup_status and engine._memory_startup_status.state == ServiceState.DOWN
    )
    response = await api.get("/api/v1/status")
    assert response.status_code == 200
    status = next(s for s in response.json()["services"] if s["service"] == "openviking")
    assert status["state"] == "down"
    assert "Native" in status["detail"]
    await engine.cancel_memory_bootstrap()


async def test_explicit_settings_cancel_provisioning_before_saving_external_connection(
    engine, api, monkeypatch
):
    entered, cancelled = asyncio.Event(), asyncio.Event()

    class Runtime:
        def __init__(self, settings, progress):
            self.settings = settings

        async def start(self, **kwargs):
            if self.settings.openviking_url:
                return False
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        async def stop(self):
            pass

    monkeypatch.setattr(memory, "ManagedMemoryRuntime", Runtime)
    engine.start_memory_bootstrap()
    await asyncio.wait_for(entered.wait(), 1)
    response = await api.put(
        "/api/v1/integrations/memory",
        json={
            "openviking_url": "http://127.0.0.1:1",
            "openviking_account": "redjohn",
            "openviking_user": "local-user",
            "service_api_key": "external-private",
        },
    )
    assert response.status_code == 200
    assert cancelled.is_set()
    assert engine.settings.openviking_api_key == "external-private"
    await engine.cancel_memory_bootstrap()


async def test_real_native_child_has_private_logs_isolated_env_and_is_reaped(tmp_path, monkeypatch):
    script = tmp_path / "native-helper"
    script.write_text(
        f"#!{sys.executable}\n"
        + """import json,os,sys,time
print(json.dumps({"argv":sys.argv[1:], "private":os.environ.get("RJ_MODEL_API_KEY"),
                 "pythonpath":os.environ.get("PYTHONPATH"),
                 "frozen":os.environ.get("_PYI_TEST")} ),flush=True)
while True:time.sleep(.1)
"""
    )
    script.chmod(0o700)
    monkeypatch.setattr(memory, "native_program", lambda _: script)
    monkeypatch.setenv("RJ_MODEL_API_KEY", "must-not-inherit")
    monkeypatch.setenv("PYTHONPATH", "must-not-inherit")
    monkeypatch.setenv("_PYI_TEST", "must-not-inherit")
    settings = Settings(redjohn_home=tmp_path / "profile")
    runtime = memory.ManagedMemoryRuntime(settings, lambda _: None)
    child = await runtime._spawn("openviking", ["--config", "/dev/null", "--port", "1"], 1)
    log = settings.profile_dir / "openviking" / "logs" / "openviking.log"
    await wait_for(lambda: bool(log.read_text()))
    record = json.loads(log.read_text().splitlines()[0])
    assert record["argv"][:2] == ["--owner-pid", str(os.getpid())]
    assert record["private"] is record["pythonpath"] is record["frozen"] is None
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    await runtime.stop()
    assert child.process.returncode is not None
    with pytest.raises(ProcessLookupError):
        os.kill(child.process.pid, 0)


async def test_subprocess_creation_cancellation_reaps_the_late_child(tmp_path, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    process = ProcessFixture()

    async def spawn(*args, **kwargs):
        entered.set()
        await release.wait()
        return process

    monkeypatch.setattr(memory, "native_program", lambda _: Path("/native-helper"))
    monkeypatch.setattr(memory.asyncio, "create_subprocess_exec", spawn)
    runtime = memory.ManagedMemoryRuntime(Settings(redjohn_home=tmp_path), lambda _: None)
    task = asyncio.create_task(runtime._spawn("openviking", [], 1))
    await entered.wait()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert process.terminated
    assert not runtime.processes


def test_closed_http_server_port_in_time_wait_can_be_reused():
    # Complete a real request with the server closing first, which leaves the
    # listener's address in TIME_WAIT after every process/socket has closed.
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            connection, _ = listener.accept()
            with connection:
                client.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                assert connection.recv(4096).startswith(b"GET /health")
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                connection.shutdown(socket.SHUT_WR)
                response = b""
                while chunk := client.recv(4096):
                    response += chunk
                assert response.endswith(b"{}")
    # Establish the regression condition before testing the production probe.
    with socket.socket() as plain:
        with pytest.raises(OSError):
            plain.bind(("127.0.0.1", port))
    memory.ensure_port_available(port)
    with socket.socket() as next_server:
        next_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        next_server.bind(("127.0.0.1", port))
        next_server.listen(1)


@pytest.mark.parametrize("reuse_address", [False, True])
def test_port_probe_still_rejects_an_active_listener(reuse_address):
    with socket.socket() as unrelated:
        unrelated.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, int(reuse_address))
        unrelated.bind(("127.0.0.1", 0))
        unrelated.listen(1)
        with pytest.raises(RJError, match="occupied by another process"):
            memory.ensure_port_available(unrelated.getsockname()[1])
