"""Extension-state cleanup guards; native engines are never executed."""

import asyncio
from types import SimpleNamespace

import pytest

from redjohn.assessment.network_tools import NetworkToolConfig, NetworkToolRunner
from redjohn.assessment.pinned_tools import BinaryPin
from redjohn.assessment.service_tools import NmapServiceConfig, NmapServiceRunner


@pytest.mark.parametrize("kind", ["network", "service"])
@pytest.mark.parametrize("state", ["open", "listener", "task", "writer"])
async def test_retained_broker_resources_block_release_even_after_active_pointer_cleared(
    tmp_path, kind, state
):
    pin = BinaryPin(tmp_path / "never-executed", "0" * 64, "fixture")
    runner = (
        NetworkToolRunner(NetworkToolConfig("naabu", pin), tmp_path)
        if kind == "network"
        else NmapServiceRunner(NmapServiceConfig(pin), tmp_path)
    )
    assert runner.resource_cleanup_verified()
    # Synthetic retained state exercises the exact guard branches. A real
    # listener/task is used where relevant; no scanner or target is contacted.
    broker = SimpleNamespace(closed=True, server=None, tasks=set(), writers=set())
    task = server = None
    if state == "open":
        broker.closed = False
    elif state == "listener":
        server = await asyncio.start_server(lambda _r, w: w.close(), "127.0.0.1", 0)
        broker.server = server
    elif state == "task":
        task = asyncio.create_task(asyncio.Event().wait())
        broker.tasks.add(task)
    else:
        broker.writers.add(object())
    runner._broker_cleanup_proof = broker
    runner.broker = None
    assert not runner.resource_cleanup_verified()
    if task:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    if server:
        server.close()
        await server.wait_closed()
    broker.closed, broker.server = True, None
    broker.tasks.clear()
    broker.writers.clear()
    assert runner.resource_cleanup_verified()
