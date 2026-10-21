"""Actual stream forwarding contracts; namespace peer attestation is synthetic."""

import asyncio

import pytest

from redjohn.assessment.egress import LinuxEgressBoundary


@pytest.mark.parametrize("preamble", [b"", b"owned-private-token\0"])
async def test_controller_preamble_is_host_only_and_empty_preserves_exact_bytes(tmp_path, preamble):
    seen = []

    async def controller(reader, writer):
        data = await reader.readexactly(len(preamble) + 5)
        seen.append(data)
        writer.write(b"reply")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    controller_server = await asyncio.start_server(controller, "127.0.0.1", 0)
    port = controller_server.sockets[0].getsockname()[1]
    boundary = LinuxEgressBoundary(
        f"http://127.0.0.1:{port}", tmp_path, controller_preamble=preamble
    )
    boundary._kernel_attestation = lambda _writer: {"pid": 123, "namespaces": {"net": "owned"}}
    boundary._peers[123] = "owned"
    forward_server = await asyncio.start_server(boundary._handle, "127.0.0.1", 0)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", forward_server.sockets[0].getsockname()[1]
    )
    try:
        writer.write(b"Shello")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 1) == b"reply"
        assert seen == [preamble + b"hello"]
        assert boundary.relay_connections == 1
        if preamble:
            assert preamble.decode() not in str(boundary._attestations)
    finally:
        writer.close()
        await writer.wait_closed()
        forward_server.close()
        controller_server.close()
        await forward_server.wait_closed()
        await controller_server.wait_closed()
        await boundary.close()


async def test_preamble_never_reaches_controller_before_current_attested_peer(tmp_path):
    seen = []

    async def controller(_reader, writer):
        seen.append(True)
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(controller, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    boundary = LinuxEgressBoundary(
        f"http://127.0.0.1:{port}", tmp_path, controller_preamble=b"secret"
    )
    boundary._kernel_attestation = lambda _writer: {"pid": 123, "namespaces": {"net": "changed"}}
    boundary._peers[123] = "old"
    forward = await asyncio.start_server(boundary._handle, "127.0.0.1", 0)
    reader, writer = await asyncio.open_connection("127.0.0.1", forward.sockets[0].getsockname()[1])
    try:
        writer.write(b"Shello")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 1) == b""
        assert seen == [] and boundary.relay_connections == 0
        assert boundary.rejected_connections == 1
    finally:
        writer.close()
        await writer.wait_closed()
        forward.close()
        server.close()
        await forward.wait_closed()
        await server.wait_closed()
        await boundary.close()


@pytest.mark.parametrize("value", ["secret", None, b"x" * 257])
def test_controller_preamble_is_bounded_host_bytes(tmp_path, value):
    with pytest.raises(ValueError, match="invalid_egress_limits"):
        LinuxEgressBoundary("http://127.0.0.1:1234", tmp_path, controller_preamble=value)
