"""Pure parser/policy contracts and actual owned SOCKS/TCP/DNS + SQLite tests.

No scanner binary is executed here. Native engine tests live in network_tools_live.
"""

import asyncio
import contextlib
import ipaddress
import struct
from dataclasses import replace

import pytest

from redjohn.assessment.models import AdapterResult, JobSpec, Surface
from redjohn.assessment.network_broker import ScopedTCPBroker, question
from redjohn.assessment.network_scope import dns_name, endpoint, numeric_ip
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.store import AssessmentStore


def dns_packet(name="owned.test", kind=1):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    return struct.pack("!6H", 1234, 0x100, 1, 0, 0, 0) + labels + struct.pack("!HH", kind, 1)


def owned_job(tmp_path, port, *, dns=False, budget=32):
    policy = EngagementPolicy(
        "owned-network",
        "owner",
        (),
        profile="isolated-lab",
        target_domains=("network",),
        network_request_budget=budget,
        allowed_networks=() if dns else ("127.0.0.0/8",),
        allowed_tcp_ports=() if dns else (str(port),),
        allowed_dns_zones=("owned.test",) if dns else (),
        allowed_dns_resolvers=(endpoint("127.0.0.1", str(port)),) if dns else (),
    )
    store = AssessmentStore(tmp_path / "network.sqlite3")
    policy = store.register(policy)
    asset = store.inventory.record_asset(
        policy,
        kind="dns_name" if dns else "ip_address",
        locator="owned.test" if dns else "127.0.0.1",
        source="imported",
    )
    kind = "dns_name" if dns else "network_endpoint"
    surface = Surface(
        "",
        resource_kind=kind,
        asset_ref=asset,
        network_address="127.0.0.1",
        network_port=str(port),
        input_location=kind,
        dns_name="owned.test" if dns else "",
        dns_type="A" if dns else "",
        source="imported",
        workflow_state="approved_seed",
    )
    sid = store.upsert_surface(policy.engagement_id, surface)
    store.submit(
        policy,
        [
            JobSpec(
                sid,
                "network_test",
                "dnsx_resolve" if dns else "naabu_ports",
                policy_revision=policy.revision,
            )
        ],
    )
    job = store.claim(policy, "owned-worker", lease_seconds=30)
    assert job is not None
    return store, policy, surface, job


async def socks_connect(address, broker, *, port=None, password=None):
    host, selected_port = address.split(":")
    reader, writer = await asyncio.open_connection(host, int(selected_port))
    writer.write(b"\x05\x01\x02")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x02"
    secret = (password or broker.nonce).encode()
    writer.write(b"\x01\x07redjohn" + bytes([len(secret)]) + secret)
    await writer.drain()
    try:
        auth = await reader.readexactly(2)
    except asyncio.IncompleteReadError:
        return reader, writer, b""
    assert auth == b"\x01\x00"
    writer.write(
        b"\x05\x01\x00\x01"
        + ipaddress.ip_address("127.0.0.1").packed
        + struct.pack("!H", port or int(broker.surface.network_port))
    )
    await writer.drain()
    try:
        reply = await reader.readexactly(10)
    except asyncio.IncompleteReadError:
        reply = b""
    return reader, writer, reply


async def close_stream(writer):
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()


@pytest.mark.parametrize("value", ["OWNED.test", "bad..test", "x.owned.test.", "* .test", "é.test"])
def test_dns_names_require_exact_canonical_ascii(value):
    with pytest.raises(ValueError):
        dns_name(value)


@pytest.mark.parametrize("value", ["example.test", "0.0.0.0", "224.0.0.1", "::", "fe80::1%en0"])
def test_broker_targets_are_numeric_unicast_and_unscoped(value):
    with pytest.raises(ValueError):
        numeric_ip(value)


def test_dns_question_parser_rebuilds_bounded_question_and_rejects_extensions():
    wire = dns_packet()
    assert question(wire) == ("owned.test", "A", wire)
    edns = wire[:10] + b"\x00\x01" + wire[12:] + b"\0" + struct.pack("!HHIH", 41, 4096, 0, 0)
    assert question(edns) == ("owned.test", "A", wire)
    with pytest.raises(ValueError, match="edns_extension"):
        question(edns[:-2] + b"\x00\x02extra")
    for invalid in [
        wire[:15],
        wire + b"extra",
        dns_packet(kind=255),
        struct.pack("!6H", 1, 0x100, 1, 0, 0, 0) + b"\xc0\x0c\0\x01\0\x01",
        struct.pack("!6H", 1, 0x100, 2, 0, 0, 0) + wire[12:],
        struct.pack("!6H", 1, 0x8100, 1, 0, 0, 0) + wire[12:],
    ]:
        with pytest.raises(ValueError):
            question(invalid)


def test_web_ip_scope_does_not_grant_port_scanning_or_dns():
    policy = EngagementPolicy(
        "http-only",
        "owner",
        ("https://owned.test",),
        allowed_ips=("127.0.0.0/8",),
        profile="active-staging",
    )
    with pytest.raises(PolicyDenied):
        policy.check_network_endpoint("127.0.0.1", "443")
    with pytest.raises(PolicyDenied):
        policy.check_dns_query("owned.test", "A", "127.0.0.1", "53")


@pytest.mark.parametrize("forbidden", [False, True], ids=["approved-open", "forbidden-port"])
async def test_actual_socks_connect_scope_and_real_upstream_success(tmp_path, forbidden):
    accepted = []

    async def target(reader, writer):
        accepted.append(True)
        await reader.read()
        await close_stream(writer)

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    store, policy, surface, job = owned_job(tmp_path, port)
    broker = ScopedTCPBroker(policy, store, surface, job)
    try:
        address = await broker.start()
        _reader, writer, reply = await socks_connect(
            address, broker, port=(port + 1 if port < 65535 else 1) if forbidden else port
        )
        await close_stream(writer)
        await asyncio.sleep(0.02)
        if forbidden:
            assert reply == b""
            assert not accepted
            assert broker.denied == 1
            assert store.network_request_usage(policy) == 0
        else:
            assert reply[1] == 0
            assert accepted == [True]
            assert broker.connected == broker.attempted == 1
            assert not broker.denied
            assert store.network_request_usage(policy) == 1
        assert store.request_usage(policy) == 0
    finally:
        await broker.close()
        server.close()
        await server.wait_closed()
        store.close()


async def test_actual_socks_refusal_is_not_a_success_and_budget_survives_restart(tmp_path):
    server = await asyncio.start_server(lambda _r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    store, policy, surface, job = owned_job(tmp_path, port)
    broker = ScopedTCPBroker(policy, store, surface, job)
    try:
        _reader, writer, reply = await socks_connect(await broker.start(), broker)
        await close_stream(writer)
        await asyncio.sleep(0.02)
        assert reply[1] == 5
        assert broker.refused == broker.attempted == 1
        assert not broker.connected and not broker.denied
        store.finish(job, AdapterResult("succeeded", "completed"))
    finally:
        await broker.close()
        store.close()
    reopened = AssessmentStore(tmp_path / "network.sqlite3")
    try:
        assert reopened.network_request_usage(policy) == 1
        assert reopened.claim(policy, "new-owner") is None
    finally:
        reopened.close()


@pytest.mark.parametrize("cancelled", [False, True], ids=["wrong-nonce", "cancelled-job"])
async def test_actual_socks_refuses_bad_nonce_or_cancelled_lease_without_connect(
    tmp_path, cancelled
):
    store, policy, surface, job = owned_job(tmp_path, 1)
    broker = ScopedTCPBroker(policy, store, surface, job)
    try:
        address = await broker.start()
        if cancelled:
            store.cancel(policy.engagement_id, job["id"])
        _reader, writer, reply = await socks_connect(
            address, broker, password=broker.nonce if cancelled else "wrong-job"
        )
        await close_stream(writer)
        await asyncio.sleep(0.02)
        assert reply == b""
        assert broker.denied == 1 and not broker.attempted
        assert store.network_request_usage(policy) == 0
    finally:
        await broker.close()
        store.close()


@pytest.mark.parametrize("mode", ["answer", "nxdomain", "forbidden-name"])
async def test_actual_tcp_dns_question_scope_and_owned_response(tmp_path, mode):
    queried = []

    async def resolver(reader, writer):
        try:
            size = struct.unpack("!H", await reader.readexactly(2))[0]
            packet = await reader.readexactly(size)
            name, kind, clean = question(packet)
            queried.append((name, kind))
            flags = 0x8183 if mode == "nxdomain" else 0x8180
            reply = (
                clean[:2]
                + struct.pack("!5H", flags, 1, 0 if mode == "nxdomain" else 1, 0, 0)
                + clean[12:]
            )
            if mode != "nxdomain":
                reply += (
                    b"\xc0\x0c"
                    + struct.pack("!HHIH", 1, 1, 60, 4)
                    + ipaddress.ip_address("127.0.0.42").packed
                )
            writer.write(struct.pack("!H", len(reply)) + reply)
            await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            await close_stream(writer)

    server = await asyncio.start_server(resolver, "127.0.0.1", 0)
    store, policy, surface, job = owned_job(tmp_path, server.sockets[0].getsockname()[1], dns=True)
    broker = ScopedTCPBroker(policy, store, surface, job)
    try:
        reader, writer, reply = await socks_connect(await broker.start(), broker)
        assert reply[1] == 0
        wire = dns_packet("forbidden.invalid" if mode == "forbidden-name" else "owned.test")
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        if mode == "forbidden-name":
            assert await reader.read() == b""
            assert queried == []
            assert broker.denied == 1 and not broker.dns_queries
        else:
            size = struct.unpack("!H", await reader.readexactly(2))[0]
            response = await reader.readexactly(size)
            assert response[:2] == wire[:2]
            assert queried == [("owned.test", "A")]
            assert broker.dns_queries == 1 and broker.response_bytes == len(response)
            assert broker.dns_rcodes == ([3] if mode == "nxdomain" else [0])
            assert store.network_request_usage(policy) == 2
            assert store.request_usage(policy) == 0
        await close_stream(writer)
    finally:
        await broker.close()
        server.close()
        await server.wait_closed()
        store.close()


def test_network_policy_and_surface_grants_are_exact_independent_and_immutable(tmp_path):
    store, policy, surface, _job = owned_job(tmp_path, 9000)
    try:
        policy.check_surface(surface)
        for mutation in [
            replace(surface, network_port="9001"),
            replace(surface, network_address="192.0.2.1"),
        ]:
            with pytest.raises(PolicyDenied):
                policy.check_surface(mutation)
        assert surface.url == ""
        assert replace(surface, network_port="9001").key != surface.key
        assert EngagementPolicy.from_mapping(policy.to_dict()) == policy
    finally:
        store.close()


async def test_actual_broker_cancellation_closes_pending_dns_stream_without_listener_deadlock(
    tmp_path,
):
    received, disconnected = asyncio.Event(), asyncio.Event()

    async def waiting_resolver(reader, writer):
        try:
            size = struct.unpack("!H", await reader.readexactly(2))[0]
            await reader.readexactly(size)
            received.set()
            await reader.read()
        finally:
            await close_stream(writer)
            disconnected.set()

    server = await asyncio.start_server(waiting_resolver, "127.0.0.1", 0)
    store, policy, surface, job = owned_job(tmp_path, server.sockets[0].getsockname()[1], dns=True)
    broker = ScopedTCPBroker(policy, store, surface, job)
    writer = None
    try:
        _reader, writer, reply = await socks_connect(await broker.start(), broker)
        assert reply[1] == 0
        wire = dns_packet()
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        await asyncio.wait_for(received.wait(), 1)
        await asyncio.wait_for(broker.close(), 2)
        await asyncio.wait_for(disconnected.wait(), 1)
        assert broker.tasks == set() and broker.writers == set()
        assert store.network_request_usage(policy) == 2
    finally:
        if writer is not None:
            await close_stream(writer)
        await broker.close()
        server.close()
        await server.wait_closed()
        store.close()
