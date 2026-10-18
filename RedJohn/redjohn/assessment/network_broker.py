"""Owned SOCKS5 TCP broker. Socket reachability and DNS questions have separate grants."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import secrets
import struct
import time
from typing import TYPE_CHECKING, Any

from redjohn.assessment.network_scope import dns_name, numeric_ip
from redjohn.assessment.policy import PolicyDenied


if TYPE_CHECKING:
    from redjohn.assessment.models import Surface
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore

DNS_TYPES = {1: "A", 28: "AAAA", 5: "CNAME"}


def question(packet: bytes) -> tuple[str, str, bytes]:
    """Decode exactly one uncompressed standard question; discard no opaque data."""
    if not 17 <= len(packet) <= 4096:
        raise ValueError("dns_wire_size_denied")
    ident, flags, count, answers, authorities, additional = struct.unpack("!6H", packet[:12])
    if flags & 0xF8FF or count != 1 or answers or authorities or additional > 1:
        raise ValueError("dns_query_header_denied")
    labels: list[str] = []
    cursor = 12
    while True:
        if cursor >= len(packet):
            raise ValueError("dns_question_truncated")
        size = packet[cursor]
        cursor += 1
        if not size:
            break
        if size > 63 or cursor + size > len(packet) or len(labels) >= 127:
            raise ValueError("dns_label_or_compression_denied")
        labels.append(packet[cursor : cursor + size].decode("ascii").lower())
        cursor += size
    if cursor + 4 > len(packet):
        raise ValueError("dns_query_extra_data_denied")
    qtype, qclass = struct.unpack("!HH", packet[cursor : cursor + 4])
    tail = packet[cursor + 4 :]
    if additional:
        # dnsx's pinned retryabledns emits one empty EDNS0 OPT (4096 bytes).
        # Validate exactly that bounded record, then strip it upstream. No
        # cookies, client-subnet extensions, options or opaque data are relayed.
        if tail != b"\0" + struct.pack("!HHIH", 41, 4096, 0, 0):
            raise ValueError("dns_query_edns_extension_denied")
    elif tail:
        raise ValueError("dns_query_extra_data_denied")
    name = dns_name(".".join(labels))
    if qtype not in DNS_TYPES or qclass != 1:
        raise ValueError("dns_query_type_denied")
    # A fresh controlled question excludes query extensions and data channels.
    encoded = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    clean = struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", qtype, 1)
    return name, DNS_TYPES[qtype], clean


class ScopedTCPBroker:
    def __init__(
        self,
        policy: EngagementPolicy,
        store: AssessmentStore,
        surface: Surface,
        job: dict[str, Any],
        *,
        timeout: float = 3,
    ) -> None:
        self.policy, self.store, self.surface, self.job = policy, store, surface, job
        self.timeout = min(timeout, 5)
        self.nonce = secrets.token_hex(24)
        self.server: asyncio.Server | None = None
        self.tasks: set[asyncio.Task[None]] = set()
        self.writers: set[asyncio.StreamWriter] = set()
        self.attempted = self.connected = self.refused = self.denied = self.dns_queries = 0
        self.response_bytes = 0
        self.dns_rcodes: list[int] = []
        self.dns_answer_counts: list[int] = []
        self.closed = False
        self.next_admission = 0.0

    def fence(self) -> None:
        if self.closed:
            raise PolicyDenied("network_broker_closed")
        self.policy.check_surface(self.surface)
        with self.store._lock:
            self.store.inventory._fence(self.store.db, self.policy)
            row = self.store.db.execute(
                "SELECT spec FROM rj_job WHERE id=? AND engagement=? AND owner=? AND attempt=? "
                "AND execution_status='running' AND cancel_requested=0 AND lease_until>?",
                (
                    self.job["id"],
                    self.policy.engagement_id,
                    self.job["owner"],
                    self.job["attempt"],
                    time.time(),
                ),
            ).fetchone()
            if row is None or row[0] != self.job["spec"]:
                raise PolicyDenied("network_job_lease_not_current")
            current = self.store.surface(self.policy.engagement_id, self.job["surface_id"])
            if current.key != self.surface.key:
                raise PolicyDenied("network_job_surface_changed")
            self.store.inventory.require_surface_active(
                self.store.db, self.policy, self.job["surface_id"]
            )

    async def start(self) -> str:
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0, limit=8192)
        port = self.server.sockets[0].getsockname()[1]
        return f"127.0.0.1:{port}"

    async def _auth(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        version, count = await reader.readexactly(2)
        if version != 5 or not 1 <= count <= 8 or 2 not in await reader.readexactly(count):
            raise PolicyDenied("socks_authentication_required")
        writer.write(b"\x05\x02")
        await writer.drain()
        version, size = await reader.readexactly(2)
        user = await reader.readexactly(size)
        size = (await reader.readexactly(1))[0]
        password = await reader.readexactly(size)
        if (
            version != 1
            or user != b"redjohn"
            or not secrets.compare_digest(password, self.nonce.encode())
        ):
            raise PolicyDenied("socks_job_nonce_required")
        writer.write(b"\x01\x00")
        await writer.drain()

    async def _target(self, reader: asyncio.StreamReader) -> tuple[str, str]:
        version, command, reserved, kind = await reader.readexactly(4)
        if (version, command, reserved) != (5, 1, 0) or kind not in {1, 4}:
            raise PolicyDenied("numeric_tcp_connect_only")
        address = str(ipaddress.ip_address(await reader.readexactly(4 if kind == 1 else 16)))
        numeric_ip(address)
        port = str(struct.unpack("!H", await reader.readexactly(2))[0])
        if (address, port) != (self.surface.network_address, self.surface.network_port):
            raise PolicyDenied("network_surface_endpoint_mismatch")
        self.fence()
        return address, port

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        if self.closed or len(self.tasks) >= 2:
            self.denied += 1
            writer.close()
            return
        self.tasks.add(task)
        self.writers.add(writer)
        upstream = None
        try:
            async with asyncio.timeout(self.timeout):
                await self._auth(reader, writer)
                address, port = await self._target(reader)
                now = time.monotonic()
                if self.attempted >= 8 or now < self.next_admission:
                    raise PolicyDenied("network_connection_rate_or_count_exceeded")
                self.next_admission = now + 0.1
                self.store.consume_network_requests(self.policy)
                self.attempted += 1
                try:
                    remote_reader, upstream = await asyncio.open_connection(
                        address, int(port), limit=8192
                    )
                except (OSError, TimeoutError):
                    self.refused += 1
                    writer.write(b"\x05\x05\x00\x01" + b"\0" * 6)
                    await writer.drain()
                    return
                self.writers.add(upstream)
                self.fence()
                self.connected += 1
                # Success is emitted only after the real approved upstream connect.
                writer.write(b"\x05\x00\x00\x01" + b"\0" * 6)
                await writer.drain()
                if self.surface.resource_kind == "dns_name":
                    await self._dns(reader, writer, remote_reader, upstream)
                elif await reader.read(1):
                    raise PolicyDenied("connect_discovery_payload_denied")
        except (ValueError, RuntimeError, OSError, TimeoutError, asyncio.IncompleteReadError):
            self.denied += 1
        finally:
            streams = [stream for stream in (writer, upstream) if stream is not None]
            for stream in streams:
                stream.close()
            try:
                for stream in streams:
                    with contextlib.suppress(OSError, TimeoutError):
                        await asyncio.wait_for(stream.wait_closed(), 1)
            finally:
                # A cancellation racing an already-running finalizer must not
                # leave closed transports/tasks retained in the owner registry.
                for stream in streams:
                    self.writers.discard(stream)
                self.tasks.discard(task)

    async def _dns(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        upstream: asyncio.StreamWriter,
    ) -> None:
        size = struct.unpack("!H", await reader.readexactly(2))[0]
        if not 17 <= size <= 4096:
            raise PolicyDenied("dns_wire_budget_exceeded")
        name, kind, clean = question(await reader.readexactly(size))
        self.policy.check_dns_query(
            name, kind, self.surface.network_address, self.surface.network_port
        )
        if (name, kind) != (self.surface.dns_name, self.surface.dns_type):
            raise PolicyDenied("dns_surface_question_mismatch")
        self.fence()
        self.store.consume_network_requests(self.policy)
        self.dns_queries += 1
        upstream.write(struct.pack("!H", len(clean)) + clean)
        await upstream.drain()
        length = struct.unpack("!H", await remote_reader.readexactly(2))[0]
        if not 12 <= length <= 4096:
            raise PolicyDenied("dns_response_budget_exceeded")
        response = await remote_reader.readexactly(length)
        ident, flags, qcount, answers, authorities, additional = struct.unpack("!6H", response[:12])
        if (
            ident != struct.unpack("!H", clean[:2])[0]
            or not flags & 0x8000
            or qcount != 1
            or flags & 0x0200
            or answers + authorities + additional > 64
        ):
            raise PolicyDenied("dns_response_identity_or_truncation_denied")
        question_bytes = clean[12:]
        if response[12 : 12 + len(question_bytes)].lower() != question_bytes.lower():
            raise PolicyDenied("dns_response_question_mismatch")
        self.fence()
        self.response_bytes += len(response)
        self.dns_rcodes.append(flags & 15)
        self.dns_answer_counts.append(answers)
        writer.write(struct.pack("!H", len(response)) + response)
        await writer.drain()

    async def close(self) -> None:
        self.closed = True
        if self.server is not None:
            self.server.close()
        # Python 3.13 Server.wait_closed also waits for accepted transports.
        # Close owned streams before awaiting the listener, including DNS waits.
        for writer in tuple(self.writers):
            writer.close()
        tasks = tuple(task for task in self.tasks if task is not asyncio.current_task())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.server is not None:
            await self.server.wait_closed()
            self.server = None
