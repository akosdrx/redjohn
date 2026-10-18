"""Fenced, authenticated banner/probe transport for observed-open TCP services.

A local relay connection proves no port state. Only actual bounded upstream
response bytes can support a service observation. The kernel relay prepends a
host-only nonce after its own peer attestation; raw workers never see that nonce.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import secrets
import time
from typing import TYPE_CHECKING, Any

from redjohn.assessment.network_broker import ScopedTCPBroker
from redjohn.assessment.policy import PolicyDenied


if TYPE_CHECKING:
    from redjohn.assessment.models import Surface
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore

HTTP_SERVICE_PROBE = b"GET / HTTP/1.0\r\n\r\n"


class ObservedServiceBroker(ScopedTCPBroker):
    def __init__(
        self,
        policy: EngagementPolicy,
        store: AssessmentStore,
        surface: Surface,
        job: dict[str, Any],
    ) -> None:
        super().__init__(policy, store, surface, job, timeout=5)
        self.preamble = b"RJ-SERVICE-1\0" + secrets.token_bytes(32)
        self.banner_types: set[str] = set()
        self.response_digests: list[str] = []
        self.sent_probe_count = 0
        self._admission_lock = asyncio.Lock()

    async def _accept(  # noqa: PLR0912 - authenticated admission then bounded stream lifecycle
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        if self.closed or len(self.tasks) >= 2:
            self.denied += 1
            writer.close()
            return
        self.tasks.add(task)
        self.writers.add(writer)
        upstream: asyncio.StreamWriter | None = None
        transfers: list[asyncio.Task[None]] = []
        try:
            async with asyncio.timeout(self.timeout):
                received = await reader.readexactly(len(self.preamble))
                if not secrets.compare_digest(received, self.preamble):
                    raise PolicyDenied("service_controller_nonce_required")
                async with self._admission_lock:
                    self.fence()
                    if self.attempted >= 8:
                        raise PolicyDenied("service_connection_count_exceeded")
                    wait = self.next_admission - time.monotonic()
                    if wait > 0:
                        await asyncio.sleep(wait)
                    self.fence()
                    self.next_admission = time.monotonic() + 0.1
                    self.store.consume_network_requests(self.policy)
                    self.attempted += 1
                    try:
                        upstream_reader, upstream = await asyncio.open_connection(
                            self.surface.network_address, int(self.surface.network_port), limit=8192
                        )
                    except OSError:
                        self.refused += 1
                        return
                    self.writers.add(upstream)
                    self.fence()
                    self.connected += 1
                transfers = [
                    asyncio.create_task(self._probe(reader, upstream)),
                    asyncio.create_task(self._response(upstream_reader, writer)),
                ]
                done, _pending = await asyncio.wait(transfers, return_when=asyncio.FIRST_COMPLETED)
                for finished in done:
                    finished.result()
        except (ValueError, RuntimeError, OSError, TimeoutError, asyncio.IncompleteReadError):
            self.denied += 1
        finally:
            for transfer in transfers:
                transfer.cancel()
            await asyncio.gather(*transfers, return_exceptions=True)
            streams = [stream for stream in (writer, upstream) if stream is not None]
            for stream in streams:
                stream.close()
            try:
                for stream in streams:
                    with contextlib.suppress(OSError, TimeoutError):
                        await asyncio.wait_for(stream.wait_closed(), 1)
            finally:
                for stream in streams:
                    self.writers.discard(stream)
                self.tasks.discard(task)

    async def _probe(
        self,
        reader: asyncio.StreamReader,
        upstream: asyncio.StreamWriter,
    ) -> None:
        received = bytearray()
        while chunk := await reader.read(len(HTTP_SERVICE_PROBE) - len(received) + 1):
            received.extend(chunk)
            self.fence()
            if not HTTP_SERVICE_PROBE.startswith(received):
                raise PolicyDenied("service_probe_payload_denied")
            if bytes(received) == HTTP_SERVICE_PROBE:
                self.store.consume_network_requests(self.policy)
                self.sent_probe_count += 1
                upstream.write(HTTP_SERVICE_PROBE)
                await upstream.drain()
                # One fixed read-only probe per connection, with no body,
                # arbitrary URL, extra header or pipelined request channel.
                if await reader.read(1):
                    raise PolicyDenied("service_extra_probe_denied")
                return
        if received:
            raise PolicyDenied("service_incomplete_probe_denied")

    async def _response(
        self,
        reader: asyncio.StreamReader,
        worker: asyncio.StreamWriter,
    ) -> None:
        total, prefix = 0, bytearray()
        digest = hashlib.sha256()
        try:
            while chunk := await reader.read(4096):
                self.fence()
                total += len(chunk)
                if total > 64 * 1024 or self.response_bytes + len(chunk) > 128 * 1024:
                    raise PolicyDenied("service_response_budget_exceeded")
                self.response_bytes += len(chunk)
                digest.update(chunk)
                if len(prefix) < 32:
                    prefix.extend(chunk[: 32 - len(prefix)])
                if prefix.startswith(b"SSH-"):
                    self.banner_types.add("ssh")
                elif prefix.startswith((b"HTTP/1.0 ", b"HTTP/1.1 ")):
                    self.banner_types.add("http")
                worker.write(chunk)
                await worker.drain()
        finally:
            if total:
                self.response_digests.append(digest.hexdigest())
