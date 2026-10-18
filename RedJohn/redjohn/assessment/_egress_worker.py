"""Trusted stdlib-only worker entrypoint inside the Linux network namespace.

This file is executed by bubblewrap, never registered as an agent tool. The
namespace contains only loopback. Its one relay connects to a private Unix
socket whose host endpoint is pinned to the assessment's inspected proxy.
"""

from __future__ import annotations

import contextlib
import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import threading
from typing import cast


def main() -> int:  # noqa: PLR0915 - one bounded namespace relay lifecycle
    config = json.loads(sys.argv[1])
    pass_fds = tuple(config.get("pass_fds", ()))
    if pass_fds not in {(), (3, 4)}:
        raise ValueError("invalid_egress_worker_descriptors")
    for descriptor in pass_fds:
        os.fstat(descriptor)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", config["port"]))
    listener.listen(32)
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.settimeout(10)
    control.connect("/run/redjohn-egress.sock")
    control.sendall(b"A")
    if control.recv(1) != b"Y":
        raise RuntimeError("egress_namespace_attestation_rejected")
    control.settimeout(None)
    capacity = threading.BoundedSemaphore(32)
    connections: set[socket.socket] = set()
    connection_lock = threading.Lock()
    stopped = threading.Event()

    def relay(client: socket.socket) -> None:
        outside = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            outside.settimeout(10)
            outside.connect("/run/redjohn-egress.sock")
            outside.sendall(b"S")
            client.settimeout(None)
            outside.settimeout(None)
            with connection_lock:
                connections.update((client, outside))
            with selectors.DefaultSelector() as selector:
                selector.register(client, selectors.EVENT_READ, outside)
                selector.register(outside, selectors.EVENT_READ, client)
                while not stopped.is_set():
                    events = selector.select(timeout=1)
                    for key, _mask in events:
                        chunk = cast("socket.socket", key.fileobj).recv(65536)
                        if not chunk:
                            return
                        key.data.sendall(chunk)
        except (OSError, ValueError):
            pass
        finally:
            with connection_lock:
                connections.difference_update((client, outside))
            client.close()
            outside.close()
            capacity.release()

    def accept() -> None:
        while not stopped.is_set():
            try:
                client, _address = listener.accept()
            except OSError:
                return
            if not capacity.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=relay, args=(client,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    # This argv comes from the trusted host API, not from a tool/job payload.
    process = subprocess.Popen(  # noqa: S603 - trusted host-owned argv
        config["argv"], stdin=sys.stdin, close_fds=True, pass_fds=pass_fds
    )

    def terminate(_signum: int, _frame: object) -> None:
        with contextlib.suppress(ProcessLookupError):
            process.terminate()

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        return process.wait()
    finally:
        stopped.set()
        listener.close()
        control.close()
        with connection_lock:
            for connection in tuple(connections):
                with contextlib.suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)
                connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
