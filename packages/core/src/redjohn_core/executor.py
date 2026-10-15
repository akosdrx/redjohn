"""Fail-closed local execution and explicitly scoped HTTP reads.

Arbitrary argv runs offline, with only runtime files readable and its run
directory writable. Network inspection uses a separately validated HTTP tool,
which pins a checked address and revalidates every redirect.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import shutil
import socket
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from .errors import RJError
from .scope import target_covered, url_in_scope


def executor_capability() -> dict[str, str | bool]:
    if sys.platform == "linux":
        from .linux_sandbox import capability
        return capability()
    available = sys.platform == "darwin" and shutil.which("sandbox-exec") is not None
    return {"available": available, "backend": "sandbox-exec", "network": "denied",
            "detail": "offline sandbox; network access uses builtin:http_get" if available else
                      "offline executor unavailable"}


def sandbox_command(argv: list[str], workdir: Path) -> list[str]:
    workdir = workdir.resolve()
    executable = shutil.which(argv[0])
    if executable is None:
        raise RJError("executor_unavailable", "executable not found", status=503)
    executable_path = Path(executable).resolve()
    roots = [Path(p) for p in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/System",
                              "/Library/Apple") if Path(p).exists()]
    runtime = Path(getattr(sys, "_MEIPASS", sys.base_prefix)).resolve()
    if runtime != Path("/") and not any(runtime.is_relative_to(root) for root in roots):
        roots.append(runtime)
    command = [str(executable_path), *argv[1:]]
    if sys.platform == "darwin" and shutil.which("sandbox-exec"):
        reads = " ".join(f"(subpath {json.dumps(str(p))})" for p in [*roots, workdir])
        profile = (
            "(version 1)(deny default)(allow process-exec)(allow process-fork)"
            "(allow signal)(allow sysctl-read)(allow mach-lookup)"
            "(allow file-read-metadata)"
            f"(allow file-read* {reads} (literal {json.dumps(str(executable_path))})"
            ' (literal "/") (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom"))'
            f"(allow file-write* (subpath {json.dumps(str(workdir))}) (literal \"/dev/null\"))"
        )
        return ["/usr/bin/sandbox-exec", "-p", profile, *command]
    if sys.platform == "linux":
        from .linux_sandbox import capability
        if not capability()["available"]:
            raise RJError("executor_unavailable", str(capability()["detail"]), status=503)
        if getattr(sys, "frozen", False):
            return [sys.executable, "--sandbox-helper", str(workdir), "--", *command]
        helper = Path(__file__).with_name("linux_sandbox.py")
        return [sys.executable, "-I", "-S", str(helper), str(workdir), "--", *command]
    raise RJError("executor_unavailable", "no supported offline sandbox; execution refused", status=503)


async def resolve_addresses(host: str, port: int) -> list[str]:
    records = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({record[4][0] for record in records})


def validate_addresses(addresses: list[str], allowed: list[str], *, cloud: bool = False) -> None:
    if not addresses:
        raise RJError("scope_violation", "DNS returned no usable address", status=403)
    for address in addresses:
        ip = ipaddress.ip_address(address)
        # Domain authorization must never implicitly authorize local services.
        # Explicit IP/CIDR scopes may authorize local labs in local products.
        if not ip.is_global and (cloud or not target_covered(address, allowed)):
            raise RJError("scope_violation", "DNS resolved to a protected address", status=403)


async def scoped_http_get(url: str, allowed: list[str], *, output_cap: int,
                          timeout: float, cloud: bool = False) -> bytes:  # noqa: ASYNC109 — HTTP timeout policy
    for _ in range(6):
        parsed = urlsplit(url)
        # Path-aware: the initial URL and every redirect hop must stay within
        # the authorized URL path, not merely the same host.
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or not url_in_scope(url, allowed)):
            raise RJError("scope_violation", "HTTP destination is outside scope", status=403)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = await resolve_addresses(parsed.hostname, port)
        validate_addresses(addresses, allowed, cloud=cloud)
        # Connect to exactly the checked IP; DNS cannot change between check
        # and connect. Preserve HTTP Host and TLS server-name verification.
        pinned = httpx.URL(url).copy_with(host=addresses[0])
        authority = parsed.netloc
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=timeout) as client:
            async with client.stream("GET", pinned, headers={"Host": authority},
                                     extensions={"sni_hostname": parsed.hostname}) as response:
                if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
                    url = urljoin(url, response.headers["location"])
                    continue
                output = bytearray(f"HTTP {response.status_code}\n".encode())
                async for chunk in response.aiter_bytes():
                    output.extend(chunk[:max(0, output_cap - len(output))])
                    if len(output) >= output_cap:
                        break
                return bytes(output)
    raise RJError("scope_violation", "HTTP redirect limit exceeded", status=403)
