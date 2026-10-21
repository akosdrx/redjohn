"""Trusted sandbox-side scanner supervisor (standard library only).

Invoked through ``python3 -c`` so local and Docker sandbox backends share the
same bounded streaming, deadline and process-group cleanup contract. It is an
internal worker, never an agent-facing arbitrary-command tool.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from types import FrameType


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _terminate(process: subprocess.Popen[bytes]) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            continue
    # Descendants can outlive their parent; always kill the original group.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def main() -> None:  # noqa: PLR0912, PLR0915 - one owned process lifecycle
    config = json.loads(sys.argv[1])
    marker = Path(".redjohn-hunt") / (config["token"] + ".pid")
    child_marker = marker.with_suffix(".child")
    marker.parent.mkdir(mode=0o700, exist_ok=True)
    marker.write_text(str(os.getpid()), encoding="ascii")
    process = None
    output: dict[str, Any] = {
        "stdout": "",
        "stderr": "",
        "exit_code": None,
        "truncated": False,
        "timed_out": False,
        "cancelled": False,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    started = time.monotonic()
    cancelled = False

    def on_signal(_number: int, _frame: FrameType | None) -> None:
        nonlocal cancelled
        cancelled = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    try:
        if "max_file_bytes" in config:
            import resource  # noqa: PLC0415 - optional POSIX specialist limit

            if config["max_file_bytes"] != 1024 * 1024:
                raise ValueError("invalid worker file limit")  # noqa: TRY301
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        for filename, expected in config.get("digests", {}).items():
            path = Path(filename)
            if path.is_symlink() or _digest(path) != expected:
                raise ValueError("pinned binary/template digest mismatch")  # noqa: TRY301
        with tempfile.TemporaryDirectory(prefix=".redjohn-nuclei-", dir=".") as home:
            env = {
                key: value
                for key, value in os.environ.items()
                if key
                in {
                    "PATH",
                    "SYSTEMROOT",
                    "TMPDIR",
                    "SSL_CERT_FILE",
                    "SSL_CERT_DIR",
                }
            }
            env["HOME"] = str(Path(home).resolve())
            env["XDG_CONFIG_HOME"] = env["HOME"]
            env["XDG_DATA_HOME"] = env["HOME"]
            # Only the internal pinned-tool runner supplies this small schema.
            # Host credentials, proxy variables and arbitrary environment keys
            # remain excluded. Go's limit is soft; the controller still owns
            # process-tree memory admission and cancellation.
            tool_environment = config.get("tool_environment", {})
            if (
                not isinstance(tool_environment, dict)
                or set(tool_environment)
                - {
                    "GOMEMLIMIT",
                    "GOMAXPROCS",
                    "VULNX_API_URL",
                    "SSL_CERT_FILE",
                    "SSL_CERT_DIR",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "NO_PROXY",
                }
                or any(
                    not isinstance(value, str) or len(value) > 512
                    for value in tool_environment.values()
                )
                or tool_environment.get("GOMEMLIMIT", "128MiB") != "128MiB"
                or tool_environment.get("GOMAXPROCS", "1") != "1"
            ):
                raise ValueError("invalid pinned-tool environment")  # noqa: TRY301 - supervisor schema boundary
            if any(name in tool_environment for name in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")):
                from urllib.parse import urlsplit  # noqa: PLC0415 - standard library only

                proxy = tool_environment.get("HTTP_PROXY", "")
                parsed_proxy = urlsplit(proxy)
                if (
                    parsed_proxy.scheme != "http"
                    or parsed_proxy.hostname != "127.0.0.1"
                    or parsed_proxy.port is None
                    or parsed_proxy.username is not None
                    or parsed_proxy.path
                    or parsed_proxy.query
                    or parsed_proxy.fragment
                    or tool_environment.get("HTTPS_PROXY") != proxy
                    or tool_environment.get("NO_PROXY") != ""
                ):
                    raise ValueError("invalid pinned-tool proxy environment")  # noqa: TRY301
            for name, filename in (
                ("SSL_CERT_FILE", "proxy-ca.pem"),
                ("SSL_CERT_DIR", "empty-ca-directory"),
            ):
                if name in tool_environment and tool_environment[name] != str(
                    Path.cwd() / filename
                ):
                    raise ValueError("invalid pinned-tool certificate path")  # noqa: TRY301
            env.update(tool_environment)
            for provider in ("PUBLIC", "GITHUB", "GITLAB", "AWS", "AZURE"):
                env[f"DISABLE_NUCLEI_TEMPLATES_{provider}_DOWNLOAD"] = "true"
            argv = list(config["argv"])
            if config.get("nuclei"):
                empty_config = Path(home) / "config.yaml"
                empty_config.write_text("{}\n", encoding="utf-8")
                argv.extend(["-config", str(empty_config.resolve())])
            for index, filename in enumerate(config.get("snapshot_files", [])):
                original = Path(filename)
                # Work from a verified private snapshot: templates cannot change
                # between controller review and the scanner's actual read.
                with original.open("rb") as handle:
                    raw = handle.read(65537)
                if len(raw) > 65536:
                    raise ValueError("template grew beyond its byte limit")  # noqa: TRY301
                if hashlib.sha256(raw).hexdigest() != config["digests"][filename]:
                    raise ValueError("template changed during preparation")  # noqa: TRY301
                snapshot = Path(home) / (str(index) + ".yaml")
                snapshot.write_bytes(raw)
                argv = [str(snapshot.resolve()) if value == filename else value for value in argv]
            if cancelled:
                output["cancelled"] = True
                return
            process = subprocess.Popen(  # noqa: S603 - internal typed argv, never agent input
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                env=env,
                start_new_session=True,
            )
            buffers = {"stdout": bytearray(), "stderr": bytearray()}
            child_marker.write_text(str(process.pid), encoding="ascii")
            assert process.stdout is not None and process.stderr is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    if cancelled or time.monotonic() - started >= config["timeout"]:
                        output["cancelled"] = cancelled
                        output["timed_out"] = not cancelled
                        _terminate(process)
                        break
                    for key, _event in selector.select(timeout=0.05):
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        channel = key.data
                        output[channel + "_bytes"] += len(chunk)
                        room = config["max_output_bytes"] - len(buffers[channel])
                        buffers[channel].extend(chunk[: max(0, room)])
                        if len(chunk) > room:
                            output["truncated"] = True
                    if output["truncated"]:
                        _terminate(process)
                        break
            output["exit_code"] = process.wait(timeout=1)
            for channel, captured in buffers.items():
                output[channel] = captured.decode("utf-8", errors="replace")
    except FileNotFoundError:
        output["error"] = "tool_missing"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        output["error"] = "worker_error"
        output["message"] = str(error)[:300]
    finally:
        if process is not None:
            _terminate(process)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        child_marker.unlink(missing_ok=True)
        marker.unlink(missing_ok=True)
        output["duration_seconds"] = time.monotonic() - started
        sys.stdout.write(json.dumps(output, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
