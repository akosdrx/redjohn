"""Bounded runtime probes; they make no assessment or external network requests."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .errors import not_found, unavailable
from .tool_catalog import TOOLS, tool_command

PROBES = {
    "nuclei": ["-version", "-duc"],
    "httpx": ["-version", "-duc"],
    "katana": ["-version", "-duc"],
    "subfinder": ["-version", "-duc"],
    "ffuf": ["-V"],
    "gau": ["--version"],
    "waybackurls": ["-h"],
    "dalfox": ["--help"],
    "arjun": ["--help"],
    "sqlmap": ["--version"],
    "zap": ["-version"],
    "playwright": ["--version"],
    "metasploit": ["--version"],
}


def check_native_tool(identifier: str) -> dict[str, Any]:
    tool = next((t for t in TOOLS if t.id == identifier), None)
    if tool is None:
        raise not_found("tool", identifier)
    command = tool_command(identifier)
    if not command or identifier not in PROBES:
        raise unavailable(f"{tool.name} is unavailable in this RedJohn build.")
    with tempfile.TemporaryDirectory(prefix="redjohn-tool-check-") as temporary:
        env = {k: os.environ[k] for k in ("PATH", "LANG", "SYSTEMROOT") if k in os.environ}
        env.update(HOME=temporary, XDG_CONFIG_HOME=temporary, XDG_CACHE_HOME=temporary, NO_COLOR="1")
        try:
            output = Path(temporary) / "probe.log"
            with output.open("wb") as stream:
                process = subprocess.Popen(
                    [*command[0], *PROBES[identifier]],
                    env=env,
                    cwd=temporary,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=stream,
                    start_new_session=True,
                )
                try:
                    process.wait(timeout=30)
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
            if process.returncode != 0:
                raise unavailable(f"{tool.name} runtime check failed (exit {process.returncode}).")
        except (OSError, subprocess.TimeoutExpired):
            raise unavailable(f"{tool.name} runtime did not respond to its check.") from None
    return {
        "state": "live",
        "detail": f"{tool.name} runtime verified ({command[1]}). MCP starts inside each web assessment.",
    }
