"""Native tool discovery shared by macOS, Debian, Ubuntu and Kali desktop builds."""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    commands: tuple[str, ...]
    source: str


TOOLS = (
    Tool("nuclei", "Nuclei", ("nuclei",), "https://github.com/projectdiscovery/nuclei"),
    Tool("zap", "OWASP ZAP", ("zaproxy", "zap.sh"), "https://www.zaproxy.org/"),
    Tool("playwright", "Playwright", (), "https://playwright.dev/"),
    Tool(
        "httpx", "HTTPX", ("httpx-toolkit", "pd-httpx", "httpx"), "https://github.com/projectdiscovery/httpx"
    ),
    Tool("ffuf", "ffuf", ("ffuf",), "https://github.com/ffuf/ffuf"),
    Tool("katana", "Katana", ("katana",), "https://github.com/projectdiscovery/katana"),
    Tool("arjun", "Arjun", ("arjun",), "https://github.com/s0md3v/Arjun"),
    Tool("dalfox", "Dalfox", ("dalfox",), "https://github.com/hahwul/dalfox"),
    Tool("sqlmap", "SQLMap", ("sqlmap",), "https://github.com/sqlmapproject/sqlmap"),
    Tool("subfinder", "Subfinder", ("subfinder",), "https://github.com/projectdiscovery/subfinder"),
    Tool("waybackurls", "Waybackurls", ("waybackurls",), "https://github.com/tomnomnom/waybackurls"),
    Tool("gau", "Gau", ("gau",), "https://github.com/lc/gau"),
    Tool("metasploit", "Metasploit", ("msfconsole",), "https://docs.metasploit.com/"),
)


def native_tools_root(settings: Any = None) -> Path:
    override = os.environ.get("RJ_TOOLS_DIR")
    if override:
        return Path(override).resolve()
    if settings is not None and getattr(settings, "profile_dir", None):
        profile_root = (Path(settings.profile_dir) / "tools").resolve()
        if profile_root.is_dir():
            return profile_root
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent.parent / "tools"
    return Path(__file__).resolve().parents[4] / "resources" / "tools"


def _candidate_tool_roots(settings: Any = None) -> list[Path]:
    override = os.environ.get("RJ_TOOLS_DIR")
    if override:
        return [Path(override).resolve()]
    roots: list[Path] = []
    if settings is not None and getattr(settings, "profile_dir", None):
        roots.append((Path(settings.profile_dir) / "tools").resolve())
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).parent.parent / "tools")
    else:
        roots.append(Path(__file__).resolve().parents[4] / "resources" / "tools")
    return list(dict.fromkeys(roots))


@lru_cache(maxsize=8)
def _read_index(path: str, modified: int) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def _tool_index_for_root(root: Path) -> dict[str, Any]:
    for name in ("tool-index.json", "build-info.json"):
        path = root / name
        try:
            return _read_index(str(path), path.stat().st_mtime_ns)
        except (OSError, ValueError, TypeError):
            continue
    return {}


def tool_index(settings: Any = None) -> dict[str, Any]:
    merged_tools: dict[str, Any] = {}
    base_doc: dict[str, Any] = {}
    for root in reversed(_candidate_tool_roots(settings)):
        doc = _tool_index_for_root(root)
        if doc:
            base_doc = {**base_doc, **doc}
            if isinstance(doc.get("tools"), dict):
                merged_tools.update(doc["tools"])
    if merged_tools:
        base_doc["tools"] = merged_tools
    return base_doc


def bundled_command(identifier: str, settings: Any = None) -> list[str] | None:
    for root in _candidate_tool_roots(settings):
        try:
            metadata = _tool_index_for_root(root)["tools"][identifier]
            command = [item.replace("{root}", str(root)) for item in metadata["command"]]
            if command and Path(command[0]).is_file() and os.access(command[0], os.X_OK):
                return command
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return None


def tool_command(identifier: str, settings: Any = None) -> tuple[list[str], str] | None:
    tool = next((item for item in TOOLS if item.id == identifier), None)
    if tool is None:
        command = (
            bundled_command(identifier, settings)
            if identifier in ("codex", "filesystem-mcp", "nist-nvd")
            else None
        )
        return (command, "bundled") if command else None
    if sys.platform != "linux" and (command := bundled_command(identifier, settings)):
        return command, "bundled"
    home = Path.home()
    directories = [
        "/opt/homebrew/bin",
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
        "/usr/local/go/bin",
        str(home / ".local" / "bin"),
        str(home / "go" / "bin"),
        *os.environ.get("PATH", os.defpath).split(os.pathsep),
    ]
    for name in tool.commands:
        binary = shutil.which(name, path=os.pathsep.join(dict.fromkeys(directories)))
        if binary:
            if identifier == "httpx":
                with Path(binary).open("rb") as source:
                    header = source.read(4096)
                if b"httpx._main" in header or b"from httpx import" in header:
                    # Python HTTPX CLI is a different application.
                    continue
            return [binary], "system"
    if command := bundled_command(identifier, settings):
        return command, "bundled"
    return None


def public_tools(settings: Any) -> dict[str, Any]:
    from .tool_provisioner import current_platform, load_manifest

    metadata = tool_index(settings).get("tools", {})
    manifest = load_manifest()
    platform = current_platform()
    result = []
    for tool in TOOLS:
        found = tool_command(tool.id, settings)
        result.append(
            {
                "id": tool.id,
                "name": tool.name,
                "source_url": tool.source,
                "available": found is not None,
                "origin": found[1] if found else None,
                "version": metadata.get(tool.id, {}).get("version")
                if found and found[1] == "bundled"
                else None,
                "downloadable": platform in manifest.get(tool.id, {}).get("artifacts", {}),
            }
        )
    return {"items": result, "platform": sys.platform}
