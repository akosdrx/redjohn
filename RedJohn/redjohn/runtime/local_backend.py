"""Docker-free local host sandbox backend for RedJohn."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import shlex
import shutil
import socket
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.manifest import Environment, Manifest
from agents.sandbox.sandboxes.unix_local import (
    UnixLocalSandboxClient,
    UnixLocalSandboxClientOptions,
    UnixLocalSandboxSession,
)
from agents.sandbox.types import ExposedPortEndpoint
from agents.sandbox.workspace_paths import SandboxPathGrant


if TYPE_CHECKING:
    from agents.sandbox.session.sandbox_session import SandboxSession


logger = logging.getLogger(__name__)

_WORKSPACE_VIRTUAL_ROOT = "/workspace"
_WORKSPACE_TOKEN_RE = re.compile(r"(?<![\w/.-])/workspace(?=/|[\s'\";&|)`]|$)")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _is_port_listening(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.15)
        return sock.connect_ex((host, port)) == 0


_KALI_READONLY_RESOURCE_PATHS = (
    "/usr/share/seclists",
    "/usr/share/wordlists",
    "/usr/share/nmap",
    "/usr/share/sqlmap",
    "/usr/share/wpscan",
    "/usr/share/metasploit-framework",
    "/usr/share/exploitdb",
    "/usr/share/webshells",
    "/usr/share/dirb",
    "/usr/share/dirbuster",
    "/usr/share/wfuzz",
    "/etc/os-release",
    "/etc/kali_version",
)


def _is_python_httpx_wrapper(binary_path: Path) -> bool:
    try:
        with binary_path.open("rb") as handle:
            header = handle.read(4096)
        return b"httpx._main" in header or b"from httpx import" in header
    except OSError:
        return False


def _ensure_kali_tool_shims(home: Path) -> Path | None:
    """Create lightweight binary aliases for Kali Linux package naming conventions."""
    shim_dir = home / ".redjohn" / "kali-shims"
    search_path = os.pathsep.join(
        [
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
            os.environ.get("PATH", ""),
        ]
    )
    pd_httpx = shutil.which("httpx-toolkit", path=search_path) or shutil.which(
        "pd-httpx", path=search_path
    )
    sys_httpx = shutil.which("httpx", path=search_path)
    needs_httpx_shim = bool(
        pd_httpx and (not sys_httpx or _is_python_httpx_wrapper(Path(sys_httpx)))
    )

    zaproxy = shutil.which("zaproxy", path=search_path)
    zap_sh = shutil.which("zap.sh", path=search_path)
    needs_zap_shim = bool(zaproxy and not zap_sh)

    chromium = shutil.which("chromium", path=search_path)
    chromium_browser = shutil.which("chromium-browser", path=search_path)
    needs_chromium_shim = bool(chromium and not chromium_browser)

    if not (needs_httpx_shim or needs_zap_shim or needs_chromium_shim):
        return shim_dir if shim_dir.is_dir() else None

    with contextlib.suppress(OSError):
        shim_dir.mkdir(parents=True, exist_ok=True)
        if needs_httpx_shim and pd_httpx:
            link = shim_dir / "httpx"
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(Path(pd_httpx).resolve())
        if needs_zap_shim and zaproxy:
            link = shim_dir / "zap.sh"
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(Path(zaproxy).resolve())
        if needs_chromium_shim and chromium:
            link = shim_dir / "chromium-browser"
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(Path(chromium).resolve())
    return shim_dir if shim_dir.is_dir() else None


def _find_host_chromium() -> str | None:
    search_path = os.pathsep.join(
        [
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/opt/homebrew/bin",
            os.environ.get("PATH", ""),
        ]
    )
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        found = shutil.which(name, path=search_path)
        if found:
            return str(Path(found).resolve())
    return None


def _apply_kali_environment_defaults(env: dict[str, str], workspace: str | None = None) -> None:
    """Populate standard Kali Linux wordlist, resource, and agent-browser paths on host."""
    if Path("/usr/share/seclists").is_dir():
        env.setdefault("SECLISTS_DIR", "/usr/share/seclists")
    if Path("/usr/share/wordlists").is_dir():
        env.setdefault("WORDLISTS_DIR", "/usr/share/wordlists")
    if Path("/usr/share/wordlists/rockyou.txt").is_file():
        env.setdefault("ROCKYOU_PATH", "/usr/share/wordlists/rockyou.txt")
    elif Path("/usr/share/wordlists/rockyou.txt.gz").is_file():
        env.setdefault("ROCKYOU_PATH", "/usr/share/wordlists/rockyou.txt.gz")
    if Path("/usr/share/nmap/scripts").is_dir():
        env.setdefault("NMAP_SCRIPTS_DIR", "/usr/share/nmap/scripts")
    if Path("/usr/share/exploitdb").is_dir():
        env.setdefault("EXPLOITDB_DIR", "/usr/share/exploitdb")

    chromium_bin = _find_host_chromium()
    if chromium_bin:
        env.setdefault("AGENT_BROWSER_EXECUTABLE_PATH", chromium_bin)
        env.setdefault("CHROME_PATH", chromium_bin)
        env.setdefault("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH", chromium_bin)
        env.setdefault("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")
    env.setdefault(
        "AGENT_BROWSER_USER_AGENT",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    )
    env.setdefault(
        "AGENT_BROWSER_ARGS",
        "--disable-dev-shm-usage,--no-first-run,--no-default-browser-check,--lang=en-US",
    )
    screenshot_base = workspace or "/workspace"
    env.setdefault("AGENT_BROWSER_SCREENSHOT_DIR", f"{screenshot_base}/.agent-browser-screenshots")
    env.setdefault("AGENT_BROWSER_IDLE_TIMEOUT_MS", "180000")


def _build_enriched_path(existing_path: str) -> str:
    home = Path.home()
    venv_bin = Path(sys.executable).resolve().parent
    shim_dir = _ensure_kali_tool_shims(home)
    extra_dirs = [
        *([shim_dir] if shim_dir is not None else []),
        venv_bin,
        home / ".npm-global" / "bin",
        Path("/opt/homebrew/bin"),
        Path("/opt/homebrew/sbin"),
        Path("/usr/local/sbin"),
        Path("/usr/local/bin"),
        Path("/usr/sbin"),
        Path("/usr/bin"),
        Path("/sbin"),
        Path("/bin"),
        Path("/usr/local/go/bin"),
        Path("/usr/share/metasploit-framework/tools/exploit"),
        home / ".local" / "bin",
        home / "go" / "bin",
        home / ".cargo" / "bin",
    ]
    entries: list[str] = []
    seen: set[str] = set()
    for candidate in [*extra_dirs, *(Path(p) for p in existing_path.split(os.pathsep) if p)]:
        entry = str(candidate)
        if entry not in seen:
            seen.add(entry)
            entries.append(entry)
    return os.pathsep.join(entries)


def _rewrite_workspace_tokens(text: str, workspace_root: Path) -> str:
    if _WORKSPACE_VIRTUAL_ROOT not in text:
        return text
    replacement = str(workspace_root)
    return _WORKSPACE_TOKEN_RE.sub(lambda _m: replacement, text)


class RedJohnLocalSandboxSession(UnixLocalSandboxSession):
    """Host-backed sandbox session that maps ``/workspace`` to the local workspace directory."""

    caido_port: int | None = None
    caido_process: asyncio.subprocess.Process | None = None

    def _remap_virtual_workspace(self, path: Path | str) -> Path | str:
        raw = path.as_posix() if isinstance(path, Path) else str(path)
        root = Path(self.state.manifest.root)
        if raw == _WORKSPACE_VIRTUAL_ROOT:
            return root
        prefix = f"{_WORKSPACE_VIRTUAL_ROOT}/"
        if raw.startswith(prefix):
            rel = raw[len(prefix) :].lstrip("/")
            return root / rel if rel else root
        return path

    def normalize_path(self, path: Path | str, *, for_write: bool = False) -> Path:
        remapped = self._remap_virtual_workspace(path)
        return super().normalize_path(remapped, for_write=for_write)

    @staticmethod
    def _workspace_relative_command_parts(
        command: Sequence[str | Path],
        workspace_root: Path,
    ) -> list[str]:
        rewritten_inputs: list[str | Path] = []
        for idx, part in enumerate(command):
            text = str(part)
            if idx > 0:
                text = _rewrite_workspace_tokens(text, workspace_root)
            rewritten_inputs.append(text)
        return UnixLocalSandboxSession._workspace_relative_command_parts(
            rewritten_inputs,
            workspace_root,
        )

    @staticmethod
    def _shell_workspace_process_context(
        *,
        command_parts: list[str],
        workspace_root: Path,
        cwd: str,
    ) -> tuple[str, list[str]]:
        if (
            len(command_parts) >= 3
            and command_parts[0] in ("sh", "bash", "zsh")
            and command_parts[1] in ("-c", "-lc")
        ):
            rewritten_cmd = _rewrite_workspace_tokens(command_parts[2], workspace_root)
            workspace_cd = f"cd {shlex.quote(str(workspace_root))} && {rewritten_cmd}"
            rewritten = [*command_parts]
            rewritten[2] = workspace_cd
            return str(workspace_root), rewritten
        return cwd, command_parts

    async def _resolved_exec_context(self) -> tuple[dict[str, str], str]:
        env, workspace = await super()._resolved_exec_context()
        # Keep the operator's real home out of agent shells. Home-relative
        # reads would otherwise reach ~/.ssh, cloud credentials and browser profiles.
        env["HOME"] = workspace
        env["WORKSPACE"] = workspace
        env["PATH"] = _build_enriched_path(env.get("PATH", os.environ.get("PATH", "")))
        _apply_kali_environment_defaults(env, workspace=workspace)

        proxy_url = env.get("http_proxy") or env.get("https_proxy") or ""
        if proxy_url.startswith("http://127.0.0.1:"):
            try:
                port = int(proxy_url.rsplit(":", 1)[1].split("/")[0])
            except (IndexError, ValueError):
                port = 0
            if port and not _is_port_listening(port):
                for key in ("http_proxy", "https_proxy", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                    env.pop(key, None)

        return env, workspace

    async def _resolve_exposed_port(self, port: int) -> ExposedPortEndpoint:
        resolved_port = self.caido_port if self.caido_port is not None else port
        return ExposedPortEndpoint(host="127.0.0.1", port=resolved_port, tls=False)


class RedJohnLocalSandboxClient(UnixLocalSandboxClient):
    """Local sandbox client that materializes bind mounts as workspace symlinks and grants."""

    redjohn_bind_mounts: list[dict[str, Any]] | None = None

    async def create(
        self,
        *,
        snapshot: Any = None,
        manifest: Manifest | None = None,
        options: UnixLocalSandboxClientOptions | None = None,
    ) -> SandboxSession:
        if sys.platform != "darwin" and os.environ.get("REDJOHN_ALLOW_UNCONFINED_LOCAL") != "1":
            raise RuntimeError(
                "The local runtime has no OS sandbox on this platform. "
                "Set REDJOHN_RUNTIME_BACKEND=docker, or set "
                "REDJOHN_ALLOW_UNCONFINED_LOCAL=1 to acknowledge host execution."
            )
        workspaces_base = Path.home() / ".redjohn" / "workspaces"
        workspaces_base.mkdir(parents=True, exist_ok=True)
        workspace_dir = Path(tempfile.mkdtemp(prefix="scan-", dir=str(workspaces_base))).resolve()

        bind_mounts = self.redjohn_bind_mounts or []
        grants: list[SandboxPathGrant] = list(manifest.extra_path_grants) if manifest else []
        seen_grant_paths: set[str] = {g.path for g in grants}

        for kali_path_str in _KALI_READONLY_RESOURCE_PATHS:
            kali_path = Path(kali_path_str)
            if kali_path.exists():
                resolved_kali = kali_path.resolve().as_posix()
                if resolved_kali not in seen_grant_paths:
                    seen_grant_paths.add(resolved_kali)
                    grants.append(SandboxPathGrant(path=resolved_kali, read_only=True))

        for spec in sorted(bind_mounts, key=lambda s: str(s.get("target", "")).count("/")):
            source_str = str(spec.get("source") or "")
            target_str = str(spec.get("target") or "")
            read_only = bool(spec.get("read_only", False))
            if not source_str or not target_str:
                continue
            source_path = Path(source_str).expanduser().resolve()
            if not source_path.exists():
                continue
            grant_key = source_path.as_posix()
            if grant_key not in seen_grant_paths:
                seen_grant_paths.add(grant_key)
                grants.append(SandboxPathGrant(path=grant_key, read_only=read_only))

            prefix = f"{_WORKSPACE_VIRTUAL_ROOT}/"
            if not target_str.startswith(prefix):
                continue
            rel_target = target_str[len(prefix) :].strip("/")
            if rel_target and "/" not in rel_target:
                # Top-level workspace subdirectory: symlink directly into workspace_dir
                dest = workspace_dir / rel_target
                if not dest.exists() and not dest.is_symlink():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.symlink_to(source_path)

        env_dict: dict[str, str] = {}
        if manifest is not None:
            env_dict.update(await manifest.environment.resolve())
        _apply_kali_environment_defaults(env_dict, workspace=str(workspace_dir))

        caido_port: int | None = None
        caido_process: asyncio.subprocess.Process | None = None
        caido_bin = shutil.which("caido-cli")
        if caido_bin is not None:
            caido_port = _find_free_port()
            caido_url = f"http://127.0.0.1:{caido_port}"
            try:
                caido_process = await asyncio.create_subprocess_exec(
                    caido_bin,
                    "--listen",
                    f"127.0.0.1:{caido_port}",
                    "--no-logging",
                    "--no-open",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    cwd=str(workspace_dir),
                    start_new_session=True,
                )
                env_dict["http_proxy"] = caido_url
                env_dict["https_proxy"] = caido_url
                env_dict["ALL_PROXY"] = caido_url
                env_dict["NO_PROXY"] = "localhost,127.0.0.1"
            except OSError:
                logger.debug("Failed to launch local caido-cli sidecar", exc_info=True)
                caido_port = None
                caido_process = None

        if caido_process is None:
            for key in ("http_proxy", "https_proxy", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                env_dict.pop(key, None)

        local_manifest = Manifest(
            root=str(workspace_dir),
            entries=dict(manifest.entries) if manifest else {},
            environment=Environment(value={**env_dict}),
            extra_path_grants=tuple(grants),
        )

        session = await super().create(
            snapshot=snapshot,
            manifest=local_manifest,
            options=options,
        )
        inner = session._inner
        if isinstance(inner, UnixLocalSandboxSession):
            inner.__class__ = RedJohnLocalSandboxSession
            inner.state.workspace_root_owned = True
            assert isinstance(inner, RedJohnLocalSandboxSession)
            inner.caido_port = caido_port
            inner.caido_process = caido_process
        return session

    async def delete(self, session: SandboxSession) -> SandboxSession:
        inner = session._inner
        if isinstance(inner, RedJohnLocalSandboxSession) and inner.caido_process is not None:
            proc = inner.caido_process
            inner.caido_process = None
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError, OSError):
                    proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except TimeoutError:
                    with contextlib.suppress(ProcessLookupError, OSError):
                        proc.kill()
        return await super().delete(session)


async def local_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any]:
    """Bring up a Docker-free local sandbox session on the host machine."""
    del image
    client = RedJohnLocalSandboxClient()
    client.redjohn_bind_mounts = bind_mounts or []
    options = UnixLocalSandboxClientOptions(exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session
