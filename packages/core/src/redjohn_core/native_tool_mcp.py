"""Session-owned native assessment tools, exposed through the official MCP SDK.

Scans are jobs: start returns immediately, status includes exit state and artifact
paths, and cancellation closes the entire native process group. No shell or
arbitrary CLI arguments are exposed. Each server has one immutable session scope.
"""

# ZAP's API and the owner PID expose no change events; poll their external state.
# ruff: noqa: ASYNC110

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import secrets
import signal
import subprocess
import time
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import httpx
try:
    from mcp.server import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[no-redef]
    from mcp.server.fastmcp.exceptions import ToolError  # type: ignore[no-redef]
from pydantic import Field

from .opsec_guard import (
    compute_response_fingerprint,
    parse_set_cookie_jar_updates,
    scan_prompt_injection,
    wrap_untrusted_target_data,
)
from .scope import url_in_scope
from .source_inspection import scan_local_ast_sinks
from .tool_catalog import native_tools_root, resolve_nuclei_templates_root, tool_command

Seconds = Annotated[int, Field(ge=10, le=900)]
Rate = Annotated[int, Field(ge=1, le=100)]
WEB_TOOLS = {
    "httpx_probe",
    "http_fingerprint_probe",
    "nuclei_scan",
    "nuclei_search_templates",
    "ffuf_scan",
    "katana_crawl",
    "arjun_scan",
    "dalfox_scan",
    "sqlmap_scan",
    "subfinder_search",
    "wayback_urls",
    "gau_urls",
    "zap_scan",
    "metasploit_search",
    "metasploit_info",
    "metasploit_assess",
    "nmap_scan",
    "wpscan_scan",
    "gobuster_scan",
    "nikto_scan",
    "ast_sink_search",
    "scan_status",
    "stop_scan",
    "tool_inventory",
}


@lru_cache(maxsize=16)
def cli_help(command: tuple[str, ...]) -> str:
    """Probe the selected CLI once per assessment; Kali may ship different flags."""
    try:
        result = subprocess.run([*command, "--help"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout + result.stderr
    except (OSError, subprocess.TimeoutExpired):
        pass
    raise ToolError("The selected tool could not report its supported options.")


class SessionTools:
    def __init__(self, workspace: Path, targets: list[str]) -> None:
        self.workspace = workspace.resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.targets = targets
        self.jobs: dict[str, dict[str, Any]] = {}
        self.tasks: set[asyncio.Task[Any]] = set()
        self.cookie_jars: dict[str, dict[str, str]] = {}
        self.zap: asyncio.subprocess.Process | None = None
        self.zap_port = 0
        self.zap_key = secrets.token_hex(24)
        self.zap_lock = asyncio.Lock()

    def url(self, value: str) -> str:
        parsed = urlsplit(value)
        wildcard_scope = not self.targets or "*" in self.targets
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or any(c.isspace() for c in value)
            or (not wildcard_scope and not url_in_scope(value, self.targets))
        ):
            raise ToolError("URL must be inside this pentest's authorized web target.")
        return value

    def domain(self, value: str) -> str:
        host = urlsplit(self.url(value)).hostname or ""
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
            raise ToolError("Choose a DNS hostname for passive reconnaissance.")
        return host

    def environment(self, directory: Path) -> dict[str, str]:
        home = directory / "home"
        home.mkdir(exist_ok=True)
        temporary = directory / "tmp"
        temporary.mkdir(exist_ok=True)
        return {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(home),
            "TMPDIR": str(temporary),
            "LANG": "en_US.UTF-8",
            "NO_COLOR": "1",
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
        }

    def new_job(self, tool: str, target: str) -> dict[str, Any]:
        identifier = f"{tool}-{secrets.token_hex(6)}"
        directory = self.workspace / "tools" / identifier
        directory.mkdir(parents=True, mode=0o700)
        job: dict[str, Any] = {
            "job_id": identifier,
            "tool": tool,
            "target": target,
            "state": "running",
            "started_at": time.time(),
            "exit_code": None,
            "directory": directory,
            "output": directory / "output.log",
            "result": None,
            "process": None,
        }
        self.jobs[identifier] = job
        return job

    def launch(
        self,
        tool: str,
        target: str,
        arguments: list[str],
        timeout: int,
        *,
        stdin: str | None = None,
        result: str | None = None,
        input_files: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        command = tool_command(tool)
        if not command:
            raise ToolError(f"{tool} is unavailable. Check Settings → Tools.")
        job = self.new_job(tool, target)
        for name, content in (input_files or {}).items():
            (job["directory"] / name).write_text(content)
        arguments = [item.replace("{job}", str(job["directory"])) for item in arguments]
        if result:
            job["result"] = job["directory"] / result
        task = asyncio.create_task(self.execute(job, [*command[0], *arguments], timeout, stdin))
        job["task"] = task
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return self.status(job["job_id"])

    @staticmethod
    async def terminate(process: asyncio.subprocess.Process) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            return
        try:
            await asyncio.wait_for(process.wait(), 3)
        except TimeoutError:
            pass
        # The group can still contain a descendant after its leader exits.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        await process.wait()

    async def spawn(self, command: list[str], **options: Any) -> asyncio.subprocess.Process:
        pending = asyncio.create_task(asyncio.create_subprocess_exec(*command, **options))
        try:
            return await asyncio.shield(pending)
        except asyncio.CancelledError:
            # Cancellation may arrive after fork, before asyncio returns the
            # child handle. Recover it and close the owned group in that gap.
            process = await pending
            await self.terminate(process)
            raise

    async def execute(
        self, job: dict[str, Any], command: list[str], duration_seconds: int, stdin: str | None
    ) -> None:
        try:
            process = await self.spawn(
                command,
                cwd=job["directory"],
                env=self.environment(job["directory"]),
                stdin=asyncio.subprocess.PIPE if stdin else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
            job["process"] = process
            if stdin and process.stdin:
                process.stdin.write(stdin.encode())
                await process.stdin.drain()
                process.stdin.close()
            async with asyncio.timeout(duration_seconds):
                total = 0
                with job["output"].open("wb") as output:
                    while chunk := await process.stdout.read(65536):  # type: ignore[union-attr]
                        total += len(chunk)
                        if total > 32 * 1024 * 1024:
                            raise ToolError("Tool output exceeded 32 MiB; narrow the scan.")
                        output.write(chunk)
                    await process.wait()
            job["exit_code"] = process.returncode
            job["state"] = "completed" if process.returncode == 0 else "failed"
        except TimeoutError:
            job.update(state="timed_out", detail="Time limit reached; results are partial.")
        except asyncio.CancelledError:
            job["state"] = "stopped"
        except Exception as error:
            job.update(state="failed", detail=str(error).replace(self.zap_key, "[redacted]")[:500])
        finally:
            if process := job.get("process"):
                await self.terminate(process)
                if job.get("exit_code") is None:
                    job["exit_code"] = process.returncode
            job["finished_at"] = time.time()

    def status(self, identifier: str) -> dict[str, Any]:
        job = self.jobs.get(identifier)
        if job is None:
            raise ToolError("Unknown job in this pentest session.")
        result = {
            key: job[key]
            for key in (
                "job_id",
                "tool",
                "target",
                "state",
                "exit_code",
                "started_at",
            )
        }
        result["detail"] = job.get("detail")
        output = job["result"] if job.get("result") and job["result"].is_file() else job["output"]
        artifacts = []
        for directory, children, names in os.walk(job["directory"]):
            children[:] = [name for name in children if name not in ("home", "tmp")]
            artifacts.extend(Path(directory) / name for name in names)
        result["artifacts"] = [str(p.relative_to(self.workspace)) for p in artifacts[:100]]
        if output.is_file() and job["state"] != "running":
            with output.open("rb") as stream:
                preview = stream.read(16385)
            decoded = preview[:16384].decode(errors="replace")
            pi_warnings = scan_prompt_injection(decoded)
            result.update(
                output=decoded,
                truncated=len(preview) > 16384,
                prompt_injection_warnings=pi_warnings,
            )
        return result

    async def shutdown(self) -> None:
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.zap:
            await self.terminate(self.zap)

    async def zap_request(self, component: str, action: str, **params: Any) -> dict[str, Any]:
        async with httpx.AsyncClient(trust_env=False, timeout=15) as client:
            response = await client.get(
                f"http://127.0.0.1:{self.zap_port}/JSON/{component}/{action}/",
                params=params, headers={"X-ZAP-API-Key": self.zap_key},
            )
            response.raise_for_status()
            data = response.json()
            if "code" in data:
                raise ToolError(f"ZAP: {data.get('message', data['code'])}")
            return data

    async def start_zap(self) -> None:
        async with self.zap_lock:
            if self.zap and self.zap.returncode is None:
                return
            import socket

            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                self.zap_port = reservation.getsockname()[1]
            command = tool_command("zap")
            if not command:
                raise ToolError("OWASP ZAP is unavailable. Check Settings → Tools.")
            directory = self.workspace / "tools" / "zap-service"
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            config = directory / "private.properties"
            config.write_text(
                f"api.key={self.zap_key}\napi.addrs.addr.name=127.0.0.1\napi.addrs.addr.regex=false\n"
            )
            config.chmod(0o600)
            with (directory / "zap.log").open("wb") as log:
                self.zap = await self.spawn(
                    [
                        *command[0],
                        "-daemon",
                        "-host",
                        "127.0.0.1",
                        "-port",
                        str(self.zap_port),
                        "-dir",
                        str(directory / "home"),
                        "-configfile",
                        str(config),
                        "-config",
                        "autoupdate.checkOnStart=false",
                        "-config",
                        "autoupdate.downloadNewRelease=false",
                    ],
                    cwd=directory,
                    env=self.environment(directory),
                    stdout=log,
                    stderr=log,
                    start_new_session=True,
                )
            try:
                async with asyncio.timeout(45):
                    while True:
                        try:
                            await self.zap_request("core", "view/version")
                            return
                        except httpx.HTTPError:
                            if self.zap.returncode is not None:
                                raise ToolError(
                                    "ZAP exited during startup. See the session's zap.log."
                                ) from None
                            await asyncio.sleep(0.5)
            except BaseException:
                await self.terminate(self.zap)
                self.zap = None
                raise

    async def zap_scan(self, job: dict[str, Any], active: bool, duration_seconds: int) -> None:
        try:
            async with asyncio.timeout(duration_seconds):
                await self.start_zap()
                context = job["job_id"]
                data = await self.zap_request("context", "action/newContext", contextName=context)
                context_id = data["contextId"]
                await self.zap_request(
                    "context",
                    "action/includeInContext",
                    contextName=context,
                    regex=re.escape(job["target"]) + ".*",
                )
                await self.zap_request(
                    "context", "action/setContextInScope", contextName=context, booleanInScope="true"
                )
                spider = await self.zap_request(
                    "spider", "action/scan", url=job["target"], contextName=context, subtreeOnly="true"
                )
                job["zap_spider"] = spider["scan"]
                while (
                    int((await self.zap_request("spider", "view/status", scanId=spider["scan"]))["status"])
                    < 100
                ):
                    await asyncio.sleep(1)
                if active:
                    scan = await self.zap_request(
                        "ascan",
                        "action/scan",
                        url=job["target"],
                        recurse="true",
                        inScopeOnly="true",
                        contextId=context_id,
                    )
                    job["zap_active"] = scan["scan"]
                    while (
                        int((await self.zap_request("ascan", "view/status", scanId=scan["scan"]))["status"])
                        < 100
                    ):
                        await asyncio.sleep(1)
                while int((await self.zap_request("pscan", "view/recordsToScan"))["recordsToScan"]):
                    await asyncio.sleep(0.5)
                alerts = await self.zap_request(
                    "core", "view/alerts", baseurl=job["target"], start=0, count=1000
                )
                job["output"].write_text(json.dumps(alerts, indent=2))
                job.update(state="completed", exit_code=0)
        except TimeoutError:
            job.update(state="timed_out", detail="ZAP time limit reached; results are partial.")
        except asyncio.CancelledError:
            job["state"] = "stopped"
        except Exception as error:
            job.update(state="failed", detail=str(error).replace(self.zap_key, "[redacted]")[:500])
        finally:
            for key, component in (("zap_spider", "spider"), ("zap_active", "ascan")):
                if key in job:
                    try:
                        await self.zap_request(component, "action/stop", scanId=job[key])
                    except Exception:
                        pass
            job["finished_at"] = time.time()


def create_server(runtime: SessionTools) -> MCPServer:
    @asynccontextmanager
    async def lifespan(_server: MCPServer):
        parent = os.getppid()

        async def watch_parent() -> None:
            while os.getppid() == parent:
                await asyncio.sleep(1)
            await runtime.shutdown()
            os._exit(0)

        watcher = asyncio.create_task(watch_parent())

        async def stop_process() -> None:
            await runtime.shutdown()
            os._exit(0)

        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, lambda: asyncio.create_task(stop_process()))
        try:
            yield {}
        finally:
            watcher.cancel()
            await runtime.shutdown()

    server = MCPServer("RedJohn native assessment tools", lifespan=lifespan)

    @server.tool()
    def tool_inventory() -> dict[str, Any]:
        """List installed native tools and the immutable scope of this session."""
        from .tool_catalog import public_tools

        return {**public_tools(None), "authorized_targets": runtime.targets}

    @server.tool()
    async def scan_status(
        job_id: str, wait_seconds: Annotated[int, Field(ge=0, le=30)] = 5
    ) -> dict[str, Any]:
        """Wait up to 30 seconds for a job and read its state/artifacts.

        completed/exit_code 0 means the process finished; inspect its output.
        stopped/timed_out is partial. Use wait_seconds=30 to avoid frequent polling.
        """
        runtime.status(job_id)
        task = runtime.jobs[job_id]["task"]
        if wait_seconds and not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), wait_seconds)
            except TimeoutError:
                pass
        return runtime.status(job_id)

    @server.tool()
    async def stop_scan(job_id: str) -> dict[str, Any]:
        """Stop a scan and its descendants; existing artifacts remain in this session."""
        runtime.status(job_id)
        task = runtime.jobs[job_id]["task"]
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return runtime.status(job_id)

    @server.tool()
    async def httpx_probe(url: str, timeout_seconds: Seconds = 30) -> dict[str, Any]:
        """Probe an authorized URL for status, title, technology and TLS metadata."""
        return runtime.launch(
            "httpx",
            runtime.url(url),
            ["-u", url, "-sc", "-title", "-td", "-server", "-json", "-silent", "-duc", "-no-stdin", "-nfs"],
            timeout_seconds,
        )

    @server.tool()
    async def http_fingerprint_probe(
        url: str,
        method: Literal["GET", "HEAD", "OPTIONS"] = "GET",
        session_profile: str = "anon",
        use_cookie_jar: bool = True,
        custom_headers: dict[str, str] | None = None,
        body_preview_chars: Annotated[int, Field(ge=0, le=8192)] = 1024,
        timeout_seconds: Annotated[int, Field(ge=3, le=60)] = 15,
    ) -> dict[str, Any]:
        """Fetch an authorized URL and return a Caido-style Response Fingerprint + Opaque Session Cookie Jar.

        Stores and reuses session cookies per `session_profile` (e.g. 'anon', 'user_a', 'user_b')
        in engine memory when `use_cookie_jar=True` while exposing ONLY `cookie_names` (never raw
        session token values) to the LLM context. Set `use_cookie_jar=False` for clean session-fixation
        or unauthenticated baseline probes. Wraps body previews in <untrusted_target_data> and scans
        for indirect prompt injection.
        """
        from .errors import RJError
        from .executor import resolve_addresses, validate_addresses

        checked_url = runtime.url(url)
        parsed = urlsplit(checked_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            addresses = await resolve_addresses(parsed.hostname or "", port)
            validate_addresses(addresses, runtime.targets)
        except (RJError, OSError) as exc:
            raise ToolError(f"Address validation failed: {exc}") from exc

        profile = re.sub(r"[^a-zA-Z0-9_-]", "_", session_profile.strip() or "anon")[:40]
        jar = runtime.cookie_jars.setdefault(profile, {})

        req_headers: dict[str, str] = {"User-Agent": "RedJohn-Assessment/1.0"}
        if custom_headers:
            for k, v in custom_headers.items():
                clean_k = str(k).strip()
                if clean_k and "\n" not in clean_k and "\r" not in clean_k and "\n" not in str(v):
                    req_headers[clean_k] = str(v).strip()

        if "host" not in {k.casefold() for k in req_headers} and parsed.netloc:
            req_headers["Host"] = parsed.netloc

        if use_cookie_jar and jar and "cookie" not in {k.casefold() for k in req_headers}:
            req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in sorted(jar.items()))

        pinned_url = httpx.URL(checked_url).copy_with(host=addresses[0])
        async with (
            httpx.AsyncClient(
                trust_env=False, follow_redirects=False, timeout=float(timeout_seconds)
            ) as client,
            client.stream(
                method,
                pinned_url,
                headers=req_headers,
                extensions={"sni_hostname": parsed.hostname} if parsed.hostname else None,
            ) as resp,
        ):
            set_cookie_list = resp.headers.get_list("set-cookie")
            if use_cookie_jar and set_cookie_list:
                jar.update(parse_set_cookie_jar_updates(set_cookie_list))
            body_bytes = bytearray()
            if method != "HEAD":
                async for chunk in resp.aiter_bytes():
                    keep = max(0, 65536 - len(body_bytes))
                    body_bytes.extend(chunk[:keep])
                    if len(body_bytes) >= 65536:
                        break
            body_text = body_bytes.decode("utf-8", errors="replace")
            status_code = resp.status_code
            resp_headers = resp.headers

        fp = compute_response_fingerprint(
            status_code=status_code,
            headers=resp_headers,
            body=body_text,
            set_cookie_headers=set_cookie_list,
        )
        preview_slice = body_text[:body_preview_chars] if body_preview_chars > 0 else ""
        isolated = wrap_untrusted_target_data(preview_slice, source=checked_url)
        header_warnings = scan_prompt_injection(
            "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
        )
        all_warnings = sorted(set(isolated["prompt_injection_warnings"]) | set(header_warnings))

        return {
            "url": checked_url,
            "method": method,
            "session_profile": profile,
            "use_cookie_jar": use_cookie_jar,
            "session_jar_cookie_names": sorted(jar.keys()) if use_cookie_jar else [],
            "fingerprint": fp,
            "body_preview": isolated["wrapped_content"] if preview_slice else "",
            "prompt_injection_detected": bool(all_warnings),
            "prompt_injection_warnings": all_warnings,
        }

    @server.tool()
    async def nuclei_scan(
        url: str,
        template: str = "",
        severity: str = "",
        tags: str = "",
        cve_id: str = "",
        rate: Rate = 10,
        timeout_seconds: Seconds = 180,
    ) -> dict[str, Any]:
        """Run official HTTP vulnerability templates via Nuclei.

        Template is a relative YAML path; empty selects the HTTP library (or Kali's default templates).
        Optionally filter by comma-separated tags (e.g. 'rce,ssti,cve') or a specific cve_id.
        Returns a job to poll via scan_status.
        """
        root = resolve_nuclei_templates_root()
        args = [
            "-u",
            runtime.url(url),
        ]
        if root.is_dir():
            selected = (root / (template or "http")).resolve()
            if (
                not selected.is_relative_to(root.resolve())
                or not selected.exists()
                or (template and selected.suffix not in (".yaml", ".yml"))
            ):
                raise ToolError("Choose a YAML template inside the Nuclei template library.")
            args += ["-t", str(selected)]
        elif template:
            if ".." in template or not re.fullmatch(r"[a-zA-Z0-9_./-]+", template):
                raise ToolError("Invalid Nuclei template path.")
            args += ["-t", template]
        args += [
            "-j",
            "-o",
            "{job}/nuclei.jsonl",
            "-silent",
            "-duc",
            "-ni",
            "-dr",
            "-no-stdin",
            "-pt",
            "http",
            "-rl",
            str(rate),
        ]
        if severity:
            if any(s not in {"info", "low", "medium", "high", "critical"} for s in severity.split(",")):
                raise ToolError("Use comma-separated Nuclei severities.")
            args += ["-severity", severity]
        if tags:
            if not re.fullmatch(r"[a-zA-Z0-9_,-]{1,120}", tags):
                raise ToolError("Use comma-separated alphanumeric Nuclei tags.")
            args += ["-tags", tags]
        if cve_id:
            normalized_cve = cve_id.strip().upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", normalized_cve):
                raise ToolError("Use a valid CVE identifier (e.g. CVE-2024-3400).")
            args += ["-id", normalized_cve]
        return runtime.launch("nuclei", url, args, timeout_seconds, result="nuclei.jsonl")

    @server.tool()
    def nuclei_search_templates(
        query: str = "",
        cve_id: str = "",
        tags: str = "",
        severity: str = "",
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
    ) -> dict[str, Any]:
        """Search local nuclei-templates by CVE ID, product keyword, tags, or severity."""
        from .vuln_intel_mcp import search_nuclei_directory

        root = resolve_nuclei_templates_root()
        matches = search_nuclei_directory(
            root, query=query, cve_id=cve_id, tags=tags, severity=severity, limit=limit
        )
        return {
            "templates_root": str(root),
            "available": root.is_dir(),
            "count": len(matches),
            "templates": matches,
        }

    @server.tool()
    async def ffuf_scan(
        url: str,
        words: Annotated[list[str], Field(min_length=1, max_length=10000)],
        rate: Rate = 10,
        timeout_seconds: Seconds = 180,
    ) -> dict[str, Any]:
        """Fuzz an authorized URL using FUZZ and an inline word list. Does not follow redirects."""
        runtime.url(url.replace("FUZZ", "redjohn-scope-check"))
        if "FUZZ" not in url or any(not w or len(w) > 200 or "\n" in w or "\r" in w for w in words):
            raise ToolError("Include FUZZ in the URL and use one nonempty word per entry.")
        for word in words:
            runtime.url(url.replace("FUZZ", word))
        return runtime.launch(
            "ffuf",
            url,
            [
                "-u",
                url,
                "-w",
                "{job}/words.txt",
                "-rate",
                str(rate),
                "-noninteractive",
                "-o",
                "{job}/ffuf.json",
                "-of",
                "json",
                "-s",
            ],
            timeout_seconds,
            result="ffuf.json",
            input_files={"words.txt": "\n".join(words) + "\n"},
        )

    @server.tool()
    async def katana_crawl(
        url: str,
        depth: Annotated[int, Field(ge=1, le=10)] = 3,
        rate: Rate = 10,
        timeout_seconds: Seconds = 180,
    ) -> dict[str, Any]:
        """Crawl links within the authorized URL prefix, keeping redirects disabled."""
        return runtime.launch(
            "katana",
            runtime.url(url),
            [
                "-u",
                url,
                "-d",
                str(depth),
                "-cs",
                "^" + re.escape(url),
                "-dr",
                "-rl",
                str(rate),
                "-j",
                "-o",
                "{job}/katana.jsonl",
                "-silent",
                "-duc",
            ],
            timeout_seconds,
            result="katana.jsonl",
        )

    @server.tool()
    async def arjun_scan(
        url: str,
        method: Literal["GET", "POST", "JSON", "XML"] = "GET",
        parameters: Annotated[list[str] | None, Field(max_length=5000)] = None,
        timeout_seconds: Seconds = 180,
    ) -> dict[str, Any]:
        """Discover HTTP parameters on the authorized endpoint."""
        inputs = {}
        found = tool_command("arjun")
        if not found:
            raise ToolError("Arjun is unavailable.")
        help_text = await asyncio.to_thread(cli_help, tuple(found[0]))
        output_flag = "-oJ" if "-oJ" in help_text else "-o"
        arguments = ["-u", url, "-m", method, output_flag, "{job}/arjun.json", "--disable-redirects"]
        if parameters:
            if any(not re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", parameter) for parameter in parameters):
                raise ToolError("Use simple HTTP parameter names.")
            inputs["parameters.txt"] = "\n".join(parameters) + "\n"
            arguments += ["-w", "{job}/parameters.txt"]
        return runtime.launch(
            "arjun", runtime.url(url), arguments, timeout_seconds, result="arjun.json", input_files=inputs
        )

    @server.tool()
    async def dalfox_scan(
        url: str, payload_limit: Annotated[int, Field(ge=1, le=3000)] = 3000,
        discover_parameters: bool = True, timeout_seconds: Seconds = 180
    ) -> dict[str, Any]:
        """Test the authorized endpoint for reflected XSS; results are session artifacts."""
        found = tool_command("dalfox")
        if not found:
            raise ToolError("Dalfox is unavailable.")
        help_text = await asyncio.to_thread(cli_help, tuple(found[0]))
        if "  scan " in help_text:
            arguments = [
                "scan",
                url,
                "--no-color",
                "--silence",
                "--format",
                "json",
                "--output",
                "{job}/dalfox.json",
                "--rate-limit",
                "10",
                "--max-payloads-per-param",
                str(payload_limit),
            ]
            if not discover_parameters:
                arguments.append("--skip-discovery")
        else:
            arguments = [
                "url",
                url,
                "--no-color",
                "--silence",
                "--format",
                "json",
                "--output",
                "{job}/dalfox.json",
            ]
            if not discover_parameters and "--skip-mining-all" in help_text:
                arguments.append("--skip-mining-all")
        return runtime.launch("dalfox", runtime.url(url), arguments, timeout_seconds, result="dalfox.json")

    @server.tool()
    async def sqlmap_scan(
        url: str,
        level: Annotated[int, Field(ge=1, le=5)] = 1,
        risk: Annotated[int, Field(ge=1, le=3)] = 1,
        timeout_seconds: Seconds = 180,
    ) -> dict[str, Any]:
        """Assess SQL injection at the authorized URL; does not dump data or open an OS shell."""
        return runtime.launch(
            "sqlmap",
            runtime.url(url),
            [
                "-u",
                url,
                "--batch",
                "--disable-coloring",
                "--ignore-redirects",
                "--level",
                str(level),
                "--risk",
                str(risk),
                "--output-dir",
                "{job}/sqlmap",
            ],
            timeout_seconds,
        )

    @server.tool()
    async def subfinder_search(url: str, timeout_seconds: Seconds = 120) -> dict[str, Any]:
        """Passive subdomain discovery for the authorized hostname. Results do not expand scope."""
        return runtime.launch(
            "subfinder",
            runtime.url(url),
            ["-d", runtime.domain(url), "-oJ", "-silent", "-duc"],
            timeout_seconds,
        )

    @server.tool()
    async def wayback_urls(url: str, timeout_seconds: Seconds = 120) -> dict[str, Any]:
        """Read archived URLs for the authorized hostname. Results do not expand scope."""
        return runtime.launch(
            "waybackurls", runtime.url(url), [], timeout_seconds, stdin=runtime.domain(url) + "\n"
        )

    @server.tool()
    async def gau_urls(url: str, timeout_seconds: Seconds = 120) -> dict[str, Any]:
        """Read public URL indexes for the authorized hostname. Results do not expand scope."""
        return runtime.launch(
            "gau", runtime.url(url), ["--threads", "2", runtime.domain(url)], timeout_seconds
        )

    @server.tool()
    async def zap_scan(url: str, active: bool = False, timeout_seconds: Seconds = 180) -> dict[str, Any]:
        """Spider and passively assess the scoped endpoint using OWASP ZAP.

        active=true adds its active scanner. Poll the job for alerts.
        """
        job = runtime.new_job("zap", runtime.url(url))
        task = asyncio.create_task(runtime.zap_scan(job, active, timeout_seconds))
        job["task"] = task
        runtime.tasks.add(task)
        task.add_done_callback(runtime.tasks.discard)
        return runtime.status(job["job_id"])

    @server.tool()
    async def metasploit_search(query: str, timeout_seconds: Seconds = 60) -> dict[str, Any]:
        """Search the bundled Metasploit module database without making target requests."""
        if not re.fullmatch(r"[a-zA-Z0-9_/ .:-]{1,160}", query):
            raise ToolError("Use module names, CVE identifiers or Metasploit search filters.")
        return runtime.launch(
            "metasploit", "module database", ["-q", "-n", "-x", f"search {query}; exit -y"], timeout_seconds
        )

    @server.tool()
    async def metasploit_info(module: str, timeout_seconds: Seconds = 60) -> dict[str, Any]:
        """Read module options and references from Metasploit."""
        if not re.fullmatch(r"[a-zA-Z0-9_/-]{1,200}", module):
            raise ToolError("Use a Metasploit module path.")
        return runtime.launch(
            "metasploit", "module database", ["-q", "-n", "-x", f"info {module}; exit -y"], timeout_seconds
        )

    @server.tool()
    async def metasploit_assess(
        url: str, module: str, action: Literal["check", "scan"] = "check", timeout_seconds: Seconds = 120
    ) -> dict[str, Any]:
        """Run a vulnerability check or web auxiliary scanner on the authorized endpoint.

        Does not launch exploit payloads.
        """
        parsed = urlsplit(runtime.url(url))
        if not re.fullmatch(r"(?:auxiliary/scanner/http|exploit)/[a-zA-Z0-9_/-]+", module):
            raise ToolError("Choose a web auxiliary scanner or an exploit module supporting check.")
        if action == "scan" and not module.startswith("auxiliary/scanner/http/"):
            raise ToolError("scan is available only for web auxiliary scanners.")
        path = parsed.path or "/"
        if not re.fullmatch(r"[a-zA-Z0-9_/.%~-]+", path):
            raise ToolError("Metasploit TARGETURI must use a simple URL path.")
        host = parsed.hostname or ""
        if not re.fullmatch(r"[a-zA-Z0-9.:-]+", host):
            raise ToolError("Invalid target hostname.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ssl = "true" if parsed.scheme == "https" else "false"
        operation = "run" if action == "scan" else "check"
        script = (
            f"use {module}; set RHOSTS {host}; set RPORT {port}; set SSL {ssl}; "
            f"set TARGETURI {path}; {operation}; exit -y"
        )
        return runtime.launch("metasploit", url, ["-q", "-n", "-x", script], timeout_seconds)

    @server.tool()
    async def nmap_scan(
        target: str,
        ports: str = "top-100",
        service_version: bool = True,
        timeout_seconds: Seconds = 180,
    ) -> dict[str, Any]:
        """Run a TCP connect / service version scan with Nmap against an authorized target."""
        host = target.strip()
        if "://" in host:
            host = urlsplit(runtime.url(host)).hostname or ""
        if not re.fullmatch(r"[a-zA-Z0-9.:-]+", host):
            raise ToolError("Provide a valid hostname or IP address for nmap_scan.")
        arguments = ["-sT", "-Pn", "-oX", "{job}/nmap.xml"]
        if service_version:
            arguments.append("-sV")
        if ports == "top-100":
            arguments += ["--top-ports", "100"]
        elif ports == "top-1000":
            arguments += ["--top-ports", "1000"]
        elif re.fullmatch(r"[0-9,-]{1,64}", ports):
            arguments += ["-p", ports]
        else:
            raise ToolError("Use 'top-100', 'top-1000', or a comma/range port list like '80,443,8000-8080'.")
        arguments.append(host)
        return runtime.launch("nmap", host, arguments, timeout_seconds, result="nmap.xml")

    @server.tool()
    async def wpscan_scan(
        url: str,
        enumerate_targets: Literal["vp", "ap", "vt", "tt", "cb", "dbe", "u"] = "vp",
        timeout_seconds: Seconds = 180,
    ) -> dict[str, Any]:
        """Assess a WordPress installation using WPScan (JSON output)."""
        arguments = [
            "--url",
            runtime.url(url),
            "--no-banner",
            "--random-user-agent",
            "--enumerate",
            enumerate_targets,
            "--format",
            "json",
            "--output",
            "{job}/wpscan.json",
        ]
        return runtime.launch("wpscan", runtime.url(url), arguments, timeout_seconds, result="wpscan.json")

    @server.tool()
    async def gobuster_scan(
        url: str,
        words: Annotated[list[str], Field(min_length=1, max_length=2000)],
        timeout_seconds: Seconds = 180,
    ) -> dict[str, Any]:
        """Run Gobuster directory enumeration against an authorized URL using the supplied wordlist."""
        if any(not word or any(c in word for c in "\r\n\0") or len(word) > 120 for word in words):
            raise ToolError("Wordlist entries must be single-line paths up to 120 characters.")
        arguments = [
            "dir",
            "-u",
            runtime.url(url),
            "-w",
            "{job}/wordlist.txt",
            "-q",
            "--no-color",
            "-o",
            "{job}/gobuster.txt",
        ]
        return runtime.launch(
            "gobuster",
            runtime.url(url),
            arguments,
            timeout_seconds,
            result="gobuster.txt",
            input_files={"wordlist.txt": "\n".join(words) + "\n"},
        )

    @server.tool()
    async def nikto_scan(
        url: str,
        timeout_seconds: Seconds = 180,
    ) -> dict[str, Any]:
        """Run a Nikto web server configuration & vulnerability check against the authorized URL."""
        arguments = [
            "-h",
            runtime.url(url),
            "-maxtime",
            f"{timeout_seconds}s",
            "-Format",
            "json",
            "-o",
            "{job}/nikto.json",
        ]
        return runtime.launch("nikto", runtime.url(url), arguments, timeout_seconds, result="nikto.json")

    @server.tool()
    async def ast_sink_search(
        path: str = ".",
        category: Literal["all", "rce", "deserialization", "sqli", "ssrf", "path_traversal", "xss"] = "all",
        limit: Annotated[int, Field(ge=1, le=250)] = 100,
    ) -> dict[str, Any]:
        """Scan local source files for AST-level dangerous sinks (Python AST + polyglot JS/TS/PHP/Go/Java/Ruby)."""
        try:
            return await asyncio.to_thread(scan_local_ast_sinks, path, category, limit)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    return server


def main(arguments: list[str] | None = None) -> int:
    default_workspace = Path(
        os.environ.get("STRIX_MCP_WORKSPACE") or (Path.home() / ".strix" / "mcp-workspace")
    )
    default_targets = os.environ.get("STRIX_MCP_TARGETS", '["*"]')
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, default=default_workspace)
    parser.add_argument("--targets", default=default_targets, help="JSON array of authorized web targets")
    args = parser.parse_args(arguments)
    targets = json.loads(args.targets)
    if not isinstance(targets, list) or not targets or not all(isinstance(t, str) and t for t in targets):
        parser.error("targets must be a nonempty string array")
    create_server(SessionTools(args.workspace, targets)).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
