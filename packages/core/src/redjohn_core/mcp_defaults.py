"""Official MCP defaults with per-pentest credentials, browser state and source scope."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .models import MCPConnection, MCPTransport, Run
from .settings import Settings
from .tool_catalog import bundled_command, native_tools_root, tool_command

PLAYWRIGHT_PACKAGE = "@playwright/mcp@0.0.83"
FILESYSTEM_PACKAGE = "@modelcontextprotocol/server-filesystem@1.0.0"
GITHUB_MCP_URL = "https://api.githubcopilot.com/mcp/"
NVD_MCP_ID = "mcp_rj_default_nist_nvd"
NVD_MCP_NAME = "redjohn-nist-nvd"
VULN_INTEL_MCP_ID = "mcp_rj_default_vuln_intel"
VULN_INTEL_MCP_NAME = "redjohn-vuln-intel"
NODE_RUNTIME_DIRECTORIES = (Path("/opt/homebrew/bin"), Path("/usr/local/bin"))


def vuln_intel_command() -> tuple[list[str], dict[str, str]]:
    """Return command and environment for the built-in multi-source vulnerability intelligence MCP."""
    env = {"RJ_TOOLS_DIR": str(native_tools_root())}
    if getattr(sys, "frozen", False):
        return [sys.executable, "--vuln-intel-mcp"], env
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    return [sys.executable, "-m", "redjohn_core.vuln_intel_mcp"], env


def resolve_node_runtime() -> tuple[str, dict[str, str]]:
    """Resolve npm for GUI launches; adjust only the managed server environment."""
    npx = shutil.which("npx")
    if npx is None:
        npx = next(
            (
                str(root / "npx")
                for root in NODE_RUNTIME_DIRECTORIES
                if (root / "npx").is_file() and os.access(root / "npx", os.X_OK)
            ),
            None,
        )
    directories = [str(Path(npx).parent)] if npx else []
    directories.extend(str(root) for root in NODE_RUNTIME_DIRECTORIES if root.is_dir())
    current = os.environ.get("PATH", os.defpath)
    path = os.pathsep.join(dict.fromkeys([*directories, *current.split(os.pathsep)]))
    return npx or "npx", {"PATH": path}


FILESYSTEM_READ_TOOLS = {
    "read_file",
    "read_text_file",
    "read_multiple_files",
    "list_directory",
    "list_directory_with_sizes",
    "directory_tree",
    "search_files",
    "get_file_info",
    "list_allowed_directories",
}
BROWSER_TOOLS = {
    "browser_navigate",
    "browser_navigate_back",
    "browser_snapshot",
    "browser_click",
    "browser_hover",
    "browser_press_key",
    "browser_type",
    "browser_fill_form",
    "browser_select_option",
    "browser_wait_for",
    "browser_evaluate",
    "browser_console_messages",
    "browser_network_requests",
    "browser_take_screenshot",
    "browser_tabs",
    "browser_close",
    "browser_handle_dialog",
    "browser_resize",
}
GITHUB_READ_TOOLS = {"get_file_contents", "get_commit", "list_commits", "list_branches", "list_tags"}


def github_token() -> str | None:
    return os.environ.get("RJ_GITHUB_TOKEN") or os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN")


def default_templates(settings: Settings) -> list[MCPConnection]:
    npx, runtime_env = resolve_node_runtime()
    playwright = bundled_command("playwright") or [npx, "-y", PLAYWRIGHT_PACKAGE]
    filesystem = bundled_command("filesystem-mcp") or [npx, "-y", FILESYSTEM_PACKAGE]
    vi_cmd, vi_env = vuln_intel_command()
    templates = [
        MCPConnection(
            mcp_id="mcp_rj_default_playwright",
            name="redjohn-playwright",
            transport=MCPTransport.STDIO,
            env=runtime_env,
            command=[
                *playwright,
                "--headless",
                "--isolated",
                "--block-service-workers",
                "--no-webmcp",
            ],
            error="Starts automatically inside Web Application Assessment sessions.",
        ),
        MCPConnection(
            mcp_id="mcp_rj_default_filesystem",
            name="redjohn-filesystem",
            transport=MCPTransport.STDIO,
            command=[*filesystem, str(settings.work_root)],
            env=runtime_env,
            error="Starts automatically read-only inside Local Project Assessment sessions.",
        ),
        MCPConnection(
            mcp_id="mcp_rj_default_github",
            name="redjohn-github",
            transport=MCPTransport.STREAMABLE_HTTP,
            url=GITHUB_MCP_URL,
            error="Set RJ_GITHUB_TOKEN for authenticated repository MCP; public REST reads work without it.",
        ),
        MCPConnection(
            mcp_id=VULN_INTEL_MCP_ID,
            name=VULN_INTEL_MCP_NAME,
            transport=MCPTransport.STDIO,
            command=vi_cmd,
            env=vi_env,
            error="Starts automatically when an assessment needs CVE, OSV, KEV, EPSS or Nuclei intel.",
        ),
    ]
    if nvd := tool_command("nist-nvd"):
        templates.append(MCPConnection(
            mcp_id=NVD_MCP_ID, name=NVD_MCP_NAME,
            transport=MCPTransport.STDIO, command=nvd[0],
            error="Starts automatically when an assessment needs vulnerability intelligence.",
        ))
    return templates


def toolkit_connection(run: Run, settings: Settings) -> MCPConnection | None:
    kind = getattr(run.target_kind, "value", run.target_kind)
    if kind != "web_application":
        return None
    directory = (settings.work_root / run.run_id).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    env = {"RJ_TOOLS_DIR": str(native_tools_root())}
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--tool-mcp"]
    else:
        command = [sys.executable, "-m", "redjohn_core.native_tool_mcp"]
        env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    return MCPConnection(
        mcp_id=f"mcp_rj_{run.run_id}_native", name=f"rj-{run.run_id}-native",
        transport=MCPTransport.STDIO, env=env,
        command=[*command, "--workspace", str(directory), "--targets", json.dumps(run.scope.allowed_targets)],
    )


def browser_origins(run: Run) -> list[str]:
    origins = set()
    for target in run.scope.allowed_targets:
        value = target if "://" in target else f"https://{target}"
        parsed = urlsplit(value)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            origins.add(f"{parsed.scheme}://{parsed.netloc}")
            if "://" not in target:
                origins.add(f"http://{parsed.netloc}")
    return sorted(origins)


def write_browser_guard(directory: Path, origins: list[str]) -> Path:
    """Intercept requests before sending; follow redirects only inside session origins.

    Upstream --allowed-origins explicitly does not check redirects. This route
    checks every redirect before fetching it, blocks service workers and closes
    WebSockets. It is an application-level guard, not an OS network sandbox.
    """
    path = directory / "redjohn-browser-scope.ts"
    script = """export default async ({ page }) => {
  const allowed = new Set(ORIGINS);
  const context = page.context();
  await context.route('**/*', async route => {
    let destination = route.request().url();
    try {
      for (let hop = 0; hop < 6; hop++) {
        if (!allowed.has(new URL(destination).origin)) return await route.abort('blockedbyclient');
        const response = await route.fetch({ url: destination, maxRedirects: 0 });
        if ([301, 302, 303, 307, 308].includes(response.status())) {
          const location = response.headers()['location'];
          if (!location) return await route.fulfill({ response });
          destination = new URL(location, destination).href;
          await response.dispose();
          continue;
        }
        return await route.fulfill({ response });
      }
      await route.abort('blockedbyclient');
    } catch { await route.abort('blockedbyclient'); }
  });
  await context.routeWebSocket('**/*', socket => socket.close());
};
""".replace("ORIGINS", json.dumps(origins))
    path.write_text(script, encoding="utf-8")
    return path


def run_connection(run: Run, settings: Settings) -> MCPConnection | None:
    selected = getattr(run, "target_kind", None)
    kind = getattr(selected, "value", selected)
    directory = settings.work_root / run.run_id
    directory.mkdir(parents=True, exist_ok=True)
    directory = directory.resolve()
    suffix = {
        "local_project": "filesystem",
        "web_application": "playwright",
        "github_repository": "github",
    }.get(kind)
    if suffix is None:
        return None  # existing CLI/cloud runs retain their operator-managed MCPs
    name = f"rj-{run.run_id}-{suffix}"
    identifier = f"mcp_rj_{run.run_id}_{suffix}"
    npx, runtime_env = resolve_node_runtime()
    if suffix == "filesystem":
        target = str(Path(run.authorized_target).resolve())
        return MCPConnection(
            mcp_id=identifier,
            name=name,
            transport=MCPTransport.STDIO,
            command=[*(bundled_command("filesystem-mcp") or [npx, "-y", FILESYSTEM_PACKAGE]), target],
            env=runtime_env,
        )
    if suffix == "playwright":
        origins = browser_origins(run)
        guard = write_browser_guard(directory, origins)
        return MCPConnection(
            mcp_id=identifier,
            name=name,
            transport=MCPTransport.STDIO,
            env=runtime_env,
            command=[
                *(bundled_command("playwright") or [npx, "-y", PLAYWRIGHT_PACKAGE]),
                "--headless",
                "--isolated",
                "--block-service-workers",
                "--no-webmcp",
                "--allowed-origins",
                ";".join(origins),
                "--init-page",
                str(guard),
                "--output-dir",
                str(directory),
            ],
        )
    if not github_token():
        return None  # public source tools still work without authenticated MCP
    return MCPConnection(
        mcp_id=identifier, name=name, transport=MCPTransport.STREAMABLE_HTTP, url=GITHUB_MCP_URL
    )
