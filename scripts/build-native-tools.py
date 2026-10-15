"""Build the pinned native toolbox. Downloads occur at build time, never at app launch."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native_bundle", BASE / "scripts/native-bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def run(command: list[str], **options) -> None:
    print("[native-tools] " + " ".join(command), flush=True)
    subprocess.run(command, check=True, **options)


def wrapper(root: Path, name: str, body: str) -> None:
    path = root / "bin" / name
    path.write_text('#!/bin/sh\nset -eu\nrj_tools_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n' + body + "\n")
    path.chmod(0o755)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=BASE / "resources/tools")
    parser.add_argument("--skip-metasploit", action="store_true", help="Development only; packaging rejects an incomplete toolbox")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    (root / "bin").mkdir(exist_ok=True)
    (root / "licenses").mkdir(exist_ok=True)
    versions = json.loads((BASE / "packaging/tool-versions.json").read_text())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64"}.get(platform.machine())
    target = f"{sys.platform}-{arch}"
    cache = BASE / "resources/.tool-downloads"
    manifest = root / "build-info.json"
    prior = json.loads(manifest.read_text()) if manifest.is_file() else {}
    stamp = {
        "platform": sys.platform, "arch": arch,
        # Record whether Metasploit was included, or a cached --skip-metasploit
        # build would be reused for a later full build and silently ship no MSF.
        "metasploit_included": not args.skip_metasploit,
        "versions_sha256": bundle.sha256(BASE / "packaging/tool-versions.json"),
        "builder_sha256": bundle.sha256(Path(__file__)),
        "python_helper_sha256": bundle.sha256(BASE / "scripts/tool-python.py"),
        "inputs_sha256": {name: bundle.sha256(BASE / name) for name in (
            "scripts/native-bundle.py", "scripts/build-metasploit.py", "scripts/nvd-rate-limit.inc",
            "packaging/tool-node-package.json", "packaging/tool-python-requirements.txt",
            # The lockfile is what `npm ci` actually resolves; omitting it meant a
            # bumped transitive dep (e.g. a patched MCP SDK) reused the stale cache.
            "packaging/tool-node-package-lock.json",
        ) if (BASE / name).is_file()},
    }
    if not args.force and all(prior.get(k) == value for k, value in stamp.items()) and prior.get("files"):
        if bundle.digest_tree(root) == prior["files"]:
            print("[native-tools] complete cached toolbox verified", flush=True)
            return 0
    tools = {}
    for identifier in ("nuclei", "httpx", "ffuf", "katana", "subfinder", "dalfox", "gau", "waybackurls"):
        release = versions[identifier]
        source = release["artifacts"].get(target)
        destination = root / "bin" / identifier
        if source:
            archive = bundle.download(source, cache)
            with tempfile.TemporaryDirectory(prefix=".tools-build-", dir=root.parent) as temporary:
                bundle.extract(archive, Path(temporary))
                candidates = [p for p in Path(temporary).rglob(identifier) if p.is_file()]
                if len(candidates) != 1:
                    raise ValueError(f"Expected one {identifier} binary")
                shutil.copy2(candidates[0], destination)
                for license_file in Path(temporary).rglob("LICENSE*"):
                    shutil.copy2(license_file, root / "licenses" / f"{identifier}-{license_file.name}")
            metadata = {"archive_url": source["url"], "archive_sha256": source["sha256"]}
        else:
            if identifier != "waybackurls":
                raise ValueError(f"No reviewed artifact for {identifier}/{target}")
            environment = {**os.environ, "GOBIN": str(root / "bin"), "GOPATH": str(cache / "go")}
            run(["go", "install", f"github.com/tomnomnom/waybackurls@{release['version']}"], env=environment)
            metadata = {"source": "github.com/tomnomnom/waybackurls", "go": subprocess.check_output(["go", "version"], text=True).strip()}
        destination.chmod(0o755)
        tools[identifier] = {"version": release["version"], "command": [f"{{root}}/bin/{identifier}"], "binary_sha256": bundle.sha256(destination), **metadata}

    runtime = root / "runtime"
    runtime.mkdir(exist_ok=True)
    for identifier in ("node", "java"):
        source = versions[identifier]["artifacts"][target]
        archive = bundle.download(source, cache)
        destination = runtime / identifier
        if destination.exists():
            shutil.rmtree(destination)
        with tempfile.TemporaryDirectory(prefix=".tools-build-", dir=root.parent) as temporary:
            bundle.extract(archive, Path(temporary))
            children = list(Path(temporary).iterdir())
            if len(children) != 1:
                raise ValueError(f"Unexpected {identifier} runtime archive")
            shutil.move(str(children[0]), destination)
        if identifier == "java" and sys.platform == "darwin":
            contents = destination / "Contents/Home"
            with tempfile.TemporaryDirectory(dir=root.parent) as temporary:
                shutil.move(str(contents), Path(temporary) / "java")
                shutil.rmtree(destination)
                shutil.move(str(Path(temporary) / "java"), destination)
    node = runtime / "node/bin/node"
    npm = runtime / "node/lib/node_modules/npm/bin/npm-cli.js"
    node_env = {**os.environ, "PATH": str(node.parent) + os.pathsep + os.environ.get("PATH", os.defpath)}
    packages = root / "node"
    packages.mkdir(exist_ok=True)
    shutil.copy2(BASE / "packaging/tool-node-package.json", packages / "package.json")
    lock = BASE / "packaging/tool-node-package-lock.json"
    if not lock.is_file():
        run([str(node), str(npm), "install", "--package-lock-only", "--ignore-scripts"], cwd=packages, env=node_env)
        shutil.copy2(packages / "package-lock.json", lock)
    else:
        shutil.copy2(lock, packages / "package-lock.json")
    run([str(node), str(npm), "ci", "--ignore-scripts", "--omit=dev"], cwd=packages, env=node_env)
    browsers = root / "browsers"
    browser_env = {**node_env, "PLAYWRIGHT_BROWSERS_PATH": str(browsers)}
    playwright = packages / "node_modules/playwright/cli.js"
    run([str(node), str(playwright), "install", "--no-shell", "chromium"], env=browser_env)
    for shell in browsers.glob("chromium_headless_shell-*"):
        shutil.rmtree(shell)
    browser_metadata = json.loads((packages / "node_modules/playwright-core/browsers.json").read_text())
    chrome = next((p for p in browsers.rglob("*") if p.is_file() and p.name in ("Chromium", "chrome", "Google Chrome for Testing") and os.access(p, os.X_OK)), None)
    if chrome is None:
        raise SystemExit("No bundled Chromium executable found under browsers/ (Playwright layout changed?)")
    chrome_rel = str(chrome.relative_to(root))
    # This path is interpolated into a generated /bin/sh wrapper inside double
    # quotes; reject anything that could break out of that context rather than
    # trust an archive-derived filename.
    if any(ch in chrome_rel for ch in '"$`\\\n'):
        raise SystemExit(f"Unsafe characters in bundled browser path: {chrome_rel!r}")
    tools["playwright"] = {"version": "0.0.83", "command": ["{root}/bin/playwright-mcp"], "browser": chrome_rel, "browser_revisions": browser_metadata}
    wrapper(root, "playwright-mcp", 'export PLAYWRIGHT_BROWSERS_PATH="$rj_tools_root/browsers"\nexec "$rj_tools_root/runtime/node/bin/node" "$rj_tools_root/node/node_modules/@playwright/mcp/cli.js" --executable-path "$rj_tools_root/' + chrome_rel + '" "$@"')
    wrapper(root, "filesystem-mcp", 'exec "$rj_tools_root/runtime/node/bin/node" "$rj_tools_root/node/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js" "$@"')
    wrapper(root, "codex", 'exec "$rj_tools_root/runtime/node/bin/node" "$rj_tools_root/node/node_modules/@openai/codex/bin/codex.js" "$@"')
    tools["codex"] = {"version": versions["codex"]["version"], "command": ["{root}/bin/codex"]}
    tools["filesystem-mcp"] = {"version": "1.0.0", "command": ["{root}/bin/filesystem-mcp"]}

    python = BASE / "resources/memory/python/bin/python3"
    if not python.is_file():
        raise ValueError("Build native memory first; Python scanners share its isolated interpreter.")
    dependencies = root / "python"
    if dependencies.exists():
        shutil.rmtree(dependencies)
    run([str(python), "-I", "-B", "-m", "pip", "install", "--no-compile", "--require-hashes", "--target", str(dependencies), "-r", str(BASE / "packaging/tool-python-requirements.txt")])
    shutil.copy2(BASE / "scripts/tool-python.py", root / "tool-python.py")
    for identifier in ("arjun", "sqlmap"):
        wrapper(root, identifier, f'exec "$rj_tools_root/../memory/python/bin/python3" -I -B "$rj_tools_root/tool-python.py" {identifier} "$@"')
        tools[identifier] = {"version": versions[identifier]["version"], "command": [f"{{root}}/bin/{identifier}"]}

    zap = root / "zap"
    if zap.exists():
        shutil.rmtree(zap)
    with tempfile.TemporaryDirectory(prefix=".tools-build-", dir=root.parent) as temporary:
        bundle.extract(bundle.download(versions["zap"]["crossplatform"], cache), Path(temporary))
        shutil.move(str(next(Path(temporary).glob("ZAP_*"))), zap)
    (zap / "zap.sh").chmod(0o755)
    wrapper(root, "zap", 'export JAVA_HOME="$rj_tools_root/runtime/java"\nexport PATH="$JAVA_HOME/bin:$PATH"\nexec "$rj_tools_root/zap/zap.sh" "$@"')
    tools["zap"] = {"version": versions["zap"]["version"], "command": ["{root}/bin/zap"]}

    nvd_source = versions["nist-nvd"]
    nvd = root / "nvd"
    if nvd.exists():
        shutil.rmtree(nvd)
    with tempfile.TemporaryDirectory(prefix=".tools-build-", dir=root.parent) as temporary:
        bundle.extract(bundle.download(nvd_source, cache), Path(temporary))
        shutil.move(str(next(Path(temporary).iterdir())), nvd)
    # Serialize outbound requests to the shared NVD quota. Cached requests do not
    # consume quota. The source remains pinned and the patch is shipped separately.
    source_file = nvd / "src/index.ts"
    content = source_file.read_text()
    marker = "    this.setupToolHandlers();"
    if content.count(marker) != 1:
        raise ValueError("Pinned NVD source changed; review the quota patch.")
    patch = (BASE / "scripts/nvd-rate-limit.inc").read_text()
    source_file.write_text(content.replace(marker, patch + "\n" + marker))
    run([str(node), str(npm), "ci", "--ignore-scripts"], cwd=nvd, env=node_env)
    run([str(node), str(npm), "run", "build"], cwd=nvd, env=node_env)
    run([str(node), str(npm), "prune", "--omit=dev", "--ignore-scripts"], cwd=nvd, env=node_env)
    wrapper(root, "nist-nvd-mcp", 'exec "$rj_tools_root/runtime/node/bin/node" "$rj_tools_root/nvd/build/index.js" "$@"')
    tools["nist-nvd"] = {"version": nvd_source["version"], "commit": nvd_source["commit"], "command": ["{root}/bin/nist-nvd-mcp"]}

    templates = root / "nuclei-templates"
    if templates.exists():
        shutil.rmtree(templates)
    bundle.extract(bundle.download(versions["nuclei-templates"], cache), templates)
    # Release archives may place files beneath one enclosing directory.
    if not (templates / "http").is_dir():
        child = next(p for p in templates.iterdir() if (p / "http").is_dir())
        with tempfile.TemporaryDirectory(dir=root.parent) as temporary:
            shutil.move(str(child), Path(temporary) / "templates")
            shutil.rmtree(templates)
            shutil.move(str(Path(temporary) / "templates"), templates)

    if not args.skip_metasploit:
        run([sys.executable, str(BASE / "scripts/build-metasploit.py"), "--output", str(root)])
        tools["metasploit"] = {"commit": versions["metasploit"]["commit"], "command": ["{root}/bin/metasploit"]}
    for unnecessary in (runtime / "node/include", runtime / "node/share/man", runtime / "node/share/doc"):
        if unnecessary.is_dir():
            shutil.rmtree(unnecessary)
    # Remove the obsolete Java layout used by the first development build.
    for obsolete in runtime.glob("jdk-*-jre"):
        shutil.rmtree(obsolete)
    stamp["tools"] = tools
    bundle.save_manifest(root / "tool-index.json", {"platform": sys.platform, "arch": arch, "tools": tools})
    stamp["files"] = bundle.digest_tree(root)
    bundle.save_manifest(manifest, stamp)
    print(f"[native-tools] toolbox built for {target}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
