"""Build a private relocatable Ruby and the pinned Metasploit runtime."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
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
    print("[metasploit] " + " ".join(command), flush=True)
    subprocess.run(command, check=True, **options)


def relocate_macos(ruby: Path, framework: Path) -> None:
    """Copy non-system dylibs and make every reference relative to its loader."""
    native = ruby / "lib/native"
    native.mkdir(exist_ok=True)
    candidates = list((ruby / "bin").iterdir())
    candidates += list((ruby / "lib").rglob("*.dylib"))
    candidates += list((ruby / "lib").rglob("*.bundle"))
    candidates += list((framework / "vendor/bundle").rglob("*.bundle"))
    candidates += list((framework / "vendor/bundle").rglob("*.dylib"))
    visited = set()
    for path in candidates:
        path = path.resolve()
        if path in visited or not path.is_file():
            continue
        visited.add(path)
        output = subprocess.run(["otool", "-L", str(path)], capture_output=True, text=True)
        if output.returncode != 0 or "is not an object file" in output.stdout:
            continue
        changed = False
        for line in output.stdout.splitlines()[1:]:
            dependency = line.strip().split(" (", 1)[0]
            if dependency.startswith("/opt/homebrew/") or dependency.startswith("/usr/local/Cellar/"):
                source = Path(dependency)
                destination = native / source.name
                if not destination.exists():
                    shutil.copy2(source, destination)
                    candidates.append(destination)
                elif bundle.sha256(source) != bundle.sha256(destination) and destination not in visited:
                    raise ValueError(f"Native dependency name collision: {source.name}")
            elif dependency.startswith(str(ruby)):
                destination = Path(dependency)
            elif dependency.startswith("@loader_path/"):
                destination = (path.parent / dependency.removeprefix("@loader_path/")).resolve()
                if not destination.is_relative_to(ruby):
                    continue
            else:
                continue
            # Keep load commands shorter than the original names in prebuilt
            # gem extensions; the private wrapper supplies this rpath's lookup.
            replacement = "@rpath/" + destination.name
            if dependency != replacement:
                run(["install_name_tool", "-change", dependency, replacement, str(path)])
                changed = True
        if path.suffix == ".dylib":
            run(["install_name_tool", "-id", "@loader_path/" + path.name, str(path)])
            changed = True
        if changed:
            run(["codesign", "--force", "--sign", "-", str(path)])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=BASE / "resources/tools")
    args = parser.parse_args()
    root = args.output.resolve()
    versions = json.loads((BASE / "packaging/tool-versions.json").read_text())
    cache = BASE / "resources/.tool-downloads"
    ruby = root / "runtime/ruby"
    ruby_binary = ruby / "bin/ruby"
    if not ruby_binary.is_file():
        archive = bundle.download(versions["ruby"], cache)
        with tempfile.TemporaryDirectory(prefix=".tools-build-ruby-", dir=root.parent) as temporary:
            bundle.extract(archive, Path(temporary))
            source = next(Path(temporary).glob("ruby-*"))
            options = [f"--prefix={ruby}", "--enable-load-relative", "--enable-shared", "--disable-install-doc"]
            environment = dict(os.environ)
            if sys.platform == "darwin":
                options += ["--with-openssl-dir=/opt/homebrew/opt/openssl@3", "--with-libyaml-dir=/opt/homebrew/opt/libyaml", "--with-readline-dir=/opt/homebrew/opt/readline"]
                environment["MACOSX_DEPLOYMENT_TARGET"] = "14.0"
            else:
                environment["LDFLAGS"] = "-Wl,-rpath,$ORIGIN/../lib"
            run([str(source / "configure"), *options], cwd=source, env=environment)
            run(["make", "-j4"], cwd=source, env=environment)
            run(["make", "install"], cwd=source, env=environment)
    version = subprocess.check_output([str(ruby_binary), "-e", "puts RUBY_VERSION"], text=True).strip()
    if version != versions["ruby"]["version"]:
        raise ValueError("Private Ruby version differs from the reviewed source pin")
    framework = root / "metasploit"
    if not framework.is_dir():
        # Reuse only the exact pinned source previously prepared by this builder.
        prepared = root / ("metasploit-framework-" + versions["metasploit"]["commit"])
        if prepared.is_dir():
            shutil.move(str(prepared), framework)
        else:
            with tempfile.TemporaryDirectory(prefix=".tools-build-msf-", dir=root.parent) as temporary:
                bundle.extract(bundle.download(versions["metasploit"], cache), Path(temporary))
                shutil.move(str(next(Path(temporary).iterdir())), framework)
    environment = {**os.environ, "PATH": str(ruby / "bin") + os.pathsep + os.environ.get("PATH", os.defpath)}
    if sys.platform == "darwin":
        environment["DYLD_LIBRARY_PATH"] = str(ruby / "lib") + ":" + str(ruby / "lib/native")
    run([str(ruby_binary), str(ruby / "bin/gem"), "install", "bundler", "-v", "2.5.22", "--force", "--no-document"], env=environment)
    command = [str(ruby_binary), str(ruby / "bin/bundle")]
    run([*command, "config", "set", "--local", "without", "development test coverage"], cwd=framework, env=environment)
    run([*command, "config", "set", "--local", "path", "vendor/bundle"], cwd=framework, env=environment)
    run([*command, "config", "unset", "--local", "build.pc"], cwd=framework, env=environment)
    if sys.platform == "darwin":
        sdk = subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()
        run([*command, "config", "set", "--local", "build.pcaprub", f"--with-pcap-dir={sdk}/usr"], cwd=framework, env=environment)
    run([*command, "install", "--jobs", "4", "--retry", "2"], cwd=framework, env=environment)
    if sys.platform == "darwin":
        relocate_macos(ruby, framework)
    # Download archives and documentation are not used by the console runtime.
    for directory in [framework / "vendor/bundle/ruby/3.3.0/cache", framework / "spec", framework / "test", framework / "docs", ruby / "share/doc"]:
        if directory.is_dir():
            shutil.rmtree(directory)
    wrapper = root / "bin/metasploit"
    wrapper.write_text(
        '#!/bin/sh\nset -eu\nrj_tools_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n'
        'export BUNDLE_GEMFILE="$rj_tools_root/metasploit/Gemfile"\n'
        'export BUNDLE_PATH="$rj_tools_root/metasploit/vendor/bundle"\n'
        'export BUNDLE_WITHOUT="development:test:coverage"\n'
        'export GIT_CEILING_DIRECTORIES="$rj_tools_root"\n'
        'if [ "$(uname -s)" = Darwin ]; then export DYLD_LIBRARY_PATH="$rj_tools_root/runtime/ruby/lib:$rj_tools_root/runtime/ruby/lib/native"; fi\n'
        'exec "$rj_tools_root/runtime/ruby/bin/ruby" "$rj_tools_root/runtime/ruby/bin/bundle" exec '
        '"$rj_tools_root/runtime/ruby/bin/ruby" "$rj_tools_root/metasploit/msfconsole" "$@"\n'
    )
    wrapper.chmod(0o755)
    run([str(wrapper), "--version"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
