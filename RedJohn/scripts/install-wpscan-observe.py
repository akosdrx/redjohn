#!/usr/bin/env python3
"""Explicit Linux CI fixture builder for a private, offline observation runtime.

No full WPScan gem is installed/required. Source archives are SHA-256 pinned,
not signature verified. WPScan's exact passive source/license stays an external
operator component, never a RedJohn redistribution or commercial entitlement.
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import io
import json
import os
import platform
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
PINS = Path(__file__).with_name("wpscan-observe-runtime-pins.json")
MAX_ARCHIVE = 48 * 1024 * 1024
MAX_TREE = 128 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_FILES = 4096
WP_GEM_SHA = "fe467ff867116fe85ab3913297d6acbbbdac815b8e8d4590535564a91eada95e"
WP_SOURCE_SHA = "9f612c9148ff3fa3213361e5e08306f6cd7a449c8946eb88cb15adf94c7e5f88"
WP_LICENSE_SHA = "72eaecf9c3497bb34fb5722eba38a4b3b0ae39235c17378547101b8329b51008"
LAUNCH = """import os,resource,sys
resource.setrlimit(resource.RLIMIT_FSIZE,(67108864,67108864))
os.execve(sys.argv[1],sys.argv[1:],dict(os.environ))
"""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        url = urlsplit(newurl)
        if (
            url.scheme != "https"
            or url.hostname
            not in {
                "github.com",
                "release-assets.githubusercontent.com",
                "rubygems.org",
                "cache.ruby-lang.org",
                "raw.githubusercontent.com",
            }
            or url.username
            or url.password
        ):
            raise ValueError("wordpress_runtime_download_redirect_denied")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(cache: Path, name: str, url: str, expected: str, maximum: int) -> Path:
    path = cache / name
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            raise ValueError("wordpress_archive_cache_type_or_size")
        data = path.read_bytes()
    else:
        opener = urllib.request.build_opener(OfficialRedirects)
        request = urllib.request.Request(
            url, headers={"User-Agent": "RedJohn-owned-offline-fixture"}
        )
        with opener.open(request, timeout=60) as response:
            data = response.read(maximum + 1)
        if len(data) <= maximum and digest(data) == expected:
            path.write_bytes(data)
            path.chmod(0o600)
    if len(data) > maximum or digest(data) != expected:
        raise ValueError("wordpress_archive_digest_or_byte_budget")
    return path


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or len(name) > 256
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or any(ord(c) < 32 for c in name)
        or str(path) != name
        or name.endswith("/")
    ):
        raise ValueError("wordpress_archive_path_denied")
    return name


def archive_files(data: bytes, *, ruby_root: str = "") -> dict[str, tuple[bytes, bool]]:
    """Bounded regular payloads; only two reviewed Ruby internal aliases allowed."""
    expanded_limit = MAX_TREE + 8 * 1024 * 1024
    if data.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            data = compressed.read(expanded_limit + 1)
    if len(data) > expanded_limit:
        raise ValueError("wordpress_archive_expanded_byte_budget")
    result: dict[str, tuple[bytes, bool]] = {}
    aliases: dict[str, str] = {}
    total = count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        seen = set()
        for member in archive:
            count += 1
            if count > MAX_FILES:
                raise ValueError("wordpress_archive_member_budget")
            name = member.name.rstrip("/") if member.isdir() else member.name
            safe_name(name)
            if name in seen:
                raise ValueError("wordpress_archive_duplicate_path")
            seen.add(name)
            if member.isdir():
                continue
            if (
                member.issym()
                and ruby_root
                and name
                in {
                    ruby_root + "/lib/libruby.so",
                    ruby_root + "/lib/libruby.so.3.3",
                }
                and member.linkname == "libruby.so.3.3.12"
            ):
                aliases[name] = ruby_root + "/lib/" + member.linkname
                continue
            if not member.isfile() or not 0 <= member.size <= MAX_FILE:
                raise ValueError("wordpress_archive_type_or_file_budget")
            total += member.size
            if total > MAX_TREE:
                raise ValueError("wordpress_archive_total_byte_budget")
            stream = archive.extractfile(member)
            assert stream is not None
            payload = stream.read(member.size + 1)
            if len(payload) != member.size:
                raise ValueError("wordpress_archive_truncated_member")
            result[name] = payload, bool(member.mode & 0o111)
    for name, target in aliases.items():
        if target not in result:
            raise ValueError("wordpress_archive_alias_target_not_regular")
        result[name] = result[target]
    if sum(len(data) for data, _executable in result.values()) > MAX_TREE:
        raise ValueError("wordpress_materialized_archive_byte_budget")
    return result


def gem_files(path: Path) -> dict[str, tuple[bytes, bool]]:
    outer = archive_files(path.read_bytes())
    if "data.tar.gz" not in outer:
        raise ValueError("wordpress_gem_data_required")
    return archive_files(outer["data.tar.gz"][0])


def write_tree(root: Path, files: dict[str, tuple[bytes, bool]]) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, (data, executable) in sorted(files.items()):
        target = root / safe_name(name)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o700 if executable else 0o600)


def run_fixed(command: list[str], cwd: Path, env: dict[str, str], log: Path, timeout: int) -> str:
    """Only fixed commands, deny-all network namespace and bounded owned group."""
    with log.open("wb") as output:
        process = subprocess.Popen(
            [
                "unshare",
                "--user",
                "--map-root-user",
                "--net",
                sys.executable,
                "-I",
                "-S",
                "-c",
                LAUNCH,
                *command,
            ],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
            raise
        finally:
            # A successful leader must not leave a background compiler/helper.
            # This is the dedicated process group created for this command.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
    if log.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("wordpress_build_log_byte_budget")
    if code:
        raise subprocess.CalledProcessError(code, command)
    return log.read_text(errors="replace")


def read_identity(text: str) -> dict[str, Any]:
    value = json.loads(text)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("ruby_revision")
        not in {
            "0581089df9f0af0fe6b64cb8167987c211100947",
            "0581089df9",
        }
        or value.get("runtime")
        != {
            "ruby": "3.3.12",
            "nokogiri": "1.19.4",
            "racc": "1.8.1",
            "network": "offline",
        }
        or not isinstance(value.get("_runtime_files"), list)
        or not 1 <= len(value["_runtime_files"]) <= 512
    ):
        raise ValueError("wordpress_installed_runtime_identity_mismatch")
    return value


def native_dependencies(text: str) -> dict[str, Path]:
    result = {}
    if "not found" in text:
        raise ValueError("wordpress_native_dependency_not_found")
    for line in text.splitlines():
        mapped = re.search(r"^\s*(\S+)\s+=>\s+(/[^\s()]+)", line)
        if mapped is not None:
            name, path = mapped[1], Path(mapped[2]).resolve()
            if "/" in name or len(name) > 128:
                raise ValueError("wordpress_native_soname_invalid")
            result[name] = path
    if len(result) > 32:
        raise ValueError("wordpress_native_dependency_count")
    return result


def gem_install_command(
    ruby: Path, archive: Path, configuration: Path, *, system_libraries: bool = False
) -> list[str]:
    # RubyGems 3.5.22 consumes common options after its subcommand. Placing
    # either configuration flag before `install` is a hard parser error.
    command = [
        str(ruby / "bin/ruby"),
        str(ruby / "bin/gem"),
        "install",
        "--norc",
        "--config-file",
        str(configuration),
        "--local",
        "--ignore-dependencies",
        "--no-document",
        str(archive),
    ]
    return command + (["--", "--use-system-libraries"] if system_libraries else [])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--external-operator-component", action="store_true", required=True)
    args = parser.parse_args()
    args.cache = args.cache.resolve()
    args.destination = args.destination.resolve()
    args.logs = args.logs.resolve()
    if platform.system() != "Linux" or platform.machine() not in {"aarch64", "x86_64"}:
        raise RuntimeError("wordpress_reviewed_linux_x64_arm64_ci_only")
    if Path("/etc/os-release").read_text().find('VERSION_ID="24.04"') == -1:
        raise RuntimeError("wordpress_reviewed_ubuntu_2404_required")
    if args.destination.exists():
        raise ValueError("wordpress_new_private_destination_required")
    args.cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.logs.mkdir(mode=0o700, parents=True, exist_ok=True)
    pins = json.loads(PINS.read_text())
    architecture = "arm64" if platform.machine() == "aarch64" else "x64"
    asset = pins["ruby"]["assets"][architecture]
    archive = fetch(
        args.cache,
        "ruby-3.3.12-" + architecture + ".tar.gz",
        asset["url"],
        asset["sha256"],
        MAX_ARCHIVE,
    )
    ruby_files = archive_files(archive.read_bytes(), ruby_root=asset["archive_root"])
    prefix = asset["archive_root"] + "/"
    if any(not path.startswith(prefix) for path in ruby_files):
        raise ValueError("wordpress_ruby_archive_root")
    ruby_files = {name[len(prefix) :]: data for name, data in ruby_files.items()}
    gems, payloads = {}, {}
    for package in pins["gems"]:
        path = fetch(
            args.cache,
            package["name"] + "-" + package["version"] + ".gem",
            package["archive_url"],
            package["archive_sha256"],
            8 * 1024 * 1024,
        )
        gems[package["name"]] = path
        payloads[package["name"]] = gem_files(path)
    wp_archive = fetch(
        args.cache,
        "wpscan-4.1.0.gem",
        "https://rubygems.org/gems/wpscan-4.1.0.gem",
        WP_GEM_SHA,
        8 * 1024 * 1024,
    )
    wp = gem_files(wp_archive)
    source, license_bytes = wp["lib/wpscan/target/platform/wordpress.rb"][0], wp["LICENSE"][0]
    if digest(source) != WP_SOURCE_SHA or digest(license_bytes) != WP_LICENSE_SHA:
        raise ValueError("wordpress_external_source_or_license_mismatch")
    # Keep all build artifacts/logs in an explicit private CI destination parent.
    args.destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="wordpress-build-", dir=args.destination.parent
    ) as temporary:
        build = Path(temporary).resolve()
        ruby, gem_home = build / "ruby", build / "gems"
        write_tree(ruby, ruby_files)
        gem_home.mkdir(mode=0o700)
        home = build / "home"
        home.mkdir(mode=0o700)
        (home / "empty-gemrc").write_text("--- {}\n")
        env = {
            "PATH": str(ruby / "bin") + ":/usr/bin:/bin",
            "HOME": str(home),
            "GEM_HOME": str(gem_home),
            "GEM_PATH": str(gem_home),
            "LD_LIBRARY_PATH": str(ruby / "lib"),
            "LANG": "C.UTF-8",
            "MAKEFLAGS": "-j2",
            "NOKOGIRI_USE_SYSTEM_LIBRARIES": "true",
        }
        run_fixed(["/usr/bin/true"], build, env, args.logs / "namespace-health.log", 5)
        build_identities = {
            "rubygems": run_fixed(
                [str(ruby / "bin/ruby"), str(ruby / "bin/gem"), "--version"],
                build,
                env,
                args.logs / "rubygems-version.log",
                5,
            ),
            "compiler": run_fixed(
                ["/usr/bin/gcc", "--version"], build, env, args.logs / "compiler.log", 5
            ),
            "make": run_fixed(
                ["/usr/bin/make", "--version"], build, env, args.logs / "make.log", 5
            ),
            "system_parser_versions": run_fixed(
                ["/usr/bin/pkg-config", "--modversion", "libxml-2.0", "libxslt", "zlib"],
                build,
                env,
                args.logs / "system-parser-versions.log",
                5,
            ),
            "build_packages": run_fixed(
                [
                    "/usr/bin/dpkg-query",
                    "-W",
                    "-f=${Package}:${Architecture}=${Version}\n",
                    "gcc",
                    "make",
                    "pkg-config",
                    "binutils",
                    "libc6-dev",
                    "libxml2-dev",
                    "libxslt1-dev",
                    "zlib1g-dev",
                ],
                build,
                env,
                args.logs / "build-packages.log",
                5,
            ),
        }
        for name in ("mini_portile2", "racc", "nokogiri"):
            command = gem_install_command(
                ruby, gems[name], home / "empty-gemrc", system_libraries=name == "nokogiri"
            )
            run_fixed(command, build, env, args.logs / (name + "-build.log"), 600)
        runtime = args.destination / "runtime"
        files = {"ruby/bin/ruby": ruby_files["bin/ruby"]}
        files.update(
            {
                "ruby/" + path: value
                for path, value in ruby_files.items()
                if path.startswith("lib/ruby/3.3.0/")
            }
        )
        files["native/libruby.so.3.3"] = ruby_files["lib/libruby.so.3.3.12"]
        for name, version in (("nokogiri", "1.19.4"), ("racc", "1.8.1")):
            lib = gem_home / "gems" / (name + "-" + version) / "lib"
            for path in sorted(lib.rglob("*")):
                if path.is_symlink():
                    raise ValueError("wordpress_compiled_gem_symlink_denied")
                if path.is_file():
                    files["packages/" + name + "/lib/" + path.relative_to(lib).as_posix()] = (
                        path.read_bytes(),
                        False,
                    )
            extension_name = "nokogiri/nokogiri.so" if name == "nokogiri" else "racc/cparse.so"
            extension = list(
                (gem_home / "extensions").glob("*/*/" + name + "-" + version + "/" + extension_name)
            )
            if len(extension) != 1 or extension[0].is_symlink():
                raise ValueError("wordpress_exact_compiled_native_extension_required")
            files["packages/" + name + "/lib/" + extension_name] = (
                extension[0].read_bytes(),
                False,
            )
        for license_pin in pins["ruby"]["license_files"]:
            path = fetch(
                args.cache,
                "ruby-" + license_pin["name"],
                license_pin["url"],
                license_pin["sha256"],
                64 * 1024,
            )
            files["licenses/ruby/" + license_pin["name"]] = path.read_bytes(), False
        for name, paths in {
            "nokogiri": ("LICENSE.md", "LICENSE-DEPENDENCIES.md"),
            "racc": ("COPYING",),
        }.items():
            for license_name in paths:
                files["licenses/" + name + "/" + license_name] = payloads[name][license_name]
        if len(files) > MAX_FILES or sum(len(value[0]) for value in files.values()) > MAX_TREE:
            raise ValueError("wordpress_selected_runtime_budget")
        write_tree(runtime, files)
        loads = [
            "ruby/lib/ruby/3.3.0",
            "ruby/lib/ruby/3.3.0/" + platform.machine() + "-linux",
            "packages/nokogiri/lib",
            "packages/racc/lib",
        ]
        command = [
            str(runtime / "ruby/bin/ruby"),
            "--disable-gems",
            "--disable-did_you_mean",
            "--disable-error_highlight",
            "-I",
            ":".join(str(runtime / path) for path in loads),
            str(ROOT / "redjohn/assessment/wpscan_observe_bootstrap.rb"),
            "--health",
        ]
        env["LD_LIBRARY_PATH"] = str(runtime / "native")
        identity = read_identity(
            run_fixed(command, build, env, args.logs / "health-before-link-copy.json", 10)
        )
        dependencies: dict[str, Path] = {}
        for path in [
            runtime / "ruby/bin/ruby",
            *[Path(p) for p in identity["_runtime_files"] if str(p).endswith(".so")],
        ]:
            text = run_fixed(
                ["/usr/bin/ldd", str(path)],
                build,
                env,
                args.logs / ("ldd-" + digest(str(path).encode())[:12] + ".log"),
                5,
            )
            for soname, actual in native_dependencies(text).items():
                if soname in dependencies and dependencies[soname] != actual:
                    raise ValueError("wordpress_native_soname_collision")
                dependencies[soname] = actual
        receipts = [
            {
                "path": "native/libruby.so.3.3",
                "source_kind": "ruby_archive",
                "package": "ruby",
                "version": "3.3.12",
                "copyright_file": "licenses/ruby/COPYING",
            }
        ]
        for soname, path in sorted(dependencies.items()):
            if soname == "libruby.so.3.3":
                continue
            package = (
                run_fixed(
                    ["/usr/bin/dpkg-query", "-S", str(path)],
                    build,
                    env,
                    args.logs / (soname + "-package.log"),
                    5,
                )
                .strip()
                .split(": ")[0]
            )
            if re.fullmatch(r"[a-z0-9.+-]+(?::(?:amd64|arm64))?", package) is None:
                raise ValueError("wordpress_os_library_package_unverified")
            version = run_fixed(
                ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package],
                build,
                env,
                args.logs / (soname + "-version.log"),
                5,
            ).strip()
            copyright_path = Path("/usr/share/doc") / package.split(":")[0] / "copyright"
            copyright_bytes = copyright_path.resolve().read_bytes()
            data = path.read_bytes()
            if len(data) > MAX_FILE or len(copyright_bytes) > 1024 * 1024:
                raise ValueError("wordpress_os_library_or_license_budget")
            (runtime / "native" / soname).write_bytes(data)
            copyright_relative = "licenses/os/" + package.replace(":", "-") + "/copyright"
            target = runtime / copyright_relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(copyright_bytes)
            receipts.append(
                {
                    "path": "native/" + soname,
                    "source_kind": "os_package",
                    "package": package,
                    "version": version,
                    "copyright_file": copyright_relative,
                }
            )
        identity = read_identity(
            run_fixed(command, build, env, args.logs / "health-relocated.json", 10)
        )
        features = []
        for loaded in identity["_runtime_files"]:
            feature = Path(loaded).relative_to(runtime).as_posix()
            safe_name(feature)
            features.append(feature)
        # Keep the actual require closure instead of unused RubyGems/RDoc,
        # bundler or complete platform trees. Any additional runtime load is
        # denied by the exact native-feature protocol and immutable snapshot.
        selected = set(features) | {"ruby/bin/ruby"}
        for path in runtime.rglob("*"):
            if path.is_file():
                relative = path.relative_to(runtime).as_posix()
                if relative not in selected and not relative.startswith(("native/", "licenses/")):
                    path.unlink()
        pruned_identity = read_identity(
            run_fixed(command, build, env, args.logs / "health-pruned-closure.json", 10)
        )
        if pruned_identity != identity:
            raise ValueError("wordpress_pruned_runtime_closure_changed")
        rows: list[dict[str, Any]] = []
        total = 0
        for path in sorted(runtime.rglob("*")):
            if path.is_symlink():
                raise ValueError("wordpress_private_runtime_symlink_denied")
            if path.is_file():
                data = path.read_bytes()
                total += len(data)
                if len(data) > MAX_FILE or total > MAX_TREE or len(rows) >= MAX_FILES:
                    raise ValueError("wordpress_final_runtime_budget")
                rows.append(
                    {
                        "path": path.relative_to(runtime).as_posix(),
                        "sha256": digest(data),
                        "executable": path == runtime / "ruby/bin/ruby",
                    }
                )
                path.chmod(0o500 if rows[-1]["executable"] else 0o400)
        document = {
            "schema_version": 1,
            "architecture": platform.machine(),
            "ruby_source_commit": pins["ruby"]["source_commit"],
            "ruby_archive_sha256": asset["sha256"],
            "gem_archive_sha256": {
                p["name"]: p["archive_sha256"] for p in pins["gems"] if p["name"] != "mini_portile2"
            },
            "runtime": identity["runtime"],
            "files": rows,
            "load_paths": loads,
            "expected_features": sorted(features),
            "license_files": [r["path"] for r in rows if r["path"].startswith("licenses/")],
            "linked_libraries": receipts,
        }
        manifest = args.destination / "runtime-manifest.json"
        manifest.write_text(json.dumps(document, indent=2) + "\n")
        component = args.destination / "operator-component"
        component.mkdir(mode=0o700)
        (component / "wordpress.rb").write_bytes(source)
        (component / "LICENSE").write_bytes(license_bytes)
        receipt = {
            "schema_version": 1,
            "runtime_manifest_sha256": digest(manifest.read_bytes()),
            "runtime_bytes": total,
            "runtime_files": len(rows),
            "upstream_signature_verified": False,
            "native_product_namespace_verified": False,
            "version": "4.1.0",
            "external_operator_component": True,
            "operator_use": "own-systems",
            "build_only_packages": ["mini_portile2-2.8.9"],
            "installer_sha256": digest(Path(__file__).read_bytes()),
            "pin_manifest_sha256": digest(PINS.read_bytes()),
            "identity": identity,
            "build_identities": build_identities,
        }
        (args.destination / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        json.dumps(
            {
                "destination": str(args.destination),
                "runtime_manifest_sha256": receipt["runtime_manifest_sha256"],
                "runtime_files": len(rows),
                "runtime_bytes": total,
                "product_boundary_proof": "pending_real_scheduler_e2e",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
