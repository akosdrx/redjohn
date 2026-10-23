"""Hatchling build hook that compiles and bundles the Rust TUI sidecar."""

from __future__ import annotations

import os
import shutil
import subprocess
import sysconfig
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):  # type: ignore[type-arg]
    """Compile the native Rust TUI sidecar and ship it inside the wheel.

    The sidecar is the only interactive interface, so every wheel is a
    platform wheel and a missing Rust toolchain is a build failure.
    """

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        # Editable installs run from the checkout, where the TUI is started
        # from the compiled release binary or ``cargo run``; there is nothing to bundle.
        if version == "editable":
            return

        root = Path(self.root)
        executable = "redjohn-tui.exe" if os.name == "nt" else "redjohn-tui"
        output = root / "build" / "sidecar" / executable
        output.parent.mkdir(parents=True, exist_ok=True)

        cargo = shutil.which("cargo")
        if cargo is None:
            raise RuntimeError("Rust/Cargo is required to build the RedJohn Rust TUI")
        tui_dir = root / "redjohn" / "interface" / "tui"
        subprocess.run(
            [
                cargo,
                "build",
                "--release",
                "--bin",
                "redjohn-tui",
            ],
            cwd=tui_dir,
            check=True,
        )
        built_binary = tui_dir / "target" / "release" / executable
        shutil.copy2(built_binary, output)

        build_data["force_include"][str(output)] = f"redjohn/bin/{executable}"
        build_data["pure_python"] = False

        # Native extension module (process-tree sampling): built as an abi3
        # cdylib and shipped inside the package next to its Python loader.
        native_dir = root / "redjohn" / "native"
        if native_dir.is_dir():
            subprocess.run(
                ["cargo", "build", "--release", "--features", "extension-module"],
                cwd=native_dir,
                check=True,
                shell=False,
            )
            cdylib = next(
                (
                    name
                    for name in (
                        "libredjohn_native.dylib",
                        "libredjohn_native.so",
                        "redjohn_native.dll",
                    )
                    if (native_dir / "target" / "release" / name).is_file()
                ),
                None,
            )
            if cdylib is None:
                raise RuntimeError("redjohn-native cdylib artifact not found after build")
            ext_suffix = str(sysconfig.get_config_var("EXT_SUFFIX"))
            native_out = root / "build" / "native" / f"redjohn_native{ext_suffix}"
            native_out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(native_dir / "target" / "release" / cdylib, native_out)
            build_data["force_include"][str(native_out)] = (
                f"redjohn/_native/redjohn_native{ext_suffix}"
            )

        platform_tag = os.environ.get("REDJOHN_WHEEL_PLATFORM_TAG")
        if not platform_tag:
            platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
        build_data["tag"] = f"py3-none-{platform_tag}"
