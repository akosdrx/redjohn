"""Loader for the optional Rust native extension (process-tree sampling).

The wheel force-includes the abi3 extension built from ``redjohn/native``.
Editable installs and checkouts resolve the artifact straight from the cargo
``target`` directory when present; without either, callers fall back to the
pure-Python ``ps`` implementation and ``NATIVE_AVAILABLE`` records that.
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import ExtensionFileLoader
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from types import ModuleType


_MODULE_NAME = "redjohn._native.redjohn_native"
_CDYLIB_NAMES = (
    "libredjohn_native.dylib",
    "libredjohn_native.so",
    "redjohn_native.dll",
)


def _load_dev_artifact() -> ModuleType | None:
    """Load the cdylib straight from the cargo target dir in a dev checkout."""
    target_dir = Path(__file__).resolve().parent.parent / "native" / "target" / "release"
    for name in _CDYLIB_NAMES:
        artifact = target_dir / name
        if not artifact.is_file():
            continue
        # A .dylib is not in EXTENSION_SUFFIXES, so the loader must be given
        # explicitly rather than derived from the file name.
        loader = ExtensionFileLoader(_MODULE_NAME, str(artifact))
        spec = importlib.util.spec_from_loader(_MODULE_NAME, loader)
        if spec is None:
            return None
        loaded = importlib.util.module_from_spec(spec)
        loader.exec_module(loaded)
        sys.modules[_MODULE_NAME] = loaded
        return loaded
    return None


def _load_native() -> ModuleType | None:
    try:
        # Intentionally lazy: the artifact only exists in wheel installs.
        from . import redjohn_native as module  # type: ignore[attr-defined]  # noqa: PLC0415
    except ImportError:
        return _load_dev_artifact()
    return cast("ModuleType", module)


_native = _load_native()
NATIVE_AVAILABLE = _native is not None


def native_sample_tree(pid: int) -> dict[str, Any] | None:
    """Rust process-tree sample, or None when the extension is unavailable."""
    if _native is None:
        return None
    return _native.sample_process_tree(pid)  # type: ignore[no-any-return]


def native_sample_forest(roots: list[int]) -> dict[str, Any] | None:
    """Rust process-forest sample, or None when the extension is unavailable."""
    if _native is None:
        return None
    return _native.sample_process_forest(roots)  # type: ignore[no-any-return]
