"""Guarded access to the OpenViking memory store.

``ov/protocol.py`` (contract boundary) lazy-imports ``ov/client.py``, which is
owned by the OpenViking agent and may not exist yet. This wrapper degrades a
missing/broken adapter module to ``MemoryUnavailable`` instead of ImportError,
so memory-dependent steps enter the visible waiting path rather than crashing.
"""

from __future__ import annotations

from typing import Any

from .ov import MemoryStore, MemoryUnavailable


def safe_memory_store(settings: Any) -> MemoryStore:
    from .ov import get_memory_store

    try:
        return get_memory_store(settings)
    except MemoryUnavailable:
        raise
    except (ImportError, ModuleNotFoundError, AttributeError) as exc:
        raise MemoryUnavailable(
            f"OpenViking adapter not available ({exc}); memory-dependent steps will wait"
        ) from exc
