"""OpenViking integration boundary (contract-level).

`MemoryStore` is the ONLY interface the engine uses for knowledge, long-term
memory and skill content. The real implementation (OpenViking server via the
official `openviking-sdk` AsyncHTTPClient) lives in `redjohn_core.ov.client`
and is owned by the OpenViking agent. A fixture fake exists ONLY for unit
tests and explicitly-marked UI demos — never silently substituted at runtime:
when OpenViking is unconfigured or down, `get_memory_store` raises
`MemoryUnavailable` and dependent agent steps move to a visible waiting/error
state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ..models import ServiceStatus


class MemoryUnavailable(RuntimeError):
    """OpenViking is not configured or not reachable. Never swallow silently."""


@dataclass
class SearchHit:
    uri: str
    score: float = 0.0
    abstract: str = ""     # L0
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class SkillHit:
    uri: str
    name: str
    version: str = ""
    description: str = ""
    content_hash: str = ""


@runtime_checkable
class MemoryStore(Protocol):
    """Verified against openviking-sdk 0.1.14 / server v0.5.0.

    See rj-cli/docs/openviking-integration.md for the exact SDK methods each
    operation maps to. Import acceptance and processed/searchable state are
    distinct: callers must poll task ids / use wait_processed, and timeouts
    are never reported as success.
    """

    async def status(self) -> ServiceStatus: ...

    # --- documents / resources -------------------------------------------------
    async def import_resource(self, path: str | Path, *, to: str | None = None,
                              wait: bool = True, timeout: float = 120.0) -> str:
        """Import a document; returns the OpenViking URI once searchable."""

    async def task_status(self, task_id: str) -> str:
        """pending|running|completed|failed|cancelled (server task states)."""

    async def wait_processed(self, timeout: float = 120.0) -> None: ...

    # --- retrieval (progressive L0/L1/L2) ---------------------------------------
    async def find(self, query: str, *, limit: int = 10) -> list[SearchHit]: ...

    async def abstract(self, uri: str) -> str: ...   # L0

    async def overview(self, uri: str) -> str: ...   # L1

    async def read(self, uri: str) -> str: ...       # L2 full content

    # --- sessions & memory --------------------------------------------------------
    async def create_session(self, *, session_id: str | None = None) -> str: ...

    async def add_message(self, session_uri: str, role: str, content: str,
                          *, message_id: str | None = None) -> None: ...

    async def commit_session(self, session_uri: str, *, wait: bool = True,
                             timeout: float = 120.0) -> str:
        """Trigger memory processing; returns task id."""

    # --- skills -------------------------------------------------------------------
    async def add_skill(self, path: str | Path, *, wait: bool = True,
                        timeout: float = 120.0) -> str: ...

    async def find_skills(self, query: str, *, limit: int = 10) -> list[SkillHit]: ...

    async def get_skill(self, uri: str, *, include_content: bool = False) -> SkillHit: ...


def get_memory_store(settings: Any) -> MemoryStore:
    """Factory: returns the real OpenViking adapter or raises MemoryUnavailable.

    Lazy-imports `redjohn_core.ov.client.OpenVikingStore` so the engine never
    hard-depends on SDK import at module load, and so tests can substitute a
    fixture implementation explicitly.
    """
    url = getattr(settings, "openviking_url", None)
    if not url:
        raise MemoryUnavailable("OpenViking is not configured (openviking_url missing)")
    from .client import OpenVikingStore

    return OpenVikingStore(settings)
