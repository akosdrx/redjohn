"""OpenViking integration package. `protocol.py` is the contract boundary;
`client.py` (real SDK adapter) is owned by the OpenViking agent."""

from .protocol import MemoryStore, MemoryUnavailable, SearchHit, SkillHit, get_memory_store

__all__ = ["MemoryStore", "MemoryUnavailable", "SearchHit", "SkillHit", "get_memory_store"]
