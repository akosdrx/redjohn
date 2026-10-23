"""OpenViking (volcengine/OpenViking) integration for RedJohn."""

from redjohn.memory.openviking.config import (
    CORE_OPENVIKING_TOOLS,
    ensure_openviking_configured,
    get_openviking_mcp_config,
    probe_openviking_status,
)
from redjohn.memory.openviking.hooks import (
    recall_pentest_memory,
    remember_pentest_broadcast,
    remember_pentest_finding,
    remember_pentest_summary,
)


__all__ = [
    "CORE_OPENVIKING_TOOLS",
    "ensure_openviking_configured",
    "get_openviking_mcp_config",
    "probe_openviking_status",
    "recall_pentest_memory",
    "remember_pentest_broadcast",
    "remember_pentest_finding",
    "remember_pentest_summary",
]
