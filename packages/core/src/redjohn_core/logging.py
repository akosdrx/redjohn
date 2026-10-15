"""Structured JSON logging with run/agent/request correlation ids.

Uses python-json-logger. Every record carries ``logger``, ``level``, ``ts``
plus any correlation extras bound via ``bind()``. Secrets must never be
passed as extras; settings are only ever logged via ``Settings.redacted()``.
"""

from __future__ import annotations

import logging
from typing import Any

_configured = False


def configure_logging(level: str | None = None) -> None:
    """Install the JSON handler once; (re)apply the level whenever one is given.

    ``get_logger`` calls this with no level merely to ensure the handler is
    installed, so it must not reset a level set earlier at startup or by
    ``PATCH /settings`` — which is why the level is applied outside the
    one-time setup guard and only when explicitly provided.
    """
    global _configured
    root = logging.getLogger("redjohn_core")
    if not _configured:
        from pythonjsonlogger.json import JsonFormatter

        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter(
            "%(levelname)s %(name)s %(message)s %(asctime)s",
            rename_fields={"levelname": "level", "name": "logger", "asctime": "ts", "message": "msg"},
            json_default=str,
        ))
        root.handlers[:] = [handler]
        root.setLevel("INFO")
        root.propagate = False
        _configured = True
    if level is not None:
        root.setLevel(level.upper())


class CorrelationAdapter(logging.LoggerAdapter[logging.Logger]):
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        extra = kwargs.setdefault("extra", {})
        for k, v in self.extra.items():
            extra.setdefault(k, v)
        return msg, kwargs


def get_logger(name: str, **ctx: Any) -> CorrelationAdapter:
    """Logger with bound correlation context (run_id=, agent_id=, request_id=)."""
    configure_logging()
    return CorrelationAdapter(logging.getLogger(f"redjohn_core.{name}"), ctx)
