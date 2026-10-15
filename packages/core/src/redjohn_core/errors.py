"""Typed engine errors -> ``{error: {code, message, details, request_id}}``."""

from __future__ import annotations

from typing import Any


class RJError(Exception):
    """Base typed error. ``code`` is stable, machine-readable (contract)."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}


def not_found(resource: str, rid: str) -> RJError:
    return RJError("not_found", f"{resource} not found: {rid}", status=404,
                   details={"resource": resource, "id": rid})


def conflict(message: str, details: dict[str, Any] | None = None) -> RJError:
    return RJError("conflict", message, status=409, details=details)


def forbidden(message: str, details: dict[str, Any] | None = None, *, code: str = "forbidden") -> RJError:
    return RJError(code, message, status=403, details=details)


def scope_violation(message: str, details: dict[str, Any] | None = None) -> RJError:
    return RJError("scope_violation", message, status=403, details=details)


def validation(message: str, details: dict[str, Any] | None = None) -> RJError:
    return RJError("validation_error", message, status=422, details=details)


def unavailable(message: str, details: dict[str, Any] | None = None, *, code: str = "unavailable") -> RJError:
    return RJError(code, message, status=503, details=details)


def unauthorized(message: str = "missing or invalid bearer token") -> RJError:
    return RJError("unauthorized", message, status=401)


def gone(message: str, details: dict[str, Any] | None = None) -> RJError:
    return RJError("cursor_expired", message, status=410, details=details)
