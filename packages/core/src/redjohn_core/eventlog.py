"""RunEvent construction + per-type ``data`` validation.

The envelope is validated by Pydantic (``events.RunEvent``); the per-type
``data`` clauses are validated with jsonschema against the canonical contract
file ``rj-cli/contracts/run-event.schema.json``. The contract file is located
by walking up from this package (editable repo layout) or via the
``RJ_CONTRACTS_DIR`` environment override. If the schema cannot be found the
engine refuses to emit events — silent contract drift is worse than a loud
startup failure. Tests always run with the real contract schema.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

from .errors import RJError
from .events import EventType, RunEvent
from .models import Run


class ContractSchemaMissing(RuntimeError):
    pass


def _candidate_paths() -> list[Path]:
    candidates: list[Path] = []
    env = os.environ.get("RJ_CONTRACTS_DIR")
    if env:
        candidates.append(Path(env) / "run-event.schema.json")
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidates.append(parent / "contracts" / "run-event.schema.json")
    return candidates


@lru_cache(maxsize=1)
def _load_schema() -> dict[str, Any]:
    for path in _candidate_paths():
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    raise ContractSchemaMissing(
        "contracts/run-event.schema.json not found; set RJ_CONTRACTS_DIR"
    )


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(
        _load_schema(), format_checker=jsonschema.FormatChecker()
    )


def validate_event(event: RunEvent) -> None:
    """Validate a fully-formed event (seq assigned) against the contract."""
    instance = event.model_dump(mode="json")
    try:
        _validator().validate(instance)
    except jsonschema.ValidationError as exc:
        raise RJError(
            "event_schema_violation",
            f"event {event.type.value} failed contract validation: {exc.message}",
            status=500,
            details={"event_type": event.type.value, "schema_path": list(exc.absolute_schema_path)},
        ) from exc


def make_event(
    run: Run,
    type_: EventType,
    data: dict[str, Any],
    *,
    agent_id: str | None = None,
    correlation_id: str | None = None,
) -> RunEvent:
    return RunEvent(
        workspace_id=run.workspace_id,
        run_id=run.run_id,
        type=type_,
        agent_id=agent_id,
        correlation_id=correlation_id,
        data=data,
    )
