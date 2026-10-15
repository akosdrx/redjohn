"""``python -m redjohn_core.contracts_export`` — regenerate the
openapi.yaml-equivalent schema document from the canonical models.

Prints JSON to stdout (never touches rj-cli/contracts/*). CI diffs:

* ``components.schemas`` — generated via ``model_json_schema`` from
  models.py / events.py (the contract anchor), and
* ``paths`` — the path -> methods map served by the app factory.

against the frozen contract in rj-cli/contracts/openapi.yaml.
"""

from __future__ import annotations

import json
from typing import Any

from . import CONTRACT_VERSION, __version__
from .api import API_PREFIX, create_app, iter_api_routes
from .events import RunEvent
from .models import (
    Agent,
    AgentLimits,
    AgentMessage,
    ErrorResponse,
    Evidence,
    Finding,
    ListPage,
    MCPConnection,
    Project,
    Report,
    Run,
    ScopePolicy,
    ServiceStatus,
    SkillRef,
    Target,
    TerminalSession,
    ToolInvocation,
    Workspace,
)

MODELS = [
    Workspace, Project, Target, ScopePolicy, AgentLimits, Run, Agent, AgentMessage,
    ToolInvocation, TerminalSession, Finding, Evidence, SkillRef, MCPConnection,
    ServiceStatus, RunEvent, ErrorResponse, ListPage, Report,
]


def export() -> dict[str, Any]:
    schemas: dict[str, Any] = {}
    for model in MODELS:
        schema = model.model_json_schema(mode="serialization")
        # pydantic emits $defs; inline names stay stable for diffing
        schemas[model.__name__] = schema

    paths: dict[str, set[str]] = {}
    app = create_app(None)
    for path, methods in iter_api_routes(app):
        if not path.startswith(API_PREFIX):
            continue
        rel = path[len(API_PREFIX):] or "/"
        paths.setdefault(rel, set()).update(methods)

    return {
        "openapi": "3.1.0",
        "info": {
            "title": "RedJohn API",
            "version": __version__,
            "x-contract-version": CONTRACT_VERSION,
            "x-generator": "redjohn_core.contracts_export",
        },
        "paths": {p: sorted(paths[p]) for p in sorted(paths)},
        "components": {"schemas": schemas},
    }


def main() -> None:
    print(json.dumps(export(), indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
