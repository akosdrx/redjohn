"""Regenerate the local integration extension, without changing the frozen v1 contract."""

from pathlib import Path

import yaml
from redjohn_core.api import API_PREFIX, create_app
from redjohn_core.models import ErrorResponse

root = Path(__file__).resolve().parents[1]
source = create_app(None).openapi()
paths = {
    path.removeprefix(API_PREFIX): operations
    for path, operations in source["paths"].items()
    if path.startswith(API_PREFIX + "/integrations/") or path == API_PREFIX + "/reports/{report_id}/download"
}
error = ErrorResponse.model_json_schema(ref_template="#/components/schemas/{model}")
schemas = source["components"]["schemas"] | error.pop("$defs", {}) | {"ErrorResponse": error}
for path, operations in paths.items():
    for operation in operations.values():
        for status in ("401", "403", "409", "422", "502", "503", "504"):
            operation["responses"][status] = {
                "description": "Typed RedJohn error",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
            }
        if path.endswith("/download"):
            operation["responses"]["200"] = {
                "description": "Authenticated report attachment",
                "content": {
                    media: {"schema": {"type": "string", "format": "binary"}}
                    for media in ("text/html", "application/json", "application/pdf")
                },
            }


def refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and child.startswith("#/components/schemas/"):
                yield child.rsplit("/", 1)[1]
            else:
                yield from refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from refs(child)


needed = set(refs(paths))
pending = list(needed)
while pending:
    identifier = pending.pop()
    for dependency in refs(schemas[identifier]):
        if dependency not in needed:
            needed.add(dependency)
            pending.append(dependency)
document = {
    "openapi": "3.1.0",
    "info": {
        "title": "RedJohn local integration extension",
        "version": "0.1.0",
        "description": (
            "CLI/Desktop profile configuration. Cloud has its own managed integration endpoints. "
            "Secrets are write-only; saving configuration does not prove model access."
        ),
    },
    "servers": [{"url": "http://127.0.0.1:8720/api/v1"}],
    "security": [{"bearerAuth": []}],
    "paths": paths,
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
        "schemas": {name: schemas[name] for name in sorted(needed)},
    },
}
(root / "contracts/local-integrations.openapi.yaml").write_text(
    yaml.safe_dump(document, sort_keys=False), encoding="utf-8"
)
