"""Pinned bounded GraphQL contracts and host-private stateful scalar bindings."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.body_tokens import _json_spans
from redjohn.assessment.media_type import replay_media_type
from redjohn.assessment.wire_encoding import WireText
from redjohn.assessment.workflow_inputs import PrivateWorkflowState
from redjohn.assessment.workflow_models import bounded_name


if TYPE_CHECKING:
    from redjohn.assessment.auth_replay import AuthReplayBinding
    from redjohn.assessment.policy import EngagementPolicy


_SHA = re.compile(r"[a-f0-9]{64}\Z")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


def _constant(_value: str) -> Any:
    raise ValueError("graphql_nonfinite_json_number")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("graphql_duplicate_json_key")
        result[key] = value
    return result


def bounded_json(raw: bytes | str) -> dict[str, Any]:
    if len(raw) > 256 * 1024:
        raise ValueError("graphql_json_budget_exceeded")
    try:
        data = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (ValueError, RecursionError):
        raise ValueError("graphql_invalid_bounded_json") from None
    if not isinstance(data, dict):
        raise ValueError("graphql_single_envelope_required")  # noqa: TRY004 - hostile wire data, not caller type
    pending: list[tuple[Any, int]] = [(data, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if depth > 32 or nodes > 4096:
            raise ValueError("graphql_json_structure_budget")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
        elif current is not None and type(current) not in {str, int, float, bool}:
            raise ValueError("graphql_invalid_scalar")
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("graphql_nonfinite_json_number")
    return data


def selected(data: dict[str, Any], pointer: str) -> Any:
    if not isinstance(pointer, str) or not re.fullmatch(
        r"(?:/[A-Za-z_][A-Za-z0-9_]{0,63}){1,8}", pointer
    ):
        raise ValueError("graphql_bounded_field_pointer_required")
    current: Any = data
    for field in pointer[1:].split("/"):
        if not isinstance(current, dict) or field not in current:
            raise ValueError("graphql_response_field_missing")
        current = current[field]
    return current


@dataclass(frozen=True)
class GraphQLContract:
    name: str
    schema_file: Path
    schema_sha256: str
    document_sha256: str
    operation_name: str
    operation_type: str
    variable_bindings: tuple[tuple[str, str], ...] = ()
    extracts: tuple[tuple[str, str], ...] = ()
    expected_error_code: str = ""
    denied_data_pointer: str = ""
    actor_pointer: str = ""
    expected_fields: tuple[tuple[str, str | bool | int | None], ...] = ()

    def __post_init__(self) -> None:  # noqa: PLR0912 - bounded explicit contract schema
        try:
            if version("graphql-core") != "3.3.0":
                raise ValueError("graphql_parser_version_not_pinned")
        except PackageNotFoundError:
            raise ValueError("graphql_parser_dependency_missing") from None
        for value in (self.name, self.operation_name):
            bounded_name(value)
        if (
            self.operation_type not in {"query", "mutation"}
            or not _SHA.fullmatch(self.schema_sha256)
            or not _SHA.fullmatch(self.document_sha256)
            or not self.schema_file.is_absolute()
            or len(self.variable_bindings) > 8
            or len(self.extracts) > 8
        ):
            raise ValueError("invalid_graphql_contract")
        for variable, reference in self.variable_bindings:
            if not _FIELD.fullmatch(variable):
                raise ValueError("invalid_graphql_variable_binding")
            bounded_name(reference)
        if len({key for key, _value in self.variable_bindings}) != len(
            self.variable_bindings
        ) or len({key for key, _value in self.extracts}) != len(self.extracts):
            raise ValueError("duplicate_graphql_contract_binding")
        for reference, pointer in self.extracts:
            bounded_name(reference)
            self._pointer(pointer)
        if len(self.expected_fields) > 16:
            raise ValueError("graphql_expected_field_budget")
        for pointer, expected in self.expected_fields:
            self._pointer(pointer)
            if expected is not None and (
                type(expected) not in {str, bool, int}
                or (isinstance(expected, str) and len(expected.encode()) > 1024)
            ):
                raise ValueError("graphql_invalid_expected_scalar")
        for pointer in (self.denied_data_pointer, self.actor_pointer):
            if pointer:
                self._pointer(pointer)
        if (
            bool(self.expected_error_code) != bool(self.denied_data_pointer)
            or (self.expected_error_code and not _FIELD.fullmatch(self.expected_error_code))
            or (self.expected_error_code and self.extracts)
            or (self.expected_error_code and self.operation_type != "query")
        ):
            raise ValueError("invalid_graphql_denial_contract")
        self.schema_text()

    @staticmethod
    def _pointer(pointer: str) -> None:
        if not isinstance(pointer, str) or not re.fullmatch(
            r"/data(?:/[A-Za-z_][A-Za-z0-9_]{0,63}){1,7}", pointer
        ):
            raise ValueError("graphql_bounded_data_pointer_required")

    def schema_text(self) -> str:
        descriptor = os.open(
            self.schema_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o022
                or info.st_size > 65536
            ):
                raise ValueError("graphql_private_pinned_schema_required")
            raw = os.read(descriptor, 65537)
            after = os.fstat(descriptor)
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise ValueError("graphql_schema_changed_during_read")
        finally:
            os.close(descriptor)
        if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != self.schema_sha256:
            raise ValueError("graphql_schema_pin_mismatch")
        return raw.decode("utf-8", errors="strict")

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> GraphQLContract:
        if not isinstance(raw, dict) or set(raw) - set(cls.__dataclass_fields__):
            raise ValueError("invalid_graphql_contract_fields")
        converted = dict(raw)
        converted["schema_file"] = Path(converted["schema_file"])
        for key in ("variable_bindings", "extracts", "expected_fields"):
            converted[key] = tuple(tuple(item) for item in converted.get(key, ()))
        return cls(**converted)

    def validate_request(self, data: dict[str, Any]) -> None:  # noqa: PLR0912 - bounded pin/AST validation
        from graphql import GraphQLError, build_ast_schema, parse, validate  # noqa: PLC0415 - explicit optional GraphQL profile
        from graphql.language.ast import FieldNode, Node, OperationDefinitionNode  # noqa: PLC0415

        if version("graphql-core") != "3.3.0":
            raise ValueError("graphql_parser_version_not_pinned")
        if (
            set(data) != {"query", "operationName", "variables"}
            or not isinstance(data["query"], str)
            or len(data["query"].encode()) > 8192
            or hashlib.sha256(data["query"].encode()).hexdigest() != self.document_sha256
            or data["operationName"] != self.operation_name
            or not isinstance(data["variables"], dict)
            or len(data["variables"]) > 16
            or len(json.dumps(data["variables"]).encode()) > 16384
        ):
            raise ValueError("graphql_exact_operation_required")
        schema_text = self.schema_text()
        try:
            document = parse(data["query"], no_location=True, max_tokens=1024)
            schema_ast = parse(schema_text, no_location=True, max_tokens=4096)
        except (GraphQLError, ValueError, RecursionError):
            raise ValueError("graphql_document_parse_budget") from None
        if len(document.definitions) != 1 or not isinstance(
            document.definitions[0], OperationDefinitionNode
        ):
            raise ValueError("graphql_one_operation_no_fragments_required")
        operation = document.definitions[0]
        if (
            operation.operation.value != self.operation_type
            or operation.name is None
            or operation.name.value != self.operation_name
            or len(operation.selection_set.selections) != 1
        ):
            raise ValueError("graphql_operation_type_mismatch")
        pending: list[tuple[Node, int]] = [(document, 0), (schema_ast, 0)]
        nodes = aliases = 0
        while pending:
            node, depth = pending.pop()
            nodes += 1
            aliases += int(isinstance(node, FieldNode) and node.alias is not None)
            if nodes > 4096 or depth > 32 or aliases > 16:
                raise ValueError("graphql_ast_complexity_budget")
            if isinstance(node, FieldNode) and node.name.value.startswith("__"):
                raise ValueError("graphql_introspection_not_reviewed")
            for key in node.keys:
                value = getattr(node, key)
                if isinstance(value, Node):
                    pending.append((value, depth + 1))
                elif isinstance(value, tuple):
                    pending.extend((item, depth + 1) for item in value if isinstance(item, Node))
        try:
            if validate(build_ast_schema(schema_ast), document):
                raise ValueError("graphql_schema_document_mismatch")
        except (GraphQLError, TypeError, RecursionError):
            raise ValueError("graphql_schema_document_mismatch") from None


class GraphQLExecution:
    def __init__(
        self,
        contract: GraphQLContract,
        binding: AuthReplayBinding,
        policy: EngagementPolicy,
        instance: dict[str, Any],
        state_file: Path,
    ) -> None:
        self.contract, self.instance = contract, instance
        if (
            binding.actor_id,
            binding.tenant_id,
            binding.session_revision,
            binding.policy_revision,
        ) != (instance["actor"], instance["tenant"], instance["session_revision"], policy.revision):
            raise ValueError("graphql_capture_identity_mismatch")
        self.private = PrivateWorkflowState(state_file, policy)
        self.record = self.private.get(instance["id"])
        if self.record and (
            type(self.record.get("produced_revision")) is not int
            or not 1 <= self.record["produced_revision"] <= instance["revision"]
        ):
            raise ValueError("graphql_private_state_not_committed")
        if self.record and (
            self.record.get("actor_id"),
            self.record.get("tenant_id"),
            self.record.get("policy_revision"),
            self.record.get("definition_id"),
        ) != (instance["actor"], instance["tenant"], policy.revision, instance["definition_id"]):
            raise ValueError("graphql_private_state_identity_mismatch")
        body, protected = binding.body_for_mutation()
        media = replay_media_type(
            body.content_type, contract_version=max(2, body.body_contract_version)
        )
        if media.family != "json":
            raise ValueError("graphql_json_body_required")
        wire = WireText.decode(body.data, media.charset)
        request = bounded_json(wire.text)
        contract.validate_request(request)
        data = body.data
        replacements = []
        values = self.record.get("values", {})
        if not isinstance(values, dict) or len(values) > 16:
            raise ValueError("graphql_private_values_budget")
        for variable, reference in contract.variable_bindings:
            pointer = "/variables/" + variable
            if any(
                token.location == "json"
                and (
                    token.selector == pointer
                    or token.selector.startswith(pointer + "/")
                    or pointer.startswith(token.selector + "/")
                )
                for token in protected
            ):
                raise ValueError("graphql_auth_token_variable_protected")
            value = values.get(reference)
            if (
                not isinstance(value, str)
                or not 1 <= len(value.encode()) <= 1024
                or self.record.get("produced_revision", 0) > instance["revision"]
            ):
                raise ValueError("graphql_prior_committed_value_required")
            _text, spans = _json_spans(body.data, pointer, charset=wire.encoding)
            if len(spans) != 1 or spans[0].kind != "string":
                raise ValueError("graphql_unique_string_variable_required")
            span = spans[0]
            replacements.append(
                (
                    wire.byte_offset(span.start),
                    wire.byte_offset(span.end),
                    wire.encode_fragment(json.dumps(value, ensure_ascii=True)),
                )
            )
            request["variables"][variable] = value
        for start, end, replacement in sorted(replacements, reverse=True):
            data = data[:start] + replacement + data[end:]
        if len(data) > 65536:
            raise ValueError("graphql_request_body_budget")
        contract.validate_request(request)
        self.body = data

    def observe(self, raw: bytes, *, content_type: str = "application/json") -> bool:  # noqa: PLR0911 - bounded explicit response assertions
        media = replay_media_type(content_type, contract_version=3)
        if media.family != "json" or len(raw) > 256 * 1024:
            raise ValueError("graphql_json_response_required")
        response = bounded_json(raw.decode(media.charset, errors="strict").removeprefix("\ufeff"))
        errors = response.get("errors", [])
        if "errors" in response and (not isinstance(errors, list) or not errors):
            return False
        if self.contract.expected_error_code:
            return (
                isinstance(errors, list)
                and 1 <= len(errors) <= 8
                and all(
                    isinstance(item, dict)
                    and isinstance(item.get("extensions"), dict)
                    and item["extensions"].get("code") == self.contract.expected_error_code
                    for item in errors
                )
                and selected(response, self.contract.denied_data_pointer) is None
            )
        if errors or not isinstance(response.get("data"), dict):
            return False
        if (
            self.contract.actor_pointer
            and selected(response, self.contract.actor_pointer) != self.instance["actor"]
        ):
            return False
        for pointer, expected in self.contract.expected_fields:
            actual = selected(response, pointer)
            if type(actual) is not type(expected) or actual != expected:
                return False
        values = dict(self.record.get("values", {}))
        for reference, pointer in self.contract.extracts:
            value = selected(response, pointer)
            if not isinstance(value, str) or not 1 <= len(value.encode()) <= 1024:
                return False
            values[reference] = value
        if len(values) > 16 or sum(len(value.encode()) for value in values.values()) > 16384:
            raise ValueError("graphql_private_value_budget")
        if self.contract.extracts:
            self.private.put(
                self.instance["id"],
                {
                    "actor_id": self.instance["actor"],
                    "tenant_id": self.instance["tenant"],
                    "policy_revision": self.instance["policy_revision"],
                    "definition_id": self.instance["definition_id"],
                    "produced_revision": self.instance["revision"] + 1,
                    "values": values,
                },
            )
        return True
