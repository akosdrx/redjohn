"""Reviewed body-token substitutions that preserve every unbound wire byte.

Bindings are private operator configuration, never target-discovered selectors.
A successful substitution produces pending capture input, not replay authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from base64 import b64encode
from dataclasses import dataclass
from typing import Any, NoReturn
from urllib.parse import quote_plus, unquote_plus

from redjohn.assessment.media_type import (
    parse_media_type,
    replay_media_type,
    same_replay_media_type,
)
from redjohn.assessment.request_body import ApprovedRequestBody, RequestBodyDenied
from redjohn.assessment.wire_encoding import WireEncodingDenied, WireText
from redjohn.assessment.xml_wire import XMLBodyDenied, XMLTokenSpan, xml_token_span


_MAX_BINDINGS = 16
_MAX_TOKEN_BYTES = 4096
_MAX_TOKEN_TOTAL = 16 * 1024
_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_STRING = re.compile(r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"')
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_PART = re.compile(
    rb'form-data; name="([A-Za-z0-9_.:-]{1,128})"(?:; filename="[^"\r\n]{1,255}")?\Z'
)


class BodyTokenDenied(ValueError):  # noqa: N818 - stable secret-free input error
    """Only a constant host-selected code may leave the private rotation path."""


def _deny(code: str) -> NoReturn:
    raise BodyTokenDenied("auth_replay_body_token_" + code)


def _utf8_size(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        _deny("invalid_utf8")


@dataclass(frozen=True, repr=False)
class BodyTokenBinding:
    location: str
    selector: str
    occurrence: int
    source_kind: str
    source_name: str


@dataclass(frozen=True, repr=False)
class _Span:
    start: int
    end: int
    kind: str = "string"
    encoding: str = "utf-8"


def _pointer(value: str) -> tuple[str, ...]:
    if value == "":
        return ()
    if not value.startswith("/") or re.search(r"~(?![01])", value):
        _deny("invalid_json_pointer")
    return tuple(item.replace("~1", "/").replace("~0", "~") for item in value[1:].split("/"))


def _json_spans(  # noqa: PLR0915 - bounded lossless JSON parser
    body: bytes, pointer: str, *, charset: str | None = None
) -> tuple[str, list[_Span]]:
    text = WireText.decode(body, charset).text
    selected = _pointer(pointer)
    spans: list[_Span] = []
    at, nodes = 0, 0

    def whitespace() -> None:
        nonlocal at
        while at < len(text) and text[at] in " \r\n\t":
            at += 1

    def string() -> tuple[int, int, str]:
        nonlocal at
        match = _STRING.match(text, at)
        if not match:
            _deny("invalid_json_structure")
        start, at = at, match.end()
        return start, at, json.loads(match.group())

    def value(path: tuple[str, ...], depth: int) -> None:  # noqa: PLR0912, PLR0915 - lossless bounded JSON walker
        nonlocal at, nodes
        nodes += 1
        if depth > 64 or nodes > 4096:
            _deny("json_structure_budget")
        whitespace()
        start = at
        kind = "non_string"
        if at >= len(text):
            _deny("invalid_json_structure")
        if text[at] == '"':
            string()
            kind = "string"
        elif text[at] == "{":
            at += 1
            whitespace()
            if at < len(text) and text[at] != "}":
                while True:
                    whitespace()
                    _, _, key = string()
                    whitespace()
                    if at >= len(text) or text[at] != ":":
                        _deny("invalid_json_structure")
                    at += 1
                    value((*path, key), depth + 1)
                    whitespace()
                    if at < len(text) and text[at] == ",":
                        at += 1
                        continue
                    break
            if at >= len(text) or text[at] != "}":
                _deny("invalid_json_structure")
            at += 1
        elif text[at] == "[":
            at += 1
            index = 0
            whitespace()
            if at < len(text) and text[at] != "]":
                while True:
                    value((*path, str(index)), depth + 1)
                    index += 1
                    whitespace()
                    if at < len(text) and text[at] == ",":
                        at += 1
                        continue
                    break
            if at >= len(text) or text[at] != "]":
                _deny("invalid_json_structure")
            at += 1
        else:
            match = _NUMBER.match(text, at)
            literal = next(
                (item for item in ("true", "false", "null") if text.startswith(item, at)), None
            )
            if match:
                at = match.end()
            elif literal:
                at += len(literal)
            else:
                _deny("invalid_json_structure")
        if path == selected:
            spans.append(_Span(start, at, kind))

    value((), 0)
    whitespace()
    if at != len(text):
        _deny("invalid_json_structure")
    return text, spans


def _form_spans(body: bytes, field: str, *, charset: str = "utf-8") -> list[_Span]:
    spans = []
    offset = 0
    for part in body.split(b"&"):
        name, equals, _value = part.partition(b"=")
        if unquote_plus(name.decode("ascii"), encoding=charset, errors="strict") == field:
            spans.append(
                _Span(
                    offset + len(name) + len(equals),
                    offset + len(part),
                    "string" if equals else "missing_equals",
                    charset,
                )
            )
        offset += len(part) + 1
    return spans


def _multipart_spans(
    body: bytes, content_type: str, field: str, *, contract_version: int = 2
) -> list[_Span]:
    parsed_type = replay_media_type(content_type, contract_version=contract_version)
    boundary = parsed_type.boundary.encode("ascii")
    delimiter = b"--" + boundary
    middle = b"\r\n" + delimiter + b"\r\n"
    pieces = body[len(delimiter) + 2 : -len(delimiter) - 6].split(middle)
    spans = []
    offset = len(delimiter) + 2
    for part in pieces:
        raw_headers, payload = part.split(b"\r\n\r\n", 1)
        disposition = next(
            (
                line.partition(b":")[2].strip(b" ")
                for line in raw_headers.split(b"\r\n")
                if line.partition(b":")[0].lower() == b"content-disposition"
            ),
            b"",
        )
        match = _PART.fullmatch(disposition)
        if match is not None and match.group(1).decode() == field:
            start = offset + len(raw_headers) + 4
            end = start + len(payload)
            kind = "file" if b"; filename=" in disposition else "string"
            encoding = "utf-8"
            if contract_version == 3:
                raw_type = next(
                    (
                        line.partition(b":")[2].strip().decode("ascii")
                        for line in raw_headers.split(b"\r\n")
                        if line.partition(b":")[0].lower() == b"content-type"
                    ),
                    None,
                )
                part_type = parse_media_type(raw_type or "text/plain")
                if kind == "file" and not (
                    raw_type is not None
                    and (
                        part_type.media_type.startswith("text/")
                        or part_type.family in {"json", "xml"}
                    )
                ):
                    kind = "binary_file"
                if kind != "binary_file":
                    wire = WireText.decode(
                        payload, dict(part_type.parameters).get("charset", parsed_type.charset)
                    )
                    encoding = wire.encoding
                    start += len(wire.preamble)
            spans.append(_Span(start, end, kind, encoding))
        offset += len(part) + len(middle)
    return spans


def _body_wire(body: ApprovedRequestBody, *, xml: bool = False) -> WireText:
    return WireText.decode(
        body.data, dict(parse_media_type(body.content_type).parameters).get("charset"), xml=xml
    )


def _span(body: ApprovedRequestBody, binding: BodyTokenBinding) -> _Span:
    try:
        return _selected_span(body, binding)
    except (WireEncodingDenied, XMLBodyDenied, UnicodeError):
        _deny("invalid_selected_wire_value")


def _selected_span(body: ApprovedRequestBody, binding: BodyTokenBinding) -> _Span:
    parsed = replay_media_type(
        body.content_type, contract_version=max(2, body.body_contract_version)
    )
    media = parsed.media_type
    if binding.location == "xml" and body.body_contract_version == 3 and parsed.family == "xml":
        selected = xml_token_span(_body_wire(body, xml=True), binding.selector, binding.occurrence)
        return _Span(selected.start, selected.end, "xml_" + selected.kind, selected.encoding)
    if binding.location == "json" and parsed.family == "json":
        wire = _body_wire(body)
        _text, spans = _json_spans(body.data, binding.selector, charset=wire.encoding)
    elif binding.location == "form" and media == "application/x-www-form-urlencoded":
        spans = _form_spans(body.data, binding.selector, charset=parsed.charset)
    elif binding.location in {"multipart", "multipart_file"} and media == "multipart/form-data":
        spans = _multipart_spans(
            body.data,
            body.content_type,
            binding.selector,
            contract_version=max(2, body.body_contract_version),
        )
    else:
        _deny("location_content_type_mismatch")
    if binding.occurrence >= len(spans):
        _deny("selector_not_found")
    result = spans[binding.occurrence]
    expected_kind = (
        "file"
        if binding.location == "multipart_file" and body.body_contract_version == 3
        else "string"
    )
    if result.kind != expected_kind:
        _deny("string_field_required")
    if binding.location == "json":
        # Convert only the selected occurrence; repeated JSON keys cannot cause
        # quadratic repeated-prefix encoding or change unrelated UTF-8 bytes.
        return _Span(
            wire.byte_offset(result.start), wire.byte_offset(result.end), encoding=wire.encoding
        )
    return result


def validate_body_token_bindings(
    body: ApprovedRequestBody, value: object
) -> tuple[BodyTokenBinding, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_BINDINGS:
        _deny("invalid_bindings")
    result = []
    selected: set[tuple[int, int]] = set()
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"location", "selector", "occurrence", "source"}
            or not isinstance(item["location"], str)
            or item["location"] not in {"json", "form", "multipart", "xml", "multipart_file"}
            or not isinstance(item["selector"], str)
            or _utf8_size(item["selector"]) > 512
            or type(item["occurrence"]) is not int
            or not 0 <= item["occurrence"] <= 127
            or not isinstance(item["source"], dict)
            or set(item["source"]) != {"kind", "name"}
            or not isinstance(item["source"]["kind"], str)
            or item["source"]["kind"] not in {"header", "cookie", "response"}
            or not isinstance(item["source"]["name"], str)
            or not _NAME.fullmatch(item["source"]["name"])
        ):
            _deny("invalid_binding")
        if item["location"] not in {"json", "xml"} and not _NAME.fullmatch(item["selector"]):
            _deny("invalid_field_name")
        if item["location"] in {"xml", "multipart_file"} and body.body_contract_version != 3:
            _deny("explicit_v3_binding_required")
        binding = BodyTokenBinding(
            item["location"],
            item["selector"],
            item["occurrence"],
            item["source"]["kind"],
            item["source"]["name"],
        )
        target = _span(body, binding)
        if (target.start, target.end) in selected or any(
            not (target.end <= start or target.start >= end) for start, end in selected
        ):
            _deny("overlapping_bindings")
        selected.add((target.start, target.end))
        result.append(binding)
    return tuple(result)


def validate_response_body_tokens(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > _MAX_BINDINGS:
        _deny("invalid_response_values")
    values = {}
    total = 0
    for name, token in value.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            _deny("invalid_response_name")
        _token(token)
        total += len(token.encode())
        values[name] = token
    if total > _MAX_TOKEN_TOTAL:
        _deny("response_token_budget")
    return values


def _token(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _utf8_size(value) > _MAX_TOKEN_BYTES
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        _deny("invalid_refreshed_value")
    return value


def _refreshed_value(
    binding: BodyTokenBinding, response: dict[str, Any], response_tokens: dict[str, str]
) -> str:
    if binding.source_kind == "header":
        candidates = [
            value
            for name, value in response["headers"].items()
            if name.lower() == binding.source_name.lower()
        ]
    elif binding.source_kind == "cookie":
        candidates = [
            item["value"] for item in response["cookies"] if item["name"] == binding.source_name
        ]
    else:
        candidates = (
            [response_tokens[binding.source_name]] if binding.source_name in response_tokens else []
        )
    if len(candidates) != 1:
        _deny("refreshed_source_missing_or_ambiguous")
    return _token(candidates[0])


def validate_rotation_token_budget(
    requests: list[dict[str, Any]], response: dict[str, Any]
) -> None:
    """Bound unique refreshed sources across every request in one rotation."""
    response_tokens = validate_response_body_tokens(response.get("body_tokens", {}))
    unique: dict[tuple[str, str], str] = {}
    for request in requests:
        if "body_tokens" not in request:
            continue
        body = ApprovedRequestBody.from_mapping(request)
        for binding in validate_body_token_bindings(body, request["body_tokens"]):
            key = (
                binding.source_kind,
                binding.source_name.lower()
                if binding.source_kind == "header"
                else binding.source_name,
            )
            unique[key] = _refreshed_value(binding, response, response_tokens)
    if (
        len(unique) > _MAX_BINDINGS
        or sum(_utf8_size(value) for value in unique.values()) > _MAX_TOKEN_TOTAL
    ):
        _deny("rotation_token_budget")


def rotate_body_tokens(request: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    """Return private pending-capture input, with no authority from old evidence."""
    body = ApprovedRequestBody.from_mapping(request)
    bindings = validate_body_token_bindings(body, request["body_tokens"])
    response_tokens = validate_response_body_tokens(response.get("body_tokens", {}))
    replacements = []
    total = 0
    for binding in bindings:
        token = _refreshed_value(binding, response, response_tokens)
        total += len(token.encode())
        if total > _MAX_TOKEN_TOTAL:
            _deny("bound_token_budget")
        target = _span(body, binding)
        replacement = _replacement(body, binding, target, token)
        replacements.append((target.start, target.end, replacement))
    data = body.data
    for start, end, replacement in sorted(replacements, reverse=True):
        data = data[:start] + replacement + data[end:]
    digest = hashlib.sha256(data).hexdigest()
    updated = {
        **request,
        "body_base64": b64encode(data).decode(),
        "body_sha256": digest,
        "request_ref": "pending-capture:" + digest,
        "replay_safety": "fresh-capture-required",
    }
    ApprovedRequestBody.from_mapping(updated)
    validate_body_token_bindings(ApprovedRequestBody.from_mapping(updated), updated["body_tokens"])
    return updated


def _replacement(
    body: ApprovedRequestBody, binding: BodyTokenBinding, target: _Span, token: str
) -> bytes:
    try:
        if binding.location == "xml":
            return XMLTokenSpan(
                target.start, target.end, target.kind.removeprefix("xml_"), target.encoding
            ).replacement(token)
        if binding.location == "json":
            return json.dumps(token, ensure_ascii=True).encode(target.encoding)
        if binding.location == "form":
            return quote_plus(token, safe="", encoding=target.encoding, errors="strict").encode(
                "ascii"
            )
        delimiter = b"--" + parse_media_type(body.content_type).boundary.encode("ascii")
        replacement = token.encode(target.encoding)
        if delimiter in replacement:
            _deny("multipart_delimiter_in_value")
    except (UnicodeError, XMLBodyDenied):
        _deny("token_not_representable_in_selected_wire_value")
    else:
        return replacement


def matches_refreshed_capture(  # noqa: PLR0911 - explicit fresh-capture rejection gates
    expected_content_type: str,
    expected_body: bytes,
    actual_content_type: str,
    actual_body: bytes,
    *,
    expected_body_contract_version: int = 1,
    actual_body_contract_version: int = 1,
) -> bool:
    """Compare a real fresh capture, allowing only regenerated multipart framing."""
    if not all(isinstance(value, str) for value in (expected_content_type, actual_content_type)):
        return False
    if not all(isinstance(value, bytes) for value in (expected_body, actual_body)):
        return False
    try:
        for content_type, data, version in (
            (expected_content_type, expected_body, expected_body_contract_version),
            (actual_content_type, actual_body, actual_body_contract_version),
        ):
            ApprovedRequestBody.from_mapping(
                {
                    "content_type": content_type,
                    "body_base64": b64encode(data).decode(),
                    "body_sha256": hashlib.sha256(data).hexdigest(),
                    "body_contract_version": version,
                }
            )
        # Extended approval must be explicit on both sides of a fresh capture.
        if (expected_body_contract_version == 3) != (actual_body_contract_version == 3):
            return False
        version = max(2, expected_body_contract_version, actual_body_contract_version)
        if not same_replay_media_type(
            expected_content_type,
            actual_content_type,
            ignore_boundary=True,
            contract_version=version,
        ):
            return False
        if (
            replay_media_type(expected_content_type, contract_version=version).media_type
            != "multipart/form-data"
        ):
            return expected_body == actual_body and (
                expected_content_type == actual_content_type
                or expected_body_contract_version == 2
                or actual_body_contract_version == 2
                or expected_body_contract_version == actual_body_contract_version == 3
            )

        def parts(content_type: str, data: bytes) -> tuple[bytes, ...]:
            delimiter = b"--" + replay_media_type(
                content_type, contract_version=version
            ).boundary.encode("ascii")
            return tuple(
                data[len(delimiter) + 2 : -len(delimiter) - 6].split(b"\r\n" + delimiter + b"\r\n")
            )

        return parts(expected_content_type, expected_body) == parts(
            actual_content_type, actual_body
        )
    except (RequestBodyDenied, ValueError, TypeError, UnicodeError):
        return False
