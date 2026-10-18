"""Bounded validation of approved request bytes; never re-encode a replay body."""

from __future__ import annotations

import hashlib
import json
import math
import re
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from typing import Any, NoReturn
from urllib.parse import parse_qsl

from redjohn.assessment.media_type import MediaTypeDenied, parse_media_type, replay_media_type


MAX_REPLAY_BODY_BYTES = 64 * 1024
HOST_REPLAY_BODY_MARKER = "REDJOHN_HOST_REPLAY_BODY_V1"
HOST_REPLAY_MULTIPART_CONTENT_TYPE = "multipart/form-data; boundary=REDJOHN_HOST_REPLAY_BOUNDARY_V1"
_BOUNDARY = re.compile(r"[A-Za-z0-9_-]{1,70}\Z")
_DISPOSITION = re.compile(
    rb'form-data; name="([A-Za-z0-9_.:-]{1,128})"(?:; filename="([^"\r\n]{1,255})")?\Z'
)
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class RequestBodyDenied(ValueError):  # noqa: N818 - secret-free contract error
    """A request body did not match the bounded replay wire contract."""


def _reject(code: str) -> NoReturn:
    raise RequestBodyDenied("auth_replay_body_" + code)


def _json_values(value: object) -> list[str]:
    if isinstance(value, dict):
        return [part for item in value.values() for part in _json_values(item)]
    if isinstance(value, (list, tuple)):
        return [part for item in value for part in _json_values(item)]
    if isinstance(value, str):
        return [value] if value else []
    if value is None or isinstance(value, bool):
        return [json.dumps(value)]
    return []


def _decode_body(encoded: str, digest: str) -> bytes:
    try:
        body = b64decode(encoded, validate=True)
    except (ValueError, UnicodeError):
        _reject("invalid_base64")
    if b64encode(body).decode() != encoded:
        _reject("noncanonical_base64")
    if len(body) > MAX_REPLAY_BODY_BYTES:
        _reject("budget_exceeded")
    if hashlib.sha256(body).hexdigest() != digest:
        _reject("hash_mismatch")
    return body


def _multipart_values(body: bytes, boundary: str, *, extended: bool = False) -> list[str]:  # noqa: PLR0912
    delimiter = b"--" + boundary.encode("ascii")
    if not body.startswith(delimiter + b"\r\n") or not body.endswith(delimiter + b"--\r\n"):
        _reject("invalid_multipart")
    pieces = body[len(delimiter) + 2 : -len(delimiter) - 6].split(b"\r\n" + delimiter + b"\r\n")
    if not 1 <= len(pieces) <= 32:
        _reject("multipart_part_budget_exceeded")
    values: list[str] = []
    for piece in pieces:
        if b"\r\n\r\n" not in piece:
            _reject("invalid_multipart")
        raw_headers, payload = piece.split(b"\r\n\r\n", 1)
        if len(raw_headers) > 4096 or delimiter in payload:
            _reject("ambiguous_multipart")
        headers: dict[bytes, bytes] = {}
        for line in raw_headers.split(b"\r\n"):
            if b":" not in line:
                _reject("invalid_multipart_headers")
            name, value = line.split(b":", 1)
            if (
                name.lower() not in {b"content-disposition", b"content-type"}
                or name.lower() in headers
            ):
                _reject("invalid_multipart_headers")
            if any(char < 32 or char > 126 for char in value):
                _reject("invalid_multipart_headers")
            headers[name.lower()] = value.strip(b" ")
        disposition = _DISPOSITION.fullmatch(headers.get(b"content-disposition", b""))
        if not disposition:
            _reject("invalid_multipart_disposition")
        filename = disposition.group(2)
        if filename is not None:
            if (
                b"/" in filename
                or b"\\" in filename
                or filename in {b".", b".."}
                or any(char < 32 or char > 126 for char in filename)
            ):
                _reject("invalid_multipart_filename")
            values.append(filename.decode("ascii"))
        media_type = headers.get(b"content-type")
        if media_type is not None:
            if extended:
                try:
                    part_type = parse_media_type(media_type.decode("ascii"))
                    charset = dict(part_type.parameters).get("charset", "utf-8")
                    if filename is None and charset.lower() != "utf-8":
                        _reject("unsupported_charset")
                except (MediaTypeDenied, UnicodeError):
                    _reject("invalid_multipart_content_type")
            elif not re.fullmatch(rb"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media_type):
                _reject("invalid_multipart_content_type")
        values.append(b64encode(payload).decode())
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            if text:
                values.append(text)
    return values


@dataclass(frozen=True, repr=False)
class ApprovedRequestBody:
    """Private exact bytes plus public integrity metadata for one reviewed POST."""

    content_type: str
    sha256: str
    data: bytes = field(repr=False)
    redaction_values: tuple[str, ...] = field(repr=False)
    body_contract_version: int = 1

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> ApprovedRequestBody:
        content_type = value.get("content_type")
        encoded = value.get("body_base64")
        digest = value.get("body_sha256")
        version = value.get("body_contract_version", 1)
        if type(version) is not int or version not in {1, 2}:
            _reject("contract_version")
        if (
            not isinstance(content_type, str)
            or len(content_type) > 256
            or not isinstance(encoded, str)
            or len(encoded) > ((MAX_REPLAY_BODY_BYTES + 2) // 3) * 4
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            _reject("invalid_schema")
        body = _decode_body(encoded, digest)
        media, boundary = content_type, ""
        if version == 2:
            try:
                parsed_type = replay_media_type(content_type)
                media, boundary = parsed_type.media_type, parsed_type.boundary
            except MediaTypeDenied as exc:
                _reject(str(exc))
        values = [encoded]
        if media in {"application/json", "application/json; charset=utf-8"}:
            try:
                decoded = body.decode("utf-8")
                numeric_values: list[str] = []

                def numeric_text(text: str) -> str:
                    # Keep exact lexical numbers without allocating arbitrary
                    # precision integers or expanding unbounded exponents.
                    numeric_values.append(text)
                    number = float(text)
                    if math.isfinite(number):
                        numeric_values.append(json.dumps(number))
                        if number.is_integer() and abs(number) < 1e18:
                            numeric_values.append(str(int(number)))
                    return text

                parsed = json.loads(
                    decoded,
                    parse_constant=lambda _value: _reject("invalid_json"),
                    object_pairs_hook=lambda pairs: tuple(item for _key, item in pairs),
                    parse_int=numeric_text,
                    parse_float=numeric_text,
                )
                body_values = _json_values(parsed)
            except (UnicodeError, ValueError, RecursionError):
                _reject("invalid_json")
            values.extend([decoded, *body_values, *numeric_values])
        elif media in {
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded; charset=utf-8",
        }:
            try:
                decoded = body.decode("ascii")
                if _BAD_ESCAPE.search(decoded):
                    _reject("invalid_form_encoding")
                pairs = parse_qsl(
                    decoded,
                    keep_blank_values=True,
                    encoding="utf-8",
                    errors="strict",
                    max_num_fields=128,
                )
            except (UnicodeError, ValueError):
                _reject("invalid_form_encoding")
            values.extend([decoded, *(item for pair in pairs for item in pair if item)])
        elif boundary or content_type.startswith("multipart/form-data; boundary="):
            boundary = boundary or content_type.removeprefix("multipart/form-data; boundary=")
            if version == 1 and not _BOUNDARY.fullmatch(boundary):
                _reject("invalid_multipart_boundary")
            values.extend(_multipart_values(body, boundary, extended=version == 2))
        else:
            _reject("unsupported_content_type")
        # Targets commonly trim form/file values before reflecting them. Keep
        # those deterministic variants private alongside the exact wire value.
        values += [value.strip() for value in values if value.strip()]
        return cls(
            content_type,
            digest,
            body,
            tuple(value for value in dict.fromkeys(values) if value),
            version,
        )
