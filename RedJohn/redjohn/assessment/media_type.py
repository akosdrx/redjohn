"""Bounded MIME interpretation; callers always retain the original wire header."""

from __future__ import annotations

import re
from dataclasses import dataclass

from redjohn.assessment.wire_encoding import WireEncodingDenied, canonical_charset


_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_BOUNDARY = re.compile(r"[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]\Z")
_MEDIA = frozenset({"application/json", "application/x-www-form-urlencoded", "multipart/form-data"})


class MediaTypeDenied(ValueError):  # noqa: N818 - constant secret-free error
    """The header is ambiguous or outside the explicitly selected replay version."""


@dataclass(frozen=True, repr=False)
class MediaType:
    media_type: str
    parameters: tuple[tuple[str, str], ...]

    @property
    def boundary(self) -> str:
        return dict(self.parameters).get("boundary", "")

    @property
    def charset(self) -> str:
        return canonical_charset(dict(self.parameters).get("charset", "utf-8"))

    @property
    def family(self) -> str:
        if self.media_type == "application/json" or (
            self.media_type.startswith("application/") and self.media_type.endswith("+json")
        ):
            return "json"
        if self.media_type in {"application/xml", "text/xml"} or (
            self.media_type.startswith("application/") and self.media_type.endswith("+xml")
        ):
            return "xml"
        return self.media_type


def _parameter_value(value: str, index: int) -> tuple[str, int]:
    if index < len(value) and value[index] == '"':
        index += 1
        chars = []
        while index < len(value) and value[index] != '"':
            if value[index] == "\\":
                index += 1
                if index >= len(value):
                    raise MediaTypeDenied("invalid_mime_syntax")
            chars.append(value[index])
            index += 1
        if index >= len(value):
            raise MediaTypeDenied("invalid_mime_syntax")
        return "".join(chars), index + 1
    match = _TOKEN.match(value, index)
    if match is None:
        raise MediaTypeDenied("invalid_mime_syntax")
    return match[0], match.end()


def parse_media_type(value: str) -> MediaType:
    """Parse at most 256 ASCII bytes and eight unique token/quoted parameters."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any((ord(c) < 32 and c != "\t") or ord(c) > 126 for c in value)
    ):
        raise MediaTypeDenied("invalid_mime_syntax")
    index = 0

    def whitespace() -> None:
        nonlocal index
        while index < len(value) and value[index] in " \t":
            index += 1

    def token() -> str:
        nonlocal index
        match = _TOKEN.match(value, index)
        if match is None:
            raise MediaTypeDenied("invalid_mime_syntax")
        index = match.end()
        return match[0]

    whitespace()
    major = token()
    if index >= len(value) or value[index] != "/":
        raise MediaTypeDenied("invalid_mime_syntax")
    index += 1
    subtype = token()
    parameters: dict[str, str] = {}
    whitespace()
    while index < len(value):
        if value[index] != ";" or len(parameters) >= 8:
            raise MediaTypeDenied("invalid_mime_syntax")
        index += 1
        whitespace()
        name = token().lower()
        if name in parameters:
            raise MediaTypeDenied("duplicate_mime_parameter")
        whitespace()
        if index >= len(value) or value[index] != "=":
            raise MediaTypeDenied("invalid_mime_syntax")
        index += 1
        whitespace()
        parameter, index = _parameter_value(value, index)
        parameters[name] = parameter
        whitespace()
    return MediaType((major + "/" + subtype).lower(), tuple(parameters.items()))


def replay_media_type(value: str, *, contract_version: int = 2) -> MediaType:
    parsed = parse_media_type(value)
    parameters = dict(parsed.parameters)
    allowed = {"charset", "boundary"} if parsed.media_type == "multipart/form-data" else {"charset"}
    if type(contract_version) is not int or contract_version not in {2, 3}:
        raise MediaTypeDenied("unsupported_body_contract_version")
    supported = parsed.media_type in _MEDIA or (
        contract_version == 3 and parsed.family in {"json", "xml"}
    )
    if not supported or not set(parameters) <= allowed:
        raise MediaTypeDenied("unsupported_content_type")
    if (
        contract_version == 2
        and "charset" in parameters
        and parameters["charset"].lower() != "utf-8"
    ):
        raise MediaTypeDenied("unsupported_charset")
    if contract_version == 3:
        try:
            canonical_charset(parameters.get("charset", "utf-8"))
        except WireEncodingDenied:
            raise MediaTypeDenied("unsupported_charset") from None
    if parsed.media_type == "multipart/form-data" and not _BOUNDARY.fullmatch(parsed.boundary):
        raise MediaTypeDenied("invalid_multipart_boundary")
    return parsed


def same_replay_media_type(
    left: str, right: str, *, ignore_boundary: bool = False, contract_version: int = 2
) -> bool:
    """Compare the selected version's MIME/charset without rewriting a header."""
    try:
        a, b = (
            replay_media_type(value, contract_version=contract_version) for value in (left, right)
        )
    except MediaTypeDenied:
        return False
    return (
        a.media_type == b.media_type
        and a.charset == b.charset
        and (ignore_boundary or a.boundary == b.boundary)
    )
