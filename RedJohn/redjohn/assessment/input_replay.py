"""Private, lossless mutation of one reviewed captured POST field.

Workers use a public query carrier. Only the trusted proxy materializes a POST;
unselected bytes, upload parts and explicitly bound session tokens stay intact.
"""

from __future__ import annotations

import hashlib
import json
import re
from base64 import b64encode
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING
from urllib.parse import quote_plus

from redjohn.assessment.body_tokens import (
    _form_spans,
    _json_spans,
    _multipart_spans,
    _Span,
    _span,
)
from redjohn.assessment.media_type import MediaTypeDenied, replay_media_type
from redjohn.assessment.request_body import ApprovedRequestBody
from redjohn.assessment.wire_encoding import WireText
from redjohn.assessment.xml_wire import XMLTokenSpan, xml_token_span


if TYPE_CHECKING:
    from redjohn.assessment.auth_replay import AuthReplayBinding
    from redjohn.assessment.models import JobSpec, Surface
    from redjohn.assessment.policy import EngagementPolicy


BODY_CAPABILITIES = frozenset({"tinja_validate", "schemathesis_validate", "oast_correlate"})
CARRIER_NAME = "rj_input"
CARRIER_BASELINE = "RJBASELINE"
MEDIA_LOCATIONS = {
    "application/json": "json",
    "application/x-www-form-urlencoded": "form",
    "multipart/form-data": "multipart",
}


class InputReplayDenied(ValueError):  # noqa: N818 - constant secret-free input code
    """A selected input cannot be materialized within its reviewed contract."""


def input_location_matches(content_type: str, location: str, *, routing_only: bool = False) -> bool:
    """Public routing only; the private body's version still authorizes decoding."""
    if routing_only and content_type == "multipart/form-data":
        return location in {"multipart", "multipart_file"}
    try:
        parsed = replay_media_type(content_type, contract_version=3)
    except MediaTypeDenied:
        return False
    expected = MEDIA_LOCATIONS.get(parsed.media_type, parsed.family)
    return location == expected or (expected == "multipart" and location == "multipart_file")


def validate_post_input(policy: EngagementPolicy, surface: Surface, spec: JobSpec) -> None:
    policy.check_replay_request(surface.url, surface.method)
    policy.check_actor(surface.actor_id)
    if (
        surface.actor_id == "anonymous"
        or surface.method != "POST"
        or surface.source != "observed"
        or not surface.request_ref
        or not surface.body_sha256
        or spec.idempotent
        or not input_location_matches(surface.content_type, surface.input_location)
        or not surface.input_name
        or len(surface.input_name.encode()) > 512
        or (
            surface.input_location not in {"json", "xml"}
            and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", surface.input_name)
        )
    ):
        raise InputReplayDenied("reviewed_named_nonidempotent_post_input_required")


def carrier_surface(surface: Surface, *, integer: bool = False) -> Surface:
    if surface.method != "POST":
        return surface
    # No original body value, token, query or upload reaches a scanner workspace.
    from urllib.parse import urlsplit  # noqa: PLC0415

    from redjohn.assessment.policy import origin_for  # noqa: PLC0415

    return replace(
        surface,
        url=origin_for(surface.url)
        + urlsplit(surface.url).path
        + "?"
        + CARRIER_NAME
        + "="
        + ("1" if integer else CARRIER_BASELINE),
        method="GET",
        content_type="",
        body_sha256="",
        input_location="query",
        input_name=CARRIER_NAME,
        input_occurrence=None,
    )


def _selected_input(body: ApprovedRequestBody, surface: Surface, numeric: bool) -> _Span:
    parsed = replay_media_type(
        body.content_type, contract_version=max(2, body.body_contract_version)
    )
    if not input_location_matches(body.content_type, surface.input_location):
        raise InputReplayDenied("body_input_location_unsupported")
    occurrence = surface.input_occurrence
    if surface.input_location == "xml":
        if body.body_contract_version != 3:
            raise InputReplayDenied("body_input_explicit_v3_required")
        wire = WireText.decode(body.data, dict(parsed.parameters).get("charset"), xml=True)
        selected = xml_token_span(
            wire, surface.input_name, occurrence or 0, unique=occurrence is None
        )
        return _Span(selected.start, selected.end, "xml_" + selected.kind, selected.encoding)
    if surface.input_location == "json":
        wire = WireText.decode(body.data, dict(parsed.parameters).get("charset"))
        _text, spans = _json_spans(body.data, surface.input_name, charset=wire.encoding)
    elif surface.input_location == "form":
        spans = _form_spans(body.data, surface.input_name, charset=parsed.charset)
    else:
        if surface.input_location == "multipart_file" and body.body_contract_version != 3:
            raise InputReplayDenied("body_input_explicit_v3_required")
        spans = _multipart_spans(
            body.data,
            body.content_type,
            surface.input_name,
            contract_version=max(2, body.body_contract_version),
        )
    if (
        not spans
        or (occurrence is None and len(spans) != 1)
        or (occurrence is not None and occurrence >= len(spans))
    ):
        raise InputReplayDenied("body_input_missing_or_ambiguous")
    span = spans[occurrence or 0]
    if surface.input_location == "json":
        # Convert only the explicitly selected occurrence; repeated keys must
        # not trigger repeated encoding of all preceding private body bytes.
        span = replace(
            span,
            start=wire.byte_offset(span.start),
            end=wire.byte_offset(span.end),
            encoding=wire.encoding,
        )
    kind = (
        "non_string"
        if numeric
        else "file"
        if surface.input_location == "multipart_file"
        else "string"
    )
    if span.kind != kind or (
        numeric
        and not re.fullmatch(r"[0-9]{1,3}", body.data[span.start : span.end].decode(span.encoding))
    ):
        raise InputReplayDenied("body_input_scalar_type_unsupported")
    return span


@dataclass(frozen=True, repr=False)
class PrivateBodyInput:
    body: ApprovedRequestBody = field(repr=False)
    location: str
    start: int
    end: int
    integer: bool = False
    encoding: str = "utf-8"
    scalar_kind: str = "string"

    @classmethod
    def from_binding(
        cls, binding: AuthReplayBinding, surface: Surface, *, integer: bool = False
    ) -> PrivateBodyInput:
        body, protected = binding.body_for_mutation()
        numeric = integer and surface.input_location == "json"
        selected = _selected_input(body, surface, numeric)
        for token in protected:
            span = _span(body, token)
            if (
                (selected.start < span.end and selected.end > span.start)
                or (span.start == span.end and selected.start <= span.start <= selected.end)
                or (selected.start == selected.end and span.start <= selected.start <= span.end)
            ):
                raise InputReplayDenied("body_input_overlaps_session_token")
        return cls(
            body,
            surface.input_location,
            selected.start,
            selected.end,
            integer,
            selected.encoding,
            selected.kind,
        )

    def mutate(self, value: str) -> bytes:
        if not isinstance(value, str) or len(value.encode()) > 4096:
            raise InputReplayDenied("body_input_value_budget_exceeded")
        if value == CARRIER_BASELINE:
            return self.body.data
        if self.integer and not re.fullmatch(r"[0-9]{1,3}", value):
            raise InputReplayDenied("body_input_integer_required")
        if self.location == "json":
            encoded = (
                value.encode(self.encoding)
                if self.integer
                else json.dumps(value, ensure_ascii=True).encode(self.encoding)
            )
        elif self.location == "form":
            encoded = quote_plus(value, safe="", encoding=self.encoding, errors="strict").encode()
        elif self.location == "xml":
            encoded = XMLTokenSpan(
                self.start, self.end, self.scalar_kind.removeprefix("xml_"), self.encoding
            ).replacement(value)
        else:
            encoded = value.encode(self.encoding)
            boundary = replay_media_type(
                self.body.content_type, contract_version=max(2, self.body.body_contract_version)
            ).boundary.encode("ascii")
            if encoded.startswith(b"--" + boundary) or b"\r\n--" + boundary in encoded:
                raise InputReplayDenied("body_input_multipart_delimiter_in_value")
        data = self.body.data[: self.start] + encoded + self.body.data[self.end :]
        # Enforce framing, delimiter, part and 64 KiB limits after substitution.
        ApprovedRequestBody.from_mapping(
            {
                "content_type": self.body.content_type,
                "body_base64": b64encode(data).decode(),
                "body_sha256": hashlib.sha256(data).hexdigest(),
                "body_contract_version": self.body.body_contract_version,
            }
        )
        return data
