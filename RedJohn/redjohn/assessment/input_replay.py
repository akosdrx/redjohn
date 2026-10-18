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
    _span,
)
from redjohn.assessment.request_body import ApprovedRequestBody


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
        or surface.input_location
        != MEDIA_LOCATIONS.get(surface.content_type.partition(";")[0].strip().lower())
        or not surface.input_name
        or len(surface.input_name.encode()) > 512
        or (
            surface.input_location != "json"
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
    )


@dataclass(frozen=True, repr=False)
class PrivateBodyInput:
    body: ApprovedRequestBody = field(repr=False)
    location: str
    start: int
    end: int
    integer: bool = False

    @classmethod
    def from_binding(
        cls, binding: AuthReplayBinding, surface: Surface, *, integer: bool = False
    ) -> PrivateBodyInput:
        body, protected = binding.body_for_mutation()
        if surface.input_location == "json":
            text, spans = _json_spans(body.data, surface.input_name)
            spans = [
                replace(s, start=len(text[: s.start].encode()), end=len(text[: s.end].encode()))
                for s in spans
            ]
        elif surface.input_location == "form":
            spans = _form_spans(body.data, surface.input_name)
        elif surface.input_location == "multipart":
            spans = _multipart_spans(body.data, body.content_type, surface.input_name)
        else:
            raise InputReplayDenied("body_input_location_unsupported")
        if len(spans) != 1:
            raise InputReplayDenied("body_input_missing_or_ambiguous")
        selected = spans[0]
        numeric = integer and surface.input_location == "json"
        if selected.kind != ("non_string" if numeric else "string") or (
            numeric and not re.fullmatch(rb"[0-9]{1,3}", body.data[selected.start : selected.end])
        ):
            raise InputReplayDenied("body_input_scalar_type_unsupported")
        for token in protected:
            span = _span(body, token)
            if selected.start < span.end and selected.end > span.start:
                raise InputReplayDenied("body_input_overlaps_session_token")
        return cls(body, surface.input_location, selected.start, selected.end, integer)

    def mutate(self, value: str) -> bytes:
        if not isinstance(value, str) or len(value.encode()) > 4096:
            raise InputReplayDenied("body_input_value_budget_exceeded")
        if value == CARRIER_BASELINE:
            return self.body.data
        if self.integer and not re.fullmatch(r"[0-9]{1,3}", value):
            raise InputReplayDenied("body_input_integer_required")
        if self.location == "json":
            encoded = (
                value.encode() if self.integer else json.dumps(value, ensure_ascii=True).encode()
            )
        elif self.location == "form":
            encoded = quote_plus(value, safe="", encoding="utf-8", errors="strict").encode()
        else:
            encoded = value.encode()
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
