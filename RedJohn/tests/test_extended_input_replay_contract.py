"""Real byte/parser contracts with synthetic private bindings; no scanner E2E."""

import hashlib
import json
from base64 import b64encode
from dataclasses import replace
from urllib.parse import quote_plus

import pytest

from redjohn.assessment.body_tokens import validate_body_token_bindings
from redjohn.assessment.input_replay import (
    InputReplayDenied,
    PrivateBodyInput,
    carrier_surface,
    input_location_matches,
)
from redjohn.assessment.models import Surface
from redjohn.assessment.request_body import ApprovedRequestBody
from tests.test_authenticated_schema_oast_contract import approved


def private_input(raw, media, location, selector, *, occurrence=None, protected=None):
    surface, binding, _body = approved("json")
    body = ApprovedRequestBody.from_mapping(
        {
            "content_type": media,
            "body_base64": b64encode(raw).decode(),
            "body_sha256": hashlib.sha256(raw).hexdigest(),
            "body_contract_version": 3,
        }
    )
    tokens = validate_body_token_bindings(body, protected) if protected else ()
    surface = replace(
        surface,
        content_type=media,
        input_location=location,
        input_name=selector,
        input_occurrence=occurrence,
        body_sha256=body.sha256,
    )
    return surface, replace(binding, _body=body, _body_tokens=tokens), body


def token(location, selector, occurrence=0):
    return {
        "location": location,
        "selector": selector,
        "occurrence": occurrence,
        "source": {"kind": "header", "name": "X-CSRF-Token"},
    }


@pytest.mark.parametrize(
    "codec",
    ["utf-8", "iso-8859-1", "windows-1250", "windows-1252", "utf-16", "utf-16-le", "utf-16-be"],
)
def test_selected_repeated_vendor_json_keeps_codec_bom_and_session_token(codec):
    text = '{"label":"café","value":"first","value":"second","csrf":"protected-token"}'
    surface, binding, body = private_input(
        text.encode(codec),
        "application/vnd.redjohn+json; charset=" + codec,
        "json",
        "/value",
        occurrence=1,
        protected=[token("json", "/csrf")],
    )
    selected = PrivateBodyInput.from_binding(binding, surface)
    value = 'café"\\&'
    expected = text.replace('"second"', json.dumps(value, ensure_ascii=True)).encode(codec)
    assert selected.mutate(value) == expected
    assert selected.mutate("RJBASELINE") == body.data
    assert carrier_surface(surface).input_occurrence is None
    with pytest.raises(ValueError, match="overlaps_session_token"):
        PrivateBodyInput.from_binding(
            binding, replace(surface, input_name="/csrf", input_occurrence=0)
        )


@pytest.mark.parametrize("kind", ["json", "form"])
def test_duplicate_requires_explicit_occurrence_including_explicit_zero(kind):
    surface, binding, body = approved(kind, duplicate=True)
    with pytest.raises(InputReplayDenied, match="missing_or_ambiguous"):
        PrivateBodyInput.from_binding(binding, surface)
    first = PrivateBodyInput.from_binding(binding, replace(surface, input_occurrence=0))
    second = PrivateBodyInput.from_binding(binding, replace(surface, input_occurrence=1))
    assert first.start < second.start
    assert first.mutate("replacement").endswith(body.data[first.end :])
    assert second.mutate("replacement").startswith(body.data[: second.start])
    assert surface.key != replace(surface, input_occurrence=0).key


@pytest.mark.parametrize("codec", ["utf-8", "iso-8859-1", "windows-1252", "utf-16"])
@pytest.mark.parametrize("selector", ["/r/value", "/r/@value"])
def test_xml_selected_text_or_attribute_keeps_declaration_bom_and_other_bytes(codec, selector):
    text = (
        f'<?xml version="1.0" encoding="{codec}"?><r value="old">'
        "<value>old</value><csrf>protected-token</csrf></r>"
    )
    surface, binding, _body = private_input(
        text.encode(codec),
        "application/xml; charset=" + codec,
        "xml",
        selector,
        protected=[token("xml", "/r/csrf")],
    )
    changed = PrivateBodyInput.from_binding(binding, surface).mutate('new<&"value')
    expected = (
        text.replace('value="old"', 'value="new&lt;&amp;&quot;value"')
        if selector.endswith("@value")
        else text.replace("<value>old</value>", '<value>new&lt;&amp;"value</value>')
    )
    assert changed == expected.encode(codec)
    with pytest.raises(ValueError, match="overlaps_session_token"):
        PrivateBodyInput.from_binding(binding, replace(surface, input_name="/r/csrf"))


def test_xml_ambiguity_and_cdata_terminator_are_rejected_without_body_change():
    surface, binding, body = private_input(
        b"<r><v>one</v><v><![CDATA[two]]></v></r>", "application/xml", "xml", "/r/v"
    )
    with pytest.raises(ValueError, match="xml_selector_ambiguous"):
        PrivateBodyInput.from_binding(binding, surface)
    selected = PrivateBodyInput.from_binding(binding, replace(surface, input_occurrence=1))
    assert selected.mutate("<&safe") == b"<r><v>one</v><v><![CDATA[<&safe]]></v></r>"
    with pytest.raises(ValueError, match="cdata_terminator"):
        selected.mutate("]]>")
    assert body.data == b"<r><v>one</v><v><![CDATA[two]]></v></r>"


@pytest.mark.parametrize("codec", ["utf-8", "iso-8859-1", "windows-1250", "windows-1252"])
def test_form_repeated_selected_field_uses_approved_percent_encoding(codec):
    raw = b"keep=one%20two&value=first&value=second&csrf=protected-token&keep=one+two"
    surface, binding, _body = private_input(
        raw,
        "application/x-www-form-urlencoded; charset=" + codec,
        "form",
        "value",
        occurrence=1,
        protected=[token("form", "csrf")],
    )
    selected = PrivateBodyInput.from_binding(binding, surface)
    expected = raw.replace(
        b"value=second", b"value=" + quote_plus("café&x", encoding=codec).encode()
    )
    assert selected.mutate("café&x") == expected


def test_text_upload_uses_part_codec_preserves_bom_binary_and_denies_delimiter_injection():
    prefix = (
        b'--OwnedBoundary\r\nContent-Disposition: form-data; name="upload"; '
        b'filename="owned.txt"\r\n'
        b"Content-Type: text/plain; charset=utf-16\r\n\r\n"
    )
    suffix = (
        b'\r\n--OwnedBoundary\r\nContent-Disposition: form-data; name="binary"; '
        b'filename="owned.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n\x00\xff\r\n--OwnedBoundary--\r\n"
    )
    raw = prefix + "café".encode("utf-16") + suffix
    surface, binding, _body = private_input(
        raw, "multipart/form-data; boundary=OwnedBoundary", "multipart_file", "upload"
    )
    selected = PrivateBodyInput.from_binding(binding, surface)
    assert selected.mutate("changed") == prefix + "changed".encode("utf-16") + suffix
    with pytest.raises(ValueError, match="scalar_type_unsupported"):
        PrivateBodyInput.from_binding(binding, replace(surface, input_name="binary"))
    ordinary, ordinary_binding, _ = approved("multipart")
    field = PrivateBodyInput.from_binding(ordinary_binding, ordinary)
    with pytest.raises(InputReplayDenied, match="multipart_delimiter"):
        field.mutate(
            '\r\n--RedJohnBoundary\r\nContent-Disposition: form-data; name="injected"\r\n\r\nx'
        )


def test_numeric_json_mutation_preserves_utf16_byte_order():
    text = '{"value":1,"private":"café"}'
    surface, binding, _ = private_input(
        text.encode("utf-16"), "application/json; charset=utf-16", "json", "/value"
    )
    selected = PrivateBodyInput.from_binding(binding, surface, integer=True)
    assert selected.mutate("42") == text.replace('"value":1', '"value":42').encode("utf-16")


@pytest.mark.parametrize("kind", ["form", "multipart", "xml_text", "xml_attribute"])
def test_empty_protected_token_cannot_be_selected_for_scanner_insertion(kind):
    if kind == "form":
        raw, media, location, selector = (
            b"csrf=&value=keep",
            "application/x-www-form-urlencoded",
            "form",
            "csrf",
        )
    elif kind == "multipart":
        raw, media, location, selector = (
            (
                b'--Owned\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n'
                b'\r\n--Owned\r\nContent-Disposition: form-data; name="value"\r\n\r\n'
                b"keep\r\n--Owned--\r\n"
            ),
            "multipart/form-data; boundary=Owned",
            "multipart",
            "csrf",
        )
    else:
        raw, media, location, selector = (
            b'<r csrf=""><csrf></csrf><value>keep</value></r>',
            "application/xml",
            "xml",
            "/r/csrf" if kind == "xml_text" else "/r/@csrf",
        )
    surface, binding, body = private_input(
        raw, media, location, selector, protected=[token(location, selector)]
    )
    with pytest.raises(InputReplayDenied, match="overlaps_session_token"):
        PrivateBodyInput.from_binding(binding, surface)
    assert body.data == raw
    other = replace(surface, input_name="/r/value" if location == "xml" else "value")
    assert b"changed" in PrivateBodyInput.from_binding(binding, other).mutate("changed")


@pytest.mark.parametrize("first", ["<v/>", "<v><child/></v>", "<v>a<!--split-->b</v>"])
def test_xml_occurrence_counts_unsupported_matching_elements_instead_of_skipping(first):
    raw = ("<r>" + first + "<v>second</v></r>").encode()
    surface, binding, _ = private_input(raw, "application/xml", "xml", "/r/v")
    with pytest.raises(ValueError, match="xml_selector_ambiguous"):
        PrivateBodyInput.from_binding(binding, surface)
    with pytest.raises(ValueError, match="xml_selected_value_not_contiguous"):
        PrivateBodyInput.from_binding(binding, replace(surface, input_occurrence=0))
    selected = PrivateBodyInput.from_binding(binding, replace(surface, input_occurrence=1))
    assert selected.mutate("changed") == raw.replace(b"second", b"changed")


def test_legacy_multipart_routing_does_not_invent_a_runtime_boundary():
    assert input_location_matches("multipart/form-data", "multipart", routing_only=True)
    assert input_location_matches("multipart/form-data", "multipart_file", routing_only=True)
    assert not input_location_matches("multipart/form-data", "multipart")
    assert input_location_matches("multipart/form-data; boundary=Reviewed", "multipart")


@pytest.mark.parametrize("value", [-1, 128, True, 1.5, "0"])
def test_surface_occurrence_is_bounded_typed_and_post_only(value):
    with pytest.raises(ValueError, match="invalid_body_input_occurrence"):
        Surface(
            "https://owned.test/input", method="POST", input_location="json", input_occurrence=value
        )
    with pytest.raises(ValueError, match="invalid_body_input_occurrence"):
        Surface("https://owned.test/input", input_location="json", input_occurrence=0)
