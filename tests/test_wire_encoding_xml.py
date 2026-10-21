"""Exact private wire offsets, charset guards and bounded XML parser contracts."""

from __future__ import annotations

import pytest

from redjohn.assessment.wire_encoding import WireEncodingDenied, WireText, canonical_charset
from redjohn.assessment.xml_wire import XMLBodyDenied, inspect_xml, xml_token_span


@pytest.mark.parametrize(
    "encoding,charset,bom",
    [
        ("utf-8", "UTF8", b""),
        ("utf-8", "utf-8", b"\xef\xbb\xbf"),
        ("iso8859-1", "latin1", b""),
        ("cp1250", "windows-1250", b""),
        ("cp1252", "windows-1252", b""),
        ("utf-16-le", "utf-16", b"\xff\xfe"),
        ("utf-16-be", "utf-16", b"\xfe\xff"),
        ("utf-16-le", "utf-16le", b""),
    ],
)
def test_exact_wire_offsets_and_fragment_encoding(encoding, charset, bom):
    text = '<r note="caf\u00e9">old&amp;token</r>'
    data = bom + text.encode(encoding)
    wire = WireText.decode(data, charset, xml=True)
    assert wire.text == text
    assert wire.byte_offset(len(text)) == len(data)
    span = xml_token_span(wire, "/r", 0)
    replacement = span.replacement("new<&token")
    rotated = data[: span.start] + replacement + data[span.end :]
    assert rotated == bom + '<r note="caf\u00e9">new&lt;&amp;token</r>'.encode(encoding)
    assert "new<&token" in inspect_xml(WireText.decode(rotated, charset, xml=True))


@pytest.mark.parametrize(
    "encoding,label,bom",
    [
        ("utf-8", "UTF-8", b""),
        ("cp1250", "windows-1250", b""),
        ("iso8859-1", "ISO-8859-1", b""),
        ("utf-16-le", "UTF-16", b"\xff\xfe"),
    ],
)
def test_xml_declaration_detection_and_exact_namespace_attribute_selection(encoding, label, bom):
    text = (
        f'<?xml version="1.0" encoding="{label}"?>'
        '<s:root xmlns:s="urn:owned" note="caf\u00e9"><s:item csrf="old&gt;token"/>'
        '<s:item csrf="keep"/></s:root>'
    )
    data = bom + text.encode(encoding)
    wire = WireText.decode(data, xml=True)
    assert canonical_charset(label) == wire.encoding or label == "UTF-16"
    span = xml_token_span(wire, "/s:root/s:item/@csrf", 1)
    rotated = data[: span.start] + span.replacement('new"&value') + data[span.end :]
    assert rotated == data.replace(
        'csrf="keep"'.encode(encoding), 'csrf="new&quot;&amp;value"'.encode(encoding)
    )
    assert 'new"&value' in inspect_xml(WireText.decode(rotated, xml=True))


def test_cdata_preserves_framing_and_rejects_terminator():
    data = b"<r><token><![CDATA[old<&]]></token><other>keep</other></r>"
    wire = WireText.decode(data, xml=True)
    span = xml_token_span(wire, "/r/token", 0)
    assert data[: span.start] + span.replacement("new<&") + data[span.end :] == data.replace(
        b"old<&", b"new<&"
    )
    with pytest.raises(XMLBodyDenied, match="cdata_terminator"):
        span.replacement("]]>")


@pytest.mark.parametrize(
    "data,charset",
    [
        (b"\xff\xfe<\x00r\x00/\x00>\x00", "utf-8"),
        (b"<r/>", "utf-16"),
        (b"<r>\xff</r>", "utf-8"),
        (b'<?xml version="1.0" encoding="iso-8859-1"?><r/>', "utf-8"),
        (b"<r/>", "utf-7"),
        (b"x" * (65536 + 1), None),
    ],
)
def test_mismatched_ambiguous_invalid_or_oversized_encoding_is_rejected(data, charset):
    with pytest.raises(WireEncodingDenied):
        WireText.decode(data, charset, xml=True)


@pytest.mark.parametrize(
    "text",
    [
        '<!DOCTYPE r [<!ENTITY secret SYSTEM "file:///owned-must-not-open">]><r>&secret;</r>',
        '<!DOCTYPE r SYSTEM "https://outside.invalid/entity"><r/>',
        '<!DOCTYPE r [<!ENTITY a "xxxx"><!ENTITY b "&a;&a;">]><r>&b;</r>',
        "<r><unclosed></r>",
        "<r>\x00</r>",
        "<r>" * 65 + "</r>" * 65,
        "<r>" + "<x/>" * 4096 + "</r>",
    ],
)
def test_xml_dtd_entities_malformed_depth_and_node_budgets_fail_closed(text):
    with pytest.raises(XMLBodyDenied):
        inspect_xml(WireText.decode(text.encode(), xml=True))


@pytest.mark.parametrize("selector", ["/r/@xmlns", "/r/@xmlns:s", "/r/*", "/r/..", "r/token"])
def test_unsafe_or_missing_xml_selectors_do_not_gain_a_rewrite(selector):
    with pytest.raises(XMLBodyDenied):
        xml_token_span(
            WireText.decode(b'<r xmlns:s="urn:owned"><token>x</token></r>', xml=True), selector, 0
        )


def test_xml_nested_or_fragmented_selected_value_does_not_drop_unbound_markup():
    for data in (b"<r><token>a<x/>b</token></r>", b"<r><token>a<!--keep-->b</token></r>"):
        with pytest.raises(XMLBodyDenied):
            xml_token_span(WireText.decode(data, xml=True), "/r/token", 0)
