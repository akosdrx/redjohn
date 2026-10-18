"""Bounded XML inspection and lossless private token spans, with no DTD/I/O.

Selectors are exact wire-prefix paths, e.g. /soap:Envelope/soap:Body/request/token
or /request/@csrf. They are operator configuration, not target-discovered XPath.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from xml.parsers import expat


if TYPE_CHECKING:
    from redjohn.assessment.wire_encoding import WireText


_NAME = re.compile(r"[^\s=<>/'\"]+\Z")
_ATTRIBUTE = re.compile(r"\s+([^\s=/>]+)\s*=\s*(['\"])(.*?)\2", re.DOTALL)


class XMLBodyDenied(ValueError):  # noqa: N818 - no untrusted XML in errors
    pass


def inspect_xml(wire: WireText) -> tuple[str, ...]:
    """Validate decoded XML under finite depth/node limits and return redactions."""
    parser = expat.ParserCreate(encoding="utf-8")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    values: list[str] = []
    text_frames: list[list[str]] = []
    depth = nodes = 0

    def start(_name: str, attributes: dict[str, str]) -> None:
        nonlocal depth, nodes
        depth += 1
        nodes += 1
        if depth > 64 or nodes > 4096 or len(attributes) > 128:
            raise XMLBodyDenied("xml_structure_budget_exceeded")
        values.extend(value for value in attributes.values() if value)
        text_frames.append([])

    def end(_name: str) -> None:
        nonlocal depth
        depth -= 1
        value = "".join(text_frames.pop())
        if value:
            values.append(value)

    def characters(text: str) -> None:
        if text and text_frames:
            text_frames[-1].append(text)

    def forbidden(*_args: object) -> None:
        raise XMLBodyDenied("xml_doctype_or_entity_forbidden")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = lambda *_args: 0
    parser.CharacterDataHandler = characters
    try:
        # An explicit UTF-8 parser consumes the already validated Unicode view;
        # original declaration/charset agreement was checked before conversion.
        parser.Parse(wire.text.encode("utf-8"), True)  # noqa: FBT003 - CPython parser completion flag
    except (expat.ExpatError, UnicodeError):
        raise XMLBodyDenied("invalid_xml") from None
    return tuple(dict.fromkeys(values))


@dataclass(frozen=True)
class XMLTokenSpan:
    start: int
    end: int
    kind: str
    encoding: str

    def replacement(self, token: str) -> bytes:
        if self.kind == "cdata":
            if "]]>" in token:
                raise XMLBodyDenied("xml_cdata_terminator_in_token")
            value = token
        else:
            value = html.escape(token, quote=self.kind == "attribute")
        try:
            return value.encode(self.encoding, errors="strict")
        except UnicodeError:
            raise XMLBodyDenied("token_not_representable_in_charset") from None


def xml_token_span(wire: WireText, selector: str, occurrence: int) -> XMLTokenSpan:  # noqa: PLR0912, PLR0915 - bounded lossless token walk
    inspect_xml(wire)
    if (
        not isinstance(selector, str)
        or len(selector.encode()) > 512
        or not selector.startswith("/")
        or type(occurrence) is not int
        or not 0 <= occurrence <= 127
    ):
        raise XMLBodyDenied("invalid_xml_selector")
    parts = selector[1:].split("/")
    attribute = parts.pop()[1:] if parts and parts[-1].startswith("@") else None
    if (
        not parts
        or not all(_NAME.fullmatch(p) for p in parts)
        or (
            attribute is not None
            and (
                not _NAME.fullmatch(attribute)
                or attribute == "xmlns"
                or attribute.startswith("xmlns:")
            )
        )
    ):
        raise XMLBodyDenied("invalid_xml_selector")
    text = wire.text
    frames: list[tuple[str, int, bool]] = []
    spans: list[tuple[int, int, str]] = []
    index = 0
    while index < len(text):
        opening = text.find("<", index)
        if opening < 0:
            break
        if text.startswith("<!--", opening):
            index = text.index("-->", opening + 4) + 3
            continue
        if text.startswith("<![CDATA[", opening):
            index = text.index("]]>", opening + 9) + 3
            continue
        if text.startswith("<?", opening):
            index = text.index("?>", opening + 2) + 2
            continue
        end, quote = opening + 1, ""
        while end < len(text):
            char = text[end]
            if quote:
                if char == quote:
                    quote = ""
            elif char in "'\"":
                quote = char
            elif char == ">":
                break
            end += 1
        tag = text[opening + 1 : end]
        if tag.startswith("/"):
            name, content_start, has_child = frames.pop()
            path = [f[0] for f in frames] + [name]
            if attribute is None and path == parts and not has_child:
                inner = text[content_start:opening]
                if "<" not in inner:
                    spans.append((content_start, opening, "text"))
                elif (
                    inner.startswith("<![CDATA[")
                    and inner.endswith("]]>")
                    and inner.count("<![CDATA[") == 1
                ):
                    spans.append((content_start + 9, opening - 3, "cdata"))
                else:
                    raise XMLBodyDenied("xml_selected_value_not_contiguous")
        else:
            if frames:
                name, content_start, _ = frames[-1]
                frames[-1] = name, content_start, True
            name = re.split(r"[\s/]", tag, maxsplit=1)[0]
            path = [f[0] for f in frames] + [name]
            if attribute is not None and path == parts:
                spans.extend(
                    (opening + 1 + match.start(3), opening + 1 + match.end(3), "attribute")
                    for match in _ATTRIBUTE.finditer(tag)
                    if match[1] == attribute
                )
            if not tag.rstrip().endswith("/"):
                frames.append((name, end + 1, False))
        index = end + 1
    if occurrence >= len(spans):
        raise XMLBodyDenied("xml_selector_not_found")
    start, end, kind = spans[occurrence]
    return XMLTokenSpan(wire.byte_offset(start), wire.byte_offset(end), kind, wire.encoding)
