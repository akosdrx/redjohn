"""Bounded explicit wire decoding with lossless byte offsets for private bodies.

This module does not infer approval, fetch data, or reserialize a request. A
selected substitution is encoded with the original body's concrete codec.
"""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass, field


_ALLOWED = frozenset({"utf-8", "iso8859-1", "cp1250", "cp1252", "utf-16", "utf-16-le", "utf-16-be"})
_DECLARATION = re.compile(
    r"\A<\?xml\s+[^?]{0,512}?encoding\s*=\s*(['\"])([A-Za-z0-9._-]{1,40})\1", re.ASCII
)
_BOMS = ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))


class WireEncodingDenied(ValueError):  # noqa: N818 - secret-free error contract
    pass


def canonical_charset(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        raise WireEncodingDenied("unsupported_charset")
    try:
        name = codecs.lookup(value).name
    except LookupError:
        raise WireEncodingDenied("unsupported_charset") from None
    if name not in _ALLOWED:
        raise WireEncodingDenied("unsupported_charset")
    return name


@dataclass(frozen=True, repr=False)
class WireText:
    text: str = field(repr=False)
    encoding: str
    preamble: bytes = field(repr=False)

    @classmethod
    def decode(cls, data: bytes, charset: str | None = None, *, xml: bool = False) -> WireText:  # noqa: PLR0912 - explicit BOM/declaration guards
        if not isinstance(data, bytes) or len(data) > 64 * 1024:
            raise WireEncodingDenied("wire_body_budget_exceeded")
        requested = canonical_charset(charset) if charset is not None else None
        preamble, detected = next(
            ((bom, enc) for bom, enc in _BOMS if data.startswith(bom)), (b"", None)
        )
        if (
            detected
            and requested
            and requested != detected
            and not (requested == "utf-16" and detected.startswith("utf-16-"))
        ):
            raise WireEncodingDenied("charset_bom_mismatch")
        encoding = detected or requested
        if encoding == "utf-16":
            raise WireEncodingDenied("utf16_byte_order_required")
        if encoding is None and xml:
            if data.startswith(b"<\x00"):
                encoding = "utf-16-le"
            elif data.startswith(b"\x00<"):
                encoding = "utf-16-be"
            else:
                prefix = data[:512].decode("ascii", errors="ignore")
                declared = _DECLARATION.match(prefix)
                encoding = canonical_charset(declared[2]) if declared else "utf-8"
        encoding = encoding or "utf-8"
        if encoding == "utf-16":
            raise WireEncodingDenied("utf16_byte_order_required")
        try:
            text = data[len(preamble) :].decode(encoding, errors="strict")
        except UnicodeError:
            raise WireEncodingDenied("invalid_wire_encoding") from None
        if xml and (declared := _DECLARATION.match(text)):
            declared_encoding = canonical_charset(declared[2])
            if declared_encoding == "utf-16":
                if not preamble or not encoding.startswith("utf-16-"):
                    raise WireEncodingDenied("xml_encoding_declaration_mismatch")
            elif declared_encoding != encoding:
                raise WireEncodingDenied("xml_encoding_declaration_mismatch")
        return cls(text, encoding, preamble)

    def byte_offset(self, character: int) -> int:
        if type(character) is not int or not 0 <= character <= len(self.text):
            raise WireEncodingDenied("invalid_character_offset")
        return len(self.preamble) + len(self.text[:character].encode(self.encoding))

    def encode_fragment(self, value: str) -> bytes:
        try:
            return value.encode(self.encoding, errors="strict")
        except UnicodeError:
            raise WireEncodingDenied("token_not_representable_in_charset") from None
