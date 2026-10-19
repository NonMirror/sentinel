"""Validate a Structured Field Item for passive policy-header inspection.

Only item syntax and its primary token are needed here. This is not a list or
dictionary parser, serializer, or typed-value API (RFC 9651 sections 4.2–4.2.10).
"""
from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote_to_bytes

_TOKEN = r"[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/-]*"
_BARE = re.compile(
    r'(?P<display>%"(?:[\x20-\x21\x23-\x24\x26-\x7e]|%[0-9a-f]{2})*")'
    r'|(?P<string>"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\["\\])*")'
    r'|(?P<binary>:[A-Za-z0-9+/=]*:)'
    r'|(?P<boolean>\?[01])'
    r'|(?P<decimal>-?[0-9]{1,12}\.[0-9]{1,3})'
    r'|(?P<integer>-?[0-9]{1,15})'
    r'|(?P<date>@-?[0-9]{1,15})'
    rf'|(?P<token>{_TOKEN})'
)
_KEY = re.compile(r"[a-z*][a-z0-9_.*-]*")


def _bare(value: str, offset: int):
    match = _BARE.match(value, offset)
    if match is None:
        return None
    kind, raw = match.lastgroup, match[0]
    try:
        if kind == "binary":
            encoded = raw[1:-1]
            base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
        elif kind == "display":
            unquote_to_bytes(raw[2:-1]).decode("utf-8", "strict")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return kind, raw, match.end()


def inspect_structured_item(value: str) -> tuple[str, str] | None:
    """Return primary kind/raw value after validating the entire Item, else None.

    Unknown and repeated parameters are legal; their values do not change the
    primary policy token. Leading/trailing SP is legal, HTAB is not SF syntax.
    """
    value = value.strip(" ")
    item = _bare(value, 0)
    if item is None:
        return None
    kind, raw, offset = item
    while offset < len(value):
        if value[offset] != ";":
            return None
        offset += 1
        while offset < len(value) and value[offset] == " ":
            offset += 1
        key = _KEY.match(value, offset)
        if key is None:
            return None
        offset = key.end()
        if offset < len(value) and value[offset] == "=":
            item = _bare(value, offset + 1)
            if item is None:
                return None
            offset = item[2]
    return kind, raw
