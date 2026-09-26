"""规则变换函数 (ModSecurity 兼容子集)."""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import re
import urllib.parse

_HTML_ENTITIES = {
    "&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"', "&#39;": "'",
    "&apos;": "'", "&nbsp;": " ", "&#x2f;": "/", "&#47;": "/",
}
_ENTITY_RE = re.compile(r"&(?:#x?[0-9a-fA-F]+|[a-zA-Z]+);")
_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_NULL_RE = re.compile(r"[\x00\x0b\x0c\x0e-\x1f\x7f]")
_WS_RE = re.compile(r"\s+")
_JS_ESCAPE_RE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|(.))")
_CSS_ESCAPE_RE = re.compile(r"\\([0-9a-fA-F]{1,6})\s?|\\(.)")


def lower(value: str, *_: str) -> str:
    return value.lower()


def upper(value: str, *_: str) -> str:
    return value.upper()


def trim(value: str, *_: str) -> str:
    return value.strip()


def trim_left(value: str, *_: str) -> str:
    return value.lstrip()


def trim_right(value: str, *_: str) -> str:
    return value.rstrip()


def remove_nulls(value: str, *_: str) -> str:
    return value.replace("\x00", "")


def compress_whitespace(value: str, *_: str) -> str:
    return _WS_RE.sub(" ", value).strip()


def remove_comments(value: str, *_: str) -> str:
    return _COMMENT_RE.sub("", value)


def replace_comments(value: str, *_: str) -> str:
    return _COMMENT_RE.sub(" ", value)


def normalize_path(value: str, *_: str) -> str:
    value = value.replace("\\", "/")
    while "//" in value:
        value = value.replace("//", "/")
    while "/./" in value:
        value = value.replace("/./", "/")
    while "/../" in value:
        value = value.replace("/../", "/")
    return value


def normalize_path_win(value: str, *_: str) -> str:
    return normalize_path(value).lower()


def url_decode(value: str, *_: str) -> str:
    try:
        return urllib.parse.unquote_plus(value)
    except Exception:
        return value


def url_decode_uni(value: str, *_: str) -> str:
    value = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), value)
    return url_decode(value)


def html_entity_decode(value: str, *_: str) -> str:
    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in _HTML_ENTITIES:
            return _HTML_ENTITIES[token]
        try:
            if token[2:3].lower() == "x":
                return chr(int(token[3:-1], 16))
            return chr(int(token[2:-1]))
        except (ValueError, OverflowError):
            return token

    return _ENTITY_RE.sub(repl, value)


def js_decode(value: str, *_: str) -> str:
    def repl(match: re.Match[str]) -> str:
        hex2, hex4, plain = match.groups()
        if hex2:
            return chr(int(hex2, 16))
        if hex4:
            return chr(int(hex4, 16))
        return plain or ""

    return _JS_ESCAPE_RE.sub(repl, value)


def css_decode(value: str, *_: str) -> str:
    def repl(match: re.Match[str]) -> str:
        hexval, plain = match.groups()
        if hexval:
            try:
                return chr(int(hexval, 16))
            except (ValueError, OverflowError):
                return ""
        return plain or ""

    return _CSS_ESCAPE_RE.sub(repl, value)


def base64_decode(value: str, *_: str) -> str:
    stripped = re.sub(r"\s+", "", value)
    if len(stripped) < 4:
        return value
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.b64decode(padded, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return value


def base64_decode_ext(value: str, *_: str) -> str:
    try:
        return base64.b64decode(value, validate=False).decode("utf-8", "replace")
    except Exception:
        return value


def hex_decode(value: str, *_: str) -> str:
    stripped = re.sub(r"\s+|0x", "", value)
    if len(stripped) % 2 or not stripped:
        return value
    try:
        return bytes.fromhex(stripped).decode("utf-8", "replace")
    except ValueError:
        return value


def sql_hex_decode(value: str, *_: str) -> str:
    def repl(match: re.Match[str]) -> str:
        try:
            return bytes.fromhex(match.group(1)).decode("utf-8", "replace")
        except ValueError:
            return match.group(0)

    return re.sub(r"0x([0-9a-fA-F]+)", repl, value)


def cmd_line(value: str, *_: str) -> str:
    value = re.sub(r"\s+", " ", value).strip().lower()
    value = re.sub(r'["\'^]', "", value)
    value = re.sub(r"\\(?=[^\\])", "/", value)
    return value


def escape_seq_decode(value: str, *_: str) -> str:
    return codecs.decode(value, "unicode_escape") if "\\" in value else value


def length(value: str, *_: str) -> str:
    return str(len(value))


def sha1(value: str, *_: str) -> str:
    return hashlib.sha1(value.encode("utf-8", "replace")).hexdigest()


def md5(value: str, *_: str) -> str:
    return hashlib.md5(value.encode("utf-8", "replace")).hexdigest()


def utf8_to_unicode(value: str, *_: str) -> str:
    return "".join(f"%u{ord(c):04x}" for c in value)


TRANSFORMS = {
    "none": lambda value, *_: value,
    "lowercase": lower,
    "uppercase": upper,
    "trim": trim,
    "trimLeft": trim_left,
    "trimRight": trim_right,
    "removeNulls": remove_nulls,
    "compressWhitespace": compress_whitespace,
    "removeComments": remove_comments,
    "removeCommentsChar": remove_comments,
    "replaceComments": replace_comments,
    "normalizePath": normalize_path,
    "normalizePathWin": normalize_path_win,
    "urlDecode": url_decode,
    "urlDecodeUni": url_decode_uni,
    "htmlEntityDecode": html_entity_decode,
    "jsDecode": js_decode,
    "cssDecode": css_decode,
    "base64Decode": base64_decode,
    "base64DecodeExt": base64_decode_ext,
    "hexDecode": hex_decode,
    "sqlHexDecode": sql_hex_decode,
    "cmdLine": cmd_line,
    "escapeSeqDecode": escape_seq_decode,
    "length": length,
    "sha1": sha1,
    "md5": md5,
    "utf8ToUnicode": utf8_to_unicode,
}


def apply_transforms(value: str, names: list[str]) -> str:
    for name in names:
        func = TRANSFORMS.get(name)
        if func is None:
            continue
        value = func(value)
    return value
