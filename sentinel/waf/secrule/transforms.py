"""``t:`` 归一化函数 (ModSecurity transforms).

规则里的 ``t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls`` 就是攻击者
绕过手法的反面: 把编码层层拆开, 再交给算子匹配。

两个性能要诀 (CRS 每请求要跑上千次变换):

* 每个函数先做**廉价的存在性判断** (``"%" not in value``) 再动手;
* 结果缓存由调用方 (:mod:`sentinel.waf.secrule.engine`) 按
  ``(变换链, 原值)`` 记忆, 同一条参数不会重复解码。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

_HEX = "0123456789abcdefABCDEF"
_HEXSET = set(_HEX)
_UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_BYTE_WHITESPACE = " \t\r\n\v\f"

_DEFAULT_MAPPING = Path(__file__).resolve().parents[2] / "vendor" / "modsecurity" / "unicode.mapping"


# --------------------------------------------------------------------------
# 全宽 / 变体字符映射表 (unicode.mapping, 由 SecUnicodeMapFile 指定)
# --------------------------------------------------------------------------
@lru_cache(maxsize=4)
def load_unicode_mapping(path: str | None = None) -> dict[int, str]:
    """载入 ``unicode.mapping``: 码位 -> 等价 ASCII 字符.

    仅使用 CRS 默认的 ``20127`` (US-ASCII) 段，避免混入其他代码页的
    同码位映射。缺失该段时返回空表，解码器仍提供低字节与全宽回退。
    """
    mapping: dict[int, str] = {}
    target = Path(path) if path else _DEFAULT_MAPPING
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:                                   # pragma: no cover
        return mapping
    active = False
    for line in text.splitlines():
        section = re.match(r"^(\d+)\s+\(", line)
        if section:
            active = section[1] == "20127"
        elif active:
            for match in re.finditer(r"\b([0-9a-fA-F]{4,6}):([0-9a-fA-F]{2})\b", line):
                mapping[int(match[1], 16)] = chr(int(match[2], 16))
    return mapping


# --------------------------------------------------------------------------
# 各变换实现
# --------------------------------------------------------------------------
def t_none(value: str) -> str:
    return value


def t_lowercase(value: str) -> str:
    return value.lower() if value.isascii() else value.translate(_ASCII_LOWER)


def t_uppercase(value: str) -> str:
    return value.upper() if value.isascii() else value.translate(_ASCII_UPPER)


def t_length(value: str) -> str:
    return str(len(value))


def t_trim(value: str) -> str:
    return value.strip(_BYTE_WHITESPACE)


def t_trim_left(value: str) -> str:
    return value.lstrip(_BYTE_WHITESPACE)


def t_trim_right(value: str) -> str:
    return value.rstrip(_BYTE_WHITESPACE)


def t_remove_whitespace(value: str) -> str:
    # ModSecurity additionally removes both NBSP bytes, even in isolation.
    return re.sub(r"[\s\xc2\xa0]+", "", value, flags=re.ASCII)


def t_compress_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value, flags=re.ASCII)


def t_remove_nulls(value: str) -> str:
    return value.replace("\x00", "") if "\x00" in value else value


def t_replace_nulls(value: str) -> str:
    return value.replace("\x00", " ") if "\x00" in value else value


def t_url_decode(value: str) -> str:
    if "%" not in value and "+" not in value:
        return value
    out: list[str] = []
    index = 0
    length = len(value)
    while index < length:
        char = value[index]
        if char == "+":
            out.append(" ")
            index += 1
            continue
        if char == "%" and index + 2 < length and \
                value[index + 1] in _HEXSET and value[index + 2] in _HEXSET:
            out.append(chr(int(value[index + 1:index + 3], 16)))
            index += 3
            continue
        out.append(char)
        index += 1
    return "".join(out)


def t_url_decode_uni(value: str) -> str:
    """``%XX`` + IIS ``%uXXXX`` 解码, 并应用全宽字符映射."""
    if "%" not in value and "+" not in value:
        return value
    out: list[str] = []
    index = 0
    length = len(value)
    while index < length:
        char = value[index]
        if char != "%":
            out.append(" " if char == "+" else char)
            index += 1
            continue
        if index + 5 < length and value[index + 1] in ("u", "U") and \
                all(c in _HEXSET for c in value[index + 2:index + 6]):
            code = int(value[index + 2:index + 6], 16)
            mapped = load_unicode_mapping().get(code)
            out.append(chr(code - 0xFEE0) if 0xFF01 <= code <= 0xFF5E
                       else mapped if mapped is not None else chr(code & 255))
            index += 6
            continue
        if index + 2 < length and value[index + 1] in _HEXSET and value[index + 2] in _HEXSET:
            out.append(chr(int(value[index + 1:index + 3], 16)))
            index += 3
            continue
        out.append(char)
        index += 1
    return "".join(out)


_UTF8_SEQ = re.compile(rb"[\xc2-\xf4][\x80-\xbf]*")


def t_utf8_to_unicode(value: str) -> str:
    """把原始 UTF-8 字节串转成 ``%uXXXX`` 转义 (与 ModSecurity 一致)."""
    raw = value.encode("latin-1", "replace")
    if all(byte < 0x80 for byte in raw):
        return value
    out: list[str] = []
    index = 0
    length = len(raw)
    while index < length:
        byte = raw[index]
        if byte < 0x80:
            out.append(chr(byte))
            index += 1
            continue
        match = _UTF8_SEQ.match(raw, index)
        if match is None:
            out.append(chr(byte))
            index += 1
            continue
        chunk = match.group(0)
        try:
            char = chunk.decode("utf-8")
        except UnicodeDecodeError:
            out.append(chr(byte))
            index += 1
            continue
        for item in char:
            out.append("%%u%04x" % ord(item))
        index = match.end()
    return "".join(out)


_ENTITY_RE = re.compile(r"&(#(?:[xX][0-9a-fA-F]+|[0-9]+)|[a-zA-Z0-9]+);?")
_NAMED_ENTITIES = {
    "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'", "nbsp": "\xa0",
    "colon": ":", "sol": "/", "lpar": "(", "rpar": ")", "comma": ",",
    "period": ".", "num": "#", "percnt": "%", "ast": "*", "plus": "+",
    "equals": "=", "quest": "?", "commat": "@", "lsqb": "[", "rsqb": "]",
    "lcub": "{", "rcub": "}", "verbar": "|", "semi": ";", "dollar": "$",
    "excl": "!", "grave": "`", "hat": "^", "lowbar": "_",
    "tab": "\t", "newline": "\n", "bsol": "\\", "lbrace": "{", "rbrace": "}",
    "lbrack": "[", "rbrack": "]", "vert": "|", "verticalline": "|", "midast": "*",
    "underbar": "_", "diacriticalgrave": "`", "shy": "\xad", "nonbreakingspace": "\xa0",
}


def t_html_entity_decode(value: str) -> str:
    if "&" not in value:
        return value

    def replace(match: re.Match[str]) -> str:
        body = match.group(1)
        if body.startswith("#"):
            hexadecimal = body[1:2].lower() == "x"
            digits = body[2:] if hexadecimal else body[1:]
            digits = digits.lstrip("0") or "0"
            # strtol's positive overflow saturates; bound conversion work too.
            limit = 16 if hexadecimal else 19
            code = ((1 << 63) - 1 if len(digits) > limit else
                    min(int(digits, 16 if hexadecimal else 10), (1 << 63) - 1))
            return chr(code & 255)
        return _NAMED_ENTITIES.get(body.lower(), match.group(0))

    return _ENTITY_RE.sub(replace, value)


_JS_ESCAPE_RE = re.compile(
    r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|([0-7]{1,3})|(.))", re.DOTALL)
_JS_SIMPLE = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
              "0": "\x00", "'": "'", '"': '"', "\\": "\\", "/": "/", "`": "`"}


def t_js_decode(value: str) -> str:
    if "\\" not in value:
        return value

    def replace(match: re.Match[str]) -> str:
        hex2, hex4, octal, simple = match.groups()
        if hex2:
            return chr(int(hex2, 16))
        if hex4:
            return chr(int(hex4, 16))
        if octal:
            return chr(int(octal, 8))
        if simple is not None:
            return _JS_SIMPLE.get(simple, simple)
        return match.group(0)

    return _JS_ESCAPE_RE.sub(replace, value)


_ESCAPE_SEQ_RE = re.compile(
    r"\\(?:[xX]([0-9a-fA-F]{2})|([0-7]{1,3})|(.))", re.DOTALL)
_ESCAPE_SIMPLE = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
                  "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"',
                  "?": "?", "`": "`", "0": "\x00"}


def t_escape_seq_decode(value: str) -> str:
    if "\\" not in value:
        return value

    def replace(match: re.Match[str]) -> str:
        hex2, octal, simple = match.groups()
        if hex2:
            return chr(int(hex2, 16))
        if octal:
            return chr(int(octal, 8) & 255)
        if simple is not None:
            return _ESCAPE_SIMPLE.get(simple, simple)
        return match.group(0)

    return _ESCAPE_SEQ_RE.sub(replace, value)


_CSS_ESCAPE_RE = re.compile(r"\\(?:([0-9a-fA-F]{1,6})[ \t\r\n\f\v]?|(\n)|(.|$))", re.DOTALL)


def t_css_decode(value: str) -> str:
    if "\\" not in value:
        return value
    def replace(match: re.Match[str]) -> str:
        digits, newline, literal = match.groups()
        if digits:
            code = int(digits, 16)
            return chr(code - 0xFEE0 if 0xFF01 <= code <= 0xFF5E else code & 255)
        return "" if newline else literal
    return _CSS_ESCAPE_RE.sub(replace, value)


_CMD_STRIP = str.maketrans({c: None for c in "\\\"'^"})
_CMD_SPACE_RE = re.compile(r"[ ,;\t\r\n]+")


def t_cmd_line(value: str) -> str:
    value = value.translate(_CMD_STRIP)
    value = _CMD_SPACE_RE.sub(" ", value)
    value = re.sub(r" (?=[/(])", "", value)
    return t_lowercase(value)


_COMMENT_RE = re.compile(r"/\*.*?(?:\*/|$)", re.DOTALL)
_COMMENT_START_RE = re.compile(r"/\*|<!--|--|#")
_COMMENT_END_RE = re.compile(r"\*/|-->")


def t_remove_comments(value: str) -> str:
    out, index = [], 0
    start = _COMMENT_START_RE.search(value)
    while start:
        out.append(value[index:start.start()])
        if start[0] in ("--", "#"):
            return "".join(out)
        end = _COMMENT_END_RE.search(value, start.end())
        if end is None:
            return "".join(out) + " "
        index = end.end()
        start = _COMMENT_START_RE.search(value, index)
    out.append(value[index:])
    return "".join(out)


def t_replace_comments(value: str) -> str:
    return _COMMENT_RE.sub(" ", value) if "/*" in value else value


def t_remove_comments_char(value: str) -> str:
    if "/" not in value and "*" not in value and "#" not in value:
        return value
    return value.replace("/", "").replace("*", "").replace("#", "")


def t_normalize_path(value: str) -> str:
    return _normalize_path(value, windows=False)


def t_normalize_path_win(value: str) -> str:
    return _normalize_path(value, windows=True)


def _normalize_path(value: str, *, windows: bool) -> str:
    if not value:
        return value
    text = value.replace("\\", "/") if windows else value
    if "/." not in text and "//" not in text and not text.startswith(("/", ".")):
        return text
    parts = text.split("/")
    stack: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if stack and stack[-1] != "..":
                stack.pop()
            elif not text.startswith("/"):
                stack.append("..")
            continue
        stack.append(part)
    prefix = "/" if text.startswith("/") else ""
    result = prefix + "/".join(stack)
    if result and text.endswith("/") and not result.endswith("/"):
        result += "/"
    return result


def t_base64_decode(value: str) -> str:
    return _base64_decode(value, extended=False)


def t_base64_decode_ext(value: str) -> str:
    return _base64_decode(value, extended=True)


_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_VALUES = {c: i for i, c in enumerate(_B64_ALPHABET)} | {"-": 62, "_": 63}


def _base64_decode(value: str, *, extended: bool) -> str:
    if not value:
        return value
    if extended:
        out = bytearray()
        accumulator = bits = digits = 0
        for index, char in enumerate(value):
            if char == "=":
                if digits % 4 == 1 and value[index + 1:index + 2] != "=":
                    return ""
                continue
            digit = _B64_VALUES.get(char)
            if digit is None:
                continue
            accumulator = (accumulator << 6) | digit
            bits += 6
            digits += 1
            if bits >= 8:
                bits -= 8
                out.append(accumulator >> bits)
                accumulator &= (1 << bits) - 1
        return out.decode("latin-1")
    try:
        candidate = value.partition("\x00")[0]
        raw = re.sub(r"[ \r\n]+", "", candidate).encode("ascii")
        return base64.b64decode(raw, validate=True).decode("latin-1")
    except (binascii.Error, ValueError, UnicodeError):
        return value


def t_hex_decode(value: str) -> str:
    def nibble(char: str) -> int:
        byte = ord(char)
        return ((byte & 0xDF) - 55 if byte >= 65 else byte - 48) & 255
    return "".join(chr((nibble(value[i]) * 16 + nibble(value[i + 1])) & 255)
                   for i in range(0, len(value) - 1, 2))


def t_base64_encode(value: str) -> str:
    return base64.b64encode(value.encode("latin-1", "replace")).decode("ascii")


def _parity(value: str, odd: bool) -> str:
    return "".join(chr((byte & 127) | ((byte.bit_count() % 2 ^ odd) << 7))
                   for byte in value.encode("latin-1", "replace"))


_SQL_HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")


def t_sql_hex_decode(value: str) -> str:
    if "0x" not in value.lower():
        return value

    def replace(match: re.Match[str]) -> str:
        digits = match.group(1)
        if len(digits) % 2:
            digits = "0" + digits
        try:
            return bytes.fromhex(digits).decode("latin-1")
        except ValueError:
            return match.group(0)

    return _SQL_HEX_RE.sub(replace, value)


def t_hex_encode(value: str) -> str:
    return value.encode("latin-1", "replace").hex()


def t_md5(value: str) -> str:
    return hashlib.md5(value.encode("latin-1", "replace")).digest().decode("latin-1")


def t_sha1(value: str) -> str:
    return hashlib.sha1(value.encode("latin-1", "replace")).digest().decode("latin-1")


def t_url_encode(value: str) -> str:
    out: list[str] = []
    for byte in value.encode("latin-1", "replace"):
        char = chr(byte)
        if char == " ":
            out.append("+")
        elif char in _UNRESERVED:
            out.append(char)
        else:
            out.append("%%%02x" % byte)
    return "".join(out)


def t_remove_comment_chars(value: str) -> str:
    return t_remove_comments_char(value)


# --------------------------------------------------------------------------
# 注册表
# --------------------------------------------------------------------------
TRANSFORMS = {
    "none": t_none,
    "lowercase": t_lowercase,
    "uppercase": t_uppercase,
    "length": t_length,
    "trim": t_trim,
    "trimleft": t_trim_left,
    "trimright": t_trim_right,
    "removewhitespace": t_remove_whitespace,
    "compresswhitespace": t_compress_whitespace,
    "removenulls": t_remove_nulls,
    "replacenulls": t_replace_nulls,
    "urldecode": t_url_decode,
    "urldecodeuni": t_url_decode_uni,
    "utf8tounicode": t_utf8_to_unicode,
    "htmlentitydecode": t_html_entity_decode,
    "jsdecode": t_js_decode,
    "escapeseqdecode": t_escape_seq_decode,
    "cssdecode": t_css_decode,
    "cmdline": t_cmd_line,
    "removecomments": t_remove_comments,
    "replacecomments": t_replace_comments,
    "removecommentschar": t_remove_comments_char,
    "removecommentchars": t_remove_comment_chars,
    "normalizepath": t_normalize_path,
    "normalizepathwin": t_normalize_path_win,
    "base64decode": t_base64_decode,
    "base64decodeext": t_base64_decode_ext,
    "base64encode": t_base64_encode,
    "parityeven7bit": lambda v: _parity(v, False),
    "parityodd7bit": lambda v: _parity(v, True),
    "parityzero7bit": lambda v: "".join(chr(b & 127) for b in v.encode("latin-1", "replace")),
    "hexdecode": t_hex_decode,
    "hexencode": t_hex_encode,
    "sqlhexdecode": t_sql_hex_decode,
    "md5": t_md5,
    "sha1": t_sha1,
    "urlencode": t_url_encode,
    "normaliseunicode": lambda v: unicodedata.normalize("NFKC", v),
}

#: 未实现的变换 -> 使用 ``none`` 并在健康检查里报告
UNSUPPORTED: set[str] = set()


def apply_transform(name: str, value: str) -> str:
    """按名应用单个变换; 未实现者原样返回 (不抛异常)."""
    func = TRANSFORMS.get(name.lower())
    if func is None:
        UNSUPPORTED.add(name.lower())
        return value
    try:
        return func(value)
    except Exception:                                 # noqa: BLE001 - 变换失败退回原值
        return value


def apply_chain(transforms: tuple[str, ...], value: str) -> str:
    """依次应用变换链."""
    for name in transforms:
        value = apply_transform(name, value)
    return value
