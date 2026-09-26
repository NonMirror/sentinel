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
_UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")

_DEFAULT_MAPPING = Path(__file__).resolve().parents[2] / "vendor" / "modsecurity" / "unicode.mapping"


# --------------------------------------------------------------------------
# 全宽 / 变体字符映射表 (unicode.mapping, 由 SecUnicodeMapFile 指定)
# --------------------------------------------------------------------------
@lru_cache(maxsize=4)
def load_unicode_mapping(path: str | None = None) -> dict[int, str]:
    """载入 ``unicode.mapping``: 码位 -> 等价 ASCII 字符.

    文件按代码页分段 (ANSI-Central Europe / Cyrillic / ...), 同一码位在不同
    代码页里可能映射到不同 ASCII 字符。CRS 用 ``20127`` (US-ASCII), 而
    ``ff01-ff5e`` 全宽区间在各代码页中完全一致 —— 取并集, 先出现者优先,
    对检测而言是更严格 (更容易命中) 的选择。
    """
    mapping: dict[int, str] = {}
    target = Path(path) if path else _DEFAULT_MAPPING
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:                                   # pragma: no cover
        return mapping
    for match in re.finditer(r"([0-9a-fA-F]{4,6}):([0-9a-fA-F]{2})", text):
        code = int(match.group(1), 16)
        if code not in mapping:
            mapping[code] = chr(int(match.group(2), 16))
    return mapping


def _map_char(char: str) -> str:
    if ord(char) < 0x80:
        return char
    return load_unicode_mapping().get(ord(char), char)


# --------------------------------------------------------------------------
# 各变换实现
# --------------------------------------------------------------------------
def t_none(value: str) -> str:
    return value


def t_lowercase(value: str) -> str:
    return value.lower()


def t_uppercase(value: str) -> str:
    return value.upper()


def t_length(value: str) -> str:
    return str(len(value))


def t_trim(value: str) -> str:
    return value.strip()


def t_trim_left(value: str) -> str:
    return value.lstrip()


def t_trim_right(value: str) -> str:
    return value.rstrip()


def t_remove_whitespace(value: str) -> str:
    return re.sub(r"\s+", "", value)


def t_compress_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value)


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
    if "%" not in value:
        return value
    out: list[str] = []
    index = 0
    length = len(value)
    changed = False
    while index < length:
        char = value[index]
        if char != "%":
            out.append(char)
            index += 1
            continue
        if index + 5 < length and value[index + 1] in ("u", "U") and \
                all(c in _HEXSET for c in value[index + 2:index + 6]):
            code = int(value[index + 2:index + 6], 16)
            out.append(chr(code))
            index += 6
            changed = True
            continue
        if index + 2 < length and value[index + 1] in _HEXSET and value[index + 2] in _HEXSET:
            out.append(chr(int(value[index + 1:index + 3], 16)))
            index += 3
            changed = True
            continue
        out.append(char)
        index += 1
    text = "".join(out)
    if not changed:
        return value
    if any(ord(c) > 0x7F for c in text):
        text = "".join(_map_char(c) for c in text)
    return text


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
            out.append("%u%04x" % ord(item))
        index = match.end()
    return "".join(out)


_ENTITY_RE = re.compile(r"&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]{1,31});")
_NAMED_ENTITIES = {
    "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'", "nbsp": "\xa0",
    "colon": ":", "sol": "/", "lpar": "(", "rpar": ")", "comma": ",",
    "period": ".", "num": "#", "percnt": "%", "ast": "*", "plus": "+",
    "equals": "=", "quest": "?", "commat": "@", "lsqb": "[", "rsqb": "]",
    "lcub": "{", "rcub": "}", "verbar": "|", "semi": ";", "dollar": "$",
    "excl": "!", "grave": "`", "Hat": "^", "tilde": "~", "lowbar": "_",
    "hyphen": "-", "Tab": "\t", "NewLine": "\n",
}


def t_html_entity_decode(value: str) -> str:
    if "&" not in value:
        return value

    def replace(match: re.Match[str]) -> str:
        body = match.group(1)
        try:
            if body.startswith("#x") or body.startswith("#X"):
                return chr(int(body[2:], 16))
            if body.startswith("#"):
                return chr(int(body[1:]))
        except (ValueError, OverflowError):
            return match.group(0)
        return _NAMED_ENTITIES.get(body, match.group(0))

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
    r"\\(?:x([0-9a-fA-F]{2})|([0-7]{1,3})|(.))", re.DOTALL)
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
            return chr(int(octal, 8))
        if simple is not None:
            return _ESCAPE_SIMPLE.get(simple, simple)
        return match.group(0)

    return _ESCAPE_SEQ_RE.sub(replace, value)


_CSS_ESCAPE_RE = re.compile(r"\\([0-9a-fA-F]{1,6})[ \t\r\n]?")
_CSS_SHORT_RE = re.compile(r"\\([^0-9a-fA-F])")


def t_css_decode(value: str) -> str:
    if "\\" not in value:
        return value
    value = _CSS_ESCAPE_RE.sub(lambda m: _safe_chr(int(m.group(1), 16)), value)
    value = _CSS_SHORT_RE.sub(lambda m: m.group(1), value)
    return value


def _safe_chr(code: int) -> str:
    try:
        return chr(code)
    except (ValueError, OverflowError):
        return ""


_CMD_STRIP = str.maketrans({c: None for c in "\\\"'`^"})
_CMD_SPACE_RE = re.compile(r"\s+")


def t_cmd_line(value: str) -> str:
    value = value.translate(_CMD_STRIP)
    value = _CMD_SPACE_RE.sub(" ", value).strip()
    return value.lower()


_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def t_remove_comments(value: str) -> str:
    return _COMMENT_RE.sub("", value) if "/*" in value else value


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
    text = value.replace("\\", "/") if windows or "\\" in value else value
    if "/." not in text and "//" not in text and not text.startswith("/"):
        return text
    parts = text.split("/")
    stack: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if stack and stack[-1] != "..":
                stack.pop()
            else:
                stack.append("..")
            continue
        stack.append(part)
    prefix = "/" if text.startswith("/") else ""
    result = prefix + "/".join(stack)
    if text.endswith("/") and not result.endswith("/"):
        result += "/"
    return result


def t_base64_decode(value: str) -> str:
    return _base64_decode(value, extended=False)


def t_base64_decode_ext(value: str) -> str:
    return _base64_decode(value, extended=True)


_B64_TABLE = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _base64_decode(value: str, *, extended: bool) -> str:
    if not value:
        return value
    candidate = value.strip()
    if len(candidate) < 4:
        return value
    try:
        raw = candidate.encode("ascii", "ignore")
        if extended:
            raw = raw.translate(_B64_TABLE)
        padding = (-len(raw)) % 4
        return base64.b64decode(raw + b"=" * padding).decode("latin-1")
    except (binascii.Error, ValueError):
        return value


def t_hex_decode(value: str) -> str:
    stripped = value.strip()
    if len(stripped) % 2 or not stripped:
        return value
    if any(c not in _HEXSET for c in stripped):
        return value
    try:
        return bytes.fromhex(stripped).decode("latin-1")
    except ValueError:
        return value


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
    return hashlib.md5(value.encode("latin-1", "replace")).hexdigest()


def t_sha1(value: str) -> str:
    return hashlib.sha1(value.encode("latin-1", "replace")).hexdigest()


def t_url_encode(value: str) -> str:
    out: list[str] = []
    for byte in value.encode("latin-1", "replace"):
        char = chr(byte)
        if char in _UNRESERVED:
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
