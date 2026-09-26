"""libinjection 风格的原生 SQLi / XSS 检测器 (纯 Python, 无第三方依赖).

CRS 的 ``REQUEST-942-*`` / ``REQUEST-941-*`` 用 ModSecurity 的 ``@detectSQLi`` /
``@detectXSS`` 算子拦截注入, 而在真实 ModSecurity 里这两个算子背后就是
**libinjection** C 库。本模块把 libinjection 的算法搬到 Sentinel 内部, 让原生
SecRule 解释器能直接跑真实的 CRS 规则, 不必再外挂 ModSecurity。

对外只有两个函数:

* :func:`detect_sqli` —— ``libinjection_sqli`` 的移植:
  SQL 词法分析 -> token 折叠 (fold) -> fingerprint 字符串 ->
  指纹表匹配 (blacklist) -> 误报抑制 (not_whitelist)。
* :func:`detect_xss` —— ``libinjection_xss`` 的移植:
  HTML5 词法分析 (``libinjection_html5``) 逐 token 判定黑标签 / 黑属性 /
  危险 URL / 危险注释。

行为基准是 **libinjection 4.0.0** (https://github.com/libinjection/libinjection),
数据表 (9352 条关键字/指纹、432 个事件属性名、20 个黑属性、20 个黑标签) 由
该版本的 ``src/libinjection_sqli_data.h`` 与 ``src/libinjection_xss.c`` 直接
生成, 因此**指纹表是全量而非抽样子集**。与 C 版的差异见文件末尾「移植说明」。

性能: 词法分析单趟扫描, 扫描循环用 ``str.find`` / 预编译正则代替逐字符
Python 循环; 折叠阶段最多保留 5 个 token, 遇到无法匹配的输入立刻退出。
典型 50 字符输入远低于 100 µs。
"""
from __future__ import annotations

import re

__all__ = ["detect_sqli", "detect_xss", "health", "LIBINJECTION_VERSION"]

#: 移植所依据的上游版本
LIBINJECTION_VERSION = "4.0.0"


# ===========================================================================
# 常量: 与 libinjection_sqli.c / libinjection_html5.c 一一对应
# ===========================================================================
#: ``stoken_t.val`` 的容量 (含结尾 NUL); 超过的 token 值会被截断,
#: 且长度 >= 该值的 bareword 不做关键字查找
_TOKEN_SIZE = 32

#: 折叠后最多保留的 token 数 (tokenvec 另有 3 个槽位供"多看一个 token"用)
_MAX_TOKENS = 5

CHAR_NULL = "\0"
CHAR_SINGLE = "'"
CHAR_DOUBLE = '"'
CHAR_TICK = "`"

# --- SQL token 类型 (libinjection_sqli.c: sqli_token_types) ---
TYPE_KEYWORD = "k"
TYPE_UNION = "U"
TYPE_GROUP = "B"
TYPE_EXPRESSION = "E"
TYPE_SQLTYPE = "t"
TYPE_FUNCTION = "f"
TYPE_BAREWORD = "n"
TYPE_NUMBER = "1"
TYPE_VARIABLE = "v"
TYPE_STRING = "s"
TYPE_OPERATOR = "o"
TYPE_LOGIC_OPERATOR = "&"
TYPE_COMMENT = "c"
TYPE_COLLATE = "A"
TYPE_LEFTPARENS = "("
TYPE_RIGHTPARENS = ")"
TYPE_LEFTBRACE = "{"
TYPE_RIGHTBRACE = "}"
TYPE_DOT = "."
TYPE_COMMA = ","
TYPE_COLON = ":"
TYPE_SEMICOLON = ";"
TYPE_TSQL = "T"
TYPE_UNKNOWN = "?"
TYPE_EVIL = "X"
TYPE_BACKSLASH = "\\"
TYPE_NONE = CHAR_NULL

# --- 解析标志 (libinjection_sqli.h: sqli_flags) ---
FLAG_QUOTE_NONE = 1
FLAG_QUOTE_SINGLE = 2
FLAG_QUOTE_DOUBLE = 4
FLAG_SQL_ANSI = 8
FLAG_SQL_MYSQL = 16

# --- HTML5 token 类型 (libinjection_html5.h: html5_type) ---
H5_DATA_TEXT = 0
H5_TAG_NAME_OPEN = 1
H5_TAG_NAME_CLOSE = 2
H5_TAG_NAME_SELFCLOSE = 3
H5_TAG_DATA = 4
H5_TAG_CLOSE = 5
H5_ATTR_NAME = 6
H5_ATTR_VALUE = 7
H5_TAG_COMMENT = 8
H5_DOCTYPE = 9

# --- HTML5 起始状态 (libinjection_html5.h: html5_flags) ---
H5_STATE_DATA = 0
H5_STATE_VALUE_NO_QUOTE = 1
H5_STATE_VALUE_SINGLE_QUOTE = 2
H5_STATE_VALUE_DOUBLE_QUOTE = 3
H5_STATE_VALUE_BACK_QUOTE = 4

#: 只看小写 a-z 的大小写转换表 —— C 版 ``cstrcasecmp`` 只处理 ASCII
_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz",
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _ascii_upper(text: str) -> str:
    """只把 ASCII 小写字母转大写 (对应 C 的 ``cb -= 0x20``)."""
    return text.translate(_ASCII_UPPER)


# ===========================================================================
# SQLi: 词法分析
# ===========================================================================
class _Token:
    """对应 C 的 ``stoken_t``."""

    __slots__ = ("pos", "len", "count", "type", "str_open", "str_close", "val")

    def __init__(self) -> None:
        self.pos = 0
        self.len = 0
        self.count = 0
        self.type = CHAR_NULL
        self.str_open = CHAR_NULL
        self.str_close = CHAR_NULL
        self.val = ""

    def clear(self) -> None:
        self.pos = 0
        self.len = 0
        self.count = 0
        self.type = CHAR_NULL
        self.str_open = CHAR_NULL
        self.str_close = CHAR_NULL
        self.val = ""

    def copy_from(self, other: "_Token") -> None:
        self.pos = other.pos
        self.len = other.len
        self.count = other.count
        self.type = other.type
        self.str_open = other.str_open
        self.str_close = other.str_close
        self.val = other.val


def _val0(token: _Token) -> str:
    """C 里 ``token->val[0]`` 越界读到的其实是结尾 NUL."""
    return token.val[0] if token.val else CHAR_NULL


def _assign(token: _Token, stype: str, pos: int, length: int, value: str) -> None:
    """对应 ``st_assign``: ``value`` 是 ``s[pos:]``, 超出 31 字节截断."""
    last = length if length < _TOKEN_SIZE else _TOKEN_SIZE - 1
    token.type = stype
    token.pos = pos
    token.len = last
    token.val = value[:last]


class _SqliState:
    """对应 C 的 ``struct libinjection_sqli_state``."""

    __slots__ = ("s", "slen", "flags", "pos", "current", "tokenvec",
                 "fingerprint", "stats_comment_ddx", "stats_comment_hash",
                 "stats_comment_c", "stats_folds", "stats_tokens")

    def __init__(self, s: str) -> None:
        self.s = s
        self.slen = len(s)
        self.flags = 0
        self.pos = 0
        #: MAX_TOKENS(5) + 1 用于判型, 再 +2 冗余 —— 与 C 的 tokenvec[8] 对齐
        self.tokenvec = [_Token() for _ in range(8)]
        self.current = self.tokenvec[0]
        self.fingerprint = ""
        self.stats_comment_ddx = 0
        self.stats_comment_hash = 0
        self.stats_comment_c = 0
        self.stats_folds = 0
        self.stats_tokens = 0

    def reset(self, flags: int) -> None:
        """对应 ``libinjection_sqli_reset``: 清空统计与 token 缓冲."""
        if flags == 0:
            flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI
        self.flags = flags
        self.pos = 0
        self.fingerprint = ""
        self.stats_comment_ddx = 0
        self.stats_comment_hash = 0
        self.stats_comment_c = 0
        self.stats_folds = 0
        self.stats_tokens = 0
        self.current = self.tokenvec[0]


# --- 字符类别 (与 C 的 strchr 集合严格一致) ---
#: ``char_is_white`` —— 注意含 Latin-1 NBSP 与 NUL
_WHITE = frozenset(" \t\n\v\f\r\xa0\x00")

#: ``parse_word`` / ``strlencspn`` 的终止字符集合 (NULL 隐含在内)
_WORD_STOP = (" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r\"\xa0\x00")
#: ``parse_var`` 的终止字符集合
_VAR_STOP = " <>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r'`\"\x00"
#: 十进制数字 -- 对应 C 的 ``ISDIGIT`` 宏, **不含** NUL
_DIGITS = "0123456789"
#: 以下集合走 ``strlenspn``/``strlencspn``: C 里 ``strchr(accept, '\0')`` 命中
#: accept 的结尾 NUL, 所以 NUL 反而算"属于该集合"
_HEXDIGITS = "0123456789ABCDEFabcdef\x00"
_BINDIGITS = "01\x00"
_MONEY = "0123456789.,\x00"
_ALPHA = "abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\x00"

_RE_WORD_STOP = re.compile("[" + re.escape(_WORD_STOP) + "]")
_RE_VAR_STOP = re.compile("[" + re.escape(_VAR_STOP) + "]")
_RE_DIGITS = re.compile("[" + re.escape(_DIGITS) + "]*")
_RE_HEXDIGITS = re.compile("[" + re.escape(_HEXDIGITS) + "]*")
_RE_BINDIGITS = re.compile("[" + re.escape(_BINDIGITS) + "]*")
_RE_MONEY = re.compile("[" + re.escape(_MONEY) + "]*")
_RE_ALPHA = re.compile("[" + re.escape(_ALPHA) + "]*")


def _spn(s: str, pos: int, end: int, pattern: re.Pattern[str]) -> int:
    """``strlenspn``: 返回 ``pos`` 起连续属于 ``pattern`` 的字符后的下标."""
    return pattern.match(s, pos, end).end()


def _cspn(s: str, pos: int, end: int, pattern: re.Pattern[str]) -> int:
    """``strlencspn``: 返回 ``pos`` 起第一个落在集合内的字符下标 (无则 ``end``)."""
    match = pattern.search(s, pos, end)
    return match.start() if match else end


def _memchr2(s: str, start: int, length: int, c0: str, c1: str) -> int:
    """``memchr2``: 在 ``s[start:start+length]`` 内找两字符序列, 返回下标或 -1."""
    if length < 2:
        return -1
    limit = start + length - 1
    index = s.find(c0, start, limit)
    while index >= 0:
        if s[index + 1] == c1:
            return index
        index = s.find(c0, index + 1, limit)
    return -1


def _is_backslash_escaped(s: str, end: int, start: int) -> int:
    """从 ``end`` 往回数连续反斜杠, 奇数个表示被转义."""
    ptr = end
    while ptr >= start and s[ptr] == "\\":
        ptr -= 1
    return (end - ptr) & 1


def _lookup_word(text: str) -> str:
    """关键字 / 操作符查表; 未命中返回 ``CHAR_NULL`` (即 TYPE_NONE)."""
    return _SQL_WORDS.get(_ascii_upper(text), CHAR_NULL)


# --- 各词法分析函数 (对应 char_parse_map 里的 parse_*) ---
def _parse_white(st: _SqliState) -> int:
    return st.pos + 1


def _parse_operator1(st: _SqliState) -> int:
    pos = st.pos
    _assign(st.current, TYPE_OPERATOR, pos, 1, st.s[pos])
    return pos + 1


def _parse_other(st: _SqliState) -> int:
    pos = st.pos
    _assign(st.current, TYPE_UNKNOWN, pos, 1, st.s[pos])
    return pos + 1


def _parse_char(st: _SqliState) -> int:
    """``( ) , ; { }`` —— token 类型就是字符本身."""
    pos = st.pos
    ch = st.s[pos]
    _assign(st.current, ch, pos, 1, ch)
    return pos + 1


def _parse_eol_comment(st: _SqliState) -> int:
    s, slen, pos = st.s, st.slen, st.pos
    endpos = s.find("\n", pos, slen)
    if endpos < 0:
        _assign(st.current, TYPE_COMMENT, pos, slen - pos, s[pos:])
        return slen
    _assign(st.current, TYPE_COMMENT, pos, endpos - pos, s[pos:])
    return endpos + 1


def _parse_hash(st: _SqliState) -> int:
    """ANSI 模式下 ``#`` 是操作符; MySQL 模式下是行尾注释."""
    st.stats_comment_hash += 1
    if st.flags & FLAG_SQL_MYSQL:
        st.stats_comment_hash += 1
        return _parse_eol_comment(st)
    _assign(st.current, TYPE_OPERATOR, st.pos, 1, "#")
    return st.pos + 1


def _parse_dash(st: _SqliState) -> int:
    """``--`` 的五种情况: 注释 / 到行尾 / 两个一元减号."""
    s, slen, pos = st.s, st.slen, st.pos
    if pos + 2 < slen and s[pos + 1] == "-" and s[pos + 2] in _WHITE:
        return _parse_eol_comment(st)
    if pos + 2 == slen and s[pos + 1] == "-":
        return _parse_eol_comment(st)
    if pos + 1 < slen and s[pos + 1] == "-" and (st.flags & FLAG_SQL_ANSI):
        st.stats_comment_ddx += 1
        return _parse_eol_comment(st)
    _assign(st.current, TYPE_OPERATOR, pos, 1, "-")
    return pos + 1


def _is_mysql_comment(s: str, slen: int, pos: int) -> bool:
    """``/*!`` 形式的 MySQL 条件注释 —— libinjection 直接判为 EVIL."""
    if pos + 2 >= slen:
        return False
    return s[pos + 2] == "!"


def _parse_slash(st: _SqliState) -> int:
    s, slen, pos = st.s, st.slen, st.pos
    pos1 = pos + 1
    if pos1 >= slen or s[pos1] != "*":
        return _parse_operator1(st)

    ctype = TYPE_COMMENT
    ptr = _memchr2(s, pos + 2, slen - (pos + 2), "*", "/")
    if ptr < 0:
        clen = slen - pos
    else:
        clen = ptr + 2 - pos

    # postgresql 允许嵌套注释 -> 解析不可靠; MySQL 条件注释 -> 直接拉黑
    if ptr >= 0 and _memchr2(s, pos + 2, ptr - (pos + 1), "/", "*") >= 0:
        ctype = TYPE_EVIL
    elif _is_mysql_comment(s, slen, pos):
        ctype = TYPE_EVIL

    _assign(st.current, ctype, pos, clen, s[pos:])
    return pos + clen


def _parse_backslash(st: _SqliState) -> int:
    s, slen, pos = st.s, st.slen, st.pos
    if pos + 1 < slen and s[pos + 1] == "N":
        _assign(st.current, TYPE_NUMBER, pos, 2, s[pos:])
        return pos + 2
    _assign(st.current, TYPE_BACKSLASH, pos, 1, s[pos])
    return pos + 1


def _parse_operator2(st: _SqliState) -> int:
    s, slen, pos = st.s, st.slen, st.pos
    if pos + 1 >= slen:
        return _parse_operator1(st)
    if pos + 2 < slen and s[pos] == "<" and s[pos + 1] == "=" and s[pos + 2] == ">":
        _assign(st.current, TYPE_OPERATOR, pos, 3, s[pos:])
        return pos + 3
    ch = _lookup_word(s[pos:pos + 2])
    if ch != CHAR_NULL:
        _assign(st.current, ch, pos, 2, s[pos:])
        return pos + 2
    if s[pos] == ":":
        _assign(st.current, TYPE_COLON, pos, 1, s[pos])
        return pos + 1
    return _parse_operator1(st)


def _parse_string_core(s: str, slen: int, pos: int, token: _Token,
                       delim: str, offset: int) -> int:
    """字符串字面量; ``offset`` 为 0 表示"假装输入以引号开头" (没有真正的引号)."""
    qpos = s.find(delim, pos + offset, slen)
    token.str_open = delim if offset > 0 else CHAR_NULL

    while True:
        if qpos < 0:
            _assign(token, TYPE_STRING, pos + offset, slen - pos - offset,
                    s[pos + offset:])
            token.str_close = CHAR_NULL
            return slen
        if _is_backslash_escaped(s, qpos - 1, pos + offset):
            qpos = s.find(delim, qpos + 1, slen)
            continue
        if qpos + 1 < slen and s[qpos + 1] == s[qpos]:
            # 双写引号转义: '' 或 ""
            qpos = s.find(delim, qpos + 2, slen)
            continue
        _assign(token, TYPE_STRING, pos + offset, qpos - (pos + offset),
                s[pos + offset:qpos])
        token.str_close = delim
        return qpos + 1


def _parse_string(st: _SqliState) -> int:
    pos = st.pos
    return _parse_string_core(st.s, st.slen, pos, st.current, st.s[pos], 1)


def _parse_estring(st: _SqliState) -> int:
    """``E'...'`` (PostgreSQL escape string)."""
    s, slen, pos = st.s, st.slen, st.pos
    if pos + 2 >= slen or s[pos + 1] != CHAR_SINGLE:
        return _parse_word(st)
    return _parse_string_core(s, slen, pos, st.current, CHAR_SINGLE, 2)


def _parse_ustring(st: _SqliState) -> int:
    """``U&'...'`` Unicode 字符串."""
    s, slen, pos = st.s, st.slen, st.pos
    if pos + 2 < slen and s[pos + 1] == "&" and s[pos + 2] == CHAR_SINGLE:
        st.pos = pos + 2
        end = _parse_string(st)
        token = st.current
        token.str_open = "u"
        if token.str_close == CHAR_SINGLE:
            token.str_close = "u"
        return end
    return _parse_word(st)


def _parse_qstring_core(st: _SqliState, offset: int) -> int:
    """Oracle ``q'[...]'`` / ``nq'...'`` 字符串."""
    s, slen = st.s, st.slen
    pos = st.pos + offset
    if (pos >= slen or (s[pos] != "q" and s[pos] != "Q") or pos + 2 >= slen
            or s[pos + 1] != CHAR_SINGLE):
        return _parse_word(st)
    ch = s[pos + 2]
    # C 里是 char (有符号), 高位字符会落进 "< 33" 分支
    if ord(ch) < 33 or ord(ch) > 127:
        return _parse_word(st)
    if ch == "(":
        ch = ")"
    elif ch == "[":
        ch = "]"
    elif ch == "{":
        ch = "}"
    elif ch == "<":
        ch = ">"

    strend = _memchr2(s, pos + 3, slen - pos - 3, ch, CHAR_SINGLE)
    token = st.current
    if strend < 0:
        _assign(token, TYPE_STRING, pos + 3, slen - pos - 3, s[pos + 3:])
        token.str_open = "q"
        token.str_close = CHAR_NULL
        return slen
    _assign(token, TYPE_STRING, pos + 3, strend - pos - 3, s[pos + 3:])
    token.str_open = "q"
    token.str_close = "q"
    return strend + 2


def _parse_qstring(st: _SqliState) -> int:
    return _parse_qstring_core(st, 0)


def _parse_nqstring(st: _SqliState) -> int:
    s, slen, pos = st.s, st.slen, st.pos
    if pos + 2 < slen and s[pos + 1] == CHAR_SINGLE:
        return _parse_estring(st)
    return _parse_qstring_core(st, 1)


def _parse_bstring(st: _SqliState) -> int:
    """``b'0101'`` 二进制字面量."""
    s, slen, pos = st.s, st.slen, st.pos
    if pos + 2 >= slen or s[pos + 1] != CHAR_SINGLE:
        return _parse_word(st)
    wlen = _spn(s, pos + 2, slen, _RE_BINDIGITS) - (pos + 2)
    if pos + 2 + wlen >= slen or s[pos + 2 + wlen] != CHAR_SINGLE:
        return _parse_word(st)
    _assign(st.current, TYPE_NUMBER, pos, wlen + 3, s[pos:])
    return pos + 2 + wlen + 1


def _parse_xstring(st: _SqliState) -> int:
    """``x'1f2a'`` 十六进制字面量."""
    s, slen, pos = st.s, st.slen, st.pos
    if pos + 2 >= slen or s[pos + 1] != CHAR_SINGLE:
        return _parse_word(st)
    wlen = _spn(s, pos + 2, slen, _RE_HEXDIGITS) - (pos + 2)
    if pos + 2 + wlen >= slen or s[pos + 2 + wlen] != CHAR_SINGLE:
        return _parse_word(st)
    _assign(st.current, TYPE_NUMBER, pos, wlen + 3, s[pos:])
    return pos + 2 + wlen + 1


def _parse_bword(st: _SqliState) -> int:
    """MS SQL Server 的 ``[bracket word]``."""
    s, slen, pos = st.s, st.slen, st.pos
    endptr = s.find("]", pos, slen)
    if endptr < 0:
        _assign(st.current, TYPE_BAREWORD, pos, slen - pos, s[pos:])
        return slen
    _assign(st.current, TYPE_BAREWORD, pos, endptr - pos + 1, s[pos:])
    return endptr + 1


def _parse_word(st: _SqliState) -> int:
    s, slen, pos = st.s, st.slen, st.pos
    token = st.current
    wlen = _cspn(s, pos, slen, _RE_WORD_STOP) - pos
    _assign(token, TYPE_BAREWORD, pos, wlen, s[pos:])

    # "SELECT.1" / SELECT`col` —— 点在词内时回退成关键字
    for i in range(token.len):
        delim = token.val[i]
        if delim == "." or delim == "`":
            ch = _lookup_word(token.val[:i])
            if ch != TYPE_NONE and ch != TYPE_BAREWORD:
                token.clear()
                _assign(token, ch, pos, i, s[pos:])
                return pos + i

    if wlen < _TOKEN_SIZE:
        ch = _lookup_word(token.val[:wlen])
        token.type = TYPE_BAREWORD if ch == CHAR_NULL else ch
    return pos + wlen


def _parse_tick(st: _SqliState) -> int:
    """MySQL 反引号: 介于字符串和裸词之间."""
    s, slen, pos = st.s, st.slen, st.pos
    end = _parse_string_core(s, slen, pos, st.current, CHAR_TICK, 1)
    token = st.current
    if _lookup_word(token.val[:token.len]) == TYPE_FUNCTION:
        token.type = TYPE_FUNCTION
    else:
        token.type = TYPE_BAREWORD
    return end


def _parse_var(st: _SqliState) -> int:
    """``@var`` / ``@@var`` (含 ``@@`version``` 这种写法)."""
    s, slen, pos = st.s, st.slen, st.pos
    token = st.current
    pos = st.pos + 1
    if pos < slen and s[pos] == "@":
        pos += 1
        token.count = 2
    else:
        token.count = 1

    if pos < slen:
        if s[pos] == CHAR_TICK:
            st.pos = pos
            end = _parse_tick(st)
            token.type = TYPE_VARIABLE
            return end
        if s[pos] == CHAR_SINGLE or s[pos] == CHAR_DOUBLE:
            st.pos = pos
            end = _parse_string(st)
            token.type = TYPE_VARIABLE
            return end

    xlen = _cspn(s, pos, slen, _RE_VAR_STOP) - pos
    _assign(token, TYPE_VARIABLE, pos, xlen, s[pos:])
    return pos + xlen


def _parse_money(st: _SqliState) -> int:
    """``$`` —— 货币量 / ``$$dollar quoted$$`` / PostgreSQL ``$tag$...$tag$``."""
    s, slen, pos = st.s, st.slen, st.pos
    if pos + 1 == slen:
        _assign(st.current, TYPE_BAREWORD, pos, 1, "$")
        return slen

    xlen = _spn(s, pos + 1, slen, _RE_MONEY) - (pos + 1)
    if xlen == 0:
        if s[pos + 1] == "$":
            strend = _memchr2(s, pos + 2, slen - pos - 2, "$", "$")
            if strend < 0:
                _assign(st.current, TYPE_STRING, pos + 2, slen - pos - 2, s[pos + 2:])
                st.current.str_open = "$"
                st.current.str_close = CHAR_NULL
                return slen
            _assign(st.current, TYPE_STRING, pos + 2, strend - pos - 2, s[pos + 2:])
            st.current.str_open = "$"
            st.current.str_close = "$"
            return strend + 2

        xlen = _spn(s, pos + 1, slen, _RE_ALPHA) - (pos + 1)
        if xlen == 0:
            _assign(st.current, TYPE_BAREWORD, pos, 1, "$")
            return pos + 1
        if pos + xlen + 1 == slen or s[pos + xlen + 1] != "$":
            _assign(st.current, TYPE_BAREWORD, pos, 1, "$")
            return pos + 1
        needle = s[pos:pos + xlen + 2]
        strend = s.find(needle, pos + xlen + 2, slen)
        if strend < 0:
            _assign(st.current, TYPE_STRING, pos + xlen + 2,
                    slen - pos - xlen - 2, s[pos + xlen + 2:])
            st.current.str_open = "$"
            st.current.str_close = CHAR_NULL
            return slen
        _assign(st.current, TYPE_STRING, pos + xlen + 2,
                strend - (pos + xlen + 2), s[pos + xlen + 2:])
        st.current.str_open = "$"
        st.current.str_close = "$"
        return strend + xlen + 2
    if xlen == 1 and s[pos + 1] == ".":
        return _parse_word(st)
    _assign(st.current, TYPE_NUMBER, pos, 1 + xlen, s[pos:])
    return pos + 1 + xlen


def _parse_number(st: _SqliState) -> int:
    s, slen, pos = st.s, st.slen, st.pos
    token = st.current
    digits_re = None

    if s[pos] == "0" and pos + 1 < slen:
        nxt = s[pos + 1]
        if nxt == "X" or nxt == "x":
            digits_re = _RE_HEXDIGITS
        elif nxt == "B" or nxt == "b":
            digits_re = _RE_BINDIGITS
        if digits_re is not None:
            xlen = _spn(s, pos + 2, slen, digits_re) - (pos + 2)
            if xlen == 0:
                _assign(token, TYPE_BAREWORD, pos, 2, s[pos:])
                return pos + 2
            _assign(token, TYPE_NUMBER, pos, 2 + xlen, s[pos:])
            return pos + 2 + xlen

    start = pos
    pos = _spn(s, pos, slen, _RE_DIGITS)

    if pos < slen and s[pos] == ".":
        pos += 1
        pos = _spn(s, pos, slen, _RE_DIGITS)
        if pos - start == 1:
            _assign(token, TYPE_DOT, start, 1, ".")
            return pos

    have_e = 0
    have_exp = 0
    if pos < slen and (s[pos] == "E" or s[pos] == "e"):
        have_e = 1
        pos += 1
        if pos < slen and (s[pos] == "+" or s[pos] == "-"):
            pos += 1
        nxt = _spn(s, pos, slen, _RE_DIGITS)
        if nxt > pos:
            have_exp = 1
            pos = nxt

    # Oracle 的浮点后缀 d/D/f/F
    if pos < slen and (s[pos] in "dDfF"):
        if pos + 1 == slen:
            pos += 1
        elif s[pos + 1] in _WHITE or s[pos + 1] == ";":
            pos += 1
        elif s[pos + 1] == "u" or s[pos + 1] == "U":
            pos += 1
        # 否则形如 "123FROM", 只吃数字部分

    # "1.e" / "10.10E": 科学计数法缺指数 -> 整段丢弃, 让后面的 "(1)" 当函数
    if not (have_e == 1 and have_exp == 0):
        _assign(token, TYPE_NUMBER, start, pos - start, s[start:])
    return pos


#: 字符 -> 词法函数的代号 (由 char_parse_map 生成)
_PARSE_FUNCS = {
    "w": _parse_white, "o": _parse_operator1, "x": _parse_other,
    "c": _parse_char, "h": _parse_hash, "d": _parse_dash, "s": _parse_slash,
    "b": _parse_backslash, "2": _parse_operator2, "S": _parse_string,
    "W": _parse_word, "V": _parse_var, "N": _parse_number, "T": _parse_tick,
    "U": _parse_ustring, "Q": _parse_qstring, "q": _parse_nqstring,
    "X": _parse_xstring, "B": _parse_bstring, "E": _parse_estring,
    "R": _parse_bword, "M": _parse_money,
}


def _tokenize(st: _SqliState) -> bool:
    """``libinjection_sqli_tokenize``: 取下一个 token, 返回是否还有."""
    if st.slen == 0:
        return False
    st.current.clear()
    s = st.s

    # 引号上下文: 假装输入以引号开头
    if st.pos == 0 and (st.flags & (FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE)):
        if st.flags & FLAG_QUOTE_SINGLE:
            delim = CHAR_SINGLE
        else:
            delim = CHAR_DOUBLE
        st.pos = _parse_string_core(s, st.slen, 0, st.current, delim, 0)
        st.stats_tokens += 1
        return True

    slen = st.slen
    while st.pos < slen:
        index = ord(s[st.pos])
        # 非 ASCII 的 Python 字符: C 里是多字节, 每个字节都落在 parse_word
        func = _parse_map[index] if index < 256 else _parse_word
        st.pos = func(st)
        if st.current.type != CHAR_NULL:
            st.stats_tokens += 1
            return True
    return False


# ===========================================================================
# SQLi: 折叠 (fold) 与指纹
# ===========================================================================
def _is_arithmetic_op(token: _Token) -> bool:
    return (token.type == TYPE_OPERATOR and token.len == 1
            and token.val in ("*", "/", "-", "+", "%"))


def _is_unary_op(token: _Token) -> bool:
    if token.type != TYPE_OPERATOR:
        return False
    length = token.len
    if length == 1:
        return token.val in ("+", "-", "!", "~")
    if length == 2:
        return token.val == "!!"
    if length == 3:
        return _ascii_upper(token.val) == "NOT"
    return False


#: ``syntax_merge_words`` 允许合并的 token 类型
_MERGE_FIRST = frozenset((TYPE_KEYWORD, TYPE_BAREWORD, TYPE_OPERATOR, TYPE_UNION,
                          TYPE_FUNCTION, TYPE_EXPRESSION, TYPE_TSQL, TYPE_SQLTYPE))
_MERGE_SECOND = _MERGE_FIRST | {TYPE_LOGIC_OPERATOR}

#: fold 里会被提升成函数的关键字 (MySQL / TSQL 里既能当变量又能当函数)
_FUNCTION_KEYWORDS = frozenset((
    "USER_ID", "USER_NAME", "DATABASE", "PASSWORD", "USER",
    "CURRENT_USER", "CURRENT_DATE", "CURRENT_TIME", "CURRENT_TIMESTAMP",
    "LOCALTIME", "LOCALTIMESTAMP",
))


def _syntax_merge_words(a: _Token, b: _Token) -> str:
    """复合关键字合并: ``UNION`` + ``ALL`` -> ``UNION ALL``; 返回新类型或 ``""``."""
    if a.type not in _MERGE_FIRST or b.type not in _MERGE_SECOND:
        return CHAR_NULL
    sz1, sz2 = a.len, b.len
    sz3 = sz1 + sz2 + 1
    if sz3 >= _TOKEN_SIZE:
        return CHAR_NULL
    merged = a.val[:sz1] + " " + b.val[:sz2]
    return _lookup_word(merged)


def _fold(st: _SqliState) -> int:
    """``libinjection_sqli_fold``: 反复合并 token, 返回有效 token 数 (<= 5)."""
    tokens = st.tokenvec
    last_comment = _Token()
    pos = 0
    left = 0
    more = True

    # 跳过开头的注释 / 左括号 / 类型声明 / 一元算符
    st.current = tokens[0]
    while more:
        more = _tokenize(st)
        cur = st.current
        if not (cur.type == TYPE_COMMENT or cur.type == TYPE_LEFTPARENS
                or cur.type == TYPE_SQLTYPE or _is_unary_op(cur)):
            break
    if not more:
        return 0
    pos += 1

    while True:
        if pos >= _MAX_TOKENS:
            t0, t1, t2, t3, t4 = tokens[0], tokens[1], tokens[2], tokens[3], tokens[4]
            if ((t0.type == TYPE_NUMBER
                 and (t1.type == TYPE_OPERATOR or t1.type == TYPE_COMMA)
                 and t2.type == TYPE_LEFTPARENS and t3.type == TYPE_NUMBER
                 and t4.type == TYPE_RIGHTPARENS)
                or (t0.type == TYPE_BAREWORD and t1.type == TYPE_OPERATOR
                    and t2.type == TYPE_LEFTPARENS
                    and (t3.type == TYPE_BAREWORD or t3.type == TYPE_NUMBER)
                    and t4.type == TYPE_RIGHTPARENS)
                or (t0.type == TYPE_NUMBER and t1.type == TYPE_RIGHTPARENS
                    and t2.type == TYPE_COMMA and t3.type == TYPE_LEFTPARENS
                    and t4.type == TYPE_NUMBER)
                or (t0.type == TYPE_BAREWORD and t1.type == TYPE_RIGHTPARENS
                    and t2.type == TYPE_OPERATOR and t3.type == TYPE_LEFTPARENS
                    and t4.type == TYPE_BAREWORD)):
                if pos > _MAX_TOKENS:
                    tokens[1].copy_from(tokens[_MAX_TOKENS])
                    pos = 2
                    left = 0
                else:
                    pos = 1
                    left = 0

        if not more or left >= _MAX_TOKENS:
            left = pos
            break

        # 取最多两个 token
        while more and pos <= _MAX_TOKENS and (pos - left) < 2:
            st.current = tokens[pos]
            more = _tokenize(st)
            if more:
                if st.current.type == TYPE_COMMENT:
                    last_comment.copy_from(st.current)
                else:
                    last_comment.type = CHAR_NULL
                    pos += 1

        if pos - left < 2:
            left = pos
            continue

        tok = tokens[left]
        nxt = tokens[left + 1]

        # --- 两个 token 的折叠规则 ---
        if tok.type == TYPE_STRING and nxt.type == TYPE_STRING:
            pos -= 1
            st.stats_folds += 1
            continue
        if tok.type == TYPE_SEMICOLON and nxt.type == TYPE_SEMICOLON:
            pos -= 1
            st.stats_folds += 1
            continue
        if ((tok.type == TYPE_OPERATOR or tok.type == TYPE_LOGIC_OPERATOR)
                and (_is_unary_op(nxt) or nxt.type == TYPE_SQLTYPE)):
            pos -= 1
            st.stats_folds += 1
            left = 0
            continue
        if tok.type == TYPE_LEFTPARENS and _is_unary_op(nxt):
            pos -= 1
            st.stats_folds += 1
            if left > 0:
                left -= 1
            continue
        merged = _syntax_merge_words(tok, nxt)
        if merged != CHAR_NULL:
            _assign(tok, merged, tok.pos, tok.len + nxt.len + 1,
                    tok.val[:tok.len] + " " + nxt.val[:nxt.len])
            pos -= 1
            st.stats_folds += 1
            if left > 0:
                left -= 1
            continue
        if (tok.type == TYPE_SEMICOLON and nxt.type == TYPE_FUNCTION
                and nxt.val[:1] in ("I", "i") and nxt.val[1:2] in ("F", "f")):
            # ; IF ... 是 T-SQL 的控制流, 不是函数
            nxt.type = TYPE_TSQL
            continue
        if ((tok.type == TYPE_BAREWORD or tok.type == TYPE_VARIABLE)
                and nxt.type == TYPE_LEFTPARENS
                and _ascii_upper(tok.val) in _FUNCTION_KEYWORDS):
            tok.type = TYPE_FUNCTION
            continue
        if tok.type == TYPE_KEYWORD and _ascii_upper(tok.val) in ("IN", "NOT IN"):
            if nxt.type == TYPE_LEFTPARENS:
                tok.type = TYPE_OPERATOR
            else:
                tok.type = TYPE_BAREWORD
            continue
        if tok.type == TYPE_OPERATOR and _ascii_upper(tok.val) in ("LIKE", "NOT LIKE"):
            if nxt.type == TYPE_LEFTPARENS:
                tok.type = TYPE_FUNCTION
        elif (tok.type == TYPE_SQLTYPE
              and nxt.type in (TYPE_BAREWORD, TYPE_NUMBER, TYPE_SQLTYPE,
                               TYPE_LEFTPARENS, TYPE_FUNCTION, TYPE_VARIABLE,
                               TYPE_STRING)):
            tok.copy_from(nxt)
            pos -= 1
            st.stats_folds += 1
            left = 0
            continue
        elif tok.type == TYPE_COLLATE and nxt.type == TYPE_BAREWORD:
            # 排序规则名太多, 带下划线的当成类型名
            if "_" in nxt.val:
                nxt.type = TYPE_SQLTYPE
                left = 0
        elif tok.type == TYPE_BACKSLASH:
            if _is_arithmetic_op(nxt):
                tok.type = TYPE_NUMBER
            else:
                tok.copy_from(nxt)
                pos -= 1
                st.stats_folds += 1
            left = 0
            continue
        elif tok.type == TYPE_LEFTPARENS and nxt.type == TYPE_LEFTPARENS:
            pos -= 1
            left = 0
            st.stats_folds += 1
            continue
        elif tok.type == TYPE_RIGHTPARENS and nxt.type == TYPE_RIGHTPARENS:
            pos -= 1
            left = 0
            st.stats_folds += 1
            continue
        elif tok.type == TYPE_LEFTBRACE and nxt.type == TYPE_BAREWORD:
            # MySQL 的 ``select {``.``.id }`` 这类怪写法: 直接判 EVIL
            if nxt.len == 0:
                nxt.type = TYPE_EVIL
                return left + 2
            left = 0
            pos -= 2
            st.stats_folds += 2
            continue
        elif nxt.type == TYPE_RIGHTBRACE:
            pos -= 1
            left = 0
            st.stats_folds += 1
            continue

        # 两个 token 的规则都用完了, 再取一个
        while more and pos <= _MAX_TOKENS and pos - left < 3:
            st.current = tokens[pos]
            more = _tokenize(st)
            if more:
                if st.current.type == TYPE_COMMENT:
                    last_comment.copy_from(st.current)
                else:
                    last_comment.type = CHAR_NULL
                    pos += 1

        if pos - left < 3:
            left = pos
            continue

        tok = tokens[left]
        nxt = tokens[left + 1]
        thr = tokens[left + 2]

        # --- 三个 token 的折叠规则 ---
        if (tok.type == TYPE_NUMBER and nxt.type == TYPE_OPERATOR
                and thr.type == TYPE_NUMBER):
            pos -= 2
            left = 0
            continue
        if (tok.type == TYPE_OPERATOR and nxt.type != TYPE_LEFTPARENS
                and thr.type == TYPE_OPERATOR):
            left = 0
            pos -= 2
            continue
        if tok.type == TYPE_LOGIC_OPERATOR and thr.type == TYPE_LOGIC_OPERATOR:
            pos -= 2
            left = 0
            continue
        if (tok.type == TYPE_VARIABLE and nxt.type == TYPE_OPERATOR
                and thr.type in (TYPE_VARIABLE, TYPE_NUMBER, TYPE_BAREWORD)):
            pos -= 2
            left = 0
            continue
        if (tok.type in (TYPE_BAREWORD, TYPE_NUMBER) and nxt.type == TYPE_OPERATOR
                and thr.type in (TYPE_NUMBER, TYPE_BAREWORD)):
            pos -= 2
            left = 0
            continue
        if (tok.type in (TYPE_BAREWORD, TYPE_NUMBER, TYPE_VARIABLE, TYPE_STRING)
                and nxt.type == TYPE_OPERATOR and nxt.val == "::"
                and thr.type == TYPE_SQLTYPE):
            pos -= 2
            left = 0
            st.stats_folds += 2
            continue
        if (tok.type in (TYPE_BAREWORD, TYPE_NUMBER, TYPE_STRING, TYPE_VARIABLE)
                and nxt.type == TYPE_COMMA
                and thr.type in (TYPE_NUMBER, TYPE_BAREWORD, TYPE_STRING,
                                 TYPE_VARIABLE)):
            pos -= 2
            left = 0
            continue
        if (tok.type in (TYPE_EXPRESSION, TYPE_GROUP, TYPE_COMMA)
                and _is_unary_op(nxt) and thr.type == TYPE_LEFTPARENS):
            nxt.copy_from(thr)
            pos -= 1
            left = 0
            continue
        if (tok.type in (TYPE_KEYWORD, TYPE_EXPRESSION, TYPE_GROUP)
                and _is_unary_op(nxt)
                and thr.type in (TYPE_NUMBER, TYPE_BAREWORD, TYPE_VARIABLE,
                                 TYPE_STRING, TYPE_FUNCTION)):
            nxt.copy_from(thr)
            pos -= 1
            left = 0
            continue
        if (tok.type == TYPE_COMMA and _is_unary_op(nxt)
                and thr.type in (TYPE_NUMBER, TYPE_BAREWORD, TYPE_VARIABLE,
                                 TYPE_STRING)):
            nxt.copy_from(thr)
            left = 0
            pos -= 3
            continue
        if (tok.type == TYPE_COMMA and _is_unary_op(nxt)
                and thr.type == TYPE_FUNCTION):
            nxt.copy_from(thr)
            pos -= 1
            left = 0
            continue
        if (tok.type == TYPE_BAREWORD and nxt.type == TYPE_DOT
                and thr.type == TYPE_BAREWORD):
            pos -= 2
            left = 0
            continue
        if (tok.type == TYPE_EXPRESSION and nxt.type == TYPE_DOT
                and thr.type == TYPE_BAREWORD):
            nxt.copy_from(thr)
            pos -= 1
            left = 0
            continue
        if (tok.type == TYPE_FUNCTION and nxt.type == TYPE_LEFTPARENS
                and thr.type != TYPE_RIGHTPARENS):
            # USER(foo) 里 USER 不是函数
            if _ascii_upper(tok.val) == "USER":
                tok.type = TYPE_BAREWORD

        left += 1

    if left < _MAX_TOKENS and last_comment.type == TYPE_COMMENT:
        tokens[left].copy_from(last_comment)
        left += 1
    if left > _MAX_TOKENS:
        left = _MAX_TOKENS
    return left


def _sqli_fingerprint(st: _SqliState, flags: int) -> str:
    """算一次 fingerprint (对应 ``libinjection_sqli_fingerprint``)."""
    st.reset(flags)
    tlen = _fold(st)

    last = st.tokenvec[tlen - 1] if tlen else None
    if (tlen > 2 and last is not None and last.type == TYPE_BAREWORD
            and last.str_open == CHAR_TICK and last.len == 0
            and last.str_close == CHAR_NULL):
        # PHP 反引号注释的魔法判定
        last.type = TYPE_COMMENT

    fingerprint = "".join(st.tokenvec[i].type for i in range(tlen))
    st.fingerprint = fingerprint

    if TYPE_EVIL in fingerprint:
        # 解析不可靠 (pgsql 嵌套注释等) —— 整个 fingerprint 塌缩成单个 X
        st.tokenvec[0].clear()
        st.tokenvec[0].type = TYPE_EVIL
        st.tokenvec[0].val = TYPE_EVIL
        st.tokenvec[1].type = CHAR_NULL
        st.fingerprint = TYPE_EVIL
    return st.fingerprint


def _cstrcasecmp(a: str, b: str, n: int) -> int:
    """C 版 ``cstrcasecmp``: ``a`` 为全大写 C 字符串, ``b`` 仅比较前 ``n`` 个字符."""
    for i in range(n):
        cb = ord(b[i])
        if 97 <= cb <= 122:
            cb -= 0x20
        ca = ord(a[i]) if i < len(a) else 0
        if ca != cb:
            return ca - cb
        if ca == 0:
            return -1
    ca = ord(a[n]) if n < len(a) else 0
    return 0 if ca == 0 else 1


def _signed_byte(ch: str) -> int:
    """C 里 ``char`` 有符号: 0x80-0xff 读出来是负数."""
    code = ord(ch)
    return code - 256 if 128 <= code <= 255 else code


def _sqli_blacklist(st: _SqliState) -> bool:
    """``libinjection_sqli_blacklist``: fingerprint 是否命中已知攻击模式."""
    fingerprint = st.fingerprint
    if len(fingerprint) < 1:
        return False
    # v0 -> v1: 前面补 '0' 并转大写, 再在关键字表里做等值查找
    return ("0" + _ascii_upper(fingerprint)) in _FP_PATTERNS


def _sqli_not_whitelist(st: _SqliState) -> bool:
    """``libinjection_sqli_not_whitelist``: 命中模式后再做误报排除."""
    fingerprint = st.fingerprint
    tlen = len(fingerprint)
    s = st.s
    tokens = st.tokenvec

    if tlen > 1 and fingerprint[tlen - 1] == TYPE_COMMENT:
        # MS 审计日志会忽略含 sp_password 的语句, 攻击者常借用
        if "sp_password" in s:
            return True

    if tlen == 2:
        if fingerprint[1] == TYPE_UNION:
            # "1 union" 太常见, 需要至少 3 个 token 才算
            return st.stats_tokens != 2
        if _val0(tokens[1]) == "#":
            return False
        if (tokens[0].type == TYPE_BAREWORD and tokens[1].type == TYPE_COMMENT
                and _val0(tokens[1]) != "/"):
            # ``nc`` 里只有 ``/*`` 型注释才算 SQLi
            return False
        if (tokens[0].type == TYPE_NUMBER and tokens[1].type == TYPE_COMMENT
                and _val0(tokens[1]) == "/"):
            return True
        if tokens[0].type == TYPE_NUMBER and tokens[1].type == TYPE_COMMENT:
            if st.stats_tokens > 2:
                # 有折叠说明不只是 "1234--BASE64"
                return True
            index = tokens[0].len
            ch = s[index] if index < len(s) else CHAR_NULL
            if _signed_byte(ch) <= 32:
                return True
            nxt = s[index + 1] if index + 1 < len(s) else CHAR_NULL
            if ch == "/" and nxt == "*":
                return True
            if ch == "-" and nxt == "-":
                return True
            return False
        if tokens[1].len > 2 and _val0(tokens[1]) == "-":
            # 正文里的 ``--`` 太多, 只有结尾的才算
            return False
    elif tlen == 3:
        if fingerprint == "sos" or fingerprint == "s&s":
            if (tokens[0].str_open == CHAR_NULL
                    and tokens[2].str_close == CHAR_NULL
                    and tokens[0].str_close == tokens[2].str_open):
                # ...foo" + "bar... 拼接
                return True
            return False
        if (fingerprint == "s&n" or fingerprint == "n&1" or fingerprint == "1&1"
                or fingerprint == "1&v" or fingerprint == "1&s"):
            # 'sexy and 17' 不是注入; 多一个 token 才是
            if st.stats_tokens == 3:
                return False
        elif tokens[1].type == TYPE_KEYWORD:
            if tokens[1].len < 5 or _cstrcasecmp("INTO", tokens[1].val, 4) != 0:
                # 只有 INTO OUTFILE / INTO DUMPFILE 才当注入
                return False

    return True


def _sqli_check(st: _SqliState) -> bool:
    return _sqli_blacklist(st) and _sqli_not_whitelist(st)


def _reparse_as_mysql(st: _SqliState) -> bool:
    return bool(st.stats_comment_ddx or st.stats_comment_hash)


def _is_sqli(s: str) -> bool:
    """``libinjection_is_sqli``: 依次尝试 无引号 / 单引号 / 双引号 上下文."""
    if not s:
        return False
    st = _SqliState(s)

    _sqli_fingerprint(st, FLAG_QUOTE_NONE | FLAG_SQL_ANSI)
    if _sqli_check(st):
        return True
    if _reparse_as_mysql(st):
        _sqli_fingerprint(st, FLAG_QUOTE_NONE | FLAG_SQL_MYSQL)
        if _sqli_check(st):
            return True

    if CHAR_SINGLE in s:
        _sqli_fingerprint(st, FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI)
        if _sqli_check(st):
            return True
        if _reparse_as_mysql(st):
            _sqli_fingerprint(st, FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL)
            if _sqli_check(st):
                return True

    if CHAR_DOUBLE in s:
        _sqli_fingerprint(st, FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL)
        if _sqli_check(st):
            return True

    return False


# ===========================================================================
# XSS: HTML5 词法分析 (libinjection_html5)
# ===========================================================================
_EOF = -1

#: ``h5_is_white`` —— C 里用 ``strchr(" \t\n\v\f\r", ch)``, 因此 NUL (结尾符)
#: 也算"空白"。``_tag_name`` 会先单独处理 NUL, 不受影响。
_H5_WHITE = frozenset(" \t\n\v\f\r\x00")
#: ``h5_skip_white`` (额外忽略 NUL 与其余控制字符)
_H5_SKIP_WHITE = frozenset("\x00 \t\n\v\f\r")


class _H5:
    """对应 C 的 ``h5_state_t``."""

    __slots__ = ("s", "slen", "pos", "is_close", "state", "token_start",
                 "token_len", "token_type")

    def __init__(self, s: str, flags: int) -> None:
        self.s = s
        self.slen = len(s)
        self.pos = 0
        self.is_close = 0
        self.token_start = 0
        self.token_len = 0
        self.token_type = H5_DATA_TEXT
        if flags == H5_STATE_DATA:
            self.state = self._data
        elif flags == H5_STATE_VALUE_NO_QUOTE:
            self.state = self._before_attribute_name
        elif flags == H5_STATE_VALUE_SINGLE_QUOTE:
            self.state = self._attribute_value_single_quote
        elif flags == H5_STATE_VALUE_DOUBLE_QUOTE:
            self.state = self._attribute_value_double_quote
        else:
            self.state = self._attribute_value_back_quote

    # -- 工具 --
    def _skip_white(self) -> int:
        s, slen = self.s, self.slen
        while self.pos < slen:
            ch = s[self.pos]
            if ch in _H5_SKIP_WHITE:
                self.pos += 1
            else:
                return ord(ch)
        return _EOF

    def _eof(self) -> int:
        return 0

    def _data(self) -> int:
        s = self.s
        index = s.find("<", self.pos, self.slen)
        if index < 0:
            self.token_start = self.pos
            self.token_len = self.slen - self.pos
            self.token_type = H5_DATA_TEXT
            self.state = self._eof
            if self.token_len == 0:
                return 0
        else:
            self.token_start = self.pos
            self.token_type = H5_DATA_TEXT
            self.token_len = index - self.pos
            self.pos = index + 1
            self.state = self._tag_open
            if self.token_len == 0:
                return self._tag_open()
        return 1

    def _tag_open(self) -> int:
        if self.pos >= self.slen:
            return 0
        ch = self.s[self.pos]
        if ch == "!":
            self.pos += 1
            return self._markup_declaration_open()
        if ch == "/":
            self.pos += 1
            self.is_close = 1
            return self._end_tag_open()
        if ch == "?":
            self.pos += 1
            return self._bogus_comment()
        if ch == "%":
            # IE<=9 / Safari<4.0.3 的私有注释格式
            self.pos += 1
            return self._bogus_comment2()
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ch == "\x00":
            return self._tag_name()
        if self.pos == 0:
            return self._data()
        self.token_start = self.pos - 1
        self.token_len = 1
        self.token_type = H5_DATA_TEXT
        self.state = self._data
        return 1

    def _end_tag_open(self) -> int:
        if self.pos >= self.slen:
            return 0
        ch = self.s[self.pos]
        if ch == ">":
            return self._data()
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
            return self._tag_name()
        self.is_close = 0
        return self._bogus_comment()

    def _tag_name_close(self) -> int:
        self.is_close = 0
        self.token_start = self.pos
        self.token_len = 1
        self.token_type = H5_TAG_NAME_CLOSE
        self.pos += 1
        self.state = self._data if self.pos < self.slen else self._eof
        return 1

    def _tag_name(self) -> int:
        s, slen, start = self.s, self.slen, self.pos
        pos = start
        while pos < slen:
            ch = s[pos]
            if ch == "\x00":
                # 老浏览器会忽略标签名里的 NUL
                pos += 1
            elif ch in _H5_WHITE:
                self.token_start = start
                self.token_len = pos - start
                self.token_type = H5_TAG_NAME_OPEN
                self.pos = pos + 1
                self.state = self._before_attribute_name
                return 1
            elif ch == "/":
                self.token_start = start
                self.token_len = pos - start
                self.token_type = H5_TAG_NAME_OPEN
                self.pos = pos + 1
                self.state = self._self_closing_start_tag
                return 1
            elif ch == ">":
                self.token_start = start
                self.token_len = pos - start
                if self.is_close:
                    self.pos = pos + 1
                    self.is_close = 0
                    self.token_type = H5_TAG_CLOSE
                    self.state = self._data
                else:
                    self.pos = pos
                    self.token_type = H5_TAG_NAME_OPEN
                    self.state = self._tag_name_close
                return 1
            else:
                pos += 1
        self.token_start = start
        self.token_len = slen - start
        self.token_type = H5_TAG_NAME_OPEN
        self.state = self._eof
        return 1

    def _before_attribute_name(self) -> int:
        while True:
            ch = self._skip_white()
            if ch == _EOF:
                return 0
            if ch == 0x2F:  # '/'
                self.pos += 1
                # 手动尾调用, 避免深递归
                if self.pos < self.slen and self.s[self.pos] != ">":
                    continue
                return self._self_closing_start_tag()
            if ch == 0x3E:  # '>'
                self.state = self._data
                self.token_start = self.pos
                self.token_len = 1
                self.token_type = H5_TAG_NAME_CLOSE
                self.pos += 1
                return 1
            return self._attribute_name()

    def _attribute_name(self) -> int:
        s, slen, start = self.s, self.slen, self.pos
        pos = start + 1
        while pos < slen:
            ch = s[pos]
            if ch in _H5_WHITE:
                self.token_start = start
                self.token_len = pos - start
                self.token_type = H5_ATTR_NAME
                self.state = self._after_attribute_name
                self.pos = pos + 1
                return 1
            if ch == "/":
                self.token_start = start
                self.token_len = pos - start
                self.token_type = H5_ATTR_NAME
                self.state = self._self_closing_start_tag
                self.pos = pos + 1
                return 1
            if ch == "=":
                self.token_start = start
                self.token_len = pos - start
                self.token_type = H5_ATTR_NAME
                self.state = self._before_attribute_value
                self.pos = pos + 1
                return 1
            if ch == ">":
                self.token_start = start
                self.token_len = pos - start
                self.token_type = H5_ATTR_NAME
                self.state = self._tag_name_close
                self.pos = pos
                return 1
            pos += 1
        self.token_start = start
        self.token_len = slen - start
        self.token_type = H5_ATTR_NAME
        self.state = self._eof
        self.pos = slen
        return 1

    def _after_attribute_name(self) -> int:
        ch = self._skip_white()
        if ch == _EOF:
            return 0
        if ch == 0x2F:  # '/'
            self.pos += 1
            return self._self_closing_start_tag()
        if ch == 0x3D:  # '='
            self.pos += 1
            return self._before_attribute_value()
        if ch == 0x3E:  # '>'
            return self._tag_name_close()
        return self._attribute_name()

    def _before_attribute_value(self) -> int:
        ch = self._skip_white()
        if ch == _EOF:
            self.state = self._eof
            return 0
        if ch == 0x22:  # '"'
            return self._attribute_value_double_quote()
        if ch == 0x27:  # "'"
            return self._attribute_value_single_quote()
        if ch == 0x60:  # '`' (IE 私有)
            return self._attribute_value_back_quote()
        return self._attribute_value_no_quote()

    def _attribute_value_quote(self, qchar: str) -> int:
        if self.pos > 0:
            self.pos += 1
        index = self.s.find(qchar, self.pos, self.slen)
        if index < 0:
            self.token_start = self.pos
            self.token_len = self.slen - self.pos
            self.token_type = H5_ATTR_VALUE
            self.state = self._eof
        else:
            self.token_start = self.pos
            self.token_len = index - self.pos
            self.token_type = H5_ATTR_VALUE
            self.state = self._after_attribute_value_quoted
            self.pos += self.token_len + 1
        return 1

    def _attribute_value_double_quote(self) -> int:
        return self._attribute_value_quote('"')

    def _attribute_value_single_quote(self) -> int:
        return self._attribute_value_quote("'")

    def _attribute_value_back_quote(self) -> int:
        return self._attribute_value_quote("`")

    def _attribute_value_no_quote(self) -> int:
        s, slen, start = self.s, self.slen, self.pos
        pos = start
        while pos < slen:
            ch = s[pos]
            if ch in _H5_WHITE:
                self.token_type = H5_ATTR_VALUE
                self.token_start = start
                self.token_len = pos - start
                self.pos = pos + 1
                self.state = self._before_attribute_name
                return 1
            if ch == ">":
                self.token_type = H5_ATTR_VALUE
                self.token_start = start
                self.token_len = pos - start
                self.pos = pos
                self.state = self._tag_name_close
                return 1
            pos += 1
        self.state = self._eof
        self.token_start = start
        self.token_len = slen - start
        self.token_type = H5_ATTR_VALUE
        return 1

    def _after_attribute_value_quoted(self) -> int:
        if self.pos >= self.slen:
            return 0
        ch = self.s[self.pos]
        if ch in _H5_WHITE:
            self.pos += 1
            return self._before_attribute_name()
        if ch == "/":
            self.pos += 1
            return self._self_closing_start_tag()
        if ch == ">":
            self.token_start = self.pos
            self.token_len = 1
            self.token_type = H5_TAG_NAME_CLOSE
            self.pos += 1
            self.state = self._data
            return 1
        return self._before_attribute_name()

    def _self_closing_start_tag(self) -> int:
        if self.pos >= self.slen:
            return 0
        if self.s[self.pos] == ">":
            self.token_start = self.pos - 1
            self.token_len = 2
            self.token_type = H5_TAG_NAME_SELFCLOSE
            self.state = self._data
            self.pos += 1
            return 1
        return self._before_attribute_name()

    def _bogus_comment(self) -> int:
        index = self.s.find(">", self.pos, self.slen)
        if index < 0:
            self.token_start = self.pos
            self.token_len = self.slen - self.pos
            self.pos = self.slen
            self.state = self._eof
        else:
            self.token_start = self.pos
            self.token_len = index - self.pos
            self.pos = index + 1
            self.state = self._data
        self.token_type = H5_TAG_COMMENT
        return 1

    def _bogus_comment2(self) -> int:
        s, slen = self.s, self.slen
        pos = self.pos
        while True:
            index = s.find("%", pos, slen)
            if index < 0 or index + 1 >= slen:
                self.token_start = self.pos
                self.token_len = slen - self.pos
                self.pos = slen
                self.token_type = H5_TAG_COMMENT
                self.state = self._eof
                return 1
            if s[index + 1] != ">":
                pos = index + 1
                continue
            self.token_start = self.pos
            self.token_len = index - self.pos
            self.pos = index + 2
            self.state = self._data
            self.token_type = H5_TAG_COMMENT
            return 1

    def _markup_declaration_open(self) -> int:
        s, pos, slen = self.s, self.pos, self.slen
        remaining = slen - pos
        if (remaining >= 7 and s[pos] in "Dd" and s[pos + 1] in "Oo"
                and s[pos + 2] in "Cc" and s[pos + 3] in "Tt"
                and s[pos + 4] in "Yy" and s[pos + 5] in "Pp"
                and s[pos + 6] in "Ee"):
            return self._doctype()
        if (remaining >= 7 and s[pos] == "[" and s[pos + 1] == "C"
                and s[pos + 2] == "D" and s[pos + 3] == "A"
                and s[pos + 4] == "T" and s[pos + 5] == "A"
                and s[pos + 6] == "["):
            self.pos += 7
            return self._cdata()
        if remaining >= 2 and s[pos] == "-" and s[pos + 1] == "-":
            self.pos += 2
            return self._comment()
        return self._bogus_comment()

    def _comment(self) -> int:
        s, slen = self.s, self.slen
        pos = self.pos
        while True:
            index = s.find("-", pos, slen)
            if index < 0 or index > slen - 3:
                return self._comment_eof()
            offset = 1
            while index + offset < slen and s[index + offset] == "\x00":
                offset += 1
            if index + offset == slen:
                return self._comment_eof()
            ch = s[index + offset]
            if ch != "-" and ch != "!":
                pos = index + 1
                continue
            offset += 1
            if index + offset == slen:
                return self._comment_eof()
            if s[index + offset] != ">":
                pos = index + 1
                continue
            offset += 1
            # 以 --> 或 -!> 结束
            self.token_start = self.pos
            self.token_len = index - self.pos
            self.pos = index + offset
            self.state = self._data
            self.token_type = H5_TAG_COMMENT
            return 1

    def _comment_eof(self) -> int:
        self.state = self._eof
        self.token_start = self.pos
        self.token_len = self.slen - self.pos
        self.token_type = H5_TAG_COMMENT
        return 1

    def _cdata(self) -> int:
        s, slen = self.s, self.slen
        pos = self.pos
        while True:
            index = s.find("]", pos, slen)
            if index < 0 or index > slen - 3:
                self.state = self._eof
                self.token_start = self.pos
                self.token_len = slen - self.pos
                self.token_type = H5_DATA_TEXT
                return 1
            if s[index + 1] == "]" and s[index + 2] == ">":
                self.state = self._data
                self.token_start = self.pos
                self.token_len = index - self.pos
                self.pos = index + 3
                self.token_type = H5_DATA_TEXT
                return 1
            pos = index + 1

    def _doctype(self) -> int:
        self.token_start = self.pos
        self.token_type = H5_DOCTYPE
        index = self.s.find(">", self.pos, self.slen)
        if index < 0:
            self.state = self._eof
            self.token_len = self.slen - self.pos
        else:
            self.state = self._data
            self.token_len = index - self.pos
            self.pos = index + 1
        return 1


# ===========================================================================
# XSS: token 判定 (libinjection_xss)
# ===========================================================================
_ATTR_NONE = 0
_ATTR_BLACK = 1
_ATTR_URL = 2
_ATTR_STYLE = 3
_ATTR_INDIRECT = 4

#: ``gsHexDecodeMap``: 十六进制字符 -> 数值, 非法字符为 256
_HEX_DECODE = [256] * 256
for _i, _c in enumerate("0123456789"):
    _HEX_DECODE[ord(_c)] = _i
for _i, _c in enumerate("abcdef"):
    _HEX_DECODE[ord(_c)] = 10 + _i
for _i, _c in enumerate("ABCDEF"):
    _HEX_DECODE[ord(_c)] = 10 + _i
del _i, _c


def _html_decode_char_at(s: str, start: int, length: int) -> tuple[int, int]:
    """``html_decode_char_at``: 解数字字符实体, 返回 ``(码点, 消耗字符数)``.

    只处理 ``&#65;`` / ``&#x41;`` 这类数字实体, 命名实体只返回 ``&``。
    和 C 版一样容忍缺少结尾分号的写法 (``&#65`` -> ``A``)。
    """
    if length == 0:
        return -1, 0
    consumed = 1
    first = s[start]
    if first != "&" or length < 3:
        return ord(first), consumed
    is_hex = s[start + 2] == "x" or s[start + 2] == "X"
    if is_hex and length < 4:
        return ord(first), consumed
    if s[start + 1] != "#":
        return ord("&"), consumed

    if is_hex:
        value = _HEX_DECODE[ord(s[start + 3]) & 0xFF]
        if value == 256:
            return ord("&"), consumed
        index = 4
        while index < length:
            ch = s[start + index]
            if ch == ";":
                return value, index + 1
            digit = _HEX_DECODE[ord(ch) & 0xFF]
            if digit == 256:
                return value, index
            value = value * 16 + digit
            if value > 0x1000FF:
                return ord("&"), consumed
            index += 1
        return value, index

    ch = ord(s[start + 2]) & 0xFF
    if ch < 0x30 or ch > 0x39:
        return ord("&"), consumed
    value = ch - 0x30
    index = 3
    while index < length:
        ch = ord(s[start + index]) & 0xFF
        if ch == 0x3B:
            return value, index + 1
        if ch < 0x30 or ch > 0x39:
            return value, index
        value = value * 10 + (ch - 0x30)
        if value > 0x1000FF:
            return ord("&"), consumed
        index += 1
    return value, index


def _htmlencode_startswith(prefix: str, s: str, start: int, length: int) -> bool:
    """``htmlencode_startswith``: 解码字符实体后判断 ``s`` 是否以 ``prefix`` 开头."""
    ai = 0
    index = start
    remaining = length
    first = True
    prefix_len = len(prefix)
    while remaining > 0:
        if ai >= prefix_len:
            return True
        cb, consumed = _html_decode_char_at(s, index, remaining)
        index += consumed
        remaining -= consumed
        if first and cb <= 32:
            # 忽略开头空白与控制字符
            continue
        first = False
        if cb == 0 or cb == 10:
            # 始终忽略 NUL 与垂直制表符
            continue
        if 97 <= cb <= 122:
            cb -= 0x20
        if ord(prefix[ai]) != cb:
            return False
        ai += 1
    return ai >= prefix_len


def _cstrcasecmp_with_null(a: str, b: str, n: int) -> int:
    """``cstrcasecmp_with_null``: 比较时跳过 ``b`` 中的 NUL, 借以绕过黑名单."""
    ai = 0
    bi = 0
    while n > 0:
        n -= 1
        cb = ord(b[bi])
        bi += 1
        if cb == 0:
            continue
        ca = ord(a[ai]) if ai < len(a) else 0
        ai += 1
        if 97 <= cb <= 122:
            cb -= 0x20
        if ca != cb:
            return 1
    ca = ord(a[ai]) if ai < len(a) else 0
    return 0 if ca == 0 else 1


def _is_black_tag(value: str) -> bool:
    """黑标签: script/iframe/svg/xsl/... —— 见 :data:`_XSS_BLACK_TAGS`."""
    length = len(value)
    if length < 3:
        return False
    for tag in _XSS_BLACK_TAGS:
        if _cstrcasecmp_with_null(tag, value, length) == 0:
            return True
    # 任何 SVG 标签 (含 onload 等)
    if value[0] in "sS" and value[1] in "vV" and value[2] in "gG":
        return True
    # 任何 XSL(t) 标签
    if value[0] in "xX" and value[1] in "sS" and value[2] in "lL":
        return True
    return False


def _is_black_attr(value: str) -> int:
    """黑属性: ``on*`` 事件处理器 / xmlns / href / style / ..."""
    length = len(value)
    if length < 2:
        return _ATTR_NONE
    if length >= 5:
        if value[0] in "oO" and value[1] in "nN":
            # onerror / onclick / ... (前缀匹配即可)
            rest = value[2:]
            rest_len = length - 2
            for name, atype in _XSS_BLACK_EVENTS:
                max_len = rest_len if rest_len < len(name) else len(name)
                if _cstrcasecmp_with_null(name, rest, max_len) == 0:
                    return atype
        # xmlns / xlink 可以凭空造标签
        if (_cstrcasecmp_with_null("XMLNS", value, 5) == 0
                or _cstrcasecmp_with_null("XLINK", value, 5) == 0):
            return _ATTR_BLACK
    for name, atype in _XSS_BLACK_ATTRS:
        if _cstrcasecmp_with_null(name, value, length) == 0:
            return atype
    return _ATTR_NONE


def _is_black_url(value: str, start: int, length: int) -> bool:
    """危险 URL 协议: ``data:`` / ``view-source:`` / ``javascript:`` / ``vbscript:``."""
    index = start
    while length > 0 and (ord(value[index]) <= 32 or ord(value[index]) >= 127):
        # 跳过空白与高位字符 (Opera 会用 UTF-8 空白, EUC-JP 里高位字节被忽略)
        index += 1
        length -= 1
    return (_htmlencode_startswith("DATA", value, index, length)
            or _htmlencode_startswith("VIEW-SOURCE", value, index, length)
            or _htmlencode_startswith("JAVA", value, index, length)
            or _htmlencode_startswith("VBSCRIPT", value, index, length))


def _is_xss_once(s: str, flags: int) -> int:
    """``libinjection_is_xss``: 单种起始状态下的检测."""
    state = _H5(s, flags)
    attr = _ATTR_NONE
    while True:
        result = state.state()
        if result != 1:
            return result

        start, length = state.token_start, state.token_len
        token_type = state.token_type
        if token_type != H5_ATTR_VALUE:
            attr = _ATTR_NONE

        if token_type == H5_DOCTYPE:
            return 1
        if token_type == H5_TAG_NAME_OPEN:
            if _is_black_tag(s[start:start + length]):
                return 1
        elif token_type == H5_ATTR_NAME:
            attr = _is_black_attr(s[start:start + length])
        elif token_type == H5_ATTR_VALUE:
            if attr == _ATTR_BLACK or attr == _ATTR_STYLE:
                return 1
            if attr == _ATTR_URL:
                if _is_black_url(s, start, length):
                    return 1
            elif attr == _ATTR_INDIRECT:
                # 属性名藏在属性值里 (SVG attributeName)
                if _is_black_attr(s[start:start + length]):
                    return 1
            attr = _ATTR_NONE
        elif token_type == H5_TAG_COMMENT:
            comment = s[start:start + length]
            # IE 用反引号结束标签
            if "`" in comment:
                return 1
            if length > 3:
                # IE 条件注释
                if comment[0] == "[" and comment[1] in "iI" and comment[2] in "fF":
                    return 1
                if comment[0] in "xX" and comment[1] in "mM" and comment[2] in "lL":
                    return 1
            if length > 5:
                # IE <?import> 伪标签与 XML 实体定义
                if _cstrcasecmp_with_null("IMPORT", comment, 6) == 0:
                    return 1
                if _cstrcasecmp_with_null("ENTITY", comment, 6) == 0:
                    return 1


def _is_xss(s: str) -> bool:
    """依次用 5 种起始状态解析, 任一种命中即为 XSS."""
    # 快路径: 没有 '<' 就拿不到标签/注释/DOCTYPE/黑标签; 没有 '=' 就拿不到属性值,
    # 而黑属性只有在出现属性值时才生效 —— 两者皆无必然不是 XSS。
    if "<" not in s and "=" not in s:
        return False
    for flags in (H5_STATE_DATA, H5_STATE_VALUE_NO_QUOTE,
                  H5_STATE_VALUE_SINGLE_QUOTE, H5_STATE_VALUE_DOUBLE_QUOTE,
                  H5_STATE_VALUE_BACK_QUOTE):
        if _is_xss_once(s, flags) != 0:
            return True
    return False


# ===========================================================================
# 对外 API
# ===========================================================================
def detect_sqli(value: str) -> bool:
    """判断 ``value`` 是否为 SQL 注入 (等价于 ModSecurity ``@detectSQLi``)."""
    if not value or len(value) < 2:
        # 最短的真实命中是 "1U" 这类 2 字符 fingerprint
        return False
    try:
        return _is_sqli(value)
    except (IndexError, ValueError):
        # 任何解析异常都不应让请求 500; 保守放行 (与算子层"未命中"一致)
        return False


def detect_xss(value: str) -> bool:
    """判断 ``value`` 是否为 XSS (等价于 ModSecurity ``@detectXSS``)."""
    if not value or len(value) < 3:
        return False
    try:
        return _is_xss(value)
    except (IndexError, ValueError):
        return False


def health() -> dict:
    """检出器的版本与数据表覆盖情况 (供引擎状态 / 报告展示)."""
    return {
        "libinjection_version": LIBINJECTION_VERSION,
        "sqli_fingerprints": len(_FP_PATTERNS),
        "sqli_keywords": len(_SQL_WORDS),
        "xss_black_tags": len(_XSS_BLACK_TAGS),
        "xss_black_attrs": len(_XSS_BLACK_ATTRS),
        "xss_black_events": len(_XSS_BLACK_EVENTS),
    }


def _selftest() -> None:
    """``python -m sentinel.waf.libinjection`` 的自检用例."""
    positives_sqli = [
        "1' OR '1'='1",              # 经典闭合引号 + 恒真
        "1 OR 1=1",                  # 无引号恒真
        "admin'--",                  # 注释截断密码校验
        "' OR 1=1#",                 # MySQL 行尾注释
        "1 UNION SELECT username,password FROM users",  # UNION 注入
        "-1 UNION SELECT NULL,NULL--",
        "1' AND SLEEP(3)--",         # 时间盲注
        "1;WAITFOR DELAY '0:0:3'--",  # MSSQL 时间盲注
        "'; DROP TABLE users--",     # 堆叠语句
        "1' AND extractvalue(1,concat(0x7e,version()))--",  # 报错注入
        "1) OR (1=1",                # 括号闭合
        "1' AND '1'='1' /*",
        "admin' OR 'x'='x'#",
        "select 1,2,3 from dual where 1=1",
        "1/*!50000union*/select 1,2",  # MySQL 条件注释 -> 直接判 EVIL
    ]
    negatives_sqli = [
        "select the best laptop for students",  # 只有 SQL 关键字, 没有语法结构
        "union station opening hours",          # 同上
        "order by popularity",                  # 同上
        "drop in the bucket lyrics",            # 同上
        "where is my package",                  # 同上
        "1 or 2 items available",               # 自然语言里的 "or"
        "2+3*4/2",                              # 纯算术
        "Hello World!",                         # 普通文本
        "O'Brien report",                       # 单引号但无注入结构
        "He said \"hello\"",
        "it's-secret",
        "a=b and c=d",                          # 形如布尔的赋值, 但不是 SQL 语法
        "2026-09-01T00:00:00Z",                 # 时间戳
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ",
        "1.e(1)",                               # 科学计数法缺指数: 只是被丢弃, 不构成注入
        "javascript basics for beginners",       # 裸 "javascript" 不是 SQLi
    ]
    positives_xss = [
        "<script>alert(1)</script>",                    # 黑标签
        "<img src=x onerror=alert(1)>",                 # on* 事件处理器
        "<svg/onload=alert(document.domain)>",          # svg 是黑标签
        "<iframe src=javascript:alert(1)>",             # 危险协议
        "\" onmouseover=\"alert(1)",                    # 属性值起始状态
        "' onfocus='alert(1)' autofocus='",
        "<a href=\"javascript:alert(1)\">click</a>",    # href 是 TYPE_ATTR_URL
        "<iframe src=\"data:text/html;base64,PHNjcmlwdD4=\">",
        "<body onload=alert(1)>",
        "<scr\x00ipt>alert(1)</scr\x00ipt>",            # NUL 绕过标签名黑名单
        "<xss style=x:expression(alert(1))>",
        "<div style=background:url(javascript:alert(1))>",
    ]
    negatives_xss = [
        "a<b>c",                       # 普通 HTML 片段, 无危险 sink
        "<p>hello world</p>",
        "2 < 3 and 4 > 1",             # 数学比较
        "select the best laptop",      # 不含标签
        "https://cdn.example.com/logo.png",
        "frontend developer",
        "C++ tutorial",
        "<div class=\"theme-dark\">x</div>",
        "user@example.com",
        # 以下两条是 libinjection 的**已知边界**, 上游同样判阴性 (已与 C 版对齐):
        "javascript:alert(document.cookie)",   # 裸协议串没有标签/属性上下文
        "&#x3c;script&#x3e;alert(1)",          # 实体解码只用于 URL 属性, 不用于标签名
    ]

    failures = 0
    for value in positives_sqli:
        if not detect_sqli(value):
            print(f"  [漏报] SQLi 应为阳性: {value!r}")
            failures += 1
    for value in negatives_sqli:
        if detect_sqli(value):
            print(f"  [误报] SQLi 应为阴性: {value!r}")
            failures += 1
    for value in positives_xss:
        if not detect_xss(value):
            print(f"  [漏报] XSS 应为阳性: {value!r}")
            failures += 1
    for value in negatives_xss:
        if detect_xss(value):
            print(f"  [误报] XSS 应为阴性: {value!r}")
            failures += 1

    total = (len(positives_sqli) + len(negatives_sqli)
             + len(positives_xss) + len(negatives_xss))
    print(f"libinjection 自检: {total - failures}/{total} 通过")
    if failures:
        raise SystemExit(1)


# ===========================================================================
# 机器生成数据区 —— 请勿手工修改
#
# 来源: libinjection 4.0.0
#   * src/libinjection_sqli_data.h 的 ``sql_keywords`` 表 (9352 项)
#   * src/libinjection_xss.c 的 BLACKATTREVENT / BLACKATTR / BLACKTAG 表
#
# 这些名字在导入时于本文件末尾建立, 上面的函数在**调用时**才解析它们。
# ===========================================================================

#: 256 项 ``char_parse_map``: 每个字节 -> :data:`_PARSE_FUNCS` 里的词法函数
_PARSE_MAP_CODES = """wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww2ShMo2Scc2ocdNsNNNNNNNNNN2c222xVWBWWEWWWWWWWWqWWQWWWUWWXWWRbxoWTWBWWEWWWWWWWWqWWQWWWUWWXWWc2cowWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"""

#: 关键字 / 指纹表, 每行 ``word+type`` (类型是行内最后一个字符, 'F' 即 fingerprint)
_SQL_TABLE_BLOB = """!!o
!<o
!=o
!>o
%=o
&&&
&=o
*=o
+=o
-=o
/=o
0&(1)OF
0&(1)UF
0&(1O(F
0&(1OFF
0&(1OSF
0&(1OVF
0&(F()F
0&(F(1F
0&(F(FF
0&(F(NF
0&(F(SF
0&(F(VF
0&(N)OF
0&(N)UF
0&(NO(F
0&(NOFF
0&(NOSF
0&(NOVF
0&(S)OF
0&(S)UF
0&(SO(F
0&(SO1F
0&(SOFF
0&(SONF
0&(SOSF
0&(SOVF
0&(V)OF
0&(V)UF
0&(VO(F
0&(VOFF
0&(VOSF
0&1O(1F
0&1O(FF
0&1O(NF
0&1O(SF
0&1O(VF
0&1OF(F
0&1OS(F
0&1OS1F
0&1OSFF
0&1OSUF
0&1OSVF
0&1OV(F
0&1OVFF
0&1OVOF
0&1OVSF
0&1OVUF
0&1UE(F
0&1UE1F
0&1UEFF
0&1UEKF
0&1UENF
0&1UESF
0&1UEVF
0&F()OF
0&F()UF
0&F(1)F
0&F(1OF
0&F(F(F
0&F(N)F
0&F(NOF
0&F(S)F
0&F(SOF
0&F(V)F
0&F(VOF
0&NO(1F
0&NO(FF
0&NO(NF
0&NO(SF
0&NO(VF
0&NOF(F
0&NOS(F
0&NOS1F
0&NOSFF
0&NOSUF
0&NOSVF
0&NOV(F
0&NOVFF
0&NOVOF
0&NOVSF
0&NOVUF
0&NUE(F
0&NUE1F
0&NUEFF
0&NUEKF
0&NUENF
0&NUESF
0&NUEVF
0&SO(1F
0&SO(FF
0&SO(NF
0&SO(SF
0&SO(VF
0&SO1(F
0&SO1FF
0&SO1NF
0&SO1SF
0&SO1UF
0&SO1VF
0&SOF(F
0&SON(F
0&SON1F
0&SONFF
0&SONUF
0&SOS(F
0&SOS1F
0&SOSFF
0&SOSUF
0&SOSVF
0&SOV(F
0&SOVFF
0&SOVOF
0&SOVSF
0&SOVUF
0&SUE(F
0&SUE1F
0&SUEFF
0&SUEKF
0&SUENF
0&SUESF
0&SUEVF
0&VO(1F
0&VO(FF
0&VO(NF
0&VO(SF
0&VO(VF
0&VOF(F
0&VOS(F
0&VOS1F
0&VOSFF
0&VOSUF
0&VOSVF
0&VUE(F
0&VUE1F
0&VUEFF
0&VUEKF
0&VUENF
0&VUESF
0&VUEVF
0)&(EKF
0)&(ENF
0)UE(1F
0)UE(FF
0)UE(NF
0)UE(SF
0)UE(VF
0)UE1KF
0)UE1OF
0)UEF(F
0)UEK(F
0)UEK1F
0)UEKFF
0)UEKNF
0)UEKSF
0)UEKVF
0)UENKF
0)UENOF
0)UESKF
0)UESOF
0)UEVKF
0)UEVOF
01&(1&F
01&(1)F
01&(1,F
01&(1OF
01&(E(F
01&(E1F
01&(EFF
01&(EKF
01&(ENF
01&(EOF
01&(ESF
01&(EVF
01&(F(F
01&(N&F
01&(N)F
01&(N,F
01&(NOF
01&(S&F
01&(S)F
01&(S,F
01&(SOF
01&(V&F
01&(V)F
01&(V,F
01&(VOF
01&1F
01&1&(F
01&1&1F
01&1&FF
01&1&NF
01&1&SF
01&1&VF
01&1)&F
01&1)CF
01&1)OF
01&1)UF
01&1;F
01&1;CF
01&1;EF
01&1;TF
01&1B(F
01&1B1F
01&1BFF
01&1BNF
01&1BSF
01&1BVF
01&1CF
01&1EKF
01&1ENF
01&1F(F
01&1K(F
01&1K1F
01&1KFF
01&1KNF
01&1KSF
01&1KVF
01&1O(F
01&1OFF
01&1OSF
01&1OVF
01&1TNF
01&1UF
01&1U(F
01&1U;F
01&1UCF
01&1UEF
01&E(1F
01&E(FF
01&E(NF
01&E(OF
01&E(SF
01&E(VF
01&E1F
01&E1;F
01&E1CF
01&E1KF
01&E1OF
01&EF(F
01&EK(F
01&EK1F
01&EKFF
01&EKNF
01&EKSF
01&EKUF
01&EKVF
01&ENF
01&EN;F
01&ENCF
01&ENKF
01&ENOF
01&ESF
01&ES;F
01&ESCF
01&ESKF
01&ESOF
01&EUEF
01&EVF
01&EV;F
01&EVCF
01&EVKF
01&EVOF
01&F()F
01&F(1F
01&F(EF
01&F(FF
01&F(NF
01&F(SF
01&F(VF
01&K&(F
01&K&1F
01&K&FF
01&K&NF
01&K&SF
01&K&VF
01&K(1F
01&K(FF
01&K(NF
01&K(SF
01&K(VF
01&K1OF
01&KCF
01&KF(F
01&KNKF
01&KO(F
01&KO1F
01&KOFF
01&KOKF
01&KONF
01&KOSF
01&KOVF
01&KSOF
01&KVOF
01&N&(F
01&N&1F
01&N&FF
01&N&NF
01&N&SF
01&N&VF
01&N)&F
01&N)CF
01&N)OF
01&N)UF
01&N;F
01&N;CF
01&N;EF
01&N;TF
01&NB(F
01&NB1F
01&NBFF
01&NBNF
01&NBSF
01&NBVF
01&NCF
01&NENF
01&NF(F
01&NK(F
01&NK1F
01&NKFF
01&NKNF
01&NKSF
01&NKVF
01&NO(F
01&NOFF
01&NOSF
01&NOVF
01&NTNF
01&NUF
01&NU(F
01&NU;F
01&NUCF
01&NUEF
01&SF
01&S&(F
01&S&1F
01&S&FF
01&S&NF
01&S&SF
01&S&VF
01&S)&F
01&S)CF
01&S)OF
01&S)UF
01&S1F
01&S1;F
01&S1CF
01&S;F
01&S;CF
01&S;EF
01&S;TF
01&SB(F
01&SB1F
01&SBFF
01&SBNF
01&SBSF
01&SBVF
01&SCF
01&SEKF
01&SENF
01&SF(F
01&SK(F
01&SK1F
01&SKFF
01&SKNF
01&SKSF
01&SKVF
01&SO(F
01&SO1F
01&SOFF
01&SONF
01&SOSF
01&SOVF
01&STNF
01&SUF
01&SU(F
01&SU;F
01&SUCF
01&SUEF
01&SVF
01&SV;F
01&SVCF
01&SVOF
01&VF
01&V&(F
01&V&1F
01&V&FF
01&V&NF
01&V&SF
01&V&VF
01&V)&F
01&V)CF
01&V)OF
01&V)UF
01&V;F
01&V;CF
01&V;EF
01&V;TF
01&VB(F
01&VB1F
01&VBFF
01&VBNF
01&VBSF
01&VBVF
01&VCF
01&VEKF
01&VENF
01&VF(F
01&VK(F
01&VK1F
01&VKFF
01&VKNF
01&VKSF
01&VKVF
01&VO(F
01&VOFF
01&VOSF
01&VSF
01&VS;F
01&VSCF
01&VSOF
01&VTNF
01&VUF
01&VU(F
01&VU;F
01&VUCF
01&VUEF
01(EF(F
01(EKFF
01(EKNF
01(ENKF
01(U(EF
01)&(1F
01)&(EF
01)&(FF
01)&(NF
01)&(SF
01)&(VF
01)&1F
01)&1&F
01)&1)F
01)&1;F
01)&1BF
01)&1CF
01)&1FF
01)&1OF
01)&1UF
01)&F(F
01)&NF
01)&N&F
01)&N)F
01)&N;F
01)&NBF
01)&NCF
01)&NFF
01)&NOF
01)&NUF
01)&SF
01)&S&F
01)&S)F
01)&S;F
01)&SBF
01)&SCF
01)&SFF
01)&SOF
01)&SUF
01)&VF
01)&V&F
01)&V)F
01)&V;F
01)&VBF
01)&VCF
01)&VFF
01)&VOF
01)&VUF
01),(1F
01),(FF
01),(NF
01),(SF
01),(VF
01);E(F
01);E1F
01);EFF
01);EKF
01);ENF
01);EOF
01);ESF
01);EVF
01);T(F
01);T1F
01);TFF
01);TKF
01);TNF
01);TOF
01);TSF
01);TVF
01)B(1F
01)B(FF
01)B(NF
01)B(SF
01)B(VF
01)B1F
01)B1&F
01)B1;F
01)B1CF
01)B1KF
01)B1NF
01)B1OF
01)B1UF
01)BF(F
01)BNF
01)BN&F
01)BN;F
01)BNCF
01)BNKF
01)BNOF
01)BNUF
01)BSF
01)BS&F
01)BS;F
01)BSCF
01)BSKF
01)BSOF
01)BSUF
01)BVF
01)BV&F
01)BV;F
01)BVCF
01)BVKF
01)BVOF
01)BVUF
01)CF
01)E(1F
01)E(FF
01)E(NF
01)E(SF
01)E(VF
01)E1CF
01)E1OF
01)EF(F
01)EK(F
01)EK1F
01)EKFF
01)EKNF
01)EKSF
01)EKVF
01)ENCF
01)ENOF
01)ESCF
01)ESOF
01)EVCF
01)EVOF
01)F(FF
01)K(1F
01)K(FF
01)K(NF
01)K(SF
01)K(VF
01)K1&F
01)K1;F
01)K1BF
01)K1EF
01)K1OF
01)K1UF
01)KB(F
01)KB1F
01)KBFF
01)KBNF
01)KBSF
01)KBVF
01)KF(F
01)KN&F
01)KN;F
01)KNBF
01)KNCF
01)KNEF
01)KNKF
01)KNUF
01)KS&F
01)KS;F
01)KSBF
01)KSEF
01)KSOF
01)KSUF
01)KUEF
01)KV&F
01)KV;F
01)KVBF
01)KVEF
01)KVOF
01)KVUF
01)O(1F
01)O(EF
01)O(FF
01)O(NF
01)O(SF
01)O(VF
01)O1F
01)O1&F
01)O1)F
01)O1;F
01)O1BF
01)O1CF
01)O1KF
01)O1UF
01)OF(F
01)ON&F
01)ON)F
01)ON;F
01)ONBF
01)ONCF
01)ONKF
01)ONUF
01)OSF
01)OS&F
01)OS)F
01)OS;F
01)OSBF
01)OSCF
01)OSKF
01)OSUF
01)OVF
01)OV&F
01)OV)F
01)OV;F
01)OVBF
01)OVCF
01)OVKF
01)OVOF
01)OVUF
01)U(EF
01)UE(F
01)UE1F
01)UEFF
01)UEKF
01)UENF
01)UESF
01)UEVF
01,(1)F
01,(1OF
01,(E(F
01,(E1F
01,(EFF
01,(EKF
01,(ENF
01,(ESF
01,(EVF
01,(F(F
01,(N)F
01,(NOF
01,(S)F
01,(SOF
01,(V)F
01,(VOF
01,F()F
01,F(1F
01,F(FF
01,F(NF
01,F(SF
01,F(VF
01;E(1F
01;E(EF
01;E(FF
01;E(NF
01;E(SF
01;E(VF
01;E1,F
01;E1;F
01;E1CF
01;E1KF
01;E1OF
01;E1TF
01;EF(F
01;EK(F
01;EK1F
01;EKFF
01;EKNF
01;EKOF
01;EKSF
01;EKVF
01;EN,F
01;EN;F
01;ENCF
01;ENEF
01;ENKF
01;ENOF
01;ENTF
01;ES,F
01;ES;F
01;ESCF
01;ESKF
01;ESOF
01;ESTF
01;EV,F
01;EV;F
01;EVCF
01;EVKF
01;EVOF
01;EVTF
01;N:TF
01;T(1F
01;T(CF
01;T(EF
01;T(FF
01;T(NF
01;T(SF
01;T(VF
01;T1(F
01;T1,F
01;T1;F
01;T1CF
01;T1FF
01;T1KF
01;T1OF
01;T1TF
01;T;F
01;T;CF
01;TF(F
01;TK(F
01;TK1F
01;TKFF
01;TKKF
01;TKNF
01;TKOF
01;TKSF
01;TKVF
01;TN(F
01;TN,F
01;TN1F
01;TN;F
01;TNCF
01;TNFF
01;TNKF
01;TNNF
01;TNOF
01;TNSF
01;TNTF
01;TNVF
01;TO(F
01;TS(F
01;TS,F
01;TS;F
01;TSCF
01;TSFF
01;TSKF
01;TSOF
01;TSTF
01;TTNF
01;TV(F
01;TV,F
01;TV;F
01;TVCF
01;TVFF
01;TVKF
01;TVOF
01;TVTF
01A(F(F
01A(N)F
01A(NOF
01A(S)F
01A(SOF
01A(V)F
01A(VOF
01AF()F
01AF(1F
01AF(FF
01AF(NF
01AF(SF
01AF(VF
01ASO(F
01ASO1F
01ASOFF
01ASONF
01ASOSF
01ASOVF
01ASUEF
01ATO(F
01ATO1F
01ATOFF
01ATONF
01ATOSF
01ATOVF
01ATUEF
01AVO(F
01AVOFF
01AVOSF
01AVUEF
01B(1)F
01B(1OF
01B(F(F
01B(NOF
01B(S)F
01B(SOF
01B(V)F
01B(VOF
01B1F
01B1&(F
01B1&1F
01B1&FF
01B1&NF
01B1&SF
01B1&VF
01B1,(F
01B1,FF
01B1;F
01B1;CF
01B1B(F
01B1B1F
01B1BFF
01B1BNF
01B1BSF
01B1BVF
01B1CF
01B1K(F
01B1K1F
01B1KFF
01B1KNF
01B1KSF
01B1KVF
01B1O(F
01B1OFF
01B1OSF
01B1OVF
01B1U(F
01B1UEF
01BE(1F
01BE(FF
01BE(NF
01BE(SF
01BE(VF
01BEK(F
01BF()F
01BF(1F
01BF(FF
01BF(NF
01BF(SF
01BF(VF
01BNF
01BN&(F
01BN&1F
01BN&FF
01BN&NF
01BN&SF
01BN&VF
01BN,(F
01BN,FF
01BN;F
01BN;CF
01BNB(F
01BNB1F
01BNBFF
01BNBNF
01BNBSF
01BNBVF
01BNCF
01BNK(F
01BNK1F
01BNKFF
01BNKNF
01BNKSF
01BNKVF
01BNO(F
01BNOFF
01BNOSF
01BNOVF
01BNU(F
01BNUEF
01BSF
01BS&(F
01BS&1F
01BS&FF
01BS&NF
01BS&SF
01BS&VF
01BS,(F
01BS,FF
01BS;F
01BS;CF
01BSB(F
01BSB1F
01BSBFF
01BSBNF
01BSBSF
01BSBVF
01BSCF
01BSK(F
01BSK1F
01BSKFF
01BSKNF
01BSKSF
01BSKVF
01BSO(F
01BSO1F
01BSOFF
01BSONF
01BSOSF
01BSOVF
01BSU(F
01BSUEF
01BVF
01BV&(F
01BV&1F
01BV&FF
01BV&NF
01BV&SF
01BV&VF
01BV,(F
01BV,FF
01BV;F
01BV;CF
01BVB(F
01BVB1F
01BVBFF
01BVBNF
01BVBSF
01BVBVF
01BVCF
01BVK(F
01BVK1F
01BVKFF
01BVKNF
01BVKSF
01BVKVF
01BVO(F
01BVOFF
01BVOSF
01BVU(F
01BVUEF
01CF
01E(1)F
01E(1OF
01E(F(F
01E(N)F
01E(NOF
01E(S)F
01E(SOF
01E(V)F
01E(VOF
01E1;TF
01E1CF
01E1O(F
01E1OFF
01E1OSF
01E1OVF
01E1T(F
01E1T1F
01E1TFF
01E1TNF
01E1TSF
01E1TVF
01E1UEF
01EF()F
01EF(1F
01EF(FF
01EF(NF
01EF(SF
01EF(VF
01EK(1F
01EK(EF
01EK(FF
01EK(NF
01EK(SF
01EK(VF
01EK1;F
01EK1CF
01EK1OF
01EK1TF
01EK1UF
01EKF(F
01EKN;F
01EKNCF
01EKNEF
01EKNTF
01EKNUF
01EKOKF
01EKS;F
01EKSCF
01EKSOF
01EKSTF
01EKSUF
01EKU(F
01EKU1F
01EKUEF
01EKUFF
01EKUSF
01EKUVF
01EKV;F
01EKVCF
01EKVOF
01EKVTF
01EKVUF
01EN;TF
01ENCF
01ENENF
01ENO(F
01ENOFF
01ENOSF
01ENOVF
01ENT(F
01ENT1F
01ENTFF
01ENTNF
01ENTSF
01ENTVF
01ENUEF
01EOKNF
01ES;TF
01ESCF
01ESO(F
01ESO1F
01ESOFF
01ESONF
01ESOSF
01ESOVF
01EST(F
01EST1F
01ESTFF
01ESTNF
01ESTSF
01ESTVF
01ESUEF
01EU(1F
01EU(FF
01EU(NF
01EU(SF
01EU(VF
01EU1,F
01EU1CF
01EU1OF
01EUEFF
01EUEKF
01EUF(F
01EUS,F
01EUSCF
01EUSOF
01EUV,F
01EUVCF
01EUVOF
01EV;TF
01EVCF
01EVO(F
01EVOFF
01EVOSF
01EVT(F
01EVT1F
01EVTFF
01EVTNF
01EVTSF
01EVTVF
01EVUEF
01F()1F
01F()FF
01F()KF
01F()NF
01F()OF
01F()SF
01F()UF
01F()VF
01F(1)F
01F(1NF
01F(1OF
01F(E(F
01F(E1F
01F(EFF
01F(EKF
01F(ENF
01F(ESF
01F(EVF
01F(F(F
01F(N)F
01F(N,F
01F(NOF
01F(S)F
01F(SOF
01F(V)F
01F(VOF
01K(1OF
01K(F(F
01K(N)F
01K(NOF
01K(S)F
01K(SOF
01K(V)F
01K(VOF
01K)&(F
01K)&1F
01K)&FF
01K)&NF
01K)&SF
01K)&VF
01K);EF
01K);TF
01K)B(F
01K)B1F
01K)BFF
01K)BNF
01K)BSF
01K)BVF
01K)E(F
01K)E1F
01K)EFF
01K)EKF
01K)ENF
01K)ESF
01K)EVF
01K)F(F
01K)O(F
01K)OFF
01K)UEF
01K1F
01K1&(F
01K1&1F
01K1&FF
01K1&NF
01K1&SF
01K1&VF
01K1;F
01K1;CF
01K1;EF
01K1;TF
01K1B(F
01K1B1F
01K1BFF
01K1BNF
01K1BSF
01K1BVF
01K1CF
01K1E(F
01K1E1F
01K1EFF
01K1EKF
01K1ENF
01K1ESF
01K1EVF
01K1O(F
01K1OFF
01K1OSF
01K1OVF
01K1U(F
01K1UEF
01KF()F
01KF(1F
01KF(FF
01KF(NF
01KF(SF
01KF(VF
01KNF
01KN&(F
01KN&1F
01KN&FF
01KN&NF
01KN&SF
01KN&VF
01KN;F
01KN;CF
01KN;EF
01KN;TF
01KNB(F
01KNB1F
01KNBFF
01KNBNF
01KNBSF
01KNBVF
01KNCF
01KNE(F
01KNE1F
01KNEFF
01KNENF
01KNESF
01KNEVF
01KNU(F
01KNUEF
01KSF
01KS&(F
01KS&1F
01KS&FF
01KS&NF
01KS&SF
01KS&VF
01KS;F
01KS;CF
01KS;EF
01KS;TF
01KSB(F
01KSB1F
01KSBFF
01KSBNF
01KSBSF
01KSBVF
01KSCF
01KSE(F
01KSE1F
01KSEFF
01KSEKF
01KSENF
01KSESF
01KSEVF
01KSO(F
01KSO1F
01KSOFF
01KSONF
01KSOSF
01KSOVF
01KSU(F
01KSUEF
01KUE(F
01KUE1F
01KUEFF
01KUEKF
01KUENF
01KUESF
01KUEVF
01KVF
01KV&(F
01KV&1F
01KV&FF
01KV&NF
01KV&SF
01KV&VF
01KV;F
01KV;CF
01KV;EF
01KV;TF
01KVB(F
01KVB1F
01KVBFF
01KVBNF
01KVBSF
01KVBVF
01KVCF
01KVE(F
01KVE1F
01KVEFF
01KVEKF
01KVENF
01KVESF
01KVEVF
01KVO(F
01KVOFF
01KVOSF
01KVU(F
01KVUEF
01N&F(F
01N(1OF
01N(F(F
01N(S)F
01N(SOF
01N(V)F
01N(VOF
01N)UEF
01N,F(F
01NE(1F
01NE(FF
01NE(NF
01NE(SF
01NE(VF
01NE1CF
01NE1OF
01NEF(F
01NENCF
01NENOF
01NESCF
01NESOF
01NEVCF
01NEVOF
01NU(EF
01NUEF
01NUE(F
01NUE1F
01NUE;F
01NUECF
01NUEFF
01NUEKF
01NUENF
01NUESF
01NUEVF
01O(1&F
01O(1)F
01O(1,F
01O(1OF
01O(E(F
01O(E1F
01O(EEF
01O(EFF
01O(EKF
01O(ENF
01O(EOF
01O(ESF
01O(EVF
01O(F(F
01O(N&F
01O(N)F
01O(N,F
01O(NOF
01O(S&F
01O(S)F
01O(S,F
01O(SOF
01O(V&F
01O(V)F
01O(V,F
01O(VOF
01OF()F
01OF(1F
01OF(EF
01OF(FF
01OF(NF
01OF(SF
01OF(VF
01OK&(F
01OK&1F
01OK&FF
01OK&NF
01OK&SF
01OK&VF
01OK(1F
01OK(FF
01OK(NF
01OK(SF
01OK(VF
01OK1CF
01OK1OF
01OKF(F
01OKNCF
01OKO(F
01OKO1F
01OKOFF
01OKONF
01OKOSF
01OKOVF
01OKSCF
01OKSOF
01OKVCF
01OKVOF
01ONSUF
01OS&(F
01OS&1F
01OS&EF
01OS&FF
01OS&KF
01OS&NF
01OS&SF
01OS&UF
01OS&VF
01OS(EF
01OS(UF
01OS)&F
01OS),F
01OS);F
01OS)BF
01OS)CF
01OS)EF
01OS)FF
01OS)KF
01OS)OF
01OS)UF
01OS,(F
01OS,FF
01OS1(F
01OS1FF
01OS1NF
01OS1SF
01OS1UF
01OS1VF
01OS;F
01OS;CF
01OS;EF
01OS;NF
01OS;TF
01OSA(F
01OSAFF
01OSASF
01OSATF
01OSAVF
01OSB(F
01OSB1F
01OSBEF
01OSBFF
01OSBNF
01OSBSF
01OSBVF
01OSCF
01OSE(F
01OSE1F
01OSEFF
01OSEKF
01OSENF
01OSEOF
01OSESF
01OSEUF
01OSEVF
01OSF(F
01OSK(F
01OSK)F
01OSK1F
01OSKBF
01OSKFF
01OSKNF
01OSKSF
01OSKUF
01OSKVF
01OST(F
01OST1F
01OSTEF
01OSTFF
01OSTNF
01OSTSF
01OSTTF
01OSTVF
01OSUF
01OSU(F
01OSU1F
01OSU;F
01OSUCF
01OSUEF
01OSUFF
01OSUKF
01OSUOF
01OSUSF
01OSUTF
01OSUVF
01OSV(F
01OSVFF
01OSVOF
01OSVSF
01OSVUF
01OU(EF
01OUEKF
01OUENF
01OVF
01OV&(F
01OV&1F
01OV&EF
01OV&FF
01OV&KF
01OV&NF
01OV&SF
01OV&UF
01OV&VF
01OV(EF
01OV(UF
01OV)&F
01OV),F
01OV);F
01OV)BF
01OV)CF
01OV)EF
01OV)FF
01OV)KF
01OV)OF
01OV)UF
01OV,(F
01OV,FF
01OV;F
01OV;CF
01OV;EF
01OV;NF
01OV;TF
01OVA(F
01OVAFF
01OVASF
01OVATF
01OVAVF
01OVB(F
01OVB1F
01OVBEF
01OVBFF
01OVBNF
01OVBSF
01OVBVF
01OVCF
01OVE(F
01OVE1F
01OVEFF
01OVEKF
01OVENF
01OVEOF
01OVESF
01OVEUF
01OVEVF
01OVF(F
01OVK(F
01OVK)F
01OVK1F
01OVKBF
01OVKFF
01OVKNF
01OVKSF
01OVKUF
01OVKVF
01OVO(F
01OVOFF
01OVOKF
01OVOSF
01OVOUF
01OVS(F
01OVS1F
01OVSFF
01OVSOF
01OVSUF
01OVSVF
01OVT(F
01OVT1F
01OVTEF
01OVTFF
01OVTNF
01OVTSF
01OVTTF
01OVTVF
01OVUF
01OVU(F
01OVU1F
01OVU;F
01OVUCF
01OVUEF
01OVUFF
01OVUKF
01OVUOF
01OVUSF
01OVUTF
01OVUVF
01SF()F
01SF(1F
01SF(FF
01SF(NF
01SF(SF
01SF(VF
01SUEF
01SUE;F
01SUECF
01SUEKF
01SVF
01SV;F
01SV;CF
01SVCF
01SVO(F
01SVOFF
01SVOSF
01T(1)F
01T(1OF
01T(F(F
01T(N)F
01T(NOF
01T(S)F
01T(SOF
01T(V)F
01T(VOF
01T1(FF
01T1O(F
01T1OFF
01T1OSF
01T1OVF
01TE(1F
01TE(FF
01TE(NF
01TE(SF
01TE(VF
01TE1NF
01TE1OF
01TEF(F
01TEK(F
01TEK1F
01TEKFF
01TEKNF
01TEKSF
01TEKVF
01TENNF
01TENOF
01TESNF
01TESOF
01TEVNF
01TEVOF
01TF()F
01TF(1F
01TF(FF
01TF(NF
01TF(SF
01TF(VF
01TN(1F
01TN(FF
01TN(SF
01TN(VF
01TN1CF
01TN1OF
01TN;EF
01TN;NF
01TN;TF
01TNE(F
01TNE1F
01TNEFF
01TNENF
01TNESF
01TNEVF
01TNF(F
01TNKNF
01TNN:F
01TNNCF
01TNNOF
01TNO(F
01TNOFF
01TNOSF
01TNOVF
01TNSCF
01TNSOF
01TNT(F
01TNT1F
01TNTFF
01TNTNF
01TNTSF
01TNTVF
01TNVCF
01TNVOF
01TS(FF
01TSO(F
01TSO1F
01TSOFF
01TSONF
01TSOSF
01TSOVF
01TTNEF
01TTNKF
01TTNNF
01TTNTF
01TV(1F
01TV(FF
01TVO(F
01TVOFF
01TVOSF
01UF
01U(1)F
01U(1OF
01U(E(F
01U(E1F
01U(EFF
01U(EKF
01U(ENF
01U(ESF
01U(EVF
01U(F(F
01U(N)F
01U(NOF
01U(S)F
01U(SOF
01U(V)F
01U(VOF
01U1,(F
01U1,FF
01U1CF
01U1O(F
01U1OFF
01U1OSF
01U1OVF
01U;F
01U;CF
01UCF
01UEF
01UE(1F
01UE(EF
01UE(FF
01UE(NF
01UE(OF
01UE(SF
01UE(VF
01UE1F
01UE1&F
01UE1(F
01UE1)F
01UE1,F
01UE1;F
01UE1BF
01UE1CF
01UE1FF
01UE1KF
01UE1NF
01UE1OF
01UE1SF
01UE1UF
01UE1VF
01UE;F
01UE;CF
01UECF
01UEFF
01UEF(F
01UEF,F
01UEF;F
01UEFCF
01UEKF
01UEK(F
01UEK1F
01UEK;F
01UEKCF
01UEKFF
01UEKNF
01UEKOF
01UEKSF
01UEKVF
01UENF
01UEN&F
01UEN(F
01UEN)F
01UEN,F
01UEN1F
01UEN;F
01UENBF
01UENCF
01UENFF
01UENKF
01UENNF
01UENOF
01UENSF
01UENUF
01UEOKF
01UEONF
01UESF
01UES&F
01UES(F
01UES)F
01UES,F
01UES1F
01UES;F
01UESBF
01UESCF
01UESFF
01UESKF
01UESOF
01UESUF
01UESVF
01UEVF
01UEV&F
01UEV(F
01UEV)F
01UEV,F
01UEV;F
01UEVBF
01UEVCF
01UEVFF
01UEVKF
01UEVNF
01UEVOF
01UEVSF
01UEVUF
01UF()F
01UF(1F
01UF(FF
01UF(NF
01UF(SF
01UF(VF
01UK(EF
01UO(EF
01UON(F
01UON1F
01UONFF
01UONSF
01US,(F
01US,FF
01USCF
01USO(F
01USO1F
01USOFF
01USONF
01USOSF
01USOVF
01UTN(F
01UTN1F
01UTNFF
01UTNNF
01UTNSF
01UTNVF
01UV,(F
01UV,FF
01UVCF
01UVO(F
01UVOFF
01UVOSF
01VF()F
01VF(1F
01VF(FF
01VF(NF
01VF(SF
01VF(VF
01VO(1F
01VO(FF
01VO(NF
01VO(SF
01VO(VF
01VOF(F
01VOS(F
01VOS1F
01VOSFF
01VOSUF
01VOSVF
01VSF
01VS;F
01VS;CF
01VSCF
01VSO(F
01VSO1F
01VSOFF
01VSONF
01VSOSF
01VSOVF
01VUEF
01VUE;F
01VUECF
01VUEKF
0;T(EFF
0;T(EKF
0;TKNCF
0E(1&(F
0E(1&1F
0E(1&FF
0E(1&NF
0E(1&SF
0E(1&VF
0E(1)&F
0E(1),F
0E(1)1F
0E(1);F
0E(1)BF
0E(1)CF
0E(1)FF
0E(1)KF
0E(1)NF
0E(1)OF
0E(1)SF
0E(1)UF
0E(1)VF
0E(1,FF
0E(1F(F
0E(1N)F
0E(1O(F
0E(1OFF
0E(1OSF
0E(1OVF
0E(1S)F
0E(1V)F
0E(1VOF
0E(E(1F
0E(E(EF
0E(E(FF
0E(E(NF
0E(E(SF
0E(E(VF
0E(E1&F
0E(E1)F
0E(E1OF
0E(EF(F
0E(EK(F
0E(EK1F
0E(EKFF
0E(EKNF
0E(EKSF
0E(EKVF
0E(EN&F
0E(EN)F
0E(ENOF
0E(ES&F
0E(ES)F
0E(ESOF
0E(EV&F
0E(EV)F
0E(EVOF
0E(F()F
0E(F(1F
0E(F(EF
0E(F(FF
0E(F(NF
0E(F(SF
0E(F(VF
0E(N&(F
0E(N&1F
0E(N&FF
0E(N&NF
0E(N&SF
0E(N&VF
0E(N(1F
0E(N(FF
0E(N(SF
0E(N(VF
0E(N)&F
0E(N),F
0E(N)1F
0E(N);F
0E(N)BF
0E(N)CF
0E(N)FF
0E(N)KF
0E(N)NF
0E(N)OF
0E(N)SF
0E(N)UF
0E(N)VF
0E(N,FF
0E(N1)F
0E(N1OF
0E(NF(F
0E(NO(F
0E(NOFF
0E(NOSF
0E(NOVF
0E(S&(F
0E(S&1F
0E(S&FF
0E(S&NF
0E(S&SF
0E(S&VF
0E(S)&F
0E(S),F
0E(S)1F
0E(S);F
0E(S)BF
0E(S)CF
0E(S)FF
0E(S)KF
0E(S)NF
0E(S)OF
0E(S)SF
0E(S)UF
0E(S)VF
0E(S,FF
0E(S1)F
0E(SF(F
0E(SO(F
0E(SO1F
0E(SOFF
0E(SONF
0E(SOSF
0E(SOVF
0E(SV)F
0E(SVOF
0E(V&(F
0E(V&1F
0E(V&FF
0E(V&NF
0E(V&SF
0E(V&VF
0E(V)&F
0E(V),F
0E(V)1F
0E(V);F
0E(V)BF
0E(V)CF
0E(V)FF
0E(V)KF
0E(V)NF
0E(V)OF
0E(V)SF
0E(V)UF
0E(V)VF
0E(V,FF
0E(VF(F
0E(VO(F
0E(VOFF
0E(VOSF
0E(VS)F
0E(VSOF
0E1&(1F
0E1&(EF
0E1&(FF
0E1&(NF
0E1&(SF
0E1&(VF
0E1&1)F
0E1&1OF
0E1&F(F
0E1&N)F
0E1&NOF
0E1&S)F
0E1&SOF
0E1&V)F
0E1&VOF
0E1)F
0E1)&(F
0E1)&1F
0E1)&FF
0E1)&NF
0E1)&SF
0E1)&VF
0E1);F
0E1);(F
0E1);CF
0E1);EF
0E1);TF
0E1)CF
0E1)KNF
0E1)O(F
0E1)O1F
0E1)OFF
0E1)ONF
0E1)OSF
0E1)OVF
0E1)UEF
0E1,(1F
0E1,(FF
0E1,(NF
0E1,(SF
0E1,(VF
0E1,F(F
0E1;(EF
0E1B(1F
0E1B(FF
0E1B(NF
0E1B(SF
0E1B(VF
0E1B1)F
0E1B1OF
0E1BF(F
0E1BN)F
0E1BNOF
0E1BS)F
0E1BSOF
0E1BV)F
0E1BVOF
0E1F()F
0E1F(1F
0E1F(FF
0E1F(NF
0E1F(SF
0E1F(VF
0E1K(1F
0E1K(EF
0E1K(FF
0E1K(NF
0E1K(SF
0E1K(VF
0E1K1)F
0E1K1KF
0E1K1OF
0E1KF(F
0E1KNF
0E1KN)F
0E1KN;F
0E1KNCF
0E1KNKF
0E1KNUF
0E1KS)F
0E1KSKF
0E1KSOF
0E1KV)F
0E1KVKF
0E1KVOF
0E1N)UF
0E1N;F
0E1N;CF
0E1NCF
0E1NKNF
0E1O(1F
0E1O(EF
0E1O(FF
0E1O(NF
0E1O(SF
0E1O(VF
0E1OF(F
0E1OS&F
0E1OS(F
0E1OS)F
0E1OS,F
0E1OS1F
0E1OS;F
0E1OSBF
0E1OSFF
0E1OSKF
0E1OSUF
0E1OSVF
0E1OV&F
0E1OV(F
0E1OV)F
0E1OV,F
0E1OV;F
0E1OVBF
0E1OVFF
0E1OVKF
0E1OVOF
0E1OVSF
0E1OVUF
0E1S;F
0E1S;CF
0E1SCF
0E1U(EF
0E1UE(F
0E1UE1F
0E1UEFF
0E1UEKF
0E1UENF
0E1UESF
0E1UEVF
0E1VF
0E1V;F
0E1V;CF
0E1VCF
0E1VO(F
0E1VOFF
0E1VOSF
0EE(F(F
0EEK(FF
0EF()&F
0EF(),F
0EF()1F
0EF();F
0EF()BF
0EF()FF
0EF()KF
0EF()NF
0EF()OF
0EF()SF
0EF()UF
0EF()VF
0EF(1&F
0EF(1)F
0EF(1,F
0EF(1OF
0EF(E(F
0EF(E1F
0EF(EFF
0EF(EKF
0EF(ENF
0EF(ESF
0EF(EVF
0EF(F(F
0EF(N&F
0EF(N)F
0EF(N,F
0EF(NOF
0EF(O)F
0EF(S&F
0EF(S)F
0EF(S,F
0EF(SOF
0EF(V&F
0EF(V)F
0EF(V,F
0EF(VOF
0EK(1&F
0EK(1(F
0EK(1)F
0EK(1,F
0EK(1FF
0EK(1NF
0EK(1OF
0EK(1SF
0EK(1VF
0EK(E(F
0EK(E1F
0EK(EFF
0EK(EKF
0EK(ENF
0EK(ESF
0EK(EVF
0EK(F(F
0EK(N&F
0EK(N(F
0EK(N)F
0EK(N,F
0EK(N1F
0EK(NFF
0EK(NOF
0EK(S&F
0EK(S(F
0EK(S)F
0EK(S,F
0EK(S1F
0EK(SFF
0EK(SOF
0EK(SVF
0EK(V&F
0EK(V(F
0EK(V)F
0EK(V,F
0EK(VFF
0EK(VOF
0EK(VSF
0EK1&(F
0EK1&1F
0EK1&FF
0EK1&NF
0EK1&SF
0EK1&VF
0EK1)F
0EK1)&F
0EK1);F
0EK1)CF
0EK1)KF
0EK1)OF
0EK1)UF
0EK1,(F
0EK1,FF
0EK1;(F
0EK1B(F
0EK1B1F
0EK1BFF
0EK1BNF
0EK1BSF
0EK1BVF
0EK1F(F
0EK1K(F
0EK1K1F
0EK1KFF
0EK1KNF
0EK1KSF
0EK1KVF
0EK1NF
0EK1N)F
0EK1N;F
0EK1NCF
0EK1NKF
0EK1O(F
0EK1OFF
0EK1OSF
0EK1OVF
0EK1SF
0EK1S;F
0EK1SCF
0EK1SFF
0EK1SKF
0EK1U(F
0EK1UEF
0EK1VF
0EK1V;F
0EK1VCF
0EK1VFF
0EK1VKF
0EK1VOF
0EKE(FF
0EKEK(F
0EKF()F
0EKF(1F
0EKF(EF
0EKF(FF
0EKF(NF
0EKF(OF
0EKF(SF
0EKF(VF
0EKN&(F
0EKN&1F
0EKN&FF
0EKN&NF
0EKN&SF
0EKN&VF
0EKN(1F
0EKN(FF
0EKN(SF
0EKN(VF
0EKN)F
0EKN)&F
0EKN);F
0EKN)CF
0EKN)KF
0EKN)OF
0EKN)UF
0EKN,(F
0EKN,FF
0EKN1F
0EKN1;F
0EKN1CF
0EKN1KF
0EKN1OF
0EKN;(F
0EKNB(F
0EKNB1F
0EKNBFF
0EKNBNF
0EKNBSF
0EKNBVF
0EKNF(F
0EKNK(F
0EKNK1F
0EKNKFF
0EKNKNF
0EKNKSF
0EKNKVF
0EKNU(F
0EKNUEF
0EKO(1F
0EKO(FF
0EKO(NF
0EKO(SF
0EKO(VF
0EKOK(F
0EKOKNF
0EKS&(F
0EKS&1F
0EKS&FF
0EKS&NF
0EKS&SF
0EKS&VF
0EKS)F
0EKS)&F
0EKS);F
0EKS)CF
0EKS)KF
0EKS)OF
0EKS)UF
0EKS,(F
0EKS,FF
0EKS1F
0EKS1;F
0EKS1CF
0EKS1FF
0EKS1KF
0EKS;(F
0EKSB(F
0EKSB1F
0EKSBFF
0EKSBNF
0EKSBSF
0EKSBVF
0EKSF(F
0EKSK(F
0EKSK1F
0EKSKFF
0EKSKNF
0EKSKSF
0EKSKVF
0EKSO(F
0EKSO1F
0EKSOFF
0EKSONF
0EKSOSF
0EKSOVF
0EKSU(F
0EKSUEF
0EKSVF
0EKSV;F
0EKSVCF
0EKSVFF
0EKSVKF
0EKSVOF
0EKV&(F
0EKV&1F
0EKV&FF
0EKV&NF
0EKV&SF
0EKV&VF
0EKV)F
0EKV)&F
0EKV);F
0EKV)CF
0EKV)KF
0EKV)OF
0EKV)UF
0EKV,(F
0EKV,FF
0EKV;(F
0EKVB(F
0EKVB1F
0EKVBFF
0EKVBNF
0EKVBSF
0EKVBVF
0EKVF(F
0EKVK(F
0EKVK1F
0EKVKFF
0EKVKNF
0EKVKSF
0EKVKVF
0EKVO(F
0EKVOFF
0EKVOSF
0EKVSF
0EKVS;F
0EKVSCF
0EKVSFF
0EKVSKF
0EKVSOF
0EKVU(F
0EKVUEF
0EN&(1F
0EN&(EF
0EN&(FF
0EN&(NF
0EN&(SF
0EN&(VF
0EN&1)F
0EN&1OF
0EN&F(F
0EN&N)F
0EN&NOF
0EN&S)F
0EN&SOF
0EN&V)F
0EN&VOF
0EN(1OF
0EN(F(F
0EN(S)F
0EN(SOF
0EN(V)F
0EN(VOF
0EN)F
0EN)&(F
0EN)&1F
0EN)&FF
0EN)&NF
0EN)&SF
0EN)&VF
0EN);F
0EN);(F
0EN);CF
0EN);EF
0EN);TF
0EN)CF
0EN)KNF
0EN)O(F
0EN)O1F
0EN)OFF
0EN)ONF
0EN)OSF
0EN)OVF
0EN)UEF
0EN,(1F
0EN,(FF
0EN,(NF
0EN,(SF
0EN,(VF
0EN,F(F
0EN1;F
0EN1;CF
0EN1O(F
0EN1OFF
0EN1OSF
0EN1OVF
0EN;(EF
0ENB(1F
0ENB(FF
0ENB(NF
0ENB(SF
0ENB(VF
0ENB1)F
0ENB1OF
0ENBF(F
0ENBN)F
0ENBNOF
0ENBS)F
0ENBSOF
0ENBV)F
0ENBVOF
0ENF()F
0ENF(1F
0ENF(FF
0ENF(NF
0ENF(SF
0ENF(VF
0ENK(1F
0ENK(EF
0ENK(FF
0ENK(NF
0ENK(SF
0ENK(VF
0ENK1)F
0ENK1KF
0ENK1OF
0ENKF(F
0ENKN)F
0ENKN,F
0ENKN;F
0ENKNBF
0ENKNCF
0ENKNKF
0ENKNUF
0ENKS)F
0ENKSKF
0ENKSOF
0ENKV)F
0ENKVKF
0ENKVOF
0ENO(1F
0ENO(EF
0ENO(FF
0ENO(NF
0ENO(SF
0ENO(VF
0ENOF(F
0ENOS&F
0ENOS(F
0ENOS)F
0ENOS,F
0ENOS1F
0ENOS;F
0ENOSBF
0ENOSFF
0ENOSKF
0ENOSUF
0ENOSVF
0ENOV&F
0ENOV(F
0ENOV)F
0ENOV,F
0ENOV;F
0ENOVBF
0ENOVFF
0ENOVKF
0ENOVOF
0ENOVSF
0ENOVUF
0ENU(EF
0ENUE(F
0ENUE1F
0ENUEFF
0ENUEKF
0ENUENF
0ENUESF
0ENUEVF
0EOK(EF
0EOKNKF
0ES&(1F
0ES&(EF
0ES&(FF
0ES&(NF
0ES&(SF
0ES&(VF
0ES&1)F
0ES&1OF
0ES&F(F
0ES&N)F
0ES&NOF
0ES&S)F
0ES&SOF
0ES&V)F
0ES&VOF
0ES)F
0ES)&(F
0ES)&1F
0ES)&FF
0ES)&NF
0ES)&SF
0ES)&VF
0ES);F
0ES);(F
0ES);CF
0ES);EF
0ES);TF
0ES)CF
0ES)KNF
0ES)O(F
0ES)O1F
0ES)OFF
0ES)ONF
0ES)OSF
0ES)OVF
0ES)UEF
0ES,(1F
0ES,(FF
0ES,(NF
0ES,(SF
0ES,(VF
0ES,F(F
0ES1F
0ES1;F
0ES1;CF
0ES1CF
0ES;(EF
0ESB(1F
0ESB(FF
0ESB(NF
0ESB(SF
0ESB(VF
0ESB1)F
0ESB1OF
0ESBF(F
0ESBN)F
0ESBNOF
0ESBS)F
0ESBSOF
0ESBV)F
0ESBVOF
0ESF()F
0ESF(1F
0ESF(FF
0ESF(NF
0ESF(SF
0ESF(VF
0ESK(1F
0ESK(EF
0ESK(FF
0ESK(NF
0ESK(SF
0ESK(VF
0ESK1)F
0ESK1KF
0ESK1OF
0ESKF(F
0ESKNF
0ESKN)F
0ESKN;F
0ESKNCF
0ESKNKF
0ESKNUF
0ESKS)F
0ESKSKF
0ESKSOF
0ESKV)F
0ESKVKF
0ESKVOF
0ESO(1F
0ESO(EF
0ESO(FF
0ESO(NF
0ESO(SF
0ESO(VF
0ESO1&F
0ESO1(F
0ESO1)F
0ESO1,F
0ESO1;F
0ESO1BF
0ESO1FF
0ESO1KF
0ESO1NF
0ESO1SF
0ESO1UF
0ESO1VF
0ESOF(F
0ESON&F
0ESON(F
0ESON)F
0ESON,F
0ESON1F
0ESON;F
0ESONBF
0ESONFF
0ESONKF
0ESONUF
0ESOS&F
0ESOS(F
0ESOS)F
0ESOS,F
0ESOS1F
0ESOS;F
0ESOSBF
0ESOSFF
0ESOSKF
0ESOSUF
0ESOSVF
0ESOV&F
0ESOV(F
0ESOV)F
0ESOV,F
0ESOV;F
0ESOVBF
0ESOVFF
0ESOVKF
0ESOVOF
0ESOVSF
0ESOVUF
0ESU(EF
0ESUE(F
0ESUE1F
0ESUEFF
0ESUEKF
0ESUENF
0ESUESF
0ESUEVF
0ESVF
0ESV;F
0ESV;CF
0ESVCF
0ESVO(F
0ESVOFF
0ESVOSF
0EV&(1F
0EV&(EF
0EV&(FF
0EV&(NF
0EV&(SF
0EV&(VF
0EV&1)F
0EV&1OF
0EV&F(F
0EV&N)F
0EV&NOF
0EV&S)F
0EV&SOF
0EV&V)F
0EV&VOF
0EV)F
0EV)&(F
0EV)&1F
0EV)&FF
0EV)&NF
0EV)&SF
0EV)&VF
0EV);F
0EV);(F
0EV);CF
0EV);EF
0EV);TF
0EV)CF
0EV)KNF
0EV)O(F
0EV)O1F
0EV)OFF
0EV)ONF
0EV)OSF
0EV)OVF
0EV)UEF
0EV,(1F
0EV,(FF
0EV,(NF
0EV,(SF
0EV,(VF
0EV,F(F
0EV;(EF
0EVB(1F
0EVB(FF
0EVB(NF
0EVB(SF
0EVB(VF
0EVB1)F
0EVB1OF
0EVBF(F
0EVBN)F
0EVBNOF
0EVBS)F
0EVBSOF
0EVBV)F
0EVBVOF
0EVF()F
0EVF(1F
0EVF(FF
0EVF(NF
0EVF(SF
0EVF(VF
0EVK(1F
0EVK(EF
0EVK(FF
0EVK(NF
0EVK(SF
0EVK(VF
0EVK1)F
0EVK1KF
0EVK1OF
0EVKF(F
0EVKNF
0EVKN)F
0EVKN;F
0EVKNCF
0EVKNKF
0EVKNUF
0EVKS)F
0EVKSKF
0EVKSOF
0EVKV)F
0EVKVKF
0EVKVOF
0EVNF
0EVN)UF
0EVN;F
0EVN;CF
0EVNCF
0EVNKNF
0EVNO(F
0EVNOFF
0EVNOSF
0EVNOVF
0EVO(1F
0EVO(EF
0EVO(FF
0EVO(NF
0EVO(SF
0EVO(VF
0EVOF(F
0EVOS&F
0EVOS(F
0EVOS)F
0EVOS,F
0EVOS1F
0EVOS;F
0EVOSBF
0EVOSFF
0EVOSKF
0EVOSUF
0EVOSVF
0EVSF
0EVS;F
0EVS;CF
0EVSCF
0EVSO(F
0EVSO1F
0EVSOFF
0EVSONF
0EVSOSF
0EVSOVF
0EVU(EF
0EVUE(F
0EVUE1F
0EVUEFF
0EVUEKF
0EVUENF
0EVUESF
0EVUEVF
0F()&(F
0F()&1F
0F()&EF
0F()&FF
0F()&KF
0F()&NF
0F()&SF
0F()&VF
0F(),(F
0F(),1F
0F(),FF
0F(),NF
0F(),SF
0F(),VF
0F()1(F
0F()1FF
0F()1NF
0F()1OF
0F()1SF
0F()1UF
0F()1VF
0F();EF
0F();NF
0F();TF
0F()A(F
0F()AFF
0F()ASF
0F()ATF
0F()AVF
0F()B(F
0F()B1F
0F()BEF
0F()BFF
0F()BNF
0F()BSF
0F()BVF
0F()CF
0F()E(F
0F()E1F
0F()EFF
0F()EKF
0F()ENF
0F()EOF
0F()ESF
0F()EUF
0F()EVF
0F()F(F
0F()K(F
0F()K)F
0F()K1F
0F()KFF
0F()KNF
0F()KSF
0F()KUF
0F()KVF
0F()N&F
0F()N(F
0F()N)F
0F()N,F
0F()N1F
0F()NEF
0F()NFF
0F()NOF
0F()NUF
0F()O(F
0F()O1F
0F()OFF
0F()OKF
0F()ONF
0F()OSF
0F()OUF
0F()OVF
0F()S(F
0F()S1F
0F()SFF
0F()SOF
0F()SUF
0F()SVF
0F()T(F
0F()T1F
0F()TEF
0F()TFF
0F()TNF
0F()TSF
0F()TTF
0F()TVF
0F()UF
0F()U(F
0F()U1F
0F()U;F
0F()UCF
0F()UEF
0F()UFF
0F()UKF
0F()UOF
0F()USF
0F()UTF
0F()UVF
0F()V(F
0F()VFF
0F()VOF
0F()VSF
0F()VUF
0F(1&(F
0F(1&1F
0F(1&FF
0F(1&NF
0F(1&SF
0F(1&VF
0F(1)F
0F(1)&F
0F(1),F
0F(1)1F
0F(1);F
0F(1)AF
0F(1)BF
0F(1)CF
0F(1)EF
0F(1)FF
0F(1)KF
0F(1)NF
0F(1)OF
0F(1)SF
0F(1)TF
0F(1)UF
0F(1)VF
0F(1,(F
0F(1,FF
0F(1O(F
0F(1OFF
0F(1OSF
0F(1OVF
0F(E(1F
0F(E(EF
0F(E(FF
0F(E(NF
0F(E(SF
0F(E(VF
0F(E1&F
0F(E1)F
0F(E1KF
0F(E1OF
0F(EF(F
0F(EK(F
0F(EK1F
0F(EKFF
0F(EKNF
0F(EKOF
0F(EKSF
0F(EKVF
0F(EN&F
0F(EN)F
0F(ENKF
0F(ENOF
0F(EOKF
0F(ES&F
0F(ES)F
0F(ESKF
0F(ESOF
0F(EV&F
0F(EV)F
0F(EVKF
0F(EVOF
0F(F()F
0F(F(1F
0F(F(EF
0F(F(FF
0F(F(NF
0F(F(SF
0F(F(VF
0F(K()F
0F(K,(F
0F(K,FF
0F(N&(F
0F(N&1F
0F(N&FF
0F(N&NF
0F(N&SF
0F(N&VF
0F(N)F
0F(N)&F
0F(N),F
0F(N)1F
0F(N);F
0F(N)AF
0F(N)BF
0F(N)CF
0F(N)EF
0F(N)FF
0F(N)KF
0F(N)NF
0F(N)OF
0F(N)SF
0F(N)TF
0F(N)UF
0F(N)VF
0F(N,(F
0F(N,FF
0F(NO(F
0F(NOFF
0F(NOSF
0F(NOVF
0F(S&(F
0F(S&1F
0F(S&FF
0F(S&NF
0F(S&SF
0F(S&VF
0F(S)F
0F(S)&F
0F(S),F
0F(S)1F
0F(S);F
0F(S)AF
0F(S)BF
0F(S)CF
0F(S)EF
0F(S)FF
0F(S)KF
0F(S)NF
0F(S)OF
0F(S)SF
0F(S)TF
0F(S)UF
0F(S)VF
0F(S,(F
0F(S,FF
0F(SO(F
0F(SO1F
0F(SOFF
0F(SONF
0F(SOSF
0F(SOVF
0F(T,(F
0F(T,FF
0F(V&(F
0F(V&1F
0F(V&FF
0F(V&NF
0F(V&SF
0F(V&VF
0F(V)F
0F(V)&F
0F(V),F
0F(V)1F
0F(V);F
0F(V)AF
0F(V)BF
0F(V)CF
0F(V)EF
0F(V)FF
0F(V)KF
0F(V)NF
0F(V)OF
0F(V)SF
0F(V)TF
0F(V)UF
0F(V)VF
0F(V,(F
0F(V,FF
0F(VO(F
0F(VOFF
0F(VOSF
0K(1),F
0K(1)AF
0K(1)KF
0K(1)OF
0K(1O(F
0K(1OFF
0K(1OSF
0K(1OVF
0K(F()F
0K(F(1F
0K(F(FF
0K(F(NF
0K(F(SF
0K(F(VF
0K(N),F
0K(N)AF
0K(N)KF
0K(N)OF
0K(NO(F
0K(NOFF
0K(NOSF
0K(NOVF
0K(S),F
0K(S)AF
0K(S)KF
0K(S)OF
0K(SO(F
0K(SO1F
0K(SOFF
0K(SONF
0K(SOSF
0K(SOVF
0K(V),F
0K(V)AF
0K(V)KF
0K(V)OF
0K(VO(F
0K(VOFF
0K(VOSF
0K1,(1F
0K1,(FF
0K1,(NF
0K1,(SF
0K1,(VF
0K1,F(F
0K1A(FF
0K1A(NF
0K1A(SF
0K1A(VF
0K1AF(F
0K1ASOF
0K1AVOF
0K1K(1F
0K1K(FF
0K1K(NF
0K1K(SF
0K1K(VF
0K1K1OF
0K1K1UF
0K1KF(F
0K1KNUF
0K1KSOF
0K1KSUF
0K1KVOF
0K1KVUF
0K1O(1F
0K1O(FF
0K1O(NF
0K1O(SF
0K1O(VF
0K1OF(F
0K1OS(F
0K1OS,F
0K1OS1F
0K1OSAF
0K1OSFF
0K1OSKF
0K1OSVF
0K1OV(F
0K1OV,F
0K1OVAF
0K1OVFF
0K1OVKF
0K1OVOF
0K1OVSF
0KF(),F
0KF()AF
0KF()KF
0KF()OF
0KF(1)F
0KF(1OF
0KF(F(F
0KF(N)F
0KF(NOF
0KF(S)F
0KF(SOF
0KF(V)F
0KF(VOF
0KN,(1F
0KN,(FF
0KN,(NF
0KN,(SF
0KN,(VF
0KN,F(F
0KNA(FF
0KNA(NF
0KNA(SF
0KNA(VF
0KNAF(F
0KNASOF
0KNAVOF
0KNK(1F
0KNK(FF
0KNK(NF
0KNK(SF
0KNK(VF
0KNK1OF
0KNK1UF
0KNKF(F
0KNKNUF
0KNKSOF
0KNKSUF
0KNKVOF
0KNKVUF
0KS,(1F
0KS,(FF
0KS,(NF
0KS,(SF
0KS,(VF
0KS,F(F
0KSA(FF
0KSA(NF
0KSA(SF
0KSA(VF
0KSAF(F
0KSASOF
0KSAVOF
0KSK(1F
0KSK(FF
0KSK(NF
0KSK(SF
0KSK(VF
0KSK1OF
0KSK1UF
0KSKF(F
0KSKNUF
0KSKSOF
0KSKSUF
0KSKVOF
0KSKVUF
0KSO(1F
0KSO(FF
0KSO(NF
0KSO(SF
0KSO(VF
0KSO1(F
0KSO1,F
0KSO1AF
0KSO1FF
0KSO1KF
0KSO1NF
0KSO1SF
0KSO1VF
0KSOF(F
0KSON(F
0KSON,F
0KSON1F
0KSONAF
0KSONFF
0KSONKF
0KSOS(F
0KSOS,F
0KSOS1F
0KSOSAF
0KSOSFF
0KSOSKF
0KSOSVF
0KSOV(F
0KSOV,F
0KSOVAF
0KSOVFF
0KSOVKF
0KSOVOF
0KSOVSF
0KV,(1F
0KV,(FF
0KV,(NF
0KV,(SF
0KV,(VF
0KV,F(F
0KVA(FF
0KVA(NF
0KVA(SF
0KVA(VF
0KVAF(F
0KVASOF
0KVAVOF
0KVK(1F
0KVK(FF
0KVK(NF
0KVK(SF
0KVK(VF
0KVK1OF
0KVK1UF
0KVKF(F
0KVKNUF
0KVKSOF
0KVKSUF
0KVKVOF
0KVKVUF
0KVO(1F
0KVO(FF
0KVO(NF
0KVO(SF
0KVO(VF
0KVOF(F
0KVOS(F
0KVOS,F
0KVOS1F
0KVOSAF
0KVOSFF
0KVOSKF
0KVOSVF
0N&(1&F
0N&(1)F
0N&(1,F
0N&(1OF
0N&(E(F
0N&(E1F
0N&(EFF
0N&(EKF
0N&(ENF
0N&(EOF
0N&(ESF
0N&(EVF
0N&(F(F
0N&(N&F
0N&(N)F
0N&(N,F
0N&(NOF
0N&(S&F
0N&(S)F
0N&(S,F
0N&(SOF
0N&(V&F
0N&(V)F
0N&(V,F
0N&(VOF
0N&1F
0N&1&(F
0N&1&1F
0N&1&FF
0N&1&NF
0N&1&SF
0N&1&VF
0N&1)&F
0N&1)CF
0N&1)OF
0N&1)UF
0N&1;F
0N&1;CF
0N&1;EF
0N&1;TF
0N&1B(F
0N&1B1F
0N&1BFF
0N&1BNF
0N&1BSF
0N&1BVF
0N&1CF
0N&1EKF
0N&1ENF
0N&1F(F
0N&1K(F
0N&1K1F
0N&1KFF
0N&1KNF
0N&1KSF
0N&1KVF
0N&1O(F
0N&1OFF
0N&1OSF
0N&1OVF
0N&1TNF
0N&1UF
0N&1U(F
0N&1U;F
0N&1UCF
0N&1UEF
0N&E(1F
0N&E(FF
0N&E(NF
0N&E(OF
0N&E(SF
0N&E(VF
0N&E1F
0N&E1;F
0N&E1CF
0N&E1KF
0N&E1OF
0N&EF(F
0N&EK(F
0N&EK1F
0N&EKFF
0N&EKNF
0N&EKSF
0N&EKVF
0N&EN;F
0N&ENCF
0N&ENKF
0N&ENOF
0N&ESF
0N&ES;F
0N&ESCF
0N&ESKF
0N&ESOF
0N&EVF
0N&EV;F
0N&EVCF
0N&EVKF
0N&EVOF
0N&F()F
0N&F(1F
0N&F(EF
0N&F(FF
0N&F(NF
0N&F(SF
0N&F(VF
0N&K&(F
0N&K&1F
0N&K&FF
0N&K&NF
0N&K&SF
0N&K&VF
0N&K(1F
0N&K(FF
0N&K(NF
0N&K(SF
0N&K(VF
0N&K1OF
0N&KCF
0N&KF(F
0N&KNKF
0N&KO(F
0N&KO1F
0N&KOFF
0N&KOKF
0N&KONF
0N&KOSF
0N&KOVF
0N&KSOF
0N&KVOF
0N&N&(F
0N&N&1F
0N&N&FF
0N&N&SF
0N&N&VF
0N&N)&F
0N&N)CF
0N&N)OF
0N&N)UF
0N&N;CF
0N&N;EF
0N&N;TF
0N&NB(F
0N&NB1F
0N&NBFF
0N&NBSF
0N&NBVF
0N&NF(F
0N&NK(F
0N&NK1F
0N&NKFF
0N&NKSF
0N&NKVF
0N&NO(F
0N&NOFF
0N&NOSF
0N&NOVF
0N&NUF
0N&NU(F
0N&NU;F
0N&NUCF
0N&NUEF
0N&S&(F
0N&S&1F
0N&S&FF
0N&S&NF
0N&S&SF
0N&S&VF
0N&S)&F
0N&S)CF
0N&S)OF
0N&S)UF
0N&S1F
0N&S1;F
0N&S1CF
0N&S;F
0N&S;CF
0N&S;EF
0N&S;TF
0N&SB(F
0N&SB1F
0N&SBFF
0N&SBNF
0N&SBSF
0N&SBVF
0N&SCF
0N&SEKF
0N&SENF
0N&SF(F
0N&SK(F
0N&SK1F
0N&SKFF
0N&SKNF
0N&SKSF
0N&SKVF
0N&SO(F
0N&SO1F
0N&SOFF
0N&SONF
0N&SOSF
0N&SOVF
0N&STNF
0N&SUF
0N&SU(F
0N&SU;F
0N&SUCF
0N&SUEF
0N&SVF
0N&SV;F
0N&SVCF
0N&SVOF
0N&VF
0N&V&(F
0N&V&1F
0N&V&FF
0N&V&NF
0N&V&SF
0N&V&VF
0N&V)&F
0N&V)CF
0N&V)OF
0N&V)UF
0N&V;F
0N&V;CF
0N&V;EF
0N&V;TF
0N&VB(F
0N&VB1F
0N&VBFF
0N&VBNF
0N&VBSF
0N&VBVF
0N&VCF
0N&VEKF
0N&VENF
0N&VF(F
0N&VK(F
0N&VK1F
0N&VKFF
0N&VKNF
0N&VKSF
0N&VKVF
0N&VO(F
0N&VOFF
0N&VOSF
0N&VSF
0N&VS;F
0N&VSCF
0N&VSOF
0N&VTNF
0N&VUF
0N&VU(F
0N&VU;F
0N&VUCF
0N&VUEF
0N)&(1F
0N)&(EF
0N)&(FF
0N)&(NF
0N)&(SF
0N)&(VF
0N)&1F
0N)&1&F
0N)&1)F
0N)&1;F
0N)&1BF
0N)&1CF
0N)&1FF
0N)&1OF
0N)&1UF
0N)&F(F
0N)&NF
0N)&N&F
0N)&N)F
0N)&N;F
0N)&NBF
0N)&NCF
0N)&NFF
0N)&NOF
0N)&NUF
0N)&SF
0N)&S&F
0N)&S)F
0N)&S;F
0N)&SBF
0N)&SCF
0N)&SFF
0N)&SOF
0N)&SUF
0N)&VF
0N)&V&F
0N)&V)F
0N)&V;F
0N)&VBF
0N)&VCF
0N)&VFF
0N)&VOF
0N)&VUF
0N),(1F
0N),(FF
0N),(NF
0N),(SF
0N),(VF
0N);E(F
0N);E1F
0N);EFF
0N);EKF
0N);ENF
0N);EOF
0N);ESF
0N);EVF
0N);T(F
0N);T1F
0N);TFF
0N);TKF
0N);TNF
0N);TOF
0N);TSF
0N);TVF
0N)B(1F
0N)B(FF
0N)B(NF
0N)B(SF
0N)B(VF
0N)B1F
0N)B1&F
0N)B1;F
0N)B1CF
0N)B1KF
0N)B1NF
0N)B1OF
0N)B1UF
0N)BF(F
0N)BNF
0N)BN&F
0N)BN;F
0N)BNCF
0N)BNKF
0N)BNOF
0N)BNUF
0N)BSF
0N)BS&F
0N)BS;F
0N)BSCF
0N)BSKF
0N)BSOF
0N)BSUF
0N)BVF
0N)BV&F
0N)BV;F
0N)BVCF
0N)BVKF
0N)BVOF
0N)BVUF
0N)E(1F
0N)E(FF
0N)E(NF
0N)E(SF
0N)E(VF
0N)E1CF
0N)E1OF
0N)EF(F
0N)EK(F
0N)EK1F
0N)EKFF
0N)EKNF
0N)EKSF
0N)EKVF
0N)ENCF
0N)ENOF
0N)ESCF
0N)ESOF
0N)EVCF
0N)EVOF
0N)F(FF
0N)K(1F
0N)K(FF
0N)K(NF
0N)K(SF
0N)K(VF
0N)K1&F
0N)K1;F
0N)K1BF
0N)K1EF
0N)K1OF
0N)K1UF
0N)KB(F
0N)KB1F
0N)KBFF
0N)KBNF
0N)KBSF
0N)KBVF
0N)KF(F
0N)KN&F
0N)KN;F
0N)KNBF
0N)KNCF
0N)KNEF
0N)KNKF
0N)KNUF
0N)KS&F
0N)KS;F
0N)KSBF
0N)KSEF
0N)KSOF
0N)KSUF
0N)KUEF
0N)KV&F
0N)KV;F
0N)KVBF
0N)KVEF
0N)KVOF
0N)KVUF
0N)O(1F
0N)O(EF
0N)O(FF
0N)O(NF
0N)O(SF
0N)O(VF
0N)O1&F
0N)O1)F
0N)O1;F
0N)O1BF
0N)O1CF
0N)O1KF
0N)O1UF
0N)OF(F
0N)ON&F
0N)ON)F
0N)ON;F
0N)ONBF
0N)ONCF
0N)ONKF
0N)ONUF
0N)OSF
0N)OS&F
0N)OS)F
0N)OS;F
0N)OSBF
0N)OSCF
0N)OSKF
0N)OSUF
0N)OVF
0N)OV&F
0N)OV)F
0N)OV;F
0N)OVBF
0N)OVCF
0N)OVKF
0N)OVOF
0N)OVUF
0N)U(EF
0N)UE(F
0N)UE1F
0N)UEFF
0N)UEKF
0N)UENF
0N)UESF
0N)UEVF
0N,(1)F
0N,(1OF
0N,(E(F
0N,(E1F
0N,(EFF
0N,(EKF
0N,(ENF
0N,(ESF
0N,(EVF
0N,(F(F
0N,(NOF
0N,(S)F
0N,(SOF
0N,(V)F
0N,(VOF
0N,F()F
0N,F(1F
0N,F(FF
0N,F(NF
0N,F(SF
0N,F(VF
0N1O(1F
0N1O(FF
0N1O(NF
0N1O(SF
0N1O(VF
0N1OF(F
0N1OS(F
0N1OS1F
0N1OSFF
0N1OSUF
0N1OSVF
0N1OV(F
0N1OVFF
0N1OVOF
0N1OVSF
0N1OVUF
0N1S;F
0N1S;CF
0N1SCF
0N1UEF
0N1UE;F
0N1UECF
0N1UEKF
0N1V;F
0N1V;CF
0N1VCF
0N1VO(F
0N1VOFF
0N1VOSF
0N;E(1F
0N;E(EF
0N;E(FF
0N;E(NF
0N;E(SF
0N;E(VF
0N;E1,F
0N;E1;F
0N;E1CF
0N;E1KF
0N;E1OF
0N;E1TF
0N;EF(F
0N;EK(F
0N;EK1F
0N;EKFF
0N;EKNF
0N;EKOF
0N;EKSF
0N;EKVF
0N;EN,F
0N;EN;F
0N;ENCF
0N;ENEF
0N;ENKF
0N;ENOF
0N;ENTF
0N;ES,F
0N;ES;F
0N;ESCF
0N;ESKF
0N;ESOF
0N;ESTF
0N;EV,F
0N;EV;F
0N;EVCF
0N;EVKF
0N;EVOF
0N;EVTF
0N;N:TF
0N;T(1F
0N;T(CF
0N;T(EF
0N;T(FF
0N;T(NF
0N;T(SF
0N;T(VF
0N;T1(F
0N;T1,F
0N;T1;F
0N;T1CF
0N;T1FF
0N;T1KF
0N;T1OF
0N;T1TF
0N;T;F
0N;T;CF
0N;TF(F
0N;TK(F
0N;TK1F
0N;TKFF
0N;TKKF
0N;TKOF
0N;TKSF
0N;TKVF
0N;TN(F
0N;TN,F
0N;TN1F
0N;TN;F
0N;TNCF
0N;TNEF
0N;TNFF
0N;TNKF
0N;TNNF
0N;TNOF
0N;TNSF
0N;TNTF
0N;TNVF
0N;TO(F
0N;TS(F
0N;TS,F
0N;TS;F
0N;TSCF
0N;TSFF
0N;TSKF
0N;TSOF
0N;TSTF
0N;TTNF
0N;TV(F
0N;TV,F
0N;TV;F
0N;TVCF
0N;TVFF
0N;TVKF
0N;TVOF
0N;TVTF
0NA(F(F
0NA(N)F
0NA(NOF
0NA(S)F
0NA(SOF
0NA(V)F
0NA(VOF
0NAF()F
0NAF(1F
0NAF(FF
0NAF(NF
0NAF(SF
0NAF(VF
0NASO(F
0NASO1F
0NASOFF
0NASONF
0NASOSF
0NASOVF
0NASUEF
0NATO(F
0NATO1F
0NATOFF
0NATONF
0NATOSF
0NATOVF
0NATUEF
0NAVO(F
0NAVOFF
0NAVOSF
0NAVUEF
0NB(1&F
0NB(1)F
0NB(1OF
0NB(F(F
0NB(N&F
0NB(NOF
0NB(S&F
0NB(S)F
0NB(SOF
0NB(V&F
0NB(V)F
0NB(VOF
0NB1F
0NB1&(F
0NB1&1F
0NB1&FF
0NB1&NF
0NB1&SF
0NB1&VF
0NB1,(F
0NB1,FF
0NB1;F
0NB1;CF
0NB1B(F
0NB1B1F
0NB1BFF
0NB1BNF
0NB1BSF
0NB1BVF
0NB1CF
0NB1K(F
0NB1K1F
0NB1KFF
0NB1KNF
0NB1KSF
0NB1KVF
0NB1O(F
0NB1OFF
0NB1OSF
0NB1OVF
0NB1U(F
0NB1UEF
0NBE(1F
0NBE(FF
0NBE(NF
0NBE(SF
0NBE(VF
0NBEK(F
0NBF()F
0NBF(1F
0NBF(FF
0NBF(NF
0NBF(SF
0NBF(VF
0NBN&(F
0NBN&1F
0NBN&FF
0NBN&NF
0NBN&SF
0NBN&VF
0NBN,(F
0NBN,FF
0NBN;F
0NBN;CF
0NBNB(F
0NBNB1F
0NBNBFF
0NBNBNF
0NBNBSF
0NBNBVF
0NBNCF
0NBNK(F
0NBNK1F
0NBNKFF
0NBNKNF
0NBNKSF
0NBNKVF
0NBNO(F
0NBNOFF
0NBNOSF
0NBNOVF
0NBNU(F
0NBNUEF
0NBSF
0NBS&(F
0NBS&1F
0NBS&FF
0NBS&NF
0NBS&SF
0NBS&VF
0NBS,(F
0NBS,FF
0NBS;F
0NBS;CF
0NBSB(F
0NBSB1F
0NBSBFF
0NBSBNF
0NBSBSF
0NBSBVF
0NBSCF
0NBSK(F
0NBSK1F
0NBSKFF
0NBSKNF
0NBSKSF
0NBSKVF
0NBSO(F
0NBSO1F
0NBSOFF
0NBSONF
0NBSOSF
0NBSOVF
0NBSU(F
0NBSUEF
0NBVF
0NBV&(F
0NBV&1F
0NBV&FF
0NBV&NF
0NBV&SF
0NBV&VF
0NBV,(F
0NBV,FF
0NBV;F
0NBV;CF
0NBVB(F
0NBVB1F
0NBVBFF
0NBVBNF
0NBVBSF
0NBVBVF
0NBVCF
0NBVK(F
0NBVK1F
0NBVKFF
0NBVKNF
0NBVKSF
0NBVKVF
0NBVO(F
0NBVOFF
0NBVOSF
0NBVU(F
0NBVUEF
0NCF
0NE(1)F
0NE(1OF
0NE(F(F
0NE(N)F
0NE(NOF
0NE(S)F
0NE(SOF
0NE(V)F
0NE(VOF
0NE1;TF
0NE1CF
0NE1O(F
0NE1OFF
0NE1OSF
0NE1OVF
0NE1T(F
0NE1T1F
0NE1TFF
0NE1TNF
0NE1TSF
0NE1TVF
0NE1UEF
0NEF()F
0NEF(1F
0NEF(FF
0NEF(NF
0NEF(SF
0NEF(VF
0NEN;TF
0NENO(F
0NENOFF
0NENOSF
0NENOVF
0NENT(F
0NENT1F
0NENTFF
0NENTNF
0NENTSF
0NENTVF
0NENUEF
0NEOKNF
0NES;TF
0NESCF
0NESO(F
0NESO1F
0NESOFF
0NESONF
0NESOSF
0NESOVF
0NEST(F
0NEST1F
0NESTFF
0NESTNF
0NESTSF
0NESTVF
0NESUEF
0NEU(1F
0NEU(FF
0NEU(NF
0NEU(SF
0NEU(VF
0NEU1,F
0NEU1CF
0NEU1OF
0NEUEFF
0NEUEKF
0NEUF(F
0NEUS,F
0NEUSCF
0NEUSOF
0NEUV,F
0NEUVCF
0NEUVOF
0NEV;TF
0NEVCF
0NEVO(F
0NEVOFF
0NEVOSF
0NEVT(F
0NEVT1F
0NEVTFF
0NEVTNF
0NEVTSF
0NEVTVF
0NEVUEF
0NF()1F
0NF()FF
0NF()KF
0NF()NF
0NF()OF
0NF()SF
0NF()UF
0NF()VF
0NF(1)F
0NF(1OF
0NF(E(F
0NF(E1F
0NF(EFF
0NF(EKF
0NF(ENF
0NF(ESF
0NF(EVF
0NF(F(F
0NF(N,F
0NF(NOF
0NF(S)F
0NF(SOF
0NF(V)F
0NF(VOF
0NK(1)F
0NK(1OF
0NK(F(F
0NK(NOF
0NK(S)F
0NK(SOF
0NK(V)F
0NK(VOF
0NK)&(F
0NK)&1F
0NK)&FF
0NK)&NF
0NK)&SF
0NK)&VF
0NK);EF
0NK);TF
0NK)B(F
0NK)B1F
0NK)BFF
0NK)BNF
0NK)BSF
0NK)BVF
0NK)E(F
0NK)E1F
0NK)EFF
0NK)EKF
0NK)ENF
0NK)ESF
0NK)EVF
0NK)F(F
0NK)O(F
0NK)OFF
0NK)UEF
0NK1F
0NK1&(F
0NK1&1F
0NK1&FF
0NK1&NF
0NK1&SF
0NK1&VF
0NK1;CF
0NK1;EF
0NK1;TF
0NK1B(F
0NK1B1F
0NK1BFF
0NK1BNF
0NK1BSF
0NK1BVF
0NK1CF
0NK1E(F
0NK1E1F
0NK1EFF
0NK1EKF
0NK1ENF
0NK1ESF
0NK1EVF
0NK1O(F
0NK1OFF
0NK1OSF
0NK1OVF
0NK1U(F
0NK1UEF
0NKF()F
0NKF(1F
0NKF(FF
0NKF(NF
0NKF(SF
0NKF(VF
0NKNF
0NKN&(F
0NKN&1F
0NKN&FF
0NKN&SF
0NKN&VF
0NKN;CF
0NKN;EF
0NKN;TF
0NKNB(F
0NKNB1F
0NKNBFF
0NKNBNF
0NKNBSF
0NKNBVF
0NKNE(F
0NKNE1F
0NKNEFF
0NKNESF
0NKNEVF
0NKNU(F
0NKNUEF
0NKSF
0NKS&(F
0NKS&1F
0NKS&FF
0NKS&NF
0NKS&SF
0NKS&VF
0NKS;F
0NKS;CF
0NKS;EF
0NKS;TF
0NKSB(F
0NKSB1F
0NKSBFF
0NKSBNF
0NKSBSF
0NKSBVF
0NKSCF
0NKSE(F
0NKSE1F
0NKSEFF
0NKSEKF
0NKSENF
0NKSESF
0NKSEVF
0NKSO(F
0NKSO1F
0NKSOFF
0NKSONF
0NKSOSF
0NKSOVF
0NKSU(F
0NKSUEF
0NKUE(F
0NKUE1F
0NKUEFF
0NKUEKF
0NKUENF
0NKUESF
0NKUEVF
0NKVF
0NKV&(F
0NKV&1F
0NKV&FF
0NKV&NF
0NKV&SF
0NKV&VF
0NKV;F
0NKV;CF
0NKV;EF
0NKV;TF
0NKVB(F
0NKVB1F
0NKVBFF
0NKVBNF
0NKVBSF
0NKVBVF
0NKVCF
0NKVE(F
0NKVE1F
0NKVEFF
0NKVEKF
0NKVENF
0NKVESF
0NKVEVF
0NKVO(F
0NKVOFF
0NKVOSF
0NKVU(F
0NKVUEF
0NO(1&F
0NO(1)F
0NO(1,F
0NO(1OF
0NO(E(F
0NO(E1F
0NO(EEF
0NO(EFF
0NO(EKF
0NO(ENF
0NO(EOF
0NO(ESF
0NO(EVF
0NO(F(F
0NO(N&F
0NO(N)F
0NO(N,F
0NO(NOF
0NO(S&F
0NO(S)F
0NO(S,F
0NO(SOF
0NO(V&F
0NO(V)F
0NO(V,F
0NO(VOF
0NOF()F
0NOF(1F
0NOF(EF
0NOF(FF
0NOF(NF
0NOF(SF
0NOF(VF
0NOK&(F
0NOK(1F
0NOK(FF
0NOK(NF
0NOK(SF
0NOK(VF
0NOK1CF
0NOK1OF
0NOKF(F
0NOKNCF
0NOKO(F
0NOKO1F
0NOKOFF
0NOKONF
0NOKOSF
0NOKOVF
0NOKSCF
0NOKSOF
0NOKVCF
0NOKVOF
0NONSUF
0NOS&(F
0NOS&1F
0NOS&EF
0NOS&FF
0NOS&KF
0NOS&NF
0NOS&SF
0NOS&UF
0NOS&VF
0NOS(EF
0NOS(UF
0NOS)&F
0NOS),F
0NOS);F
0NOS)BF
0NOS)CF
0NOS)EF
0NOS)FF
0NOS)KF
0NOS)OF
0NOS)UF
0NOS,(F
0NOS,FF
0NOS1(F
0NOS1FF
0NOS1NF
0NOS1SF
0NOS1UF
0NOS1VF
0NOS;F
0NOS;CF
0NOS;EF
0NOS;TF
0NOSA(F
0NOSAFF
0NOSASF
0NOSATF
0NOSAVF
0NOSB(F
0NOSB1F
0NOSBEF
0NOSBFF
0NOSBNF
0NOSBSF
0NOSBVF
0NOSCF
0NOSE(F
0NOSE1F
0NOSEFF
0NOSEKF
0NOSENF
0NOSEOF
0NOSESF
0NOSEUF
0NOSEVF
0NOSF(F
0NOSK(F
0NOSK)F
0NOSK1F
0NOSKBF
0NOSKFF
0NOSKNF
0NOSKSF
0NOSKUF
0NOSKVF
0NOST(F
0NOST1F
0NOSTEF
0NOSTFF
0NOSTNF
0NOSTSF
0NOSTTF
0NOSTVF
0NOSUF
0NOSU(F
0NOSU1F
0NOSU;F
0NOSUCF
0NOSUEF
0NOSUFF
0NOSUKF
0NOSUOF
0NOSUSF
0NOSUTF
0NOSUVF
0NOSV(F
0NOSVFF
0NOSVOF
0NOSVSF
0NOSVUF
0NOU(EF
0NOUEKF
0NOUENF
0NOV&(F
0NOV&1F
0NOV&EF
0NOV&FF
0NOV&KF
0NOV&NF
0NOV&SF
0NOV&UF
0NOV&VF
0NOV(EF
0NOV(UF
0NOV)&F
0NOV),F
0NOV);F
0NOV)BF
0NOV)CF
0NOV)EF
0NOV)FF
0NOV)KF
0NOV)OF
0NOV)UF
0NOV,(F
0NOV,FF
0NOV;F
0NOV;CF
0NOV;EF
0NOV;NF
0NOV;TF
0NOVA(F
0NOVAFF
0NOVASF
0NOVATF
0NOVAVF
0NOVB(F
0NOVB1F
0NOVBEF
0NOVBFF
0NOVBNF
0NOVBSF
0NOVBVF
0NOVCF
0NOVE(F
0NOVE1F
0NOVEFF
0NOVEKF
0NOVENF
0NOVEOF
0NOVESF
0NOVEUF
0NOVEVF
0NOVF(F
0NOVK(F
0NOVK)F
0NOVK1F
0NOVKBF
0NOVKFF
0NOVKNF
0NOVKSF
0NOVKUF
0NOVKVF
0NOVO(F
0NOVOFF
0NOVOKF
0NOVOSF
0NOVOUF
0NOVS(F
0NOVS1F
0NOVSFF
0NOVSOF
0NOVSUF
0NOVSVF
0NOVT(F
0NOVT1F
0NOVTEF
0NOVTFF
0NOVTNF
0NOVTSF
0NOVTTF
0NOVTVF
0NOVUF
0NOVU(F
0NOVU1F
0NOVU;F
0NOVUCF
0NOVUEF
0NOVUFF
0NOVUKF
0NOVUOF
0NOVUSF
0NOVUTF
0NOVUVF
0NSO1UF
0NSONUF
0NSOSUF
0NSOVUF
0NSUEF
0NSUE;F
0NSUECF
0NSUEKF
0NT(1)F
0NT(1OF
0NT(F(F
0NT(N)F
0NT(NOF
0NT(S)F
0NT(SOF
0NT(V)F
0NT(VOF
0NT1(FF
0NT1O(F
0NT1OFF
0NT1OSF
0NT1OVF
0NTE(1F
0NTE(FF
0NTE(NF
0NTE(SF
0NTE(VF
0NTE1NF
0NTE1OF
0NTEF(F
0NTEK(F
0NTEK1F
0NTEKFF
0NTEKNF
0NTEKSF
0NTEKVF
0NTENNF
0NTENOF
0NTESNF
0NTESOF
0NTEVNF
0NTEVOF
0NTF()F
0NTF(1F
0NTF(FF
0NTF(NF
0NTF(SF
0NTF(VF
0NTN(1F
0NTN(FF
0NTN(SF
0NTN(VF
0NTN1CF
0NTN1OF
0NTN;EF
0NTN;NF
0NTN;TF
0NTNE(F
0NTNE1F
0NTNEFF
0NTNENF
0NTNESF
0NTNEVF
0NTNF(F
0NTNKNF
0NTNN:F
0NTNNCF
0NTNNOF
0NTNO(F
0NTNOFF
0NTNOSF
0NTNOVF
0NTNSCF
0NTNSOF
0NTNT(F
0NTNT1F
0NTNTFF
0NTNTNF
0NTNTSF
0NTNTVF
0NTNVCF
0NTNVOF
0NTS(FF
0NTSO(F
0NTSO1F
0NTSOFF
0NTSONF
0NTSOSF
0NTSOVF
0NTTNEF
0NTTNKF
0NTTNNF
0NTTNTF
0NTV(1F
0NTV(FF
0NTVO(F
0NTVOFF
0NTVOSF
0NU(1)F
0NU(1OF
0NU(E(F
0NU(E1F
0NU(EFF
0NU(EKF
0NU(ENF
0NU(ESF
0NU(EVF
0NU(F(F
0NU(N)F
0NU(NOF
0NU(S)F
0NU(SOF
0NU(V)F
0NU(VOF
0NU1,(F
0NU1,FF
0NU1CF
0NU1O(F
0NU1OFF
0NU1OSF
0NU1OVF
0NU;F
0NU;CF
0NUCF
0NUEF
0NUE(1F
0NUE(EF
0NUE(FF
0NUE(NF
0NUE(OF
0NUE(SF
0NUE(VF
0NUE1F
0NUE1&F
0NUE1(F
0NUE1)F
0NUE1,F
0NUE1;F
0NUE1BF
0NUE1CF
0NUE1FF
0NUE1KF
0NUE1NF
0NUE1OF
0NUE1SF
0NUE1UF
0NUE1VF
0NUE;F
0NUE;CF
0NUECF
0NUEFF
0NUEF(F
0NUEF,F
0NUEF;F
0NUEFCF
0NUEKF
0NUEK(F
0NUEK1F
0NUEK;F
0NUEKCF
0NUEKFF
0NUEKNF
0NUEKOF
0NUEKSF
0NUEKVF
0NUENF
0NUEN&F
0NUEN(F
0NUEN)F
0NUEN,F
0NUEN1F
0NUEN;F
0NUENBF
0NUENCF
0NUENFF
0NUENKF
0NUENOF
0NUENSF
0NUENUF
0NUEOKF
0NUEONF
0NUESF
0NUES&F
0NUES(F
0NUES)F
0NUES,F
0NUES1F
0NUES;F
0NUESBF
0NUESCF
0NUESFF
0NUESKF
0NUESOF
0NUESUF
0NUESVF
0NUEVF
0NUEV&F
0NUEV(F
0NUEV)F
0NUEV,F
0NUEV;F
0NUEVBF
0NUEVCF
0NUEVFF
0NUEVKF
0NUEVNF
0NUEVOF
0NUEVSF
0NUEVUF
0NUF()F
0NUF(1F
0NUF(FF
0NUF(NF
0NUF(SF
0NUF(VF
0NUK(EF
0NUO(EF
0NUON(F
0NUON1F
0NUONFF
0NUONSF
0NUS,(F
0NUS,FF
0NUSCF
0NUSO(F
0NUSO1F
0NUSOFF
0NUSONF
0NUSOSF
0NUSOVF
0NUTN(F
0NUTN1F
0NUTNFF
0NUTNNF
0NUTNSF
0NUTNVF
0NUV,(F
0NUV,FF
0NUVCF
0NUVO(F
0NUVOFF
0NUVOSF
0S&(1&F
0S&(1)F
0S&(1,F
0S&(1OF
0S&(E(F
0S&(E1F
0S&(EFF
0S&(EKF
0S&(ENF
0S&(EOF
0S&(ESF
0S&(EVF
0S&(F(F
0S&(N&F
0S&(N)F
0S&(N,F
0S&(NOF
0S&(S&F
0S&(S)F
0S&(S,F
0S&(SOF
0S&(V&F
0S&(V)F
0S&(V,F
0S&(VOF
0S&1F
0S&1&(F
0S&1&1F
0S&1&FF
0S&1&NF
0S&1&SF
0S&1&VF
0S&1)&F
0S&1)CF
0S&1)OF
0S&1)UF
0S&1;F
0S&1;CF
0S&1;EF
0S&1;TF
0S&1B(F
0S&1B1F
0S&1BFF
0S&1BNF
0S&1BSF
0S&1BVF
0S&1CF
0S&1EKF
0S&1ENF
0S&1F(F
0S&1K(F
0S&1K1F
0S&1KFF
0S&1KNF
0S&1KSF
0S&1KVF
0S&1O(F
0S&1OFF
0S&1OSF
0S&1OVF
0S&1TNF
0S&1UF
0S&1U(F
0S&1U;F
0S&1UCF
0S&1UEF
0S&E(1F
0S&E(FF
0S&E(NF
0S&E(OF
0S&E(SF
0S&E(VF
0S&E1F
0S&E1;F
0S&E1CF
0S&E1KF
0S&E1OF
0S&EF(F
0S&EK(F
0S&EK1F
0S&EKFF
0S&EKNF
0S&EKSF
0S&EKVF
0S&ENF
0S&EN;F
0S&ENCF
0S&ENKF
0S&ENOF
0S&ESF
0S&ES;F
0S&ESCF
0S&ESKF
0S&ESOF
0S&EVF
0S&EV;F
0S&EVCF
0S&EVKF
0S&EVOF
0S&F()F
0S&F(1F
0S&F(EF
0S&F(FF
0S&F(NF
0S&F(SF
0S&F(VF
0S&K&(F
0S&K&1F
0S&K&FF
0S&K&NF
0S&K&SF
0S&K&VF
0S&K(1F
0S&K(FF
0S&K(NF
0S&K(SF
0S&K(VF
0S&K1OF
0S&KCF
0S&KF(F
0S&KNKF
0S&KO(F
0S&KO1F
0S&KOFF
0S&KOKF
0S&KONF
0S&KOSF
0S&KOVF
0S&KSOF
0S&KVOF
0S&NF
0S&N&(F
0S&N&1F
0S&N&FF
0S&N&NF
0S&N&SF
0S&N&VF
0S&N)&F
0S&N)CF
0S&N)OF
0S&N)UF
0S&N;F
0S&N;CF
0S&N;EF
0S&N;TF
0S&NB(F
0S&NB1F
0S&NBFF
0S&NBNF
0S&NBSF
0S&NBVF
0S&NCF
0S&NENF
0S&NF(F
0S&NK(F
0S&NK1F
0S&NKFF
0S&NKNF
0S&NKSF
0S&NKVF
0S&NO(F
0S&NOFF
0S&NOSF
0S&NOVF
0S&NTNF
0S&NUF
0S&NU(F
0S&NU;F
0S&NUCF
0S&NUEF
0S&SF
0S&S&(F
0S&S&1F
0S&S&FF
0S&S&NF
0S&S&SF
0S&S&VF
0S&S)&F
0S&S)CF
0S&S)OF
0S&S)UF
0S&S1F
0S&S1;F
0S&S1CF
0S&S;F
0S&S;CF
0S&S;EF
0S&S;TF
0S&SB(F
0S&SB1F
0S&SBFF
0S&SBNF
0S&SBSF
0S&SBVF
0S&SCF
0S&SEKF
0S&SENF
0S&SF(F
0S&SK(F
0S&SK1F
0S&SKFF
0S&SKNF
0S&SKSF
0S&SKVF
0S&SO(F
0S&SO1F
0S&SOFF
0S&SONF
0S&SOSF
0S&SOVF
0S&STNF
0S&SUF
0S&SU(F
0S&SU;F
0S&SUCF
0S&SUEF
0S&SVF
0S&SV;F
0S&SVCF
0S&SVOF
0S&VF
0S&V&(F
0S&V&1F
0S&V&FF
0S&V&NF
0S&V&SF
0S&V&VF
0S&V)&F
0S&V)CF
0S&V)OF
0S&V)UF
0S&V;F
0S&V;CF
0S&V;EF
0S&V;TF
0S&VB(F
0S&VB1F
0S&VBFF
0S&VBNF
0S&VBSF
0S&VBVF
0S&VCF
0S&VEKF
0S&VENF
0S&VF(F
0S&VK(F
0S&VK1F
0S&VKFF
0S&VKNF
0S&VKSF
0S&VKVF
0S&VO(F
0S&VOFF
0S&VOSF
0S&VSF
0S&VS;F
0S&VSCF
0S&VSOF
0S&VTNF
0S&VUF
0S&VU(F
0S&VU;F
0S&VUCF
0S&VUEF
0S(EF(F
0S(EKFF
0S(EKNF
0S(ENKF
0S(U(EF
0S)&(1F
0S)&(EF
0S)&(FF
0S)&(NF
0S)&(SF
0S)&(VF
0S)&1F
0S)&1&F
0S)&1)F
0S)&1;F
0S)&1BF
0S)&1CF
0S)&1FF
0S)&1OF
0S)&1UF
0S)&F(F
0S)&NF
0S)&N&F
0S)&N)F
0S)&N;F
0S)&NBF
0S)&NCF
0S)&NFF
0S)&NOF
0S)&NUF
0S)&SF
0S)&S&F
0S)&S)F
0S)&S;F
0S)&SBF
0S)&SCF
0S)&SFF
0S)&SOF
0S)&SUF
0S)&VF
0S)&V&F
0S)&V)F
0S)&V;F
0S)&VBF
0S)&VCF
0S)&VFF
0S)&VOF
0S)&VUF
0S),(1F
0S),(FF
0S),(NF
0S),(SF
0S),(VF
0S);E(F
0S);E1F
0S);EFF
0S);EKF
0S);ENF
0S);EOF
0S);ESF
0S);EVF
0S);T(F
0S);T1F
0S);TFF
0S);TKF
0S);TNF
0S);TOF
0S);TSF
0S);TVF
0S)B(1F
0S)B(FF
0S)B(NF
0S)B(SF
0S)B(VF
0S)B1F
0S)B1&F
0S)B1;F
0S)B1CF
0S)B1KF
0S)B1NF
0S)B1OF
0S)B1UF
0S)BF(F
0S)BNF
0S)BN&F
0S)BN;F
0S)BNCF
0S)BNKF
0S)BNOF
0S)BNUF
0S)BSF
0S)BS&F
0S)BS;F
0S)BSCF
0S)BSKF
0S)BSOF
0S)BSUF
0S)BVF
0S)BV&F
0S)BV;F
0S)BVCF
0S)BVKF
0S)BVOF
0S)BVUF
0S)CF
0S)E(1F
0S)E(FF
0S)E(NF
0S)E(SF
0S)E(VF
0S)E1CF
0S)E1OF
0S)EF(F
0S)EK(F
0S)EK1F
0S)EKFF
0S)EKNF
0S)EKSF
0S)EKVF
0S)ENCF
0S)ENOF
0S)ESCF
0S)ESOF
0S)EVCF
0S)EVOF
0S)F(FF
0S)K(1F
0S)K(FF
0S)K(NF
0S)K(SF
0S)K(VF
0S)K1&F
0S)K1;F
0S)K1BF
0S)K1EF
0S)K1OF
0S)K1UF
0S)KB(F
0S)KB1F
0S)KBFF
0S)KBNF
0S)KBSF
0S)KBVF
0S)KF(F
0S)KN&F
0S)KN;F
0S)KNBF
0S)KNCF
0S)KNEF
0S)KNKF
0S)KNUF
0S)KS&F
0S)KS;F
0S)KSBF
0S)KSEF
0S)KSOF
0S)KSUF
0S)KUEF
0S)KV&F
0S)KV;F
0S)KVBF
0S)KVEF
0S)KVOF
0S)KVUF
0S)O(1F
0S)O(EF
0S)O(FF
0S)O(NF
0S)O(SF
0S)O(VF
0S)O1F
0S)O1&F
0S)O1)F
0S)O1;F
0S)O1BF
0S)O1CF
0S)O1KF
0S)O1UF
0S)OF(F
0S)ON&F
0S)ON)F
0S)ON;F
0S)ONBF
0S)ONCF
0S)ONKF
0S)ONUF
0S)OSF
0S)OS&F
0S)OS)F
0S)OS;F
0S)OSBF
0S)OSCF
0S)OSKF
0S)OSUF
0S)OVF
0S)OV&F
0S)OV)F
0S)OV;F
0S)OVBF
0S)OVCF
0S)OVKF
0S)OVOF
0S)OVUF
0S)U(EF
0S)UE(F
0S)UE1F
0S)UEFF
0S)UEKF
0S)UENF
0S)UESF
0S)UEVF
0S,(1)F
0S,(1OF
0S,(E(F
0S,(E1F
0S,(EFF
0S,(EKF
0S,(ENF
0S,(ESF
0S,(EVF
0S,(F(F
0S,(N)F
0S,(NOF
0S,(S)F
0S,(SOF
0S,(V)F
0S,(VOF
0S,F()F
0S,F(1F
0S,F(FF
0S,F(NF
0S,F(SF
0S,F(VF
0S1F()F
0S1F(1F
0S1F(FF
0S1F(NF
0S1F(SF
0S1F(VF
0S1NCF
0S1S;F
0S1S;CF
0S1SCF
0S1UEF
0S1UE;F
0S1UECF
0S1UEKF
0S1VF
0S1V;F
0S1V;CF
0S1VCF
0S1VO(F
0S1VOFF
0S1VOSF
0S;E(1F
0S;E(EF
0S;E(FF
0S;E(NF
0S;E(SF
0S;E(VF
0S;E1,F
0S;E1;F
0S;E1CF
0S;E1KF
0S;E1OF
0S;E1TF
0S;EF(F
0S;EK(F
0S;EK1F
0S;EKFF
0S;EKNF
0S;EKOF
0S;EKSF
0S;EKVF
0S;EN,F
0S;EN;F
0S;ENCF
0S;ENEF
0S;ENKF
0S;ENOF
0S;ENTF
0S;ES,F
0S;ES;F
0S;ESCF
0S;ESKF
0S;ESOF
0S;ESTF
0S;EV,F
0S;EV;F
0S;EVCF
0S;EVKF
0S;EVOF
0S;EVTF
0S;N:TF
0S;T(1F
0S;T(CF
0S;T(EF
0S;T(FF
0S;T(NF
0S;T(SF
0S;T(VF
0S;T1(F
0S;T1,F
0S;T1;F
0S;T1CF
0S;T1FF
0S;T1KF
0S;T1OF
0S;T1TF
0S;T;F
0S;T;CF
0S;TF(F
0S;TK(F
0S;TK1F
0S;TKFF
0S;TKKF
0S;TKNF
0S;TKOF
0S;TKSF
0S;TKVF
0S;TN(F
0S;TN,F
0S;TN1F
0S;TN;F
0S;TNCF
0S;TNEF
0S;TNFF
0S;TNKF
0S;TNNF
0S;TNOF
0S;TNSF
0S;TNTF
0S;TNVF
0S;TO(F
0S;TS(F
0S;TS,F
0S;TS;F
0S;TSCF
0S;TSFF
0S;TSKF
0S;TSOF
0S;TSTF
0S;TTNF
0S;TV(F
0S;TV,F
0S;TV;F
0S;TVCF
0S;TVFF
0S;TVKF
0S;TVOF
0S;TVTF
0SA(F(F
0SA(N)F
0SA(NOF
0SA(S)F
0SA(SOF
0SA(V)F
0SA(VOF
0SAF()F
0SAF(1F
0SAF(FF
0SAF(NF
0SAF(SF
0SAF(VF
0SASO(F
0SASO1F
0SASOFF
0SASONF
0SASOSF
0SASOVF
0SASUEF
0SATO(F
0SATO1F
0SATOFF
0SATONF
0SATOSF
0SATOVF
0SATUEF
0SAVO(F
0SAVOFF
0SAVOSF
0SAVUEF
0SB(1)F
0SB(1OF
0SB(F(F
0SB(NOF
0SB(S)F
0SB(SOF
0SB(V)F
0SB(VOF
0SB1F
0SB1&(F
0SB1&1F
0SB1&FF
0SB1&NF
0SB1&SF
0SB1&VF
0SB1,(F
0SB1,FF
0SB1;F
0SB1;CF
0SB1B(F
0SB1B1F
0SB1BFF
0SB1BNF
0SB1BSF
0SB1BVF
0SB1CF
0SB1K(F
0SB1K1F
0SB1KFF
0SB1KNF
0SB1KSF
0SB1KVF
0SB1O(F
0SB1OFF
0SB1OSF
0SB1OVF
0SB1U(F
0SB1UEF
0SBE(1F
0SBE(FF
0SBE(NF
0SBE(SF
0SBE(VF
0SBEK(F
0SBF()F
0SBF(1F
0SBF(FF
0SBF(NF
0SBF(SF
0SBF(VF
0SBNF
0SBN&(F
0SBN&1F
0SBN&FF
0SBN&NF
0SBN&SF
0SBN&VF
0SBN,(F
0SBN,FF
0SBN;F
0SBN;CF
0SBNB(F
0SBNB1F
0SBNBFF
0SBNBNF
0SBNBSF
0SBNBVF
0SBNCF
0SBNK(F
0SBNK1F
0SBNKFF
0SBNKNF
0SBNKSF
0SBNKVF
0SBNO(F
0SBNOFF
0SBNOSF
0SBNOVF
0SBNU(F
0SBNUEF
0SBSF
0SBS&(F
0SBS&1F
0SBS&FF
0SBS&NF
0SBS&SF
0SBS&VF
0SBS,(F
0SBS,FF
0SBS;F
0SBS;CF
0SBSB(F
0SBSB1F
0SBSBFF
0SBSBNF
0SBSBSF
0SBSBVF
0SBSCF
0SBSK(F
0SBSK1F
0SBSKFF
0SBSKNF
0SBSKSF
0SBSKVF
0SBSO(F
0SBSO1F
0SBSOFF
0SBSONF
0SBSOSF
0SBSOVF
0SBSU(F
0SBSUEF
0SBVF
0SBV&(F
0SBV&1F
0SBV&FF
0SBV&NF
0SBV&SF
0SBV&VF
0SBV,(F
0SBV,FF
0SBV;F
0SBV;CF
0SBVB(F
0SBVB1F
0SBVBFF
0SBVBNF
0SBVBSF
0SBVBVF
0SBVCF
0SBVK(F
0SBVK1F
0SBVKFF
0SBVKNF
0SBVKSF
0SBVKVF
0SBVO(F
0SBVOFF
0SBVOSF
0SBVU(F
0SBVUEF
0SCF
0SE(1)F
0SE(1OF
0SE(F(F
0SE(N)F
0SE(NOF
0SE(S)F
0SE(SOF
0SE(V)F
0SE(VOF
0SE1;TF
0SE1CF
0SE1O(F
0SE1OFF
0SE1OSF
0SE1OVF
0SE1T(F
0SE1T1F
0SE1TFF
0SE1TNF
0SE1TSF
0SE1TVF
0SE1UEF
0SEF()F
0SEF(1F
0SEF(FF
0SEF(NF
0SEF(SF
0SEF(VF
0SEK(1F
0SEK(EF
0SEK(FF
0SEK(NF
0SEK(SF
0SEK(VF
0SEK1;F
0SEK1CF
0SEK1OF
0SEK1TF
0SEK1UF
0SEKF(F
0SEKN;F
0SEKNCF
0SEKNEF
0SEKNTF
0SEKNUF
0SEKOKF
0SEKS;F
0SEKSCF
0SEKSOF
0SEKSTF
0SEKSUF
0SEKU(F
0SEKU1F
0SEKUEF
0SEKUFF
0SEKUSF
0SEKUVF
0SEKV;F
0SEKVCF
0SEKVOF
0SEKVTF
0SEKVUF
0SEN;TF
0SENCF
0SENENF
0SENO(F
0SENOFF
0SENOSF
0SENOVF
0SENT(F
0SENT1F
0SENTFF
0SENTNF
0SENTSF
0SENTVF
0SENUEF
0SEOKNF
0SES;TF
0SESCF
0SESO(F
0SESO1F
0SESOFF
0SESONF
0SESOSF
0SESOVF
0SEST(F
0SEST1F
0SESTFF
0SESTNF
0SESTSF
0SESTVF
0SESUEF
0SEU(1F
0SEU(FF
0SEU(NF
0SEU(SF
0SEU(VF
0SEU1,F
0SEU1CF
0SEU1OF
0SEUEFF
0SEUEKF
0SEUF(F
0SEUS,F
0SEUSCF
0SEUSOF
0SEUV,F
0SEUVCF
0SEUVOF
0SEV;TF
0SEVCF
0SEVO(F
0SEVOFF
0SEVOSF
0SEVT(F
0SEVT1F
0SEVTFF
0SEVTNF
0SEVTSF
0SEVTVF
0SEVUEF
0SF()1F
0SF()FF
0SF()KF
0SF()NF
0SF()OF
0SF()SF
0SF()UF
0SF()VF
0SF(1)F
0SF(1NF
0SF(1OF
0SF(E(F
0SF(E1F
0SF(EFF
0SF(EKF
0SF(ENF
0SF(ESF
0SF(EVF
0SF(F(F
0SF(N)F
0SF(N,F
0SF(NOF
0SF(S)F
0SF(SOF
0SF(V)F
0SF(VOF
0SK(1)F
0SK(1OF
0SK(F(F
0SK(N)F
0SK(NOF
0SK(S)F
0SK(SOF
0SK(V)F
0SK(VOF
0SK)&(F
0SK)&1F
0SK)&FF
0SK)&NF
0SK)&SF
0SK)&VF
0SK);EF
0SK);TF
0SK)B(F
0SK)B1F
0SK)BFF
0SK)BNF
0SK)BSF
0SK)BVF
0SK)E(F
0SK)E1F
0SK)EFF
0SK)EKF
0SK)ENF
0SK)ESF
0SK)EVF
0SK)F(F
0SK)O(F
0SK)OFF
0SK)UEF
0SK1F
0SK1&(F
0SK1&1F
0SK1&FF
0SK1&NF
0SK1&SF
0SK1&VF
0SK1;F
0SK1;CF
0SK1;EF
0SK1;TF
0SK1B(F
0SK1B1F
0SK1BFF
0SK1BNF
0SK1BSF
0SK1BVF
0SK1CF
0SK1E(F
0SK1E1F
0SK1EFF
0SK1EKF
0SK1ENF
0SK1ESF
0SK1EVF
0SK1O(F
0SK1OFF
0SK1OSF
0SK1OVF
0SK1U(F
0SK1UEF
0SKF()F
0SKF(1F
0SKF(FF
0SKF(NF
0SKF(SF
0SKF(VF
0SKNF
0SKN&(F
0SKN&1F
0SKN&FF
0SKN&NF
0SKN&SF
0SKN&VF
0SKN;F
0SKN;CF
0SKN;EF
0SKN;TF
0SKNB(F
0SKNB1F
0SKNBFF
0SKNBNF
0SKNBSF
0SKNBVF
0SKNCF
0SKNE(F
0SKNE1F
0SKNEFF
0SKNENF
0SKNESF
0SKNEVF
0SKNU(F
0SKNUEF
0SKSF
0SKS&(F
0SKS&1F
0SKS&FF
0SKS&NF
0SKS&SF
0SKS&VF
0SKS;F
0SKS;CF
0SKS;EF
0SKS;TF
0SKSB(F
0SKSB1F
0SKSBFF
0SKSBNF
0SKSBSF
0SKSBVF
0SKSCF
0SKSE(F
0SKSE1F
0SKSEFF
0SKSEKF
0SKSENF
0SKSESF
0SKSEVF
0SKSO(F
0SKSO1F
0SKSOFF
0SKSONF
0SKSOSF
0SKSOVF
0SKSU(F
0SKSUEF
0SKUE(F
0SKUE1F
0SKUEFF
0SKUEKF
0SKUENF
0SKUESF
0SKUEVF
0SKVF
0SKV&(F
0SKV&1F
0SKV&FF
0SKV&NF
0SKV&SF
0SKV&VF
0SKV;F
0SKV;CF
0SKV;EF
0SKV;TF
0SKVB(F
0SKVB1F
0SKVBFF
0SKVBNF
0SKVBSF
0SKVBVF
0SKVCF
0SKVE(F
0SKVE1F
0SKVEFF
0SKVEKF
0SKVENF
0SKVESF
0SKVEVF
0SKVO(F
0SKVOFF
0SKVOSF
0SKVU(F
0SKVUEF
0SO(1&F
0SO(1)F
0SO(1,F
0SO(1OF
0SO(E(F
0SO(E1F
0SO(EEF
0SO(EFF
0SO(EKF
0SO(ENF
0SO(EOF
0SO(ESF
0SO(EVF
0SO(F(F
0SO(N&F
0SO(N)F
0SO(N,F
0SO(NOF
0SO(S&F
0SO(S)F
0SO(S,F
0SO(SOF
0SO(V&F
0SO(V)F
0SO(V,F
0SO(VOF
0SO1&(F
0SO1&1F
0SO1&EF
0SO1&FF
0SO1&KF
0SO1&NF
0SO1&SF
0SO1&UF
0SO1&VF
0SO1(EF
0SO1(UF
0SO1)&F
0SO1),F
0SO1);F
0SO1)BF
0SO1)CF
0SO1)EF
0SO1)FF
0SO1)KF
0SO1)OF
0SO1)UF
0SO1,(F
0SO1,FF
0SO1;F
0SO1;CF
0SO1;EF
0SO1;NF
0SO1;TF
0SO1A(F
0SO1AFF
0SO1ASF
0SO1ATF
0SO1AVF
0SO1B(F
0SO1B1F
0SO1BEF
0SO1BFF
0SO1BNF
0SO1BSF
0SO1BVF
0SO1CF
0SO1E(F
0SO1E1F
0SO1EFF
0SO1EKF
0SO1ENF
0SO1EOF
0SO1ESF
0SO1EUF
0SO1EVF
0SO1F(F
0SO1K(F
0SO1K)F
0SO1K1F
0SO1KBF
0SO1KFF
0SO1KNF
0SO1KSF
0SO1KUF
0SO1KVF
0SO1N&F
0SO1N(F
0SO1N,F
0SO1NEF
0SO1NUF
0SO1SUF
0SO1SVF
0SO1T(F
0SO1T1F
0SO1TEF
0SO1TFF
0SO1TNF
0SO1TSF
0SO1TTF
0SO1TVF
0SO1UF
0SO1U(F
0SO1U1F
0SO1U;F
0SO1UCF
0SO1UEF
0SO1UFF
0SO1UKF
0SO1UOF
0SO1USF
0SO1UTF
0SO1UVF
0SO1V(F
0SO1VFF
0SO1VOF
0SO1VSF
0SO1VUF
0SOF()F
0SOF(1F
0SOF(EF
0SOF(FF
0SOF(NF
0SOF(SF
0SOF(VF
0SOK&(F
0SOK&1F
0SOK&FF
0SOK&NF
0SOK&SF
0SOK&VF
0SOK(1F
0SOK(FF
0SOK(NF
0SOK(SF
0SOK(VF
0SOK1CF
0SOK1OF
0SOKF(F
0SOKNCF
0SOKO(F
0SOKO1F
0SOKOFF
0SOKONF
0SOKOSF
0SOKOVF
0SOKSCF
0SOKSOF
0SOKVCF
0SOKVOF
0SON&(F
0SON&1F
0SON&EF
0SON&FF
0SON&KF
0SON&NF
0SON&SF
0SON&UF
0SON&VF
0SON(1F
0SON(EF
0SON(FF
0SON(SF
0SON(UF
0SON(VF
0SON)&F
0SON),F
0SON);F
0SON)BF
0SON)CF
0SON)EF
0SON)FF
0SON)KF
0SON)OF
0SON)UF
0SON,(F
0SON,FF
0SON1(F
0SON1OF
0SON1UF
0SON1VF
0SON;F
0SON;CF
0SON;EF
0SON;NF
0SON;TF
0SONA(F
0SONAFF
0SONASF
0SONATF
0SONAVF
0SONB(F
0SONB1F
0SONBEF
0SONBFF
0SONBNF
0SONBSF
0SONBVF
0SONE(F
0SONE1F
0SONEFF
0SONENF
0SONEOF
0SONESF
0SONEUF
0SONEVF
0SONF(F
0SONK(F
0SONK)F
0SONK1F
0SONKBF
0SONKFF
0SONKSF
0SONKUF
0SONKVF
0SONSUF
0SONT(F
0SONT1F
0SONTEF
0SONTFF
0SONTNF
0SONTSF
0SONTTF
0SONTVF
0SONUF
0SONU(F
0SONU1F
0SONU;F
0SONUCF
0SONUEF
0SONUFF
0SONUKF
0SONUOF
0SONUSF
0SONUTF
0SONUVF
0SOSF
0SOS&(F
0SOS&1F
0SOS&EF
0SOS&FF
0SOS&KF
0SOS&NF
0SOS&SF
0SOS&UF
0SOS&VF
0SOS(EF
0SOS(UF
0SOS)&F
0SOS),F
0SOS);F
0SOS)BF
0SOS)CF
0SOS)EF
0SOS)FF
0SOS)KF
0SOS)OF
0SOS)UF
0SOS,(F
0SOS,FF
0SOS1(F
0SOS1FF
0SOS1NF
0SOS1SF
0SOS1UF
0SOS1VF
0SOS;F
0SOS;CF
0SOS;EF
0SOS;NF
0SOS;TF
0SOSA(F
0SOSAFF
0SOSASF
0SOSATF
0SOSAVF
0SOSB(F
0SOSB1F
0SOSBEF
0SOSBFF
0SOSBNF
0SOSBSF
0SOSBVF
0SOSCF
0SOSE(F
0SOSE1F
0SOSEFF
0SOSEKF
0SOSENF
0SOSEOF
0SOSESF
0SOSEUF
0SOSEVF
0SOSF(F
0SOSK(F
0SOSK)F
0SOSK1F
0SOSKBF
0SOSKFF
0SOSKNF
0SOSKSF
0SOSKUF
0SOSKVF
0SOST(F
0SOST1F
0SOSTEF
0SOSTFF
0SOSTNF
0SOSTSF
0SOSTTF
0SOSTVF
0SOSUF
0SOSU(F
0SOSU1F
0SOSU;F
0SOSUCF
0SOSUEF
0SOSUFF
0SOSUKF
0SOSUOF
0SOSUSF
0SOSUTF
0SOSUVF
0SOSV(F
0SOSVFF
0SOSVOF
0SOSVSF
0SOSVUF
0SOU(EF
0SOUEKF
0SOUENF
0SOVF
0SOV&(F
0SOV&1F
0SOV&EF
0SOV&FF
0SOV&KF
0SOV&NF
0SOV&SF
0SOV&UF
0SOV&VF
0SOV(EF
0SOV(UF
0SOV)&F
0SOV),F
0SOV);F
0SOV)BF
0SOV)CF
0SOV)EF
0SOV)FF
0SOV)KF
0SOV)OF
0SOV)UF
0SOV,(F
0SOV,FF
0SOV;F
0SOV;CF
0SOV;EF
0SOV;NF
0SOV;TF
0SOVA(F
0SOVAFF
0SOVASF
0SOVATF
0SOVAVF
0SOVB(F
0SOVB1F
0SOVBEF
0SOVBFF
0SOVBNF
0SOVBSF
0SOVBVF
0SOVCF
0SOVE(F
0SOVE1F
0SOVEFF
0SOVEKF
0SOVENF
0SOVEOF
0SOVESF
0SOVEUF
0SOVEVF
0SOVF(F
0SOVK(F
0SOVK)F
0SOVK1F
0SOVKBF
0SOVKFF
0SOVKNF
0SOVKSF
0SOVKUF
0SOVKVF
0SOVO(F
0SOVOFF
0SOVOKF
0SOVOSF
0SOVOUF
0SOVS(F
0SOVS1F
0SOVSFF
0SOVSOF
0SOVSUF
0SOVSVF
0SOVT(F
0SOVT1F
0SOVTEF
0SOVTFF
0SOVTNF
0SOVTSF
0SOVTTF
0SOVTVF
0SOVUF
0SOVU(F
0SOVU1F
0SOVU;F
0SOVUCF
0SOVUEF
0SOVUFF
0SOVUKF
0SOVUOF
0SOVUSF
0SOVUTF
0SOVUVF
0ST(1)F
0ST(1OF
0ST(F(F
0ST(N)F
0ST(NOF
0ST(S)F
0ST(SOF
0ST(V)F
0ST(VOF
0ST1(FF
0ST1O(F
0ST1OFF
0ST1OSF
0ST1OVF
0STE(1F
0STE(FF
0STE(NF
0STE(SF
0STE(VF
0STE1NF
0STE1OF
0STEF(F
0STEK(F
0STEK1F
0STEKFF
0STEKNF
0STEKSF
0STEKVF
0STENNF
0STENOF
0STESNF
0STESOF
0STEVNF
0STEVOF
0STF()F
0STF(1F
0STF(FF
0STF(NF
0STF(SF
0STF(VF
0STN(1F
0STN(FF
0STN(SF
0STN(VF
0STN1CF
0STN1OF
0STN;EF
0STN;NF
0STN;TF
0STNE(F
0STNE1F
0STNEFF
0STNENF
0STNESF
0STNEVF
0STNF(F
0STNKNF
0STNN:F
0STNNCF
0STNNOF
0STNO(F
0STNOFF
0STNOSF
0STNOVF
0STNSCF
0STNSOF
0STNT(F
0STNT1F
0STNTFF
0STNTNF
0STNTSF
0STNTVF
0STNVCF
0STNVOF
0STS(FF
0STSO(F
0STSO1F
0STSOFF
0STSONF
0STSOSF
0STSOVF
0STTNEF
0STTNKF
0STTNNF
0STTNTF
0STV(1F
0STV(FF
0STVO(F
0STVOFF
0STVOSF
0SU(1)F
0SU(1OF
0SU(E(F
0SU(E1F
0SU(EFF
0SU(EKF
0SU(ENF
0SU(ESF
0SU(EVF
0SU(F(F
0SU(N)F
0SU(NOF
0SU(S)F
0SU(SOF
0SU(V)F
0SU(VOF
0SU1,(F
0SU1,FF
0SU1CF
0SU1O(F
0SU1OFF
0SU1OSF
0SU1OVF
0SU;F
0SU;CF
0SUCF
0SUEF
0SUE(1F
0SUE(EF
0SUE(FF
0SUE(NF
0SUE(OF
0SUE(SF
0SUE(VF
0SUE1F
0SUE1&F
0SUE1(F
0SUE1)F
0SUE1,F
0SUE1;F
0SUE1BF
0SUE1CF
0SUE1FF
0SUE1KF
0SUE1NF
0SUE1OF
0SUE1SF
0SUE1UF
0SUE1VF
0SUE;F
0SUE;CF
0SUECF
0SUEFF
0SUEF(F
0SUEF,F
0SUEF;F
0SUEFCF
0SUEKF
0SUEK(F
0SUEK1F
0SUEK;F
0SUEKCF
0SUEKFF
0SUEKNF
0SUEKOF
0SUEKSF
0SUEKVF
0SUENF
0SUEN&F
0SUEN(F
0SUEN)F
0SUEN,F
0SUEN1F
0SUEN;F
0SUENBF
0SUENCF
0SUENFF
0SUENKF
0SUENOF
0SUENSF
0SUENUF
0SUEOKF
0SUEONF
0SUESF
0SUES&F
0SUES(F
0SUES)F
0SUES,F
0SUES1F
0SUES;F
0SUESBF
0SUESCF
0SUESFF
0SUESKF
0SUESOF
0SUESUF
0SUESVF
0SUEVF
0SUEV&F
0SUEV(F
0SUEV)F
0SUEV,F
0SUEV;F
0SUEVBF
0SUEVCF
0SUEVFF
0SUEVKF
0SUEVNF
0SUEVOF
0SUEVSF
0SUEVUF
0SUF()F
0SUF(1F
0SUF(FF
0SUF(NF
0SUF(SF
0SUF(VF
0SUK(EF
0SUO(EF
0SUON(F
0SUON1F
0SUONFF
0SUONSF
0SUS,(F
0SUS,FF
0SUSCF
0SUSO(F
0SUSO1F
0SUSOFF
0SUSONF
0SUSOSF
0SUSOVF
0SUTN(F
0SUTN1F
0SUTNFF
0SUTNNF
0SUTNSF
0SUTNVF
0SUV,(F
0SUV,FF
0SUVCF
0SUVO(F
0SUVOFF
0SUVOSF
0SVF()F
0SVF(1F
0SVF(FF
0SVF(NF
0SVF(SF
0SVF(VF
0SVO(1F
0SVO(FF
0SVO(NF
0SVO(SF
0SVO(VF
0SVOF(F
0SVOS(F
0SVOS1F
0SVOSFF
0SVOSUF
0SVOSVF
0SVS;F
0SVS;CF
0SVSCF
0SVSO(F
0SVSO1F
0SVSOFF
0SVSONF
0SVSOSF
0SVSOVF
0SVUEF
0SVUE;F
0SVUECF
0SVUEKF
0T(1)FF
0T(1)OF
0T(1F(F
0T(1N)F
0T(1O(F
0T(1OFF
0T(1OSF
0T(1OVF
0T(1S)F
0T(1V)F
0T(1VOF
0T(F()F
0T(F(1F
0T(F(FF
0T(F(NF
0T(F(SF
0T(F(VF
0T(N(1F
0T(N(FF
0T(N(SF
0T(N(VF
0T(N)FF
0T(N)OF
0T(N1)F
0T(N1OF
0T(NF(F
0T(NN)F
0T(NNOF
0T(NO(F
0T(NOFF
0T(NOSF
0T(NOVF
0T(NS)F
0T(NSOF
0T(NV)F
0T(NVOF
0T(S)FF
0T(S)OF
0T(S1)F
0T(SF(F
0T(SN)F
0T(SNOF
0T(SO(F
0T(SO1F
0T(SOFF
0T(SONF
0T(SOSF
0T(SOVF
0T(SV)F
0T(SVOF
0T(V)FF
0T(V)OF
0T(VF(F
0T(VO(F
0T(VOFF
0T(VOSF
0T(VS)F
0T(VSOF
0T(VV)F
0T1F(1F
0T1F(FF
0T1F(NF
0T1F(SF
0T1F(VF
0T1O(1F
0T1O(FF
0T1O(NF
0T1O(SF
0T1O(VF
0T1OF(F
0T1OSFF
0T1OVFF
0T1OVOF
0TF()FF
0TF()OF
0TF(1)F
0TF(1OF
0TF(F(F
0TF(N)F
0TF(NOF
0TF(S)F
0TF(SOF
0TF(V)F
0TF(VOF
0TN(1)F
0TN(1OF
0TN(F(F
0TN(S)F
0TN(SOF
0TN(V)F
0TN(VOF
0TN1;F
0TN1;CF
0TN1O(F
0TN1OFF
0TN1OSF
0TN1OVF
0TNF()F
0TNF(1F
0TNF(FF
0TNF(NF
0TNF(SF
0TNF(VF
0TNN;F
0TNN;CF
0TNNO(F
0TNNOFF
0TNNOSF
0TNNOVF
0TNO(1F
0TNO(FF
0TNO(NF
0TNO(SF
0TNO(VF
0TNOF(F
0TNOSFF
0TNOVFF
0TNOVOF
0TNS;F
0TNS;CF
0TNSO(F
0TNSO1F
0TNSOFF
0TNSONF
0TNSOSF
0TNSOVF
0TNV;F
0TNV;CF
0TNVO(F
0TNVOFF
0TNVOSF
0TSF(1F
0TSF(FF
0TSF(NF
0TSF(SF
0TSF(VF
0TSO(1F
0TSO(FF
0TSO(NF
0TSO(SF
0TSO(VF
0TSO1FF
0TSOF(F
0TSONFF
0TSOSFF
0TSOVFF
0TSOVOF
0TVF(1F
0TVF(FF
0TVF(NF
0TVF(SF
0TVF(VF
0TVO(1F
0TVO(FF
0TVO(NF
0TVO(SF
0TVO(VF
0TVOF(F
0TVOSFF
0U(E(1F
0U(E(FF
0U(E(KF
0U(E(NF
0U(E(SF
0U(E(VF
0U(E1)F
0U(E1OF
0U(EF(F
0U(EK(F
0U(EK1F
0U(EKFF
0U(EKNF
0U(EKOF
0U(EKSF
0U(EKVF
0U(EN)F
0U(ENKF
0U(ENOF
0U(EOKF
0U(ES)F
0U(ESOF
0U(EV)F
0U(EVOF
0UE(1)F
0UE(1,F
0UE(1OF
0UE(F(F
0UE(N)F
0UE(N,F
0UE(NOF
0UE(S)F
0UE(S,F
0UE(SOF
0UE(V)F
0UE(V,F
0UE(VOF
0UE1F
0UE1,(F
0UE1,FF
0UE1;F
0UE1;CF
0UE1CF
0UE1K(F
0UE1K1F
0UE1KFF
0UE1KNF
0UE1KSF
0UE1KVF
0UE1O(F
0UE1OFF
0UE1OSF
0UE1OVF
0UEF()F
0UEF(1F
0UEF(FF
0UEF(NF
0UEF(SF
0UEF(VF
0UEK(1F
0UEK(FF
0UEK(NF
0UEK(SF
0UEK(VF
0UEK1F
0UEK1,F
0UEK1;F
0UEK1CF
0UEK1KF
0UEK1OF
0UEKF(F
0UEKNF
0UEKN(F
0UEKN,F
0UEKN;F
0UEKNCF
0UEKNKF
0UEKSF
0UEKS,F
0UEKS;F
0UEKSCF
0UEKSKF
0UEKSOF
0UEKVF
0UEKV,F
0UEKV;F
0UEKVCF
0UEKVKF
0UEKVOF
0UEN()F
0UEN,(F
0UEN,FF
0UEN;F
0UEN;CF
0UENCF
0UENK(F
0UENK1F
0UENKFF
0UENKNF
0UENKSF
0UENKVF
0UENO(F
0UENOFF
0UENOSF
0UENOVF
0UESF
0UES,(F
0UES,FF
0UES;F
0UES;CF
0UESCF
0UESK(F
0UESK1F
0UESKFF
0UESKNF
0UESKSF
0UESKVF
0UESO(F
0UESO1F
0UESOFF
0UESONF
0UESOSF
0UESOVF
0UEVF
0UEV,(F
0UEV,FF
0UEV;F
0UEV;CF
0UEVCF
0UEVK(F
0UEVK1F
0UEVKFF
0UEVKNF
0UEVKSF
0UEVKVF
0UEVO(F
0UEVOFF
0UEVOSF
0UF(1OF
0UF(F(F
0UF(NOF
0UF(SOF
0UF(VOF
0V&(1&F
0V&(1)F
0V&(1,F
0V&(1OF
0V&(E(F
0V&(E1F
0V&(EFF
0V&(EKF
0V&(ENF
0V&(EOF
0V&(ESF
0V&(EVF
0V&(F(F
0V&(N&F
0V&(N)F
0V&(N,F
0V&(NOF
0V&(S&F
0V&(S)F
0V&(S,F
0V&(SOF
0V&(V&F
0V&(V)F
0V&(V,F
0V&(VOF
0V&1F
0V&1&(F
0V&1&1F
0V&1&FF
0V&1&NF
0V&1&SF
0V&1&VF
0V&1)&F
0V&1)CF
0V&1)OF
0V&1)UF
0V&1;F
0V&1;CF
0V&1;EF
0V&1;TF
0V&1B(F
0V&1B1F
0V&1BFF
0V&1BNF
0V&1BSF
0V&1BVF
0V&1CF
0V&1EKF
0V&1ENF
0V&1F(F
0V&1K(F
0V&1K1F
0V&1KFF
0V&1KNF
0V&1KSF
0V&1KVF
0V&1O(F
0V&1OFF
0V&1OSF
0V&1OVF
0V&1TNF
0V&1UF
0V&1U(F
0V&1U;F
0V&1UCF
0V&1UEF
0V&E(1F
0V&E(FF
0V&E(NF
0V&E(OF
0V&E(SF
0V&E(VF
0V&E1F
0V&E1;F
0V&E1CF
0V&E1KF
0V&E1OF
0V&EF(F
0V&EK(F
0V&EK1F
0V&EKFF
0V&EKNF
0V&EKSF
0V&EKVF
0V&ENF
0V&EN;F
0V&ENCF
0V&ENKF
0V&ENOF
0V&ESF
0V&ES;F
0V&ESCF
0V&ESKF
0V&ESOF
0V&EVF
0V&EV;F
0V&EVCF
0V&EVKF
0V&EVOF
0V&F()F
0V&F(1F
0V&F(EF
0V&F(FF
0V&F(NF
0V&F(SF
0V&F(VF
0V&K&(F
0V&K&1F
0V&K&FF
0V&K&NF
0V&K&SF
0V&K&VF
0V&K(1F
0V&K(FF
0V&K(NF
0V&K(SF
0V&K(VF
0V&K1OF
0V&KCF
0V&KF(F
0V&KNKF
0V&KO(F
0V&KO1F
0V&KOFF
0V&KOKF
0V&KONF
0V&KOSF
0V&KOVF
0V&KSOF
0V&KVOF
0V&NF
0V&N&(F
0V&N&1F
0V&N&FF
0V&N&NF
0V&N&SF
0V&N&VF
0V&N)&F
0V&N)CF
0V&N)OF
0V&N)UF
0V&N;F
0V&N;CF
0V&N;EF
0V&N;TF
0V&NB(F
0V&NB1F
0V&NBFF
0V&NBNF
0V&NBSF
0V&NBVF
0V&NCF
0V&NENF
0V&NF(F
0V&NK(F
0V&NK1F
0V&NKFF
0V&NKNF
0V&NKSF
0V&NKVF
0V&NO(F
0V&NOFF
0V&NOSF
0V&NOVF
0V&NTNF
0V&NUF
0V&NU(F
0V&NU;F
0V&NUCF
0V&NUEF
0V&SF
0V&S&(F
0V&S&1F
0V&S&FF
0V&S&NF
0V&S&SF
0V&S&VF
0V&S)&F
0V&S)CF
0V&S)OF
0V&S)UF
0V&S1F
0V&S1;F
0V&S1CF
0V&S;F
0V&S;CF
0V&S;EF
0V&S;TF
0V&SB(F
0V&SB1F
0V&SBFF
0V&SBNF
0V&SBSF
0V&SBVF
0V&SCF
0V&SEKF
0V&SENF
0V&SF(F
0V&SK(F
0V&SK1F
0V&SKFF
0V&SKNF
0V&SKSF
0V&SKVF
0V&SO(F
0V&SO1F
0V&SOFF
0V&SONF
0V&SOSF
0V&SOVF
0V&STNF
0V&SUF
0V&SU(F
0V&SU;F
0V&SUCF
0V&SUEF
0V&SVF
0V&SV;F
0V&SVCF
0V&SVOF
0V&VF
0V&V&(F
0V&V&1F
0V&V&FF
0V&V&NF
0V&V&SF
0V&V&VF
0V&V)&F
0V&V)CF
0V&V)OF
0V&V)UF
0V&V;F
0V&V;CF
0V&V;EF
0V&V;TF
0V&VB(F
0V&VB1F
0V&VBFF
0V&VBNF
0V&VBSF
0V&VBVF
0V&VCF
0V&VEKF
0V&VENF
0V&VF(F
0V&VK(F
0V&VK1F
0V&VKFF
0V&VKNF
0V&VKSF
0V&VKVF
0V&VO(F
0V&VOFF
0V&VOSF
0V&VSF
0V&VS;F
0V&VSCF
0V&VSOF
0V&VTNF
0V&VUF
0V&VU(F
0V&VU;F
0V&VUCF
0V&VUEF
0V(EF(F
0V(EKFF
0V(EKNF
0V(ENKF
0V(U(EF
0V)&(1F
0V)&(EF
0V)&(FF
0V)&(NF
0V)&(SF
0V)&(VF
0V)&1F
0V)&1&F
0V)&1)F
0V)&1;F
0V)&1BF
0V)&1CF
0V)&1FF
0V)&1OF
0V)&1UF
0V)&F(F
0V)&NF
0V)&N&F
0V)&N)F
0V)&N;F
0V)&NBF
0V)&NCF
0V)&NFF
0V)&NOF
0V)&NUF
0V)&SF
0V)&S&F
0V)&S)F
0V)&S;F
0V)&SBF
0V)&SCF
0V)&SFF
0V)&SOF
0V)&SUF
0V)&VF
0V)&V&F
0V)&V)F
0V)&V;F
0V)&VBF
0V)&VCF
0V)&VFF
0V)&VOF
0V)&VUF
0V),(1F
0V),(FF
0V),(NF
0V),(SF
0V),(VF
0V);E(F
0V);E1F
0V);EFF
0V);EKF
0V);ENF
0V);EOF
0V);ESF
0V);EVF
0V);T(F
0V);T1F
0V);TFF
0V);TKF
0V);TNF
0V);TOF
0V);TSF
0V);TVF
0V)B(1F
0V)B(FF
0V)B(NF
0V)B(SF
0V)B(VF
0V)B1F
0V)B1&F
0V)B1;F
0V)B1CF
0V)B1KF
0V)B1NF
0V)B1OF
0V)B1UF
0V)BF(F
0V)BNF
0V)BN&F
0V)BN;F
0V)BNCF
0V)BNKF
0V)BNOF
0V)BNUF
0V)BSF
0V)BS&F
0V)BS;F
0V)BSCF
0V)BSKF
0V)BSOF
0V)BSUF
0V)BVF
0V)BV&F
0V)BV;F
0V)BVCF
0V)BVKF
0V)BVOF
0V)BVUF
0V)CF
0V)E(1F
0V)E(FF
0V)E(NF
0V)E(SF
0V)E(VF
0V)E1CF
0V)E1OF
0V)EF(F
0V)EK(F
0V)EK1F
0V)EKFF
0V)EKNF
0V)EKSF
0V)EKVF
0V)ENCF
0V)ENOF
0V)ESCF
0V)ESOF
0V)EVCF
0V)EVOF
0V)F(FF
0V)K(1F
0V)K(FF
0V)K(NF
0V)K(SF
0V)K(VF
0V)K1&F
0V)K1;F
0V)K1BF
0V)K1EF
0V)K1OF
0V)K1UF
0V)KB(F
0V)KB1F
0V)KBFF
0V)KBNF
0V)KBSF
0V)KBVF
0V)KF(F
0V)KN&F
0V)KN;F
0V)KNBF
0V)KNCF
0V)KNEF
0V)KNKF
0V)KNUF
0V)KS&F
0V)KS;F
0V)KSBF
0V)KSEF
0V)KSOF
0V)KSUF
0V)KUEF
0V)KV&F
0V)KV;F
0V)KVBF
0V)KVEF
0V)KVOF
0V)KVUF
0V)O(1F
0V)O(EF
0V)O(FF
0V)O(NF
0V)O(SF
0V)O(VF
0V)O1F
0V)O1&F
0V)O1)F
0V)O1;F
0V)O1BF
0V)O1CF
0V)O1KF
0V)O1UF
0V)OF(F
0V)ONF
0V)ON&F
0V)ON)F
0V)ON;F
0V)ONBF
0V)ONCF
0V)ONKF
0V)ONUF
0V)OSF
0V)OS&F
0V)OS)F
0V)OS;F
0V)OSBF
0V)OSCF
0V)OSKF
0V)OSUF
0V)OVF
0V)OV&F
0V)OV)F
0V)OV;F
0V)OVBF
0V)OVCF
0V)OVKF
0V)OVOF
0V)OVUF
0V)U(EF
0V)UE(F
0V)UE1F
0V)UEFF
0V)UEKF
0V)UENF
0V)UESF
0V)UEVF
0V,(1)F
0V,(1OF
0V,(E(F
0V,(E1F
0V,(EFF
0V,(EKF
0V,(ENF
0V,(ESF
0V,(EVF
0V,(F(F
0V,(N)F
0V,(NOF
0V,(S)F
0V,(SOF
0V,(V)F
0V,(VOF
0V,F()F
0V,F(1F
0V,F(FF
0V,F(NF
0V,F(SF
0V,F(VF
0V;E(1F
0V;E(EF
0V;E(FF
0V;E(NF
0V;E(SF
0V;E(VF
0V;E1,F
0V;E1;F
0V;E1CF
0V;E1KF
0V;E1OF
0V;E1TF
0V;EF(F
0V;EK(F
0V;EK1F
0V;EKFF
0V;EKNF
0V;EKOF
0V;EKSF
0V;EKVF
0V;EN,F
0V;EN;F
0V;ENCF
0V;ENEF
0V;ENKF
0V;ENOF
0V;ENTF
0V;ES,F
0V;ES;F
0V;ESCF
0V;ESKF
0V;ESOF
0V;ESTF
0V;EV,F
0V;EV;F
0V;EVCF
0V;EVKF
0V;EVOF
0V;EVTF
0V;N:TF
0V;T(1F
0V;T(CF
0V;T(EF
0V;T(FF
0V;T(NF
0V;T(SF
0V;T(VF
0V;T1(F
0V;T1,F
0V;T1;F
0V;T1CF
0V;T1FF
0V;T1KF
0V;T1OF
0V;T1TF
0V;T;F
0V;T;CF
0V;TF(F
0V;TK(F
0V;TK1F
0V;TKFF
0V;TKKF
0V;TKNF
0V;TKOF
0V;TKSF
0V;TKVF
0V;TN(F
0V;TN,F
0V;TN1F
0V;TN;F
0V;TNCF
0V;TNEF
0V;TNFF
0V;TNKF
0V;TNNF
0V;TNOF
0V;TNSF
0V;TNTF
0V;TNVF
0V;TO(F
0V;TS(F
0V;TS,F
0V;TS;F
0V;TSCF
0V;TSFF
0V;TSKF
0V;TSOF
0V;TSTF
0V;TTNF
0V;TV(F
0V;TV,F
0V;TV;F
0V;TVCF
0V;TVFF
0V;TVKF
0V;TVOF
0V;TVTF
0VA(F(F
0VA(N)F
0VA(NOF
0VA(S)F
0VA(SOF
0VA(V)F
0VA(VOF
0VAF()F
0VAF(1F
0VAF(FF
0VAF(NF
0VAF(SF
0VAF(VF
0VASO(F
0VASO1F
0VASOFF
0VASONF
0VASOSF
0VASOVF
0VASUEF
0VATO(F
0VATO1F
0VATOFF
0VATONF
0VATOSF
0VATOVF
0VATUEF
0VAVO(F
0VAVOFF
0VAVOSF
0VAVUEF
0VB(1)F
0VB(1OF
0VB(F(F
0VB(NOF
0VB(S)F
0VB(SOF
0VB(V)F
0VB(VOF
0VB1F
0VB1&(F
0VB1&1F
0VB1&FF
0VB1&NF
0VB1&SF
0VB1&VF
0VB1,(F
0VB1,FF
0VB1;F
0VB1;CF
0VB1B(F
0VB1B1F
0VB1BFF
0VB1BNF
0VB1BSF
0VB1BVF
0VB1CF
0VB1K(F
0VB1K1F
0VB1KFF
0VB1KNF
0VB1KSF
0VB1KVF
0VB1O(F
0VB1OFF
0VB1OSF
0VB1OVF
0VB1U(F
0VB1UEF
0VBE(1F
0VBE(FF
0VBE(NF
0VBE(SF
0VBE(VF
0VBEK(F
0VBF()F
0VBF(1F
0VBF(FF
0VBF(NF
0VBF(SF
0VBF(VF
0VBNF
0VBN&(F
0VBN&1F
0VBN&FF
0VBN&NF
0VBN&SF
0VBN&VF
0VBN,(F
0VBN,FF
0VBN;F
0VBN;CF
0VBNB(F
0VBNB1F
0VBNBFF
0VBNBNF
0VBNBSF
0VBNBVF
0VBNCF
0VBNK(F
0VBNK1F
0VBNKFF
0VBNKNF
0VBNKSF
0VBNKVF
0VBNO(F
0VBNOFF
0VBNOSF
0VBNOVF
0VBNU(F
0VBNUEF
0VBSF
0VBS&(F
0VBS&1F
0VBS&FF
0VBS&NF
0VBS&SF
0VBS&VF
0VBS,(F
0VBS,FF
0VBS;F
0VBS;CF
0VBSB(F
0VBSB1F
0VBSBFF
0VBSBNF
0VBSBSF
0VBSBVF
0VBSCF
0VBSK(F
0VBSK1F
0VBSKFF
0VBSKNF
0VBSKSF
0VBSKVF
0VBSO(F
0VBSO1F
0VBSOFF
0VBSONF
0VBSOSF
0VBSOVF
0VBSU(F
0VBSUEF
0VBVF
0VBV&(F
0VBV&1F
0VBV&FF
0VBV&NF
0VBV&SF
0VBV&VF
0VBV,(F
0VBV,FF
0VBV;F
0VBV;CF
0VBVB(F
0VBVB1F
0VBVBFF
0VBVBNF
0VBVBSF
0VBVBVF
0VBVCF
0VBVK(F
0VBVK1F
0VBVKFF
0VBVKNF
0VBVKSF
0VBVKVF
0VBVO(F
0VBVOFF
0VBVOSF
0VBVU(F
0VBVUEF
0VCF
0VE(1)F
0VE(1OF
0VE(F(F
0VE(N)F
0VE(NOF
0VE(S)F
0VE(SOF
0VE(V)F
0VE(VOF
0VE1;TF
0VE1CF
0VE1O(F
0VE1OFF
0VE1OSF
0VE1OVF
0VE1T(F
0VE1T1F
0VE1TFF
0VE1TNF
0VE1TSF
0VE1TVF
0VE1UEF
0VEF()F
0VEF(1F
0VEF(FF
0VEF(NF
0VEF(SF
0VEF(VF
0VEK(1F
0VEK(EF
0VEK(FF
0VEK(NF
0VEK(SF
0VEK(VF
0VEK1;F
0VEK1CF
0VEK1OF
0VEK1TF
0VEK1UF
0VEKF(F
0VEKN;F
0VEKNCF
0VEKNEF
0VEKNTF
0VEKNUF
0VEKOKF
0VEKS;F
0VEKSCF
0VEKSOF
0VEKSTF
0VEKSUF
0VEKU(F
0VEKU1F
0VEKUEF
0VEKUFF
0VEKUSF
0VEKUVF
0VEKV;F
0VEKVCF
0VEKVOF
0VEKVTF
0VEKVUF
0VEN;TF
0VENCF
0VENENF
0VENO(F
0VENOFF
0VENOSF
0VENOVF
0VENT(F
0VENT1F
0VENTFF
0VENTNF
0VENTSF
0VENTVF
0VENUEF
0VEOKNF
0VES;TF
0VESCF
0VESO(F
0VESO1F
0VESOFF
0VESONF
0VESOSF
0VESOVF
0VEST(F
0VEST1F
0VESTFF
0VESTNF
0VESTSF
0VESTVF
0VESUEF
0VEU(1F
0VEU(FF
0VEU(NF
0VEU(SF
0VEU(VF
0VEU1,F
0VEU1CF
0VEU1OF
0VEUEFF
0VEUEKF
0VEUF(F
0VEUS,F
0VEUSCF
0VEUSOF
0VEUV,F
0VEUVCF
0VEUVOF
0VEV;TF
0VEVCF
0VEVO(F
0VEVOFF
0VEVOSF
0VEVT(F
0VEVT1F
0VEVTFF
0VEVTNF
0VEVTSF
0VEVTVF
0VEVUEF
0VF()1F
0VF()FF
0VF()KF
0VF()NF
0VF()OF
0VF()SF
0VF()UF
0VF()VF
0VF(1)F
0VF(1NF
0VF(1OF
0VF(E(F
0VF(E1F
0VF(EFF
0VF(EKF
0VF(ENF
0VF(ESF
0VF(EVF
0VF(F(F
0VF(N)F
0VF(N,F
0VF(NOF
0VF(S)F
0VF(SOF
0VF(V)F
0VF(VOF
0VK(1)F
0VK(1OF
0VK(F(F
0VK(N)F
0VK(NOF
0VK(S)F
0VK(SOF
0VK(V)F
0VK(VOF
0VK)&(F
0VK)&1F
0VK)&FF
0VK)&NF
0VK)&SF
0VK)&VF
0VK);EF
0VK);TF
0VK)B(F
0VK)B1F
0VK)BFF
0VK)BNF
0VK)BSF
0VK)BVF
0VK)E(F
0VK)E1F
0VK)EFF
0VK)EKF
0VK)ENF
0VK)ESF
0VK)EVF
0VK)F(F
0VK)O(F
0VK)OFF
0VK)UEF
0VK1F
0VK1&(F
0VK1&1F
0VK1&FF
0VK1&NF
0VK1&SF
0VK1&VF
0VK1;F
0VK1;CF
0VK1;EF
0VK1;TF
0VK1B(F
0VK1B1F
0VK1BFF
0VK1BNF
0VK1BSF
0VK1BVF
0VK1CF
0VK1E(F
0VK1E1F
0VK1EFF
0VK1EKF
0VK1ENF
0VK1ESF
0VK1EVF
0VK1O(F
0VK1OFF
0VK1OSF
0VK1OVF
0VK1U(F
0VK1UEF
0VKF()F
0VKF(1F
0VKF(FF
0VKF(NF
0VKF(SF
0VKF(VF
0VKNF
0VKN&(F
0VKN&1F
0VKN&FF
0VKN&NF
0VKN&SF
0VKN&VF
0VKN;F
0VKN;CF
0VKN;EF
0VKN;TF
0VKNB(F
0VKNB1F
0VKNBFF
0VKNBNF
0VKNBSF
0VKNBVF
0VKNCF
0VKNE(F
0VKNE1F
0VKNEFF
0VKNENF
0VKNESF
0VKNEVF
0VKNU(F
0VKNUEF
0VKSF
0VKS&(F
0VKS&1F
0VKS&FF
0VKS&NF
0VKS&SF
0VKS&VF
0VKS;F
0VKS;CF
0VKS;EF
0VKS;TF
0VKSB(F
0VKSB1F
0VKSBFF
0VKSBNF
0VKSBSF
0VKSBVF
0VKSCF
0VKSE(F
0VKSE1F
0VKSEFF
0VKSEKF
0VKSENF
0VKSESF
0VKSEVF
0VKSO(F
0VKSO1F
0VKSOFF
0VKSONF
0VKSOSF
0VKSOVF
0VKSU(F
0VKSUEF
0VKUE(F
0VKUE1F
0VKUEFF
0VKUEKF
0VKUENF
0VKUESF
0VKUEVF
0VKVF
0VKV&(F
0VKV&1F
0VKV&FF
0VKV&NF
0VKV&SF
0VKV&VF
0VKV;F
0VKV;CF
0VKV;EF
0VKV;TF
0VKVB(F
0VKVB1F
0VKVBFF
0VKVBNF
0VKVBSF
0VKVBVF
0VKVCF
0VKVE(F
0VKVE1F
0VKVEFF
0VKVEKF
0VKVENF
0VKVESF
0VKVEVF
0VKVO(F
0VKVOFF
0VKVOSF
0VKVU(F
0VKVUEF
0VO(1&F
0VO(1)F
0VO(1,F
0VO(1OF
0VO(E(F
0VO(E1F
0VO(EEF
0VO(EFF
0VO(EKF
0VO(ENF
0VO(EOF
0VO(ESF
0VO(EVF
0VO(F(F
0VO(N&F
0VO(N)F
0VO(N,F
0VO(NOF
0VO(S&F
0VO(S)F
0VO(S,F
0VO(SOF
0VO(V&F
0VO(V)F
0VO(V,F
0VO(VOF
0VOF()F
0VOF(1F
0VOF(EF
0VOF(FF
0VOF(NF
0VOF(SF
0VOF(VF
0VOK&(F
0VOK&1F
0VOK&FF
0VOK&NF
0VOK&SF
0VOK&VF
0VOK(1F
0VOK(FF
0VOK(NF
0VOK(SF
0VOK(VF
0VOK1CF
0VOK1OF
0VOKF(F
0VOKNCF
0VOKO(F
0VOKO1F
0VOKOFF
0VOKONF
0VOKOSF
0VOKOVF
0VOKSCF
0VOKSOF
0VOKVCF
0VOKVOF
0VOSF
0VOS&(F
0VOS&1F
0VOS&EF
0VOS&FF
0VOS&KF
0VOS&NF
0VOS&SF
0VOS&UF
0VOS&VF
0VOS(EF
0VOS(UF
0VOS)&F
0VOS),F
0VOS);F
0VOS)BF
0VOS)CF
0VOS)EF
0VOS)FF
0VOS)KF
0VOS)OF
0VOS)UF
0VOS,(F
0VOS,FF
0VOS1(F
0VOS1FF
0VOS1NF
0VOS1SF
0VOS1UF
0VOS1VF
0VOS;F
0VOS;CF
0VOS;EF
0VOS;NF
0VOS;TF
0VOSA(F
0VOSAFF
0VOSASF
0VOSATF
0VOSAVF
0VOSB(F
0VOSB1F
0VOSBEF
0VOSBFF
0VOSBNF
0VOSBSF
0VOSBVF
0VOSCF
0VOSE(F
0VOSE1F
0VOSEFF
0VOSEKF
0VOSENF
0VOSEOF
0VOSESF
0VOSEUF
0VOSEVF
0VOSF(F
0VOSK(F
0VOSK)F
0VOSK1F
0VOSKBF
0VOSKFF
0VOSKNF
0VOSKSF
0VOSKUF
0VOSKVF
0VOST(F
0VOST1F
0VOSTEF
0VOSTFF
0VOSTNF
0VOSTSF
0VOSTTF
0VOSTVF
0VOSUF
0VOSU(F
0VOSU1F
0VOSU;F
0VOSUCF
0VOSUEF
0VOSUFF
0VOSUKF
0VOSUOF
0VOSUSF
0VOSUTF
0VOSUVF
0VOSV(F
0VOSVFF
0VOSVOF
0VOSVSF
0VOSVUF
0VOU(EF
0VOUEKF
0VOUENF
0VT(1)F
0VT(1OF
0VT(F(F
0VT(N)F
0VT(NOF
0VT(S)F
0VT(SOF
0VT(V)F
0VT(VOF
0VT1(FF
0VT1O(F
0VT1OFF
0VT1OSF
0VT1OVF
0VTE(1F
0VTE(FF
0VTE(NF
0VTE(SF
0VTE(VF
0VTE1NF
0VTE1OF
0VTEF(F
0VTEK(F
0VTEK1F
0VTEKFF
0VTEKNF
0VTEKSF
0VTEKVF
0VTENNF
0VTENOF
0VTESNF
0VTESOF
0VTEVNF
0VTEVOF
0VTF()F
0VTF(1F
0VTF(FF
0VTF(NF
0VTF(SF
0VTF(VF
0VTN(1F
0VTN(FF
0VTN(SF
0VTN(VF
0VTN1CF
0VTN1OF
0VTN;EF
0VTN;NF
0VTN;TF
0VTNE(F
0VTNE1F
0VTNEFF
0VTNENF
0VTNESF
0VTNEVF
0VTNF(F
0VTNKNF
0VTNN:F
0VTNNCF
0VTNNOF
0VTNO(F
0VTNOFF
0VTNOSF
0VTNOVF
0VTNSCF
0VTNSOF
0VTNT(F
0VTNT1F
0VTNTFF
0VTNTNF
0VTNTSF
0VTNTVF
0VTNVCF
0VTNVOF
0VTS(FF
0VTSO(F
0VTSO1F
0VTSOFF
0VTSONF
0VTSOSF
0VTSOVF
0VTTNEF
0VTTNKF
0VTTNNF
0VTTNTF
0VTV(1F
0VTV(FF
0VTVO(F
0VTVOFF
0VTVOSF
0VUF
0VU(1)F
0VU(1OF
0VU(E(F
0VU(E1F
0VU(EFF
0VU(EKF
0VU(ENF
0VU(ESF
0VU(EVF
0VU(F(F
0VU(N)F
0VU(NOF
0VU(S)F
0VU(SOF
0VU(V)F
0VU(VOF
0VU1,(F
0VU1,FF
0VU1CF
0VU1O(F
0VU1OFF
0VU1OSF
0VU1OVF
0VU;F
0VU;CF
0VUCF
0VUEF
0VUE(1F
0VUE(EF
0VUE(FF
0VUE(NF
0VUE(OF
0VUE(SF
0VUE(VF
0VUE1F
0VUE1&F
0VUE1(F
0VUE1)F
0VUE1,F
0VUE1;F
0VUE1BF
0VUE1CF
0VUE1FF
0VUE1KF
0VUE1NF
0VUE1OF
0VUE1SF
0VUE1UF
0VUE1VF
0VUE;F
0VUE;CF
0VUECF
0VUEFF
0VUEF(F
0VUEF,F
0VUEF;F
0VUEFCF
0VUEKF
0VUEK(F
0VUEK1F
0VUEK;F
0VUEKCF
0VUEKFF
0VUEKNF
0VUEKOF
0VUEKSF
0VUEKVF
0VUENF
0VUEN&F
0VUEN(F
0VUEN)F
0VUEN,F
0VUEN1F
0VUEN;F
0VUENBF
0VUENCF
0VUENFF
0VUENKF
0VUENOF
0VUENSF
0VUENUF
0VUEOKF
0VUEONF
0VUESF
0VUES&F
0VUES(F
0VUES)F
0VUES,F
0VUES1F
0VUES;F
0VUESBF
0VUESCF
0VUESFF
0VUESKF
0VUESOF
0VUESUF
0VUESVF
0VUEVF
0VUEV&F
0VUEV(F
0VUEV)F
0VUEV,F
0VUEV;F
0VUEVBF
0VUEVCF
0VUEVFF
0VUEVKF
0VUEVNF
0VUEVOF
0VUEVSF
0VUEVUF
0VUF()F
0VUF(1F
0VUF(FF
0VUF(NF
0VUF(SF
0VUF(VF
0VUK(EF
0VUO(EF
0VUON(F
0VUON1F
0VUONFF
0VUONSF
0VUS,(F
0VUS,FF
0VUSCF
0VUSO(F
0VUSO1F
0VUSOFF
0VUSONF
0VUSOSF
0VUSOVF
0VUTN(F
0VUTN1F
0VUTNFF
0VUTNNF
0VUTNSF
0VUTNVF
0VUV,(F
0VUV,FF
0VUVCF
0VUVO(F
0VUVOFF
0VUVOSF
0XF
::o
:=o
<<o
<=o
<>o
<@o
>=o
>>o
@>o
ABORTk
ABSf
ACCESSIBLEk
ACOSf
ADDDATEf
ADDTIMEf
AES_DECRYPTf
AES_ENCRYPTf
AGAINSTk
AGEf
ALL_USERSk
ALTERk
ALTER DOMAINk
ALTER TABLEk
ANALYZEk
AND&
ANYf
ANYARRAYt
ANYELEMENTt
ANYNONARRYt
APPLOCK_MODEf
APPLOCK_TESTf
APP_NAMEf
ARRAY_AGGf
ARRAY_CATf
ARRAY_DIMf
ARRAY_FILLf
ARRAY_LENGTHf
ARRAY_LOWERf
ARRAY_NDIMSf
ARRAY_PREPENDf
ARRAY_TO_JSONf
ARRAY_TO_STRINGf
ARRAY_UPPERf
ASk
ASCk
ASCIIf
ASENSITIVEk
ASINf
ASSEMBLYPROPERTYf
ASYMKEY_IDf
AT TIMEn
AT TIME ZONEk
ATANf
ATAN2f
AUTOINCREMENTk
AVGf
BEFOREk
BEGINT
BEGIN DECLARET
BEGIN GOTOT
BEGIN TRYT
BEGIN TRY DECLARET
BENCHMARKf
BETWEENo
BIGINTt
BIGSERIALt
BINf
BINARYt
BINARY_DOUBLE_INFINITY1
BINARY_DOUBLE_NAN1
BINARY_FLOAT_INFINITY1
BINARY_FLOAT_NAN1
BINBINARYf
BIT_ANDf
BIT_COUNTf
BIT_LENGTHf
BIT_ORf
BIT_XORf
BLOBk
BOOLEANt
BOOL_ANDf
BOOL_ORf
BOTHk
BTRIMf
BYn
BYTEAt
CALLT
CASCADEk
CASEE
CASTf
CBOOLf
CBRTf
CBYTEf
CCURf
CDATEf
CDBLf
CEILf
CEILINGf
CERTENCODEDf
CERTPRIVATEKEYf
CERT_IDf
CERT_PROPERTYf
CHANGEk
CHANGESf
CHARf
CHARACTERt
CHARACTER VARYINGt
CHARACTER_LENGTHf
CHARINDEXf
CHARSETf
CHAR_LENGTHf
CHDIRf
CHDRIVEf
CHECKn
CHECKSUM_AGGf
CHOOSEf
CHRf
CINTf
CLNGf
CLOCK_TIMESTAMPf
COALESCEf
COERCIBILITYf
COLLATEA
COLLATIONf
COLLATIONPROPERTYf
COLUMNk
COLUMNPROPERTYf
COLUMNS_UPDATEDf
COL_LENGTHf
COL_NAMEf
COMPRESSf
CONCATf
CONCAT_WSf
CONDITIONk
CONNECTION_IDf
CONSTRAINTk
CONTINUEk
CONVf
CONVERTf
CONVERT_FROMf
CONVERT_TOf
CONVERT_TZf
COSf
COTf
COUNTf
COUNT_BIGk
CRC32f
CREATEE
CREATE ORn
CREATE OR REPLACET
CROSSn
CROSS JOINk
CSNGf
CSTRINGt
CTXSYS.DRITHSX.SNf
CUME_DISTf
CURDATEf
CURDIRf
CURRENT DATEv
CURRENT DEGREEv
CURRENT FUNCTIONv
CURRENT FUNCTION PATHv
CURRENT PATHv
CURRENT SCHEMAv
CURRENT SERVERv
CURRENT TIMEv
CURRENT TIMEZONEv
CURRENTUSERf
CURRENT_DATABASEf
CURRENT_DATEv
CURRENT_PATHv
CURRENT_QUERYf
CURRENT_SCHEMAf
CURRENT_SCHEMASf
CURRENT_SERVERv
CURRENT_SETTINGf
CURRENT_TIMEv
CURRENT_TIMESTAMPv
CURRENT_TIMEZONEv
CURRENT_USERv
CURRVALf
CURSORk
CURSOR_STATUSf
CURTIMEf
CVARf
DATABASEn
DATABASEPROPERTYEXf
DATABASESk
DATABASE_PRINCIPAL_IDf
DATALENGTHf
DATEf
DATEADDf
DATEDIFFf
DATEFROMPARTSf
DATENAMEf
DATEPARTf
DATESERIALf
DATETIME2FROMPARTSf
DATETIMEFROMPARTSf
DATETIMEOFFSETFROMPARTSf
DATEVALUEf
DATE_ADDf
DATE_FORMATf
DATE_PARTf
DATE_SUBf
DATE_TRUNCf
DAVGf
DAYf
DAYNAMEf
DAYOFMONTHf
DAYOFWEEKf
DAYOFYEARf
DAY_HOURk
DAY_MICROSECONDk
DAY_MINUTEk
DAY_SECONDk
DBMS_LOCK.SLEEPf
DBMS_PIPE.RECEIVE_MESSAGEf
DBMS_UTILITY.SQLID_TO_SQLHASHf
DB_IDf
DB_NAMEf
DCOUNTf
DECk
DECIMALt
DECLARET
DECODEf
DECRYPTBYASMKEYf
DECRYPTBYCERTf
DECRYPTBYKEYf
DECRYPTBYKEYAUTOCERTf
DECRYPTBYPASSPHRASEf
DEFAULTk
DEGREESf
DELAYk
DELAYEDk
DELETET
DENSE_RANKf
DESCk
DESCRIBEk
DES_DECRYPTf
DES_ENCRYPTf
DETERMINISTICk
DFIRSTf
DIFFERENCEf
DISTINCTk
DISTINCTROWk
DIVo
DLASTf
DLOOKUPf
DMAXf
DMINf
DOn
DOUBLEt
DOUBLE PRECISIONt
DROPT
DSUMf
DUALn
EACHk
ELSEk
ELSEIFk
ELTf
ENCLOSEDk
ENCODEf
ENCRYPTf
ENCRYPTBYASMKEYf
ENCRYPTBYCERTf
ENCRYPTBYKEYf
ENCRYPTBYPASSPHRASEf
ENUM_FIRSTf
ENUM_LASTf
ENUM_RANGEf
EOMONTHf
EQVo
ESCAPEDk
EVENTDATAf
EXCEPTU
EXECT
EXECUTET
EXECUTE ASE
EXECUTE AS LOGINE
EXISTSf
EXITk
EXPf
EXPLAINk
EXPORT_SETf
EXTRACTf
EXTRACTVALUEf
EXTRACT_VALUEf
FALSE1
FETCHk
FIELDf
FILEDATETIMEf
FILEGROUPPROPERTYf
FILEGROUP_IDf
FILEGROUP_NAMEf
FILELENf
FILEPROPERTYf
FILETOBLOBf
FILETOCLOBf
FILE_IDf
FILE_IDEXf
FILE_NAMEf
FIND_IN_SETf
FIRST_VALUEf
FLOATt
FLOAT4t
FLOAT8t
FLOORf
FN_VIRTUALFILESTATSf
FORn
FOR UPDATEk
FOR UPDATE NOWAITk
FOR UPDATE OFk
FOR UPDATE SKIPk
FOR UPDATE SKIP LOCKEDk
FOR UPDATE WAITk
FORCEk
FOREIGNk
FORMATf
FOUND_ROWSf
FROMk
FROM_BASE64f
FROM_DAYSf
FROM_UNIXTIMEf
FULL JOINk
FULL OUTERk
FULL OUTER JOINk
FULLTEXTk
FULLTEXTCATALOGPROPERTYf
FULLTEXTSERVICEPROPERTYf
FUNCTIONk
GENERATE_SERIESf
GENERATE_SUBSCRIPTSf
GETATTRf
GETDATEf
GETUTCDATEf
GET_BITf
GET_BYTEf
GET_FORMATf
GET_LOCKf
GOT
GOTOT
GRANTk
GREATESTf
GROUPn
GROUP BYB
GROUPINGf
GROUPING_IDf
GROUP_CONCATf
HANDLERT
HASHBYTESf
HAS_PERMS_BY_NAMEf
HAVINGB
HEXf
HIGH_PRIORITYk
HOST_NAMEf
HOURf
HOUR_MICROSECONDk
HOUR_MINUTEk
HOUR_SECONDk
IDENTIFYf
IDENT_CURRENTf
IDENT_INCRf
IDENT_SEEDf
IFf
IF EXISTSf
IF NOTf
IF NOT EXISTSf
IFFf
IFNULLf
IGNOREk
IIFf
INk
IN BOOLEANn
IN BOOLEAN MODEk
INDEXk
INDEXKEY_PROPERTYf
INDEXPROPERTYf
INDEX_COLf
INET_ATONf
INET_NTOAf
INFILEk
INITCAPf
INNERk
INNER JOINk
INOUTk
INSENSITIVEk
INSERTE
INSERT DELAYEDE
INSERT DELAYED INTOT
INSERT HIGH_PRIORITYE
INSERT HIGH_PRIORITY INTOT
INSERT IGNOREE
INSERT IGNORE INTOT
INSERT INTOT
INSERT LOW_PRIORITYE
INSERT LOW_PRIORITY INTOT
INSTRf
INSTRREVf
INTt
INT1t
INT2t
INT3t
INT4t
INT8t
INTEGERt
INTERSECTU
INTERSECT ALLU
INTERVALk
INTOk
INTO DUMPFILEk
INTO OUTFILEk
ISo
IS DISTINCTn
IS DISTINCT FROMo
IS NOTo
IS NOT DISTINCTn
IS NOT DISTINCT FROMo
ISDATEf
ISEMPTYf
ISFINITEf
ISNULLf
ISNUMERICf
IS_FREE_LOCKf
IS_MEMBERf
IS_OBJECTSIGNEDf
IS_ROLEMEMBERf
IS_SRVROLEMEMBERf
IS_USED_LOCKf
ITERATEk
JOINk
JSON_KEYSf
JULIANDAYf
JUSTIFY_DAYSf
JUSTIFY_HOURSf
JUSTIFY_INTERVALf
KEYSk
KEY_GUIDf
KEY_IDf
KILLk
LAGf
LASTVALf
LAST_INSERT_IDf
LAST_INSERT_ROWIDf
LAST_VALUEf
LCASEf
LEADf
LEADINGk
LEASTf
LEAVEk
LEFTf
LEFT JOINk
LEFT OUTERk
LEFT OUTER JOINk
LENGTHf
LIKEo
LIMITB
LINEARk
LINESk
LNf
LOADk
LOAD DATAT
LOAD XMLT
LOAD_EXTENSIONf
LOAD_FILEf
LOCALTIMEv
LOCALTIMESTAMPv
LOCATEf
LOCKn
LOCK INn
LOCK IN SHAREn
LOCK IN SHARE MODEk
LOCK TABLEk
LOCK TABLESk
LOGf
LOG10f
LOG2f
LONGBLOBk
LONGTEXTk
LOOPk
LOWERf
LOWER_INCf
LOWER_INFf
LOW_PRIORITYk
LPADf
LTRIMf
MAKEDATEf
MAKE_SETf
MASKLENf
MASTER_BINDk
MASTER_POS_WAITf
MASTER_SSL_VERIFY_SERVER_CERTk
MATCHk
MAXf
MAXVALUEk
MD5f
MEDIUMBLOBk
MEDIUMINTk
MEDIUMTEXTk
MERGEk
MICROSECONDf
MIDf
MIDDLEINTk
MINf
MINUTEf
MINUTE_MICROSECONDk
MINUTE_SECONDk
MKDIRf
MODo
MODEn
MODIFIESk
MONEYt
MONTHf
MONTHNAMEf
NAME_CONSTf
NATURALn
NATURAL FULLk
NATURAL FULL OUTER JOINk
NATURAL INNERk
NATURAL JOINk
NATURAL LEFTk
NATURAL LEFT OUTERk
NATURAL LEFT OUTER JOINk
NATURAL OUTERk
NATURAL RIGHTk
NATURAL RIGHT OUTER JOINk
NETMASKf
NEXT VALUEn
NEXT VALUE FORk
NEXTVALf
NOTo
NOT BETWEENo
NOT INk
NOT LIKEo
NOT REGEXPo
NOT RLIKEo
NOT SIMILARo
NOT SIMILAR TOo
NOTNULLk
NOWf
NOWAITk
NO_WRITE_TO_BINLOGk
NTH_VALUEf
NTILEf
NULLv
NULLIFf
NUMERICt
NZf
OBJECTPROPERTYf
OBJECTPROPERTYEXf
OBJECT_DEFINITIONf
OBJECT_IDf
OBJECT_NAMEf
OBJECT_SCHEMA_NAMEf
OCTf
OCTET_LENGTHf
OFFSETk
OIDt
OLD_PASSWORDf
ONE_SHOTk
OPENk
OPENDATASOURCEf
OPENQUERYf
OPENROWSETf
OPENXMLf
OPTIMIZEk
OPTIONk
OPTIONALLYk
OR&
ORDf
ORDERn
ORDER BYB
ORIGINAL_DB_NAMEf
ORIGINAL_LOGINf
OUTn
OUTERn
OUTFILEk
OVERLAPSf
OVERLAYf
OWN3Dk
OWN3D BYB
PARSENAMEf
PARTITIONk
PARTITION BYB
PASSWORDn
PATHINDEXf
PATINDEXf
PERCENTILE_COUNTf
PERCENTILE_DISCf
PERCENTILE_RANKf
PERCENT_RANKf
PERIOD_ADDf
PERIOD_DIFFf
PERMISSIONSf
PG_ADVISORY_LOCKf
PG_BACKEND_PIDf
PG_CANCEL_BACKENDf
PG_CLIENT_ENCODINGf
PG_CONF_LOAD_TIMEf
PG_CREATE_RESTORE_POINTf
PG_HAS_ROLEf
PG_IS_IN_RECOVERYf
PG_IS_OTHER_TEMP_SCHEMAf
PG_LISTENING_CHANNELSf
PG_LS_DIRf
PG_MY_TEMP_SCHEMAf
PG_POSTMASTER_START_TIMEf
PG_READ_BINARY_FILEf
PG_READ_FILEf
PG_RELOAD_CONFf
PG_ROTATE_LOGFILEf
PG_SLEEPf
PG_START_BACKUPf
PG_STAT_FILEf
PG_STOP_BACKUPf
PG_SWITCH_XLOGf
PG_TERMINATE_BACKENDf
PG_TRIGGER_DEPTHf
PIf
POSITIONf
POWf
POWERf
PRECISIONk
PREVIOUS VALUEn
PREVIOUS VALUE FORk
PRIMARYk
PRINTT
PROCEDUREk
PROCEDURE ANALYSEf
PUBLISHINGSERVERNAMEf
PURGEk
PWDCOMPAREf
PWDENCRYPTf
QUARTERf
QUOTEf
QUOTENAMEf
QUOTE_IDENTf
QUOTE_LITERALf
QUOTE_NULLABLEf
RADIANSf
RAISEERRORE
RANDf
RANDOMf
RANDOMBLOBf
RANGEk
RANKf
READk
READ WRITEk
READSk
READ_WRITEk
REALt
REFERENCESk
REGCLASSt
REGCONFIGt
REGDICTIONARYt
REGEXPo
REGEXP_INSTRf
REGEXP_MATCHESf
REGEXP_REPLACEf
REGEXP_SPLIT_TO_ARRAYf
REGEXP_SPLIT_TO_TABLEf
REGEXP_SUBSTRf
REGOPERt
REGOPERATORt
REGPROCt
REGPROCEDUREt
REGTYPEt
RELEASEk
RELEASE_LOCKf
RENAMEk
REPEATk
REPLACEk
REPLICATEf
REQUIREk
RESIGNALk
RESTRICTk
RETURNk
REVERSEf
REVOKEk
RIGHTn
RIGHT JOINk
RIGHT OUTERk
RIGHT OUTER JOINk
RLIKEo
ROUNDf
ROWf
ROW_COUNTf
ROW_NUMBERf
ROW_TO_JSONf
RPADf
RTRIMf
SCHAMA_NAMEf
SCHEMAk
SCHEMASk
SCHEMA_IDf
SCOPE_IDENTITYf
SECOND_MICROSECONDk
SEC_TO_TIMEf
SELECTE
SELECT ALLE
SELECT DISTINCTE
SENSITIVEk
SEPARATORk
SERIALt
SERIAL2t
SERIAL4t
SERIAL8t
SERVERPROPERTYf
SESSION_USERf
SETE
SETATTRf
SETSEEDf
SETVALf
SET_BITf
SET_BYTEf
SET_CONFIGf
SET_MASKLENf
SHAf
SHA1f
SHA2f
SHOWn
SHUTDOWNT
SIGNf
SIGNALk
SIGNBYASMKEYf
SIGNBYCERTf
SIMILARk
SIMILAR TOo
SINf
SLEEPf
SMALLDATETIMEFROMPARTSf
SMALLINTt
SMALLSERIALt
SOMEf
SOUNDEXf
SOUNDSo
SOUNDS LIKEo
SPACEf
SPATIALk
SPECIFICk
SPLIT_PARTf
SQLk
SQLEXCEPTIONk
SQLITE_VERSIONf
SQLSTATEk
SQLWARNINGk
SQL_BIG_RESULTk
SQL_BUFFER_RESULTk
SQL_CACHEk
SQL_CALC_FOUND_ROWSk
SQL_NO_CACHEk
SQL_SMALL_RESULTk
SQL_VARIANT_PROPERTYf
SQRTf
SSLk
STARTINGk
STATEMENT_TIMESTAMPf
STATS_DATEf
STDDEVf
STDDEV_POPf
STDDEV_SAMPf
STRAIGHT_JOINk
STRCMPf
STRCOMPf
STRCONVf
STRING_AGGf
STRING_TO_ARRAYf
STRPOSf
STR_TO_DATEf
STUFFf
SUBDATEf
SUBSTRf
SUBSTRINGf
SUBSTRING_INDEXf
SUBTIMEf
SUMf
SUSER_IDf
SUSER_NAMEf
SUSER_SIDf
SUSER_SNAMEf
SWITCHOFFETf
SYS.DATABASE_NAMEn
SYS.FN_BUILTIN_PERMISSIONSf
SYS.FN_GET_AUDIT_FILEf
SYS.FN_MY_PERMISSIONSf
SYS.STRAGGf
SYSCOLUMNSk
SYSDATEf
SYSDATETIMEf
SYSDATETIMEOFFSETf
SYSOBJECTSk
SYSTEM_USERf
SYSUSERSk
SYSUTCDATETMEf
TABLEn
TANf
TERMINATEDk
TERTIARY_WEIGHTSf
TEXTt
TEXTPOSf
TEXTPTRf
TEXTVALIDf
THENk
TIMEk
TIMEDIFFf
TIMEFROMPARTSf
TIMEOFDAYf
TIMESERIALf
TIMESTAMPt
TIMESTAMPADDf
TIMEVALUEf
TIME_FORMATf
TIME_TO_SECf
TINYBLOBk
TINYINTk
TINYTEXTk
TODATETIMEOFFSETf
TOPk
TOTALf
TOTAL_CHANGESf
TO_ASCIIf
TO_BASE64f
TO_CHARf
TO_DATEf
TO_DAYSf
TO_HEXf
TO_NUMBERf
TO_SECONDSf
TO_TIMESTAMPf
TRAILINGn
TRANSACTION_TIMESTAMPf
TRANSLATEf
TRIGGERk
TRIGGER_NESTLEVELf
TRIMf
TRUE1
TRUNCf
TRUNCATEf
TRYT
TRY_CASTf
TRY_CONVERTf
TRY_PARSEf
TYPEOFf
TYPEPROPERTYf
TYPE_IDf
TYPE_NAMEf
UCASEf
UESCAPEo
UNCOMPRESSf
UNCOMPRESS_LENGTHf
UNDOk
UNHEXf
UNICODEf
UNIONU
UNION ALLU
UNION ALL DISTINCTU
UNION DISTINCTU
UNION DISTINCT ALLU
UNIQUEn
UNIX_TIMESTAMPf
UNI_ONU
UNKNOWNv
UNLOCKk
UNNESTf
UNSIGNEDk
UPDATEE
UPDATEXMLf
UPPERf
UPPER_INCf
UPPER_INFf
USAGEk
USET
USERn
USER_IDn
USER_LOCK.SLEEPf
USER_NAMEn
USINGf
UTC_DATEk
UTC_TIMEk
UTC_TIMESTAMPk
UTL_HTTP.REQUESTf
UTL_INADDR.GET_HOST_ADDRESSf
UTL_INADDR.GET_HOST_NAMEf
UUIDf
UUID_SHORTf
VALUESk
VARf
VARBINARYk
VARCHARt
VARCHARACTERk
VARIANCEf
VARPf
VARYINGk
VAR_POPf
VAR_SAMPf
VERIFYSIGNEDBYASMKEYf
VERIFYSIGNEDBYCERTf
VERSIONf
VOIDt
WAITk
WAITFORn
WAITFOR DELAYE
WAITFOR RECEIVEE
WAITFOR TIMEE
WEEKf
WEEKDAYf
WEEKDAYNAMEf
WEEKOFYEARf
WHENk
WHEREk
WHILET
WIDTH_BUCKETf
WITHn
WITH ROLLUPk
XMLAGGf
XMLCOMMENTf
XMLCONCATf
XMLELEMENTf
XMLEXISTSf
XMLFORESTf
XMLFORMATf
XMLPIf
XMLROOTf
XMLTYPEf
XML_IS_WELL_FORMEDf
XOR&
XPATHf
XPATH_EXISTSf
XP_EXECRESULTSETk
YEARf
YEARWEEKf
YEAR_MONTHk
ZEROBLOBf
ZEROFILLk
^=o
_ARMSCII8t
_ASCIIt
_BIG5t
_BINARYt
_CP1250t
_CP1251t
_CP1257t
_CP850t
_CP852t
_CP866t
_CP932t
_DEC8t
_EUCJPMSt
_EUCKRt
_GB2312t
_GBKt
_GEOSTD8t
_GREEKt
_HEBREWt
_HP8t
_KEYBCS2t
_KOI8Rt
_KOI8Ut
_LATIN1t
_LATIN2t
_LATIN5t
_LATIN7t
_MACCEt
_MACROMANt
_SJISt
_SWE7t
_TIS620t
_UJISt
_USC2t
_UTF8t
|/o
|=o
||&
~*o"""

#: 黑标签 / 黑属性 / 黑事件处理器
_XSS_TABLE_BLOB = """APPLET,BASE,COMMENT,EMBED,FRAME,FRAMESET,HANDLER,IFRAME,IMPORT,ISINDEX,LINK,LISTENER,META,NOSCRIPT,OBJECT,SCRIPT,STYLE,VMLFRAME,XML,XSS
ACTIONA,ATTRIBUTENAMEI,BYA,BACKGROUNDA,DATAFORMATASB,DATASRCB,DYNSRCA,FILTERS,FORMACTIONA,FOLDERA,FROMA,HANDLERA,HREFA,LOWSRCA,POSTERA,SRCA,STYLES,TOA,VALUESA,XLINK:HREFA
ABORTB,ACCESSKEYNOTFOUNDB,ACTIVATEB,ACTIVEB,ADDSOURCEBUFFERB,ADDSTREAMB,ADDTRACKB,AFTERPAINTB,AFTERPRINTB,AFTERSCRIPTEXECUTEB,ANIMATIONCANCELB,ANIMATIONENDB,ANIMATIONITERATIONB,ANIMATIONSTARTB,AUDIOENDB,AUDIOCOMPLETEB,AUDIOPROCESSB,AUDIOSTARTB,AUTOCOMPLETEB,AUTOCOMPLETEERRORB,AUXCLICKB,BACKGROUNDFETCHABORTB,BACKGROUNDFETCHCLICKB,BACKGROUNDFETCHFAILB,BACKGROUNDFETCHSUCCESSB,BEFOREACTIVATEB,BEFORECOPYB,BEFORECUTB,BEFOREINPUTB,BEFORELOADB,BEFOREMATCHB,BEFOREPASTEB,BEFOREPRINTB,BEFORESCRIPTEXECUTEB,BEFORETOGGLEB,BEFOREUNLOADB,BEGINEVENTB,BLOCKEDB,BLURB,BOUNDARYB,BUFFEREDAMOUNTLOWB,BUFFEREDCHANGEB,CACHEDB,CANCELB,CANPLAYB,CANPLAYTHROUGHB,CHANGEB,CHARGINGCHANGEB,CHARGINGTIMECHANGEB,CHECKINGB,CLICKB,CLOSEB,CLOSINGB,COMPLETEB,COMPOSITIONENDB,COMPOSITIONSTARTB,COMPOSITIONCHANGEB,COMPOSITIONUPDATEB,COMMANDB,CONFIGURATIONCHANGEB,CONNECTB,CONNECTINGB,CONNECTIONSTATECHANGEB,CONTENTVISIBILITYAUTOSTATECHANGEB,CONTEXTLOSTB,CONTEXTMENUB,CONTEXTRESTOREDB,CONTROLLERCHANGEB,COOKIECHANGEB,COORDINATORSTATECHANGEB,COPYB,COUPONCODECHANGEDB,CUECHANGEB,CURRENTENTRYCHANGEB,CUTB,DATAAVAILABLEB,DATACHANNELB,DBLCLICKB,DEQUEUEB,DEVICECHANGEB,DEVICELIGHTB,DEVICEMOTIONB,DEVICEORIENTATIONB,DEVICEORIENTATIONABSOLUTEB,DISCHARGINGTIMECHANGEB,DISCONNECTB,DISPOSEB,DOMACTIVATEB,DOMCHARACTERDATAMODIFIEDB,DOMCONTENTLOADEDB,DOMNODEINSERTEDB,DOMNODEINSERTEDINTODOCUMENTB,DOMNODEREMOVEDB,DOMNODEREMOVEDFROMDOCUMENTB,DOMSUBTREEMODIFIEDB,DOWNLOADINGB,DRAGB,DRAGENDB,DRAGENTERB,DRAGLEAVEB,DRAGEXITB,DRAGOVERB,DRAGSTARTB,DROPB,DURATIONCHANGEB,EMPTIEDB,ENCRYPTEDB,EDGEUICANCELEDB,EDGEUICOMPLETEDB,EDGEUISTARTEDB,EDITORBEFOREINPUTB,EDITORINPUTB,ENDB,ENDEDB,ENDEVENTB,ENDSTREAMINGB,ENTERB,ENTERPICTUREINPICTUREB,ERRORB,EXITB,FENCEDTREECLICKB,FETCHB,FINISHB,FOCUSB,FOCUSINB,FOCUSOUTB,FORMCHANGEB,FORMCHECKBOXSTATECHANGEB,FORMDATAB,FORMINVALIDB,FORMRADIOSTATECHANGEB,FORMRESETB,FORMSELECTB,FORMSUBMITB,FULLSCREENCHANGEB,FULLSCREENERRORB,GAMEPADAXISMOVEB,GAMEPADBUTTONDOWNB,GAMEPADBUTTONUPB,GAMEPADCONNECTEDB,GAMEPADDISCONNECTEDB,GATHERINGSTATECHANGEB,GESTURECHANGEB,GESTUREENDB,GESTURESCROLLENDB,GESTURESCROLLSTARTB,GESTURESCROLLUPDATEB,GESTURESTARTB,GESTURETAPB,GESTURETAPDOWNB,GOTPOINTERCAPTUREB,HASHCHANGEB,ICECANDIDATEB,ICECANDIDATEERRORB,ICECONNECTIONSTATECHANGEB,ICEGATHERINGSTATECHANGEB,IMAGEABORTB,INACTIVEB,INPUTB,INPUTSOURCESCHANGEB,INSTALLB,INVALIDB,INVOKEB,KEYDOWNB,KEYPRESSB,KEYSTATUSESCHANGEB,KEYUPB,LANGUAGECHANGEB,LEAVEPICTUREINPICTUREB,LEGACYATTRMODIFIEDB,LEGACYCHARACTERDATAMODIFIEDB,LEGACYDOMACTIVATEB,LEGACYDOMFOCUSINB,LEGACYDOMFOCUSOUTB,LEGACYMOUSELINEORPAGESCROLLB,LEGACYMOUSEPIXELSCROLLB,LEGACYNODEINSERTEDB,LEGACYNODEINSERTEDINTODOCUMENTB,LEGACYNODEREMOVEDB,LEGACYNODEREMOVEDFROMDOCUMENTB,LEGACYSUBTREEMODIFIEDB,LEGACYTEXTINPUTB,LEVELCHANGEB,LOADB,LOADEDDATAB,LOADEDMETADATAB,LOADENDB,LOADINGB,LOADINGDONEB,LOADINGERRORB,LOADSTARTB,LOSTPOINTERCAPTUREB,MAGNIFYGESTUREB,MAGNIFYGESTURESTARTB,MAGNIFYGESTUREUPDATEB,MARKB,MEDIARECORDERDATAAVAILABLEB,MEDIARECORDERSTOPB,MEDIARECORDERWARNINGB,MERCHANTVALIDATIONB,MESSAGEB,MESSAGEERRORB,MOUSEDOUBLECLICKB,MOUSEDOWNB,MOUSEENTERB,MOUSEEXPLOREBYTOUCHB,MOUSEHITTESTB,MOUSELEAVEB,MOUSELONGTAPB,MOUSEMOVEB,MOUSEOUTB,MOUSEOVERB,MOUSEUPB,MOUSEWHEELB,MOZFULLSCREENCHANGEB,MOZFULLSCREENERRORB,MOZPOINTERLOCKCHANGEB,MOZPOINTERLOCKERRORB,MOZVISUALRESIZEB,MOZVISUALSCROLLB,MUTEB,NAVIGATEB,NAVIGATEERRORB,NAVIGATESUCCESSB,NEGOTIATIONNEEDEDB,NEXTTRACKB,NOMATCHB,NOTIFICATIONCLICKB,NOTIFICATIONCLOSEB,NOUPDATEB,OBSOLETEB,OFFLINEB,ONLINEB,OPENB,ORIENTATIONCHANGEB,OVERFLOWCHANGEDB,OVERSCROLLB,PAGEHIDEB,PAGEREVEALB,PAGESHOWB,PAGESWAPB,PASTEB,PAUSEB,PAYERDETAILCHANGEB,PAYMENTAUTHORIZEDB,PAYMENTMETHODCHANGEB,PAYMENTMETHODSELECTEDB,PLAYB,PLAYINGB,POINTERAUXCLICKB,POINTERCANCELB,POINTERCLICKB,POINTERDOWNB,POINTERENTERB,POINTERGOTCAPTUREB,POINTERLEAVEB,POINTERLOCKCHANGEB,POINTERLOCKERRORB,POINTERLOSTCAPTUREB,POINTERMOVEB,POINTEROUTB,POINTEROVERB,POINTERRAWUPDATEB,POINTERUPB,POPSTATEB,PRESSTAPGESTUREB,PREVIOUSTRACKB,PROPERTYCHANGEB,PROCESSORERRORB,PROGRESSB,PUSHB,PUSHNOTIFICATIONB,PUSHSUBSCRIPTIONCHANGEB,QUALITYCHANGEB,RATECHANGEB,READYSTATECHANGEB,REDRAWB,REJECTIONHANDLEDB,RELEASEB,REMOVEB,REMOVESOURCEBUFFERB,REMOVESTREAMB,REMOVETRACKB,REPEATB,REPEATEVENTB,RESETB,RESIZEB,RESOURCETIMINGBUFFERFULLB,RESULTB,RESUMEB,ROTATEGESTUREB,ROTATEGESTURESTARTB,ROTATEGESTUREUPDATEB,RTCTRANSFORMB,SCROLLB,SCROLLEDAREACHANGEDB,SCROLLENDB,SCROLLPORTOVERFLOWB,SCROLLPORTUNDERFLOWB,SCROLLSNAPCHANGEB,SCROLLSNAPCHANGINGB,SEARCHB,SECURITYPOLICYVIOLATIONB,SEEKEDB,SEEKINGB,SELECTB,SELECTEDCANDIDATEPAIRCHANGEB,SELECTENDB,SELECTIONCHANGEB,SELECTSTARTB,SHIPPINGADDRESSCHANGEB,SHIPPINGCONTACTSELECTEDB,SHIPPINGMETHODSELECTEDB,SHIPPINGOPTIONCHANGEB,SHOWB,SIGNALINGSTATECHANGEB,SLOTCHANGEB,SMILBEGINEVENTB,SMILENDEVENTB,SMILREPEATEVENTB,SORTB,SOUNDENDB,SOUNDSTARTB,SOURCECLOSEB,SOURCEENDEDB,SOURCEOPENB,SPEECHENDB,SPEECHSTARTB,SQUEEZEB,SQUEEZEENDB,SQUEEZESTARTB,STALLEDB,STARTB,STARTEDB,STARTSTREAMINGB,STATECHANGEB,STOPB,STORAGEB,SUBMITB,SVGLOADB,SVGSCROLLB,SWIPEGESTUREB,SWIPEGESTUREENDB,SWIPEGESTUREMAYSTARTB,SWIPEGESTURESTARTB,SWIPEGESTUREUPDATEB,SUCCESSB,SUSPENDB,TAPGESTUREB,TEXTINPUTB,TIMEOUTB,TIMEUPDATEB,TOGGLEB,TONECHANGEB,TOUCHCANCELB,TOUCHENDB,TOUCHFORCECHANGEB,TOUCHMOVEB,TOUCHSTARTB,TRACKB,TRANSITIONCANCELB,TRANSITIONENDB,TRANSITIONRUNB,TRANSITIONSTARTB,UNCAPTUREDERRORB,UNHANDLEDREJECTIONB,UNIDENTIFIEDEVENTB,UNLOADB,UNMUTEB,USERPROXIMITYB,UPDATEB,UPDATEENDB,UPDATEFOUNDB,UPDATEREADYB,UPDATESTARTB,UPGRADENEEDEDB,VALIDATEMERCHANTB,VERSIONCHANGEB,VISIBILITYCHANGEB,VOICESCHANGEDB,VOLUMECHANGEB,VRDISPLAYACTIVATEB,VRDISPLAYCONNECTB,VRDISPLAYDEACTIVATEB,VRDISPLAYDISCONNECTB,VRDISPLAYPRESENTCHANGEB,WAITINGB,WAITINGFORKEYB,WEBGLCONTEXTCREATIONERRORB,WEBGLCONTEXTLOSTB,WEBGLCONTEXTRESTOREDB,WEBKITANIMATIONENDB,WEBKITANIMATIONITERATIONB,WEBKITANIMATIONSTARTB,WEBKITASSOCIATEFORMCONTROLSB,WEBKITAUTOFILLREQUESTB,WEBKITBEFORETEXTINSERTEDB,WEBKITBEGINFULLSCREENB,WEBKITCURRENTPLAYBACKTARGETISWIRELESSCHANGEDB,WEBKITENDFULLSCREENB,WEBKITFULLSCREENCHANGEB,WEBKITFULLSCREENERRORB,WEBKITKEYADDEDB,WEBKITKEYERRORB,WEBKITKEYMESSAGEB,WEBKITMEDIASESSIONMETADATACHANGEDB,WEBKITMOUSEFORCECHANGEDB,WEBKITMOUSEFORCEDOWNB,WEBKITMOUSEFORCEUPB,WEBKITMOUSEFORCEWILLBEGINB,WEBKITNEEDKEYB,WEBKITNETWORKINFOCHANGEB,WEBKITPLAYBACKTARGETAVAILABILITYCHANGEDB,WEBKITPRESENTATIONMODECHANGEDB,WEBKITREMOVESOURCEBUFFERB,WEBKITSHADOWROOTATTACHEDB,WEBKITSOURCECLOSEB,WEBKITSOURCEENDEDB,WEBKITSOURCEOPENB,WEBKITTRANSITIONENDB,WHEELB,WRITEB,WRITEENDB,WRITESTARTB,XULBROADCASTB,XULCOMMANDUPDATEB,XULPOPUPHIDDENB,XULPOPUPHIDINGB,XULPOPUPSHOWINGB,XULPOPUPSHOWNB,XULSYSTEMSTATUSBARCLICKB,ZOOMB"""


def _load_tables() -> None:
    """展开上面的紧凑数据表 (导入时执行一次)."""
    global _parse_map, _SQL_WORDS, _FP_PATTERNS
    global _XSS_BLACK_TAGS, _XSS_BLACK_ATTRS, _XSS_BLACK_EVENTS

    _parse_map = [
        _PARSE_FUNCS[_PARSE_MAP_CODES[i]] if i < 256 else _parse_word
        for i in range(256)
    ]

    words: dict[str, str] = {}
    patterns: set[str] = set()
    for line in _SQL_TABLE_BLOB.split("\n"):
        if not line:
            continue
        word, kind = line[:-1], line[-1]
        if kind == "F":
            patterns.add(word)
        else:
            words[word] = kind
    _SQL_WORDS = words
    _FP_PATTERNS = frozenset(patterns)

    blobs = _XSS_TABLE_BLOB.split("\n")
    _XSS_BLACK_TAGS = tuple(blobs[0].split(",")) if blobs and blobs[0] else ()
    _XSS_BLACK_ATTRS = tuple(
        (entry[:-1], _ATTR_BY_CODE[entry[-1]])
        for entry in blobs[1].split(",") if entry
    ) if len(blobs) > 1 else ()
    _XSS_BLACK_EVENTS = tuple(
        (entry[:-1], _ATTR_BY_CODE[entry[-1]])
        for entry in blobs[2].split(",") if entry
    ) if len(blobs) > 2 else ()


#: 黑属性类型代号 -> 常量
_ATTR_BY_CODE = {"A": _ATTR_URL, "B": _ATTR_BLACK, "S": _ATTR_STYLE,
                 "I": _ATTR_INDIRECT}

#: 运行时由 :func:`_load_tables` 填充
_parse_map: list = []
_SQL_WORDS: dict[str, str] = {}
_FP_PATTERNS: frozenset[str] = frozenset()
_XSS_BLACK_TAGS: tuple[str, ...] = ()
_XSS_BLACK_ATTRS: tuple[tuple[str, int], ...] = ()
_XSS_BLACK_EVENTS: tuple[tuple[str, int], ...] = ()

_load_tables()


if __name__ == "__main__":
    _selftest()
