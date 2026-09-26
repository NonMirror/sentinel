"""SecRule 算子 (ModSecurity operators).

算子拿到的是**已经过 ``t:`` 变换**的值, 返回布尔命中结果。
``!`` 取反在 :func:`evaluate` 内部统一处理, 各算子只实现正向语义。
"""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

from ..libinjection import detect_sqli, detect_xss
from .syntax import Operator

#: 编译失败的正则 (供引擎健康检查展示: 解释器覆盖率的诚实指标)
FAILED_PATTERNS: set[str] = set()

#: 通过方言改写才编译成功的正则 (说明 Python ``re`` 与 PCRE 存在差异)
TRANSLATED_PATTERNS: set[str] = set()


def _xbrace(match: re.Match[str]) -> str:
    """PCRE ``\\x{bf}`` -> Python ``\\xbf`` / ``\\uXXXX``."""
    code = int(match.group(1), 16)
    if code <= 0xFF:
        return "\\x%02x" % code
    if code <= 0xFFFF:
        return "\\u%04x" % code
    return re.escape(chr(code))


#: PCRE 允许 ``(?i)`` 出现在模式任意位置且**全局生效**; Python 要求它必须在
#: 最前面, 否则报 "global flags not at the start of the expression"。
#: 例如 CRS 里的 ``^(?i)up`` —— 语义等价于 ``(?i)^up``。
_GLOBAL_FLAGS_RE = re.compile(r"\(\?([imsx]+)\)")


def _hoist_global_flags(pattern: str) -> str:
    flags: list[str] = []

    def collect(match: re.Match[str]) -> str:
        for flag in match.group(1):
            if flag not in flags:
                flags.append(flag)
        return ""

    stripped = _GLOBAL_FLAGS_RE.sub(collect, pattern)
    if not flags:
        return pattern
    ordered = "".join(sorted(flags))
    if stripped.startswith(f"(?{ordered})"):
        return stripped
    return f"(?{ordered}){stripped}"


#: 直接可替换的方言差异 (Python 完全不认识的写法)
_SIMPLE_FIXUPS = (
    # PCRE 花括号十六进制转义: CRS 的 UTF-8 边界匹配大量使用
    (re.compile(r"\\x\{([0-9a-fA-F]{1,6})\}"), _xbrace),
    # PCRE 分支重置 (?|...) —— CRS 用它让各分支共享组号; 转成普通非捕获组,
    # 组号偏移不影响判定 (CRS 只用 TX:0 = 整体匹配)
    (re.compile(r"\(\?\|"), lambda _m: "(?:"),
    # 字符类里的 \--9 是 PCRE 的「连字符到 9」区间; Python 需写成 \x2d-9
    (re.compile(r"\\--"), lambda _m: "\\x2d-"),
)

#: 单字符转义方言 (需要感知转义奇偶, 用扫描器而非正则替换)
_ESCAPE_FIXUP = {
    "h": "[ \t]",        # PCRE 水平空白
    "H": r"\S",          # Python 无 \H, 用 \S 近似
    "R": r"(?:\r\n|[\r\n])",
    "z": r"\Z",          # PCRE \z == Python \Z (绝对结尾)
    "Z": r"(?=\n?\Z)",   # PCRE \Z == 结尾或末尾换行之前
}


def _translate_escapes(pattern: str) -> str:
    """改写单字符转义方言, 尊重反斜杠奇偶性 (``\\\\h`` 不动)."""
    out: list[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char != "\\" or index + 1 >= length:
            out.append(char)
            index += 1
            continue
        nxt = pattern[index + 1]
        replacement = _ESCAPE_FIXUP.get(nxt)
        if replacement is None or nxt in "xuc":
            out.append(char)
            out.append(nxt)
            index += 2
            continue
        out.append(replacement)
        index += 2
    return "".join(out)


def _pcre_to_python(pattern: str) -> str:
    for regex, replace in _SIMPLE_FIXUPS:
        pattern = regex.sub(replace, pattern)
    pattern = _hoist_global_flags(pattern)
    return _translate_escapes(pattern)


@lru_cache(maxsize=4096)
def compile_pattern(pattern: str) -> re.Pattern[str] | None:
    """编译并缓存正则; 失败返回 None 并登记 (不抛异常).

    先在 Python ``re`` 下直接编译 —— 绝大多数 CRS 规则本就兼容, 保持原语义;
    只有在失败时才走 PCRE 方言改写, 这样改写永远不会影响已经正确的规则。
    """
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except (re.error, OverflowError, RecursionError):
        pass
    translated = _pcre_to_python(pattern)
    try:
        compiled = re.compile(translated)
    except (re.error, OverflowError, RecursionError):
        FAILED_PATTERNS.add(pattern[:200])
        return None
    TRANSLATED_PATTERNS.add(pattern[:200])
    return compiled


# --------------------------------------------------------------------------
# 数值 / 字符串比较
# --------------------------------------------------------------------------
def _as_number(text: str) -> float | None:
    try:
        return float(text.strip())
    except (TypeError, ValueError):
        return None


def _compare(left: str, right: str, op: str) -> bool:
    """ModSecurity 语义: 两边都是数字时按数值比较, 否则按字符串."""
    left_num, right_num = _as_number(left), _as_number(right)
    if left_num is not None and right_num is not None:
        return _cmp(left_num, right_num, op)
    return _cmp(left, right, op)


def _cmp(left, right, op: str) -> bool:
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op == "ge":
        return left >= right
    if op == "gt":
        return left > right
    if op == "le":
        return left <= right
    if op == "lt":
        return left < right
    return False


# --------------------------------------------------------------------------
# 字节范围 / 编码校验
# --------------------------------------------------------------------------
@lru_cache(maxsize=64)
def _parse_byte_ranges(spec: str) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        low, _, high = chunk.partition("-")
        try:
            start = int(low)
            end = int(high) if high else start
        except ValueError:
            continue
        ranges.append((start, end))
    return tuple(ranges)


def _validate_byte_range(value: str, spec: str) -> bool:
    ranges = _parse_byte_ranges(spec)
    if not ranges:
        return True
    raw = value.encode("latin-1", "replace")
    for byte in raw:
        if not any(start <= byte <= end for start, end in ranges):
            return False
    return True


def _validate_utf8(value: str) -> bool:
    try:
        value.encode("latin-1", "strict").decode("utf-8", "strict")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False
    return True


_URL_ENCODING_RE = re.compile(r"%(?![0-9a-fA-F]{2})")


def _validate_url_encoding(value: str) -> bool:
    return _URL_ENCODING_RE.search(value) is None


# --------------------------------------------------------------------------
# IP 匹配
# --------------------------------------------------------------------------
@lru_cache(maxsize=64)
def _parse_ip_list(spec: str) -> tuple:
    entries = []
    for chunk in spec.split():
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            entries.append(ipaddress.ip_network(chunk, strict=False))
        except ValueError:
            continue
    return tuple(entries)


def _ip_match(value: str, spec: str) -> bool:
    networks = _parse_ip_list(spec)
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(address in network for network in networks)


# --------------------------------------------------------------------------
# 主入口
# --------------------------------------------------------------------------
def evaluate(operator: Operator, value: str, mask: str = "") -> bool:
    """对单个变换后的值求值 (含 ``!`` 取反)."""
    result = _evaluate_positive(operator, value)
    return (not result) if operator.negated else result


def _evaluate_positive(operator: Operator, value: str) -> bool:  # noqa: C901
    name = operator.name
    argument = operator.argument

    if name == "rx":
        pattern = operator.compiled
        if pattern is None and not operator.dynamic:
            pattern = compile_pattern(argument)
        if pattern is None:
            return False
        return pattern.search(value) is not None

    if name in ("pm", "pmfromfile"):
        words = operator.words
        if not words:
            return False
        low = value.lower()
        return any(word.lower() in low for word in words)

    if name == "contains":
        return argument.lower() in value.lower()

    if name == "containsword":
        return re.search(rf"(?<!\w){re.escape(argument)}(?!\w)",
                         value, re.IGNORECASE) is not None

    if name == "streq":
        return value == argument

    if name == "strmatch":
        return value.lower() == argument.lower()

    if name == "beginswith":
        return value.startswith(argument)

    if name == "endswith":
        return value.endswith(argument)

    if name in ("eq", "ne", "ge", "gt", "le", "lt"):
        return _compare(value, argument, name)

    if name == "within":
        return value in argument.split()

    if name in ("ipmatch", "ipmatchfromfile"):
        words = operator.words if name == "ipmatchfromfile" else ()
        spec = " ".join(words) if words else argument
        return _ip_match(value, spec)

    # 校验类算子语义**相反**: ModSecurity 里它们命中于「校验失败」
    # (validate_byte_range.cc: `ret = (count != 0)`)。写反会让
    # ``@validateByteRange`` 在每一个正常请求上命中。
    if name == "validatebyterange":
        return not _validate_byte_range(value, argument)

    if name == "validateutf8encoding":
        return not _validate_utf8(value)

    if name == "validateurlencoding":
        return not _validate_url_encoding(value)

    # ModSecurity 里这两个算子由 libinjection C 库实现, 这里用等价的原生 Python
    # 移植 (:mod:`sentinel.waf.libinjection`), 而不是 signatures.py 里的启发式。
    if name == "detectsqli":
        return detect_sqli(value)

    if name == "detectxss":
        return detect_xss(value)

    if name == "unconditionalmatch":
        return True

    if name == "nomatch":
        return False

    if name == "rsub":
        pattern, _, _replacement = argument.partition(" ")
        compiled = compile_pattern(pattern)
        return compiled is not None and compiled.search(value) is not None

    return False


def health() -> dict[str, object]:
    """解释器算子覆盖率 (供引擎状态与报告展示)."""
    return {
        "failed_patterns": len(FAILED_PATTERNS),
        "translated_patterns": len(TRANSLATED_PATTERNS),
        "failed_samples": sorted(FAILED_PATTERNS)[:5],
        "translated_samples": sorted(TRANSLATED_PATTERNS)[:5],
    }


def reset_health() -> None:
    FAILED_PATTERNS.clear()
    TRANSLATED_PATTERNS.clear()
    compile_pattern.cache_clear()
