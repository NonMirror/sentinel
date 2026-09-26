"""模板表达式: ``{{...}}`` 变量替换与 nuclei DSL 求值.

模板里有两套完全不同的语言, 必须分开处理:

* **``{{...}}`` 插值** —— 出现在 ``path`` / ``body`` / ``headers`` / ``raw`` 中,
  做字符串替换 (``{{BaseURL}}/api``、``{{base64(user)}}``)。
* **DSL 表达式** —— 出现在 ``matchers[].dsl`` 里, 是**布尔求值**,
  形如 ``status_code == 200 && contains(body, "admin")``。

DSL 用 :mod:`ast` 白名单求值, 不用 :func:`eval` —— 模板来自外部仓库
(nuclei-templates 是第三方内容), 直接执行等于把任意代码执行权交出去。
"""
from __future__ import annotations

import ast
import base64
import hashlib
import random
import re
import string
import time
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote, unquote, urlsplit

# --------------------------------------------------------------------------
# 响应上下文
# --------------------------------------------------------------------------
@dataclass
class ResponseContext:
    """一次 HTTP 响应 + 目标信息, DSL 与匹配器的求值环境."""

    url: str = ""
    status_code: int = 0
    body: str = ""
    body_bytes: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    duration: float = 0.0
    request: str = ""
    template_id: str = ""
    variables: dict[str, str] = field(default_factory=dict)
    #: 提取器产出的内部变量 (供后续 matcher / request 使用)
    extracted: dict[str, str] = field(default_factory=dict)

    # ---------------- 派生量 ----------------
    @property
    def content_length(self) -> int:
        return len(self.body_bytes)

    @property
    def content_type(self) -> str:
        return self.header("content-type")

    @property
    def all_headers(self) -> str:
        return "".join(f"{k}: {v}\n" for k, v in self.headers.items())

    # 目标 URL 由扫描器给出, 仍可能畸形 (模板允许指向任意 host), 一律容错。
    def _split(self):
        try:
            return urlsplit(self.url)
        except ValueError:
            return urlsplit("")

    @property
    def scheme(self) -> str:
        return self._split().scheme or "http"

    @property
    def host(self) -> str:
        parts = self._split()
        try:
            return parts.hostname or ""
        except ValueError:
            return ""

    @property
    def port(self) -> str:
        parts = self._split()
        try:
            if parts.port:
                return str(parts.port)
        except ValueError:
            pass
        return "443" if parts.scheme == "https" else "80"

    @property
    def path(self) -> str:
        return self._split().path or "/"

    @property
    def filename(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    def header(self, name: str) -> str:
        low = name.lower()
        if low == "content-type":
            for key, value in self.headers.items():
                if key.lower() == "content-type":
                    return value
        for key, value in self.headers.items():
            if key.lower() == low:
                return value
        return ""

    # ---------------- 取值 (DSL 变量) ----------------
    def lookup(self, name: str) -> Any:
        if name in self.extracted:
            return self.extracted[name]
        if name in self.variables:
            return self.variables[name]
        builtin = _BUILTIN_VARS.get(name)
        if builtin is not None:
            return builtin(self)
        return ""


_BUILTIN_VARS: dict[str, Callable[[ResponseContext], Any]] = {
    "status_code": lambda c: c.status_code,
    "body": lambda c: c.body,
    "all_headers": lambda c: c.all_headers,
    "content_length": lambda c: c.content_length,
    "content_type": lambda c: c.content_type,
    "duration": lambda c: c.duration,
    "host": lambda c: c.host,
    "port": lambda c: c.port,
    "scheme": lambda c: c.scheme,
    "path": lambda c: c.path,
    "file": lambda c: c.filename,
    "filename": lambda c: c.filename,
    "template_id": lambda c: c.template_id,
    "url": lambda c: c.url,
    "raw": lambda c: c.request,
    "type": lambda c: "http",
}


# --------------------------------------------------------------------------
# {{...}} 插值
# --------------------------------------------------------------------------
#: 模板中的内建变量 (与 nuclei 同名)
_TEMPLATE_VARS = {
    "BaseURL": lambda v: f"{v.get('Scheme', 'http')}://{v.get('Host', '')}",
    "RootURL": lambda v: f"{v.get('Scheme', 'http')}://{v.get('Host', '')}",
    "Hostname": lambda v: v.get("Host", ""),
    "Host": lambda v: v.get("Hostname", ""),
}

_INNER_RE = re.compile(r"\{\{([^{}]*)\}\}")
_RAND_ALPHA = string.ascii_letters
_RAND_ALNUM = string.ascii_letters + string.digits


def render(text: str, variables: dict[str, str], *, depth: int = 4) -> str:
    """把 ``{{...}}`` 展开成具体字符串.

    由内向外替换 (``{{base64({{Hostname}})}}`` 先算里层), 每次替换后重扫,
    最多 :4`` 层 —— 防止模板里自引用造成死循环。
    """
    if not text or "{{" not in text:
        return text
    for _ in range(depth):
        replaced = _INNER_RE.sub(
            lambda m: _resolve(m.group(1), variables), text)
        if replaced == text:
            break
        text = replaced
    return text


def _resolve(token: str, variables: dict[str, str]) -> str:
    token = token.strip()
    if not token:
        return ""
    if "(" in token:
        value = _call_helper(token, variables)
        if value is not None:
            return value
    if "." in token and "(" not in token:
        # {{foo.bar}} 形式的取值; 模板里极少, 退化为原样保留
        head = token.split(".", 1)[0]
        if head in variables:
            return variables[head]
    if token in variables:
        return variables[token]
    builtin = _TEMPLATE_VARS.get(token)
    if builtin is not None:
        return builtin(variables)
    return ""                                  # 未定义变量 -> 空串 (与 nuclei 一致)


_HELPER_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$", re.S)


def _call_helper(token: str, variables: dict[str, str]) -> str | None:
    match = _HELPER_RE.match(token)
    if match is None:
        return None
    name, raw_args = match.group(1), match.group(2)
    func = _HELPERS.get(name)
    if func is None:
        return None
    args = [_literal(a) for a in _split_args(raw_args)]
    try:
        return str(func(*args))
    except Exception:                        # noqa: BLE001 - 模板容错
        return ""


def _split_args(text: str) -> list[str]:
    parts, buffer, quote, depth = [], [], "", 0
    for char in text:
        if quote:
            buffer.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            buffer.append(char)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)
    if buffer:
        parts.append("".join(buffer))
    return [p.strip() for p in parts if p.strip()]


def _literal(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def _randstr(length: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(int(length)))


#: 模板插值里可用的辅助函数 (与 nuclei 的 helper 同名)
_HELPERS: dict[str, Callable[..., Any]] = {
    "base64": lambda v: base64.b64encode(str(v).encode()).decode(),
    "base64_decode": lambda v: base64.b64decode(str(v) + "===").decode("utf-8", "replace"),
    "url_encode": lambda v: quote(str(v), safe=""),
    "url_decode": lambda v: unquote(str(v)),
    "to_lower": lambda v: str(v).lower(),
    "to_upper": lambda v: str(v).upper(),
    "trim": lambda v: str(v).strip(),
    "md5": lambda v: hashlib.md5(str(v).encode()).hexdigest(),
    "sha1": lambda v: hashlib.sha1(str(v).encode()).hexdigest(),
    "sha256": lambda v: hashlib.sha256(str(v).encode()).hexdigest(),
    "hex_encode": lambda v: str(v).encode().hex(),
    "concat": lambda *parts: "".join(str(p) for p in parts),
    "join": lambda sep, items: str(sep).join(str(i) for i in items),
    "replace": lambda v, a, b: str(v).replace(str(a), str(b)),
    "randstr": _randstr,
    "rand_text_alpha": lambda n=8: "".join(random.choice(_RAND_ALPHA) for _ in range(int(n))),
    "rand_text_alphanumeric": lambda n=8: "".join(random.choice(_RAND_ALNUM) for _ in range(int(n))),
    "rand_int": lambda lo=0, hi=1000: random.randint(int(lo), int(hi)),
}


# --------------------------------------------------------------------------
# DSL
# --------------------------------------------------------------------------
_ALLOWED_NODES = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.USub,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod,
    ast.Call, ast.Name, ast.Load, ast.Constant, ast.List, ast.Tuple, ast.IfExp,
    ast.In, ast.NotIn, ast.keyword,
)


class DslError(Exception):
    """DSL 语法错误 (模板自身的问题)."""


def _translate(expression: str) -> str:
    """nuclei DSL 的运算符 -> Python 运算符.

    ``&&``/``||``/前缀 ``!`` 是 nuclei 写法; ``!=`` 必须原样保留, 否则
    ``status_code != 404`` 会被翻译坏。
    """
    text = expression.replace("&&", " and ").replace("||", " or ")
    text = re.sub(r"!(?!=)", " not ", text)
    text = re.sub(r"\btrue\b", "True", text)
    text = re.sub(r"\bfalse\b", "False", text)
    # 表达式可能以 ``!`` 开头 (``!contains(body, "x")``), 替换后会留下前导空格;
    # eval 模式下 ast.parse 会把前导空白判为 "unexpected indent"。
    return text.strip()


def evaluate_dsl(expression: str, ctx: ResponseContext) -> Any:
    """安全求值一条 DSL 表达式, 返回其结果 (失败抛 :class:`DslError`)."""
    source = _translate(expression.strip())
    if not source:
        return False
    try:
        with warnings.catch_warnings():
            # 模板里的正则字面量常写成 "\s" / "\." —— Python 会为这种
            # 「无效转义序列」刷一屏 SyntaxWarning, 与我们的判定无关。
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source, mode="eval")
    except SyntaxError as exc:
        raise DslError(f"DSL 语法错误: {expression!r} ({exc.msg})") from exc
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise DslError(f"DSL 使用了不允许的语法: {type(node).__name__}")
        if isinstance(node, ast.Call) and not isinstance(node.func, ast.Name):
            raise DslError("DSL 只允许调用内建函数")
    try:
        return eval(compile(tree, "<dsl>", "eval"),  # noqa: S307 - 已白名单校验
                    {"__builtins__": {}}, _builder(ctx))
    except DslError:
        raise
    except Exception as exc:                          # noqa: BLE001 - 求值期错误
        raise DslError(f"DSL 求值失败: {expression!r} ({exc})") from exc


def _builder(ctx: ResponseContext) -> dict[str, Any]:
    scope: dict[str, Any] = {name: func(ctx) for name, func in _BUILTIN_VARS.items()}
    scope.update(_DSL_FUNCS)
    scope["header"] = lambda name: ctx.header(str(name))
    scope["cookie"] = lambda name: ctx.header("cookie")
    scope.update({k: v for k, v in ctx.extracted.items()})
    scope.update(ctx.variables)
    return scope


# ---- DSL 函数实现 ----
def _contains(haystack: Any, needle: Any) -> bool:
    return str(needle) in str(haystack)


def _icontains(haystack: Any, needle: Any) -> bool:
    return str(needle).lower() in str(haystack).lower()


def _regex(pattern: Any, value: Any) -> bool:
    try:
        with warnings.catch_warnings():
            # 模板里的正则可能是 ``[[``/``(?<`` 这类 Python 会告警的写法;
            # 告警与「是否命中」无关, 不该刷屏。
            warnings.simplefilter("ignore", FutureWarning)
            return re.search(str(pattern), str(value)) is not None
    except (re.error, TypeError):
        return False


def _compare_versions(left: Any, right: Any) -> bool:
    """``compare_versions(v1, '>=1.2.3')`` 风格的版本比较."""
    text = str(right).strip()
    match = re.match(r"^(>=|<=|!=|==|>|<)?\s*(.+)$", text)
    operator = (match.group(1) if match and match.group(1) else "==")
    target = (match.group(2) if match else text).strip()
    return _version_cmp(str(left), target, operator)


def _version_cmp(left: str, right: str, operator: str) -> bool:
    def parts(value: str) -> list:
        return [int(p) if p.isdigit() else p
                for p in re.split(r"[.\-_+]", value.strip())]

    a, b = parts(left), parts(right)
    for index in range(max(len(a), len(b))):
        x = a[index] if index < len(a) else 0
        y = b[index] if index < len(b) else 0
        if isinstance(x, int) and isinstance(y, int):
            if x != y:
                return {"==": False, "!=": True, ">": x > y, "<": x < y,
                        ">=": x > y, "<=": x < y}[operator]
            continue
        sx, sy = str(x), str(y)
        if sx != sy:
            return {"==": False, "!=": True, ">": sx > sy, "<": sx < sy,
                    ">=": sx > sy, "<=": sx < sy}[operator]
    return operator in ("==", ">=", "<=")


def _equals_any(value: Any, candidates: Any) -> bool:
    items = candidates if isinstance(candidates, (list, tuple)) else [candidates]
    return any(str(value) == str(item) for item in items)


def _contains_all(haystack: Any, needles: Any) -> bool:
    items = needles if isinstance(needles, (list, tuple)) else [needles]
    text = str(haystack)
    return all(str(n) in text for n in items)


def _contains_any(haystack: Any, needles: Any) -> bool:
    items = needles if isinstance(needles, (list, tuple)) else [needles]
    text = str(haystack)
    return any(str(n) in text for n in items)


def _to_number(value: Any) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0


def _substr(value: Any, start: Any, length: Any = None) -> str:
    text = str(value)
    begin = int(_to_number(start))
    if length is None:
        return text[begin:]
    return text[begin:begin + int(_to_number(length))]


def _json_minify(value: Any) -> str:
    import json
    try:
        return json.dumps(json.loads(str(value)), separators=(",", ":"))
    except (ValueError, TypeError):
        return str(value)


def _remove_bad_chars(value: Any, charset: Any) -> str:
    bad = set(str(charset))
    return "".join(c for c in str(value) if c not in bad)


_DSL_FUNCS: dict[str, Callable[..., Any]] = {
    "contains": _contains,
    "icontains": _icontains,
    "contains_all": _contains_all,
    "contains_any": _contains_any,
    "equals_any": _equals_any,
    "regex": _regex,
    "compare_versions": _compare_versions,
    "tolower": lambda v: str(v).lower(),
    "toupper": lambda v: str(v).upper(),
    "trim": lambda v: str(v).strip(),
    "trim_space": lambda v: str(v).strip(" \t\r\n"),
    "trim_left": lambda v: str(v).lstrip(),
    "trim_right": lambda v: str(v).rstrip(),
    "len": lambda v: len(v),
    "count": lambda v: len(v),
    "to_number": _to_number,
    "to_string": lambda v: str(v),
    "startswith": lambda v, p: str(v).startswith(str(p)),
    "endswith": lambda v, p: str(v).endswith(str(p)),
    "is_empty": lambda v: not v,
    "concat": lambda *parts: "".join(str(p) for p in parts),
    "join": lambda sep, items: str(sep).join(str(i) for i in items),
    "split": lambda v, sep: str(v).split(str(sep)),
    "substr": _substr,
    "index_of": lambda v, n: str(v).find(str(n)),
    "replace": lambda v, a, b: str(v).replace(str(a), str(b)),
    "replace_regex": lambda v, p, r: re.sub(str(p), str(r), str(v)),
    "remove_bad_chars": _remove_bad_chars,
    "md5": lambda v: hashlib.md5(str(v).encode()).hexdigest(),
    "sha1": lambda v: hashlib.sha1(str(v).encode()).hexdigest(),
    "sha256": lambda v: hashlib.sha256(str(v).encode()).hexdigest(),
    "base64": lambda v: base64.b64encode(str(v).encode()).decode(),
    "base64_decode": lambda v: base64.b64decode(str(v) + "===").decode("utf-8", "replace"),
    "hex_encode": lambda v: str(v).encode().hex(),
    "hex_decode": lambda v: bytes.fromhex(str(v)).decode("utf-8", "replace"),
    "url_encode": lambda v: quote(str(v), safe=""),
    "url_decode": lambda v: unquote(str(v)),
    "json_minify": _json_minify,
    "unix_time": lambda: int(time.time()),
    "rand_int": lambda lo=0, hi=1000: random.randint(int(lo), int(hi)),
    "rand_text_alpha": lambda n=8: "".join(random.choice(_RAND_ALPHA) for _ in range(int(n))),
    "rand_text_alphanumeric": lambda n=8: "".join(random.choice(_RAND_ALNUM) for _ in range(int(n))),
    "rand_text_numeric": lambda n=8: "".join(random.choice(string.digits) for _ in range(int(n))),
    "dsl": lambda v: v,
}


def dsl_health() -> dict[str, object]:
    """DSL 函数覆盖率 (供引擎状态展示)."""
    return {"functions": len(_DSL_FUNCS), "helpers": len(_HELPERS)}
