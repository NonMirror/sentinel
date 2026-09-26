"""事务状态与变量解析 (ModSecurity 变量空间).

一次请求 = 一个 :class:`Transaction`. 它把 :class:`~sentinel.core.models.HttpRequest`
摊平成 ModSecurity 的变量集合, 并持有 ``TX`` 集合 (异常评分 / 捕获组 / CRS 状态)。

两个容易踩的坑, 这里显式处理:

* **TX 键大小写不敏感**: CRS 用 ``setvar:'tx.blocking_inbound_anomaly_score=...'``
  写, 却用 ``%{TX.BLOCKING_INBOUND_ANOMALY_SCORE}`` 读。若按键区分大小写,
  CRS 会静默失效 —— 所以 TX 键统一小写归一。
* **``&`` 计数与「变量存在性」**: ``&TX:foo`` 在未设置时返回 0, CRS 的初始化
  规则完全依赖这一点 (``SecRule &TX:x "@eq 0"`` 只在该变量未定义时命中)。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from ...core.models import HttpRequest
from .syntax import Variable

_MACRO_RE = re.compile(r"%\{([^}]*)\}")


@dataclass(slots=True)
class Match:
    """一次变量命中: 变量名 + 归一化后的值 + 原始值."""

    name: str
    value: str
    key: str = ""


@dataclass
class Transaction:
    """单个请求的规则执行上下文."""

    request: HttpRequest
    #: TX 集合 (键统一小写)
    tx: dict[str, str] = field(default_factory=dict)
    #: 本事务的匹配记录 (规则 id -> 命中信息)
    matched: list[tuple[int, str, str]] = field(default_factory=list)
    #: 上一次匹配的变量 (供 %{MATCHED_VAR} 使用)
    matched_var: str = ""
    matched_var_name: str = ""
    #: capture 写入的 TX:0..TX:9
    _cache: dict[str, list[Match]] = field(default_factory=dict)
    #: 运行时被 ctl 关闭 / 移除的规则
    disabled_rules: set[int] = field(default_factory=set)
    removed_targets: list[tuple[int, str]] = field(default_factory=list)

    # ------------------------------------------------------------------
    # 构造
    # ------------------------------------------------------------------
    def __post_init__(self) -> None:
        self._cache: dict[str, list[Match]] = {}
        self._args = self._parse_args()

    # ------------------------------------------------------------------
    # 静态变量
    # ------------------------------------------------------------------
    def _parse_args(self) -> list[Match]:
        """ARGS = QUERY_STRING 参数 + urlencoded 请求体参数 (ModSecurity 语义)."""
        out: list[Match] = []
        seen: set[tuple[str, int]] = set()
        for position, source in enumerate((self.request.query, self._body_form())):
            if not source:
                continue
            for key, value in parse_qsl(source, keep_blank_values=True):
                marker = (key, 0 if position == 0 else 1)
                if marker in seen:
                    continue
                seen.add(marker)
                out.append(Match(name="ARGS", value=value, key=key))
        return out

    def _body_form(self) -> str:
        content_type = self.request.content_type.lower()
        # ModSecurity 在请求缺 Content-Type 时按 urlencoded 处理请求体; 只有显式
        # 声明了别的类型 (json / multipart / xml) 才不按表单解析。
        if content_type and "application/x-www-form-urlencoded" not in content_type:
            return ""
        return self.request.body.decode("latin-1", "replace")

    @property
    def headers(self) -> list[Match]:
        return [Match(name="REQUEST_HEADERS", value=value, key=key)
                for key, value in self.request.headers.items()]

    def _cookies(self) -> list[Match]:
        raw = self.request.get_header("Cookie")
        if not raw:
            return []
        out: list[Match] = []
        for chunk in raw.split(";"):
            key, sep, value = chunk.partition("=")
            if sep:
                out.append(Match(name="REQUEST_COOKIES", value=value.strip(),
                                 key=key.strip()))
        return out

    # ------------------------------------------------------------------
    # 变量解析
    # ------------------------------------------------------------------
    def resolve(self, variable: Variable) -> list[Match]:
        """解析一个目标, 返回全部命中 (未命中返回空列表).

        ``&VAR`` (count) 返回**命中个数**而非值 —— CRS 的整套默认值填充都写成
        ``SecRule &TX:x "@eq 0" "...,setvar:'tx.x=...'"``, 少了这一步, CRS 会
        带着一堆空变量运行, 表现为大面积误报 (例如 ``allowed_methods`` 为空时
        所有正常请求都会命中 911100)。
        """
        cache_key = str(variable)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        matches = self._resolve_uncached(variable)
        if variable.count:
            matches = [Match(name=variable.name, value=str(len(matches)),
                             key=":".join(variable.selectors))]
        if len(self._cache) < 512:
            self._cache[cache_key] = matches
        return matches

    def _resolve_uncached(self, variable: Variable) -> list[Match]:  # noqa: C901
        name = variable.name
        selector = variable.selectors[0] if variable.selectors else None
        request = self.request

        if name == "ARGS":
            matches = list(self._args)
        elif name == "ARGS_GET":
            matches = [m for m in self._args
                       if any(k == m.key for k, _ in
                              parse_qsl(request.query, keep_blank_values=True))]
        elif name == "ARGS_POST":
            form = set(parse_qsl(self._body_form(), keep_blank_values=True))
            matches = [m for m in self._args if any(k == m.key for k, _ in form)]
        elif name == "ARGS_NAMES":
            matches = [Match(name="ARGS_NAMES", value=m.key, key=m.key)
                       for m in self._args]
        elif name == "ARGS_GET_NAMES":
            matches = [m for m in self._args if self._is_get_arg(m.key)]
            matches = [Match(name="ARGS_GET_NAMES", value=m.key, key=m.key)
                       for m in matches]
        elif name == "ARGS_POST_NAMES":
            matches = [m for m in self._args if not self._is_get_arg(m.key)]
            matches = [Match(name="ARGS_POST_NAMES", value=m.key, key=m.key)
                       for m in matches]

        elif name == "REQUEST_HEADERS":
            matches = self.headers
            if selector:
                matches = [m for m in matches if _ci_equal(m.key, selector)]
        elif name == "REQUEST_HEADERS_NAMES":
            matches = [Match(name="REQUEST_HEADERS_NAMES", value=k, key=k)
                       for k in request.headers]
        elif name == "REQUEST_COOKIES":
            matches = self._cookies()
            if selector:
                matches = [m for m in matches if _ci_equal(m.key, selector)]
        elif name == "REQUEST_COOKIES_NAMES":
            matches = [Match(name="REQUEST_COOKIES_NAMES", value=m.key, key=m.key)
                       for m in self._cookies()]

        elif name == "TX":
            if selector:
                value = self.tx.get(selector.lower())
                matches = [] if value is None else [
                    Match(name="TX", value=str(value), key=selector)]
            else:
                matches = [Match(name="TX", value=v, key=k)
                           for k, v in sorted(self.tx.items())]
        elif name == "IP":
            matches = [Match(name="IP", value=request.remote_addr)]
        elif name == "REMOTE_ADDR":
            matches = [Match(name="REMOTE_ADDR", value=request.remote_addr)]
        elif name == "REMOTE_PORT":
            matches = [Match(name="REMOTE_PORT", value=str(request.remote_port))]

        elif name == "REQUEST_LINE":
            matches = [Match(name="REQUEST_LINE",
                             value=f"{request.method} {request.target} {request.version}")]
        elif name == "REQUEST_METHOD":
            matches = [Match(name="REQUEST_METHOD", value=request.method)]
        elif name == "REQUEST_PROTOCOL":
            matches = [Match(name="REQUEST_PROTOCOL", value=request.version)]
        elif name == "REQUEST_URI":
            matches = [Match(name="REQUEST_URI", value=request.target)]
        elif name == "REQUEST_URI_RAW":
            matches = [Match(name="REQUEST_URI_RAW", value=request.target)]
        elif name == "QUERY_STRING":
            matches = [Match(name="QUERY_STRING", value=request.query)] \
                if request.query else []
        elif name == "REQUEST_FILENAME":
            matches = [Match(name="REQUEST_FILENAME",
                             value=unquote_plus(request.path or "/"))]
        elif name == "REQUEST_BASENAME":
            base = (request.path or "/").rsplit("/", 1)[-1]
            matches = [Match(name="REQUEST_BASENAME", value=unquote_plus(base))] \
                if base else []
        elif name in ("REQUEST_BODY", "REQUEST_BODY_LENGTH"):
            text = request.body.decode("latin-1", "replace")
            matches = [Match(name=name, value=text)] if text else []
        elif name == "REQBODY_PROCESSOR":
            matches = [Match(name="REQBODY_PROCESSOR",
                             value=self.body_processor())]
        elif name == "UNIQUE_ID":
            matches = []

        elif name == "FILES":
            matches = []
        elif name in ("FILES_NAMES", "FILES_SIZES", "FILES_TMPNAMES"):
            matches = []

        elif name == "MATCHED_VAR":
            matches = [Match(name="MATCHED_VAR", value=self.matched_var)] \
                if self.matched_var else []
        elif name == "MATCHED_VAR_NAME":
            matches = [Match(name="MATCHED_VAR_NAME", value=self.matched_var_name)] \
                if self.matched_var_name else []
        else:
            matches = []

        if variable.negated:
            # 取反目标在当前实现中用于「排除」语义; 由引擎在算子层处理
            return matches
        return matches

    def _is_get_arg(self, key: str) -> bool:
        return any(k == key for k, _ in parse_qsl(self.request.query,
                                                  keep_blank_values=True))

    def body_processor(self) -> str:
        ctype = self.request.content_type.lower()
        if not self.request.body:
            return "URLENCODED"
        if "multipart/form-data" in ctype:
            return "MULTIPART"
        if "xml" in ctype:
            return "XML"
        if "json" in ctype:
            return "JSON"
        return "URLENCODED"

    # ------------------------------------------------------------------
    # TX
    # ------------------------------------------------------------------
    def get_tx(self, key: str, default: str = "") -> str:
        return self.tx.get(key.lower(), default)

    def set_tx(self, key: str, value: str) -> None:
        self.tx[key.lower()] = value

    def get_tx_int(self, key: str, default: int = 0) -> int:
        try:
            return int(float(self.tx.get(key.lower(), default)))
        except (TypeError, ValueError):
            return default

    def capture(self, groups: list[str]) -> None:
        """记录捕获组 (TX:0 = 完整匹配, TX:1.. = 分组)."""
        for index, value in enumerate(groups[:10]):
            self.tx[str(index)] = value
        for index in range(len(groups), 10):
            self.tx.pop(str(index), None)

    # ------------------------------------------------------------------
    # 宏展开 %{...}
    # ------------------------------------------------------------------
    def expand(self, text: str) -> str:
        """展开 ``%{...}`` 宏 (不区分大小写地查找集合)."""
        if "%{" not in text:
            return text

        def replace(match: re.Match[str]) -> str:
            token = match.group(1).strip()
            return self.lookup_macro(token)

        return _MACRO_RE.sub(replace, text)

    def lookup_macro(self, token: str) -> str:
        if not token:
            return ""
        collection, _, key = token.partition(".")
        collection = collection.strip().upper()
        key = key.strip()
        variable = Variable(name=collection,
                            selectors=(key,) if key else ())
        matches = self.resolve(variable)
        if not matches:
            return ""
        return ", ".join(m.value for m in matches)

    def invalidate(self) -> None:
        """规则修改了 ARGS/TX 之后清空缓存."""
        self._cache.clear()


def _ci_equal(left: str, right: str) -> bool:
    return left.lower() == right.lower()


def query_pairs(query: str) -> list[tuple[str, str]]:
    return parse_qsl(query, keep_blank_values=True)


def split_target(target: str) -> tuple[str, str]:
    parts = urlsplit(target)
    return parts.path or "/", parts.query
