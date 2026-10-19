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
from urllib.parse import parse_qsl, unquote, urlsplit

from ...core.models import HttpRequest
from ..parser import parse_json_arguments, parse_multipart, parse_xml_values
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
    removed_tag_targets: list[tuple[str, str]] = field(default_factory=list)

    # ------------------------------------------------------------------
    # 构造
    # ------------------------------------------------------------------
    def __post_init__(self) -> None:
        self._cache: dict[str, list[Match]] = {}
        self._get_args = [Match(name="ARGS", key=k, value=v)
                          for k, v in query_pairs(self.request.query)]
        self._forced_body_processor: str | None = None
        self._parse_body()

    def _parse_body(self, processor: str | None = None) -> None:
        form = (self.request.body.decode("latin-1") if processor == "URLENCODED"
                else self._body_form() if processor is None else "")
        self._post_args = [Match(name="ARGS", key=k, value=v)
                           for k, v in query_pairs(form)]
        self._body_error = False
        self._parsed_body_hides_raw = False
        self._body_processor = "URLENCODED"
        self._multipart = None
        media_type = self.request.content_type.lower().partition(";")[0].strip()
        if processor == "JSON" or (processor is None and (media_type == "application/json" or media_type.endswith("+json"))):
            self._body_processor = "JSON"
            fields = parse_json_arguments(self.request.body, array_prefix="array_")
            self._body_error = fields is None
            if fields is None:
                fields = [("BODY", self.request.body.decode("utf-8", "replace"))]
            self._post_args = [Match(name="ARGS", key=f"json.{k}" if k else "json", value=v)
                               for k, v in fields]
        self._xml_text: list[Match] = []
        self._xml_attributes: list[Match] = []
        if processor == "XML" or (processor is None and (media_type in ("application/xml", "text/xml") or media_type.endswith("+xml"))):
            self._parsed_body_hides_raw = True
            self._body_processor = "XML"
            xml = parse_xml_values(self.request.body)
            self._body_error = xml is None
            if xml is None:
                self._xml_text = [Match(name="XML", value=self.request.body.decode("utf-8", "replace"))]
            else:
                text, attributes = xml
                self._xml_text = [Match(name="XML", value=text)]
                self._xml_attributes = [Match(name="XML", key=k, value=v) for k, v in attributes]
        if processor == "MULTIPART" or (processor is None and media_type == "multipart/form-data"):
            self._parsed_body_hides_raw = True
            self._body_processor = "MULTIPART"
            self._multipart = parse_multipart(self.request.body, self.request.content_type)
            self._body_error = bool(self._multipart.errors)
            self._post_args = [Match(name="ARGS", key=p.name, value=p.value.decode("latin-1"))
                               for p in self._multipart.parts if p.filename is None]
            if self._body_error:
                self._post_args.append(Match(name="ARGS", key="BODY", value=self.request.body.decode("latin-1")))
        self._args = self._parse_args()

    def set_body_processor(self, processor: str) -> bool:
        """Apply a ctl override to body fields, error flags and cached variables."""
        processor = processor.upper()
        if processor not in {"JSON", "XML", "URLENCODED", "MULTIPART"}:
            return False
        if processor != self._forced_body_processor:
            self._parse_body(processor)
            self._forced_body_processor = processor
            self.invalidate()
        self.set_tx("reqbody_processor_override", processor)
        return True

    # ------------------------------------------------------------------
    # 静态变量
    # ------------------------------------------------------------------
    def _parse_args(self) -> list[Match]:
        """Combine query fields with decoded form or JSON body fields."""
        return self._get_args + self._post_args

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
        # Match ModSecurity's cookie collection, including name-only entries.
        # Only the final pair loses trailing whitespace; other value spaces are data.
        for chunk in raw.rstrip(" \t\r\n\v\f").split(";"):
            key, _, value = chunk.partition("=")
            key = key.lstrip(" \t\r\n\v\f")
            if key:
                out.append(Match(name="REQUEST_COOKIES", value=value, key=key))
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
        elif name == "ARGS_COMBINED_SIZE":
            size = sum(len(m.key) + len(m.value) for m in self._get_args)
            text_values = self._body_processor == "JSON"
            text_names = text_values or self._body_processor == "MULTIPART"
            for argument in self._post_args:
                # Structured parsers return text names/JSON values; forms and
                # multipart values already use byte-preserving Latin-1 strings.
                size += len(argument.key.encode("utf-8", "surrogatepass")) if text_names else len(argument.key)
                size += len(argument.value.encode("utf-8", "surrogatepass")) if text_values else len(argument.value)
            matches = [Match(name=name, value=str(size))]
        elif name == "ARGS_GET":
            matches = list(self._get_args)
        elif name == "ARGS_POST":
            matches = list(self._post_args)
        elif name == "ARGS_NAMES":
            matches = [Match(name="ARGS_NAMES", value=m.key, key=m.key)
                       for m in self._args]
        elif name == "ARGS_GET_NAMES":
            matches = self._get_args
            matches = [Match(name="ARGS_GET_NAMES", value=m.key, key=m.key)
                       for m in matches]
        elif name == "ARGS_POST_NAMES":
            matches = self._post_args
            matches = [Match(name="ARGS_POST_NAMES", value=m.key, key=m.key)
                       for m in matches]

        elif name == "REQUEST_HEADERS":
            matches = self.headers
        elif name == "REQUEST_HEADERS_NAMES":
            matches = [Match(name="REQUEST_HEADERS_NAMES", value=k, key=k)
                       for k in request.headers]
        elif name == "REQUEST_COOKIES":
            matches = self._cookies()
        elif name == "REQUEST_COOKIES_NAMES":
            matches = [Match(name="REQUEST_COOKIES_NAMES", value=m.key, key=m.key)
                       for m in self._cookies()]
        elif name == "XML":
            # shortcut: CRS's two XPath selectors only; extend for custom XPath rules.
            matches = (self._xml_text if selector == "/*" else
                       self._xml_attributes if selector == "//@*" else [])

        elif name == "TX":
            if selector and not (selector.startswith("/") and selector.endswith("/")):
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
                             value=unquote(urlsplit(request.target).path or "/", encoding="latin-1"))]
        elif name == "REQUEST_BASENAME":
            base = re.split(r"[/\\]", unquote(urlsplit(request.target).path or "/", encoding="latin-1"))[-1]
            matches = [Match(name="REQUEST_BASENAME", value=base)]
        elif name == "REQUEST_BODY_LENGTH":
            matches = [Match(name=name, value=str(len(request.body)))]
        elif name == "REQUEST_BODY":
            text = request.body.decode("latin-1", "replace")
            # XML/MIME syntax is not a field value. JSON retains its raw surface
            # too, including keys whose values are arrays or empty containers.
            # Parsing errors retain raw inspection to avoid a blind spot.
            available = not self._parsed_body_hides_raw or self._body_error
            matches = [Match(name=name, value=text)] if text and available else []
        elif name == "REQBODY_PROCESSOR":
            matches = [Match(name="REQBODY_PROCESSOR",
                             value=self.body_processor())]
        elif name in ("REQBODY_ERROR", "REQBODY_PROCESSOR_ERROR"):
            matches = [Match(name=name, value=str(int(self._body_error)))]
        elif name == "UNIQUE_ID":
            matches = []

        elif name in ("FILES", "FILES_NAMES", "FILES_SIZES", "FILES_COMBINED_SIZE",
                      "MULTIPART_PART_HEADERS", "MULTIPART_NAME", "MULTIPART_FILENAME"):
            parts = self._multipart.parts if self._multipart else []
            files = [p for p in parts if p.filename is not None]
            if name == "FILES_COMBINED_SIZE":
                matches = [Match(name=name, value=str(sum(len(p.value) for p in files)))]
            elif name == "MULTIPART_PART_HEADERS":
                matches = [Match(name=name, key=p.name, value=line) for p in parts for line in p.headers]
            elif name == "MULTIPART_NAME":
                matches = [Match(name=name, key=p.name, value=p.name) for p in parts]
            else:
                matches = [Match(name=name, key=p.name,
                                 value=p.name if name == "FILES_NAMES" else
                                 str(len(p.value)) if name == "FILES_SIZES" else p.filename)
                           for p in files]
        elif name == "FILES_TMPNAMES":
            matches = []  # Inspection never writes uploaded content to disk.

        elif name == "MATCHED_VAR":
            matches = [Match(name="MATCHED_VAR", value=self.matched_var)] \
                if self.matched_var else []
        elif name == "MATCHED_VAR_NAME":
            matches = [Match(name="MATCHED_VAR_NAME", value=self.matched_var_name)] \
                if self.matched_var_name else []
        elif name in ("MATCHED_VARS", "MATCHED_VARS_NAMES"):
            matches = [Match(name=name, key=key, value=value if name == "MATCHED_VARS" else key)
                       for _, key, value in self.matched]
        else:
            matches = []

        if selector and (name.startswith("ARGS") or name == "TX" or name.startswith("FILES")
                         or name.startswith("REQUEST_HEADERS") or name.startswith("REQUEST_COOKIES")
                         or name.startswith("MULTIPART") or name.startswith("MATCHED_VARS")):
            insensitive = name == "TX" or name.startswith(("REQUEST_HEADERS", "REQUEST_COOKIES"))
            if len(selector) > 2 and selector.startswith("/") and selector.endswith("/"):
                try:
                    pattern = re.compile(selector[1:-1], re.I)
                except re.error:
                    return []
                matches = [m for m in matches if pattern.search(m.key)]
            else:
                matches = [m for m in matches if (_ci_equal(m.key, selector) if insensitive else m.key == selector)]
        if variable.negated:
            # 取反目标在当前实现中用于「排除」语义; 由引擎在算子层处理
            return matches
        return matches

    def body_processor(self) -> str:
        return self._body_processor

    # ------------------------------------------------------------------
    # TX
    # ------------------------------------------------------------------
    def get_tx(self, key: str, default: str = "") -> str:
        return self.tx.get(key.lower(), default)

    def set_tx(self, key: str, value: str) -> None:
        self.tx[key.lower()] = value
        self.invalidate()

    def get_tx_int(self, key: str, default: int = 0) -> int:
        try:
            return int(float(self.tx.get(key.lower(), default)))
        except (TypeError, ValueError, OverflowError):
            return default

    def capture(self, groups: list[str]) -> None:
        """记录捕获组 (TX:0 = 完整匹配, TX:1.. = 分组)."""
        for index, value in enumerate(groups[:10]):
            self.tx[str(index)] = value
        for index in range(len(groups), 10):
            self.tx.pop(str(index), None)
        self.invalidate()

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
    """Keep decoded argument bytes in Latin-1 strings for SecRule transforms.

    UTF-8 text decoding here would replace invalid bytes and change byte lengths
    before rules can apply their explicit decoding/validation transformations.
    """
    return parse_qsl(query, keep_blank_values=True, encoding="latin-1", errors="strict")


def split_target(target: str) -> tuple[str, str]:
    parts = urlsplit(target)
    return parts.path or "/", parts.query
