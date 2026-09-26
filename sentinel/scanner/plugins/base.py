"""原生主动扫描插件框架 — w13scan 插件体系的原生重写 (Sentinel 自研).

w13scan 的插件模型是 ``PluginBase.audit()``: 引擎把一份 (请求, 响应) 交给插件, 插件
自行组合 payload 并通过 ``self.success(result)`` 上报。Sentinel 保留"插件即检测单元"
这一形态, 但把隐式上下文显式化:

  * :class:`PluginContext`  — 只读扫描上下文 + 注入辅助, 取代 w13scan 挂在插件实例上的
    ``self.requests`` / ``self.response`` 全局态 (w13scan 的插件实例是复用的, 那个设计
    在多线程下本身就是竞态源);
  * :class:`Plugin`         — 声明式元数据 (``category`` / ``severity`` / ``cwe`` /
    ``owasp`` / ``scope`` / ``deep_only``) + ``run(ctx) -> list[Finding]``, 取代
    w13scan 只有一个 ``name`` 字符串的自由格式, 便于分级、报表与选择性启用;
  * :class:`PluginRegistry` — **独立注册表**。刻意与 :mod:`sentinel.scanner.detectors`
    的 ``DETECTORS`` 分开: 两者服务于不同引擎 (``w13scan`` 与 ``builtin``), 合并会让
    "多引擎融合"退化成同一份代码跑两遍, 也就失去了交叉验证的意义。

插件按 ``scope`` 分三档执行, 对应 w13scan 的 PerFile / PerFolder / PerServer:

============  ==========================================================
``param``     逐 (接口, 参数) 执行 — SQLi / XSS / 命令注入 ...
``endpoint``  逐接口执行一次     — CORS / 信息泄露 ...
``server``    每目标执行一次     — 备份文件 / 未授权路径 / 面板探测 ...
============  ==========================================================

约定: 插件**不允许**吞掉异常, 抛出的异常由引擎 :class:`~sentinel.scanner.engines.
w13scan.W13ScanEngine` 捕获并计入 ``last_error`` —— 单个插件崩溃不影响整体扫描。
"""
from __future__ import annotations

import html
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Iterator, Sequence
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from ...core.models import Finding, Severity
from ..client import HttpClient, HttpResult
from ..crawler import Endpoint, Target
from ..detectors import OobRegistry

# --------------------------------------------------------------------------
# 作用域 / 分类
# --------------------------------------------------------------------------
SCOPE_PARAM = "param"
SCOPE_ENDPOINT = "endpoint"
SCOPE_SERVER = "server"
SCOPES = (SCOPE_PARAM, SCOPE_ENDPOINT, SCOPE_SERVER)

#: 分类 -> 中文标签 (TUI / 报告展示)
PLUGIN_CATEGORIES: dict[str, str] = {
    "sqli": "SQL 注入",
    "xss": "跨站脚本",
    "rce": "命令/代码执行",
    "lfi": "文件读取/路径穿越",
    "ssrf": "服务端请求伪造",
    "redirect": "开放重定向",
    "crlf": "响应头注入",
    "jsonp": "JSONP 劫持",
    "cors": "跨域配置错误",
    "xxe": "XML 外部实体",
    "ssti": "模板注入",
    "csrf": "跨站请求伪造",
    "upload": "文件上传",
    "auth": "认证与授权",
    "smuggling": "HTTP 请求走私",
    "deserialization": "反序列化",
    "backup": "备份文件泄漏",
    "dirlist": "目录与源码泄漏",
    "info": "信息泄漏",
}

#: OWASP Top 10 (2021) 简写, 便于插件声明时少打字
A01, A02, A03, A04, A05 = "A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021"
A06, A07, A08, A09, A10 = "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021"


# --------------------------------------------------------------------------
# 通用小工具 (被多个插件家族共用)
# --------------------------------------------------------------------------
def with_param(url: str, param: str, payload: str, safe: str = "") -> str:
    """把 ``payload`` 写入 URL 的 ``param`` 参数 (其余参数保留)."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = payload
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query, quote_via=quote, safe=safe), ""))


def snippet(text: str, needle: str, width: int = 80) -> str:
    """截取 ``needle`` 附近的片段作为证据, 便于报告定位."""
    if not needle:
        return text[:width * 2]
    index = text.lower().find(needle.lower())
    if index < 0:
        return text[:width * 2]
    return text[max(0, index - 24):index + len(needle) + width][:240]


def similarity(left: str, right: str, limit: int = 4000) -> float:
    """两段响应的相似度 (0..1). 用于布尔盲注 / 未授权的差分判定."""
    a, b = left[:limit], right[:limit]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def reflected_raw(body: str, payload: str) -> bool:
    """``payload`` 是否**未经 HTML 实体编码**地出现在 ``body`` 中.

    这是反射型 XSS 与"仅回显但已转义"的分水岭: 若响应里只有 ``&lt;script&gt;``
    而没有 ``<script>``, 说明服务端做了实体编码, 不构成 XSS。
    """
    if payload not in body:
        return False
    escaped = html.escape(payload, quote=False)
    return not (escaped != payload and escaped in body and payload not in body)


def is_ip_host(host: str) -> bool:
    """主机名是否为 IP 字面量 (备份域名扫描对 IP 没有意义)."""
    name = host.split(":")[0]
    return all(part.isdigit() for part in name.split(".")) and name.count(".") == 3


# --------------------------------------------------------------------------
# 上下文
# --------------------------------------------------------------------------
@dataclass
class PluginContext:
    """单次插件执行的只读上下文 + 注入辅助.

    ``endpoint`` 为 :class:`~sentinel.scanner.crawler.Endpoint`; ``param`` / ``position``
    描述本次要打的位置 (``query`` | ``form`` | ``endpoint`` | ``server``)。
    """

    client: HttpClient
    target: Target
    endpoint: Endpoint
    param: str = ""
    position: str = "query"
    deep: bool = False
    time_delay: int = 3
    time_threshold_s: float = 2.4
    oob: OobRegistry | None = None
    oob_host: str = "127.0.0.1"
    oob_port: int = 9999
    findings: list[Finding] = field(default_factory=list)

    # ---------------- 地址 ----------------
    @property
    def base_url(self) -> str:
        parts = urlsplit(self.target.base_url)
        return f"{parts.scheme}://{parts.netloc}"

    def absolute(self, path: str) -> str:
        """把站内路径拼成绝对 URL."""
        return self.base_url.rstrip("/") + "/" + path.lstrip("/")

    @property
    def host(self) -> str:
        return urlsplit(self.target.base_url).netloc

    # ---------------- 请求 ----------------
    def request(self, method: str, url: str, body: bytes | str | None = None,
                headers: dict[str, str] | None = None) -> HttpResult:
        return self.client.request(method, url,
                                   body.encode() if isinstance(body, str) else body,
                                   headers)

    def raw(self, url: str, headers: dict[str, str] | None = None,
            method: str = "GET") -> HttpResult:
        return self.client.request(method, url, None, headers)

    def inject(self, payload: str, *, param: str | None = None,
               position: str | None = None, safe: str = "",
               method: str | None = None) -> HttpResult:
        """把 ``payload`` 注入到指定参数.

        ``safe`` 控制 URL 编码白名单: 路径穿越 / 命令拼接这类载荷需要保留 ``/`` ``\\``
        等字符的原貌, 否则服务端看到的语义就变了。
        """
        param = self.param if param is None else param
        position = position or self.position
        if position == "form":
            fields = {name: "1" for name in (self.endpoint.form_fields or [param])}
            fields[param] = payload
            body = urlencode(fields, quote_via=quote, safe=safe)
            return self.request(method or "POST", self.endpoint.url, body)
        return self.request(method or "GET",
                            with_param(self.endpoint.url, param, payload, safe))

    def inject_body(self, body: bytes | str, content_type: str = "application/xml",
                    method: str = "POST") -> HttpResult:
        """整体替换请求体 (XXE / 上传这类需要自定义 body 的插件使用)."""
        payload = body.encode() if isinstance(body, str) else body
        return self.client.request(method, self.endpoint.url, payload,
                                   {"Content-Type": content_type})

    # ---------------- 结果 ----------------
    def add(self, **kwargs) -> Finding:
        """登记一条漏洞发现 (自动带上引擎标识)."""
        kwargs.setdefault("conn_id", "w13scan")
        finding = Finding(**kwargs)
        self.findings.append(finding)
        return finding


# --------------------------------------------------------------------------
# 插件基类
# --------------------------------------------------------------------------
class Plugin(ABC):
    """主动扫描插件基类.

    子类至少要给出 ``name`` / ``title`` / ``category`` / ``severity`` / ``cwe`` /
    ``owasp`` 与 ``run``。``name`` 沿用 w13scan 的插件名 (``sqli_error`` / ``xss`` /
    ``net_xss`` / ``webpack`` ...), 便于与上游插件目录对照。
    """

    #: w13scan 插件名 (注册表主键, 全局唯一)
    name: str = ""
    #: 中文标题 (报告展示)
    title: str = ""
    category: str = "info"
    severity: Severity = Severity.MEDIUM
    cwe: str = ""
    owasp: str = ""
    description: str = ""
    #: 执行档位: param / endpoint / server
    scope: str = SCOPE_PARAM
    #: 仅深度扫描启用 (慢 / 侵入性强)
    deep_only: bool = False
    #: 参数名提示; 空元组或含 ``*`` 表示通用
    param_hints: tuple[str, ...] = ()
    #: 适用的注入位置
    positions: tuple[str, ...] = ("query", "form")
    references: tuple[str, ...] = ()

    @abstractmethod
    def run(self, ctx: PluginContext) -> list[Finding]:
        """执行检测并返回发现 (可以同时写入 ``ctx.findings``)."""

    # ---------------- 选择 ----------------
    def matches(self, param: str, position: str = "query") -> bool:
        """参数名提示是否命中 (参数级插件在选择阶段过滤, 避免无谓请求).

        w13scan 还会把载荷打进 Cookie (``PLACE.COOKIE``); Sentinel 的爬虫不采集
        Cookie, 因此 ``positions`` 只支持 ``query`` / ``form`` 两种注入位置。
        """
        if position in ("query", "form") and position not in self.positions:
            return False
        hints = self.param_hints
        if not hints or "*" in hints:
            return True
        low = (param or "").lower()
        return any(hint in low for hint in hints)

    def info(self) -> dict[str, str]:
        return {
            "name": self.name, "title": self.title, "category": self.category,
            "severity": self.severity.value, "cwe": self.cwe, "owasp": self.owasp,
            "scope": self.scope, "deep_only": str(self.deep_only),
            "description": self.description,
        }

    def __repr__(self) -> str:  # pragma: no cover - 调试友好
        return f"<{type(self).__name__} {self.name} scope={self.scope}>"


# --------------------------------------------------------------------------
# 注册表
# --------------------------------------------------------------------------
class PluginRegistry:
    """插件注册表 (插件名 -> 实例).

    实例在注册时创建一次并复用 —— 这让插件**必须**保持无状态, 状态一律走
    :class:`PluginContext`。引擎会在多线程里并发调用同一个实例。
    """

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}
        self._lock = threading.Lock()

    def register(self, plugin_cls: type[Plugin]) -> type[Plugin]:
        """注册插件类 (可作装饰器)."""
        plugin = plugin_cls()
        name = plugin.name
        if not name:
            raise ValueError(f"{plugin_cls.__name__} 缺少 name")
        with self._lock:
            if name in self._plugins:
                raise ValueError(f"插件重名: {name}")
            self._plugins[name] = plugin
        return plugin_cls

    def get(self, name: str) -> Plugin | None:
        return self._plugins.get(name)

    def names(self) -> list[str]:
        return sorted(self._plugins)

    def all(self) -> list[Plugin]:
        return [self._plugins[name] for name in self.names()]

    def __len__(self) -> int:
        return len(self._plugins)

    def __contains__(self, name: object) -> bool:
        return name in self._plugins

    def __iter__(self) -> Iterator[Plugin]:
        return iter(self.all())

    def select(self, *, scope: str | None = None, deep: bool = False,
               names: Sequence[str] | None = None,
               categories: Sequence[str] | None = None) -> list[Plugin]:
        """按档位/深度/名字/分类筛选插件 (保持名字序, 结果可复现)."""
        wanted = set(names) if names else None
        wanted_cat = set(categories) if categories else None
        out: list[Plugin] = []
        for plugin in self.all():
            if scope is not None and plugin.scope != scope:
                continue
            if plugin.deep_only and not deep:
                continue
            if wanted is not None and plugin.name not in wanted:
                continue
            if wanted_cat is not None and plugin.category not in wanted_cat:
                continue
            out.append(plugin)
        return out

    def categories(self) -> dict[str, int]:
        """分类 -> 插件数量."""
        out: dict[str, int] = {}
        for plugin in self._plugins.values():
            out[plugin.category] = out.get(plugin.category, 0) + 1
        return dict(sorted(out.items()))

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for plugin in self._plugins.values():
            out[plugin.severity.value] = out.get(plugin.severity.value, 0) + 1
        return out

    def summary(self) -> dict[str, object]:
        return {
            "plugins": len(self._plugins),
            "by_category": self.categories(),
            "by_severity": self.by_severity(),
            "deep_only": sum(1 for p in self._plugins.values() if p.deep_only),
        }

    def validate(self) -> list[str]:
        """自检: 返回元数据缺陷清单 (空列表表示注册表健康)."""
        problems: list[str] = []
        for name, plugin in sorted(self._plugins.items()):
            if not plugin.title:
                problems.append(f"{name}: 缺少 title")
            if plugin.category not in PLUGIN_CATEGORIES:
                problems.append(f"{name}: 未知 category {plugin.category!r}")
            if plugin.scope not in SCOPES:
                problems.append(f"{name}: 未知 scope {plugin.scope!r}")
            if not plugin.cwe.startswith("CWE-"):
                problems.append(f"{name}: cwe 必须形如 CWE-89")
            if not plugin.owasp.startswith("A") or ":" not in plugin.owasp:
                problems.append(f"{name}: owasp 必须形如 A03:2021")
            if not plugin.description:
                problems.append(f"{name}: 缺少 description")
        return problems


#: 全局插件注册表 (各插件模块 import 本模块的 ``register`` 完成自注册)
registry = PluginRegistry()


def register(plugin_cls: type[Plugin]) -> type[Plugin]:
    """``@register`` 装饰器: 把插件类登记到全局注册表."""
    return registry.register(plugin_cls)
