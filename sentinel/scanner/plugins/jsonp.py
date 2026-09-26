"""JSONP 劫持插件 (移植 w13scan ``jsonp.py``).

w13scan 的思路: 先确认 ``callback`` 参数被原样反射成函数名, 再用一个**伪造 Referer**
重放请求 —— 若仍然返回可执行脚本, 说明服务端没有做来源校验, 任意站点都能跨域读取
该接口的数据。这里保留这条两级判定, 并补充"响应里含敏感字段"作为提权证据。
"""
from __future__ import annotations

from ...core.models import Finding, Severity
from ..vulndb import JSONP_MARKER, JSONP_PARAMS
from .base import A01, Plugin, PluginContext, register, snippet

#: 伪造来源 (JSONP 劫持的实际攻击场景)
EVIL_REFERER = "http://evil.sentinel.test/hijack.html"

#: 响应中出现的敏感字段名 -> 说明数据可被跨域窃取
SENSITIVE_FIELDS: tuple[str, ...] = (
    "token", "password", "passwd", "secret", "email", "phone", "mobile",
    "idcard", "user", "username", "userid", "session", "apikey", "api_key",
    "realname", "address", "balance", "role",
)


@register
class Jsonp(Plugin):
    """JSONP 敏感信息泄漏 / 劫持 (w13scan ``jsonp``)."""

    name = "jsonp"
    title = "JSONP 劫持"
    category = "jsonp"
    severity = Severity.MEDIUM
    cwe = "CWE-346"
    owasp = A01
    description = "改写 callback 参数并用伪造 Referer 重放, 判定是否可被跨域窃取数据"
    param_hints = tuple(JSONP_PARAMS) + ("jsonp", "json_callback", "call", "func")
    references = ("https://owasp.org/www-community/attacks/JSON_Hijacking",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        result = ctx.inject(JSONP_MARKER)
        if not result.status or not result.body:
            return []
        if not _is_jsonp(result.text, JSONP_MARKER):
            return []
        # 伪造 Referer 重放: 服务端仍然返回可执行脚本 -> 无来源校验
        hijack = ctx.raw(result.url, {"Referer": EVIL_REFERER})
        if not hijack.status or not _is_jsonp(hijack.text, JSONP_MARKER):
            return [ctx.add(
                vuln_type="jsonp", url=result.url, method=result.method,
                param=ctx.param, payload=f"{ctx.param}={JSONP_MARKER}",
                evidence=snippet(result.text, JSONP_MARKER, 60),
                severity=Severity.LOW, confidence=0.6,
                proof="callback 参数被原样反射为函数名, 但伪造 Referer 后不再返回 "
                      "JSONP, 存在来源校验 (劫持风险降低)")]
        leaked = [name for name in SENSITIVE_FIELDS
                  if f'"{name}"' in hijack.text.lower() or f"'{name}'" in hijack.text.lower()]
        return [ctx.add(
            vuln_type="jsonp", url=result.url, method=result.method,
            param=ctx.param, payload=f"{ctx.param}={JSONP_MARKER}",
            evidence=snippet(hijack.text, JSONP_MARKER, 80),
            severity=self.severity, confidence=0.9 if leaked else 0.75,
            proof="callback 未校验且无 Referer 来源校验, 任意站点可跨域读取响应"
                  + (f"; 响应字段 {leaked[:6]} 含敏感数据" if leaked else ""),
        )]


def _is_jsonp(body: str, marker: str) -> bool:
    """响应是否是"以我们给的函数名开头的可执行脚本"."""
    head = body.lstrip()[:200]
    return head.startswith(f"{marker}(") or f"{marker}(" in head


__all__ = ["EVIL_REFERER", "SENSITIVE_FIELDS", "Jsonp"]
