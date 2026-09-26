"""开放重定向插件 (w13scan 通过 ``VulType.REDIRECT`` 归类, 由各插件附带检测).

判定要求 3xx 的 ``Location`` 指向我们控制的标记域名 —— 只看"响应里出现了外部 URL"
会把普通的参数回显误报成跳转漏洞。除 ``Location`` 外还覆盖 ``Refresh`` 响应头与
HTML ``<meta refresh>`` / ``location.href`` 两种纯前端跳转。
"""
from __future__ import annotations

from ...core.models import Finding, Severity
from ..vulndb import REDIRECT_MARKER, REDIRECT_PAYLOADS
from .base import A01, Plugin, PluginContext, register, snippet

#: 附加载荷 (协议相对 / 反斜杠绕过 / 白名单后缀绕过)
EXTRA_PAYLOADS: tuple[str, ...] = (
    f"//{REDIRECT_MARKER}",
    f"/\\{REDIRECT_MARKER}",
    f"https:/{REDIRECT_MARKER}/",
    f"//{REDIRECT_MARKER}/%2f..",
    f"http://evil.sentinel.test@{REDIRECT_MARKER}/",
)


@register
class OpenRedirect(Plugin):
    """开放重定向 (w13scan ``VulType.REDIRECT``)."""

    name = "open_redirect"
    title = "开放重定向"
    category = "redirect"
    severity = Severity.MEDIUM
    cwe = "CWE-601"
    owasp = A01
    description = "注入外部域名, 依据 3xx Location / Refresh 头 / 前端跳转判定重定向劫持"
    param_hints = ("next", "url", "redirect", "redirect_url", "redirect_uri", "return",
                   "returnurl", "return_url", "goto", "target", "to", "dest",
                   "destination", "continue", "jump", "link", "back", "from", "out",
                   "callback", "forward", "ref", "referer", "logout")
    references = ("https://owasp.org/www-community/attacks/Open_redirect",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        payloads = tuple(REDIRECT_PAYLOADS) + EXTRA_PAYLOADS
        for payload in payloads:
            result = ctx.inject(payload)
            if not result.status:
                continue
            location = result.location
            if 300 <= result.status < 400 and REDIRECT_MARKER in location:
                return [self._finding(ctx, result, payload,
                                      f"HTTP {result.status} Location: {location}",
                                      "服务端把用户可控参数直接用作跳转目标")]
            refresh = result.header("Refresh")
            if REDIRECT_MARKER in refresh:
                return [self._finding(ctx, result, payload,
                                      f"Refresh: {refresh}",
                                      "Refresh 响应头携带用户可控跳转目标")]
            body = result.text
            if REDIRECT_MARKER in body and (
                    f"location.href" in body or "location.replace" in body
                    or "http-equiv" in body.lower()):
                return [self._finding(ctx, result, payload,
                                      snippet(body, REDIRECT_MARKER, 60),
                                      "页面脚本/元刷新把用户可控参数当作跳转目标", 0.75)]
        return []

    def _finding(self, ctx: PluginContext, result, payload: str, evidence: str,
                 proof: str, confidence: float = 0.95) -> Finding:
        return ctx.add(
            vuln_type="redirect", url=result.url, method=result.method,
            param=ctx.param, payload=payload, evidence=evidence,
            severity=self.severity, confidence=confidence,
            proof=proof + ", 可用于钓鱼/凭据窃取")


__all__ = ["EXTRA_PAYLOADS", "OpenRedirect"]
