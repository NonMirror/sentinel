"""CSRF 插件 (w13scan 无独立插件; 覆盖面来自 ``VulType`` 之外的社区插件).

判定是**启发式**的: "表单里没有反 CSRF 令牌"本身不等于漏洞 —— 服务端可能用
``SameSite=Strict`` Cookie、双重提交或自定义请求头做了防护。因此:

  * 普通模式只做静态分析 (表单字段名 + 响应 Set-Cookie), 不发任何写请求;
  * 深度模式额外做一次"无令牌提交", 只有当服务端**真的接受了**这次提交 (非 4xx)
    时才提升置信度。

证据里会写明命中的是哪种信号, 便于人工复核。
"""
from __future__ import annotations

import re
from urllib.parse import urlencode

from ...core.models import Finding, Severity
from .base import A01, SCOPE_ENDPOINT, Plugin, PluginContext, register

#: 反 CSRF 令牌字段名特征
TOKEN_HINTS: tuple[str, ...] = (
    "csrf", "xsrf", "token", "nonce", "authenticity", "requestverification",
    "verification", "captcha", "anti_forgery", "antiforgery",
)

#: 会改变服务端状态的方法
STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")

_INPUT_NAME_RE = re.compile(r"""<input[^>]*name=["']([^"']+)["']""", re.I)


@register
class Csrf(Plugin):
    """跨站请求伪造 (启发式)."""

    name = "csrf"
    title = "跨站请求伪造 (CSRF)"
    category = "csrf"
    severity = Severity.MEDIUM
    cwe = "CWE-352"
    owasp = A01
    description = "分析表单字段与 Cookie 属性判断是否有反 CSRF 防护, 深度模式下做无令牌提交验证"
    scope = SCOPE_ENDPOINT
    references = ("https://owasp.org/www-community/attacks/csrf",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        if (ctx.endpoint.method or "GET").upper() not in STATE_CHANGING:
            return []
        page = ctx.raw(ctx.endpoint.url)
        html_fields = _INPUT_NAME_RE.findall(page.text) if page.status else []
        fields = sorted({name for name in (set(ctx.endpoint.form_fields) | set(html_fields))
                         if name and not name.startswith("__")})
        if not fields:
            return []
        low = [name.lower() for name in fields]
        if any(hint in name for name in low for hint in TOKEN_HINTS):
            return []

        same_site = _samesite(page)
        evidence = f"表单字段 {fields} 中未见反 CSRF 令牌"
        confidence = 0.55
        if same_site:
            evidence += f"; 会话 Cookie SameSite={same_site}"
            if same_site in ("strict", "lax"):
                confidence = 0.35
        if ctx.deep:
            body = urlencode({name: "sentinel9137" for name in fields})
            probe = ctx.request(ctx.endpoint.method or "POST", ctx.endpoint.url, body)
            if not probe.status or probe.status >= 400:
                return []          # 无令牌提交被拒绝 -> 存在防护
            evidence += f"; 无令牌提交被接受 (HTTP {probe.status})"
            confidence = max(confidence, 0.8)
        return [ctx.add(
            vuln_type="csrf", url=ctx.endpoint.url, method=ctx.endpoint.method or "POST",
            param="", payload="", evidence=evidence,
            severity=self.severity, confidence=confidence,
            proof="状态变更接口未发现反 CSRF 令牌, 攻击者页面可诱使已登录用户提交请求"
                  + ("" if ctx.deep else "; 启发式静态判定, 建议开启深度扫描复验"))]


def _samesite(page) -> str:
    cookie = page.header("Set-Cookie") if page.status else ""
    match = re.search(r"SameSite=(\w+)", cookie, re.I)
    return match.group(1).lower() if match else ""


__all__ = ["STATE_CHANGING", "TOKEN_HINTS", "Csrf"]
