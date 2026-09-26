"""CORS 配置错误插件 (w13scan 无独立插件, Sentinel 内置检测器已有同类逻辑).

与内置检测器的区别: 这里额外区分三种风险等级 ——
  * 反射任意 Origin + ``Allow-Credentials: true`` -> 高危 (可跨域读取带凭据的响应);
  * ``Allow-Origin: *`` + ``Allow-Credentials: true`` -> 浏览器本身会拒绝该组合,
    但配置意图错误, 记中危;
  * 仅反射 Origin 无凭据 -> 低危 (信息可跨域读取, 但拿不到登录态)。

同时检查 ``Access-Control-Allow-Headers`` 是否也反射了 ``Access-Control-Request-Headers``,
这通常意味着配置是"无脑回显请求头", 攻击面更大。
"""
from __future__ import annotations

from ...core.models import Finding, Severity
from .base import A05, SCOPE_ENDPOINT, Plugin, PluginContext, register

#: 探测用恶意来源
EVIL_ORIGIN = "http://evil.sentinel.test"
EVIL_HEADERS = "X-Sentinel-Probe, Authorization"


@register
class Cors(Plugin):
    """跨域资源共享配置错误."""

    name = "cors"
    title = "CORS 跨域配置错误"
    category = "cors"
    severity = Severity.MEDIUM
    cwe = "CWE-942"
    owasp = A05
    description = "发送恶意 Origin/预检请求, 依据 Access-Control-Allow-* 反射情况判定"
    scope = SCOPE_ENDPOINT
    references = ("https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        probe = ctx.raw(ctx.endpoint.url, {
            "Origin": EVIL_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": EVIL_HEADERS,
        })
        if not probe.status:
            return []
        allow_origin = probe.header("Access-Control-Allow-Origin")
        allow_cred = probe.header("Access-Control-Allow-Credentials").lower()
        reflect_headers = EVIL_HEADERS.split(",")[0].strip().lower() in \
            probe.header("Access-Control-Allow-Headers").lower()
        if allow_origin not in (EVIL_ORIGIN, "*"):
            return []
        credentialed = allow_cred == "true"
        if allow_origin == EVIL_ORIGIN and credentialed:
            severity, confidence = Severity.HIGH, 0.95
            proof = "任意来源均可携带凭据跨域读取响应"
        elif allow_origin == "*" and credentialed:
            severity, confidence = Severity.MEDIUM, 0.9
            proof = "配置了通配来源又允许凭据 (浏览器会拒绝该组合), 配置意图存在风险"
        elif allow_origin == EVIL_ORIGIN:
            severity, confidence = Severity.LOW, 0.8
            proof = "跨域来源被原样反射, 但未允许携带凭据"
        else:
            return []
        if reflect_headers:
            proof += "; 且 Allow-Headers 同样反射了请求头"
        return [ctx.add(
            vuln_type="cors", url=ctx.endpoint.url, method="GET", param="Origin",
            payload=f"Origin: {EVIL_ORIGIN}",
            evidence=f"Access-Control-Allow-Origin: {allow_origin}; "
                     f"Allow-Credentials: {allow_cred or '-'}; "
                     f"Allow-Headers: {probe.header('Access-Control-Allow-Headers') or '-'}",
            severity=severity, confidence=confidence, proof=proof)]


__all__ = ["EVIL_HEADERS", "EVIL_ORIGIN", "Cors"]
