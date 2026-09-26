"""CRLF / HTTP 响应头注入插件 (w13scan ``VulType.CRLF``).

当参数被拼进响应头 (最常见的是 ``Location`` 与 ``Set-Cookie``) 且 ``\\r\\n`` 未被过滤
时, 攻击者可以伪造响应头乃至整个响应体 (response splitting)。插件用 ``%0d%0a`` 变体
发送, 由服务端解码后才会形成真正的换行 —— 这样既避开 ``http.client`` 对请求行控制
字符的拦截, 又能真实触发漏洞。

判定以"响应里多出了一个我们注入的头"为准, 而不是"响应里出现了标记字符串", 后者在
参数回显场景下必然误报。
"""
from __future__ import annotations

import re

from ...core.models import Finding, Severity
from .base import A03, Plugin, PluginContext, register, snippet

#: 注入头名 (出现即证明换行被接受)
INJECT_HEADER = "Sentinel-Inject"
INJECT_VALUE = "9137"

#: 响应体里出现"完整的第二个响应起始行"才算真正的响应拆分。
#: 只出现"换行 + 注入头"是不够的 —— 参数被原样回显时, 服务端解码出的 \\r\\n 同样会
#: 出现在正文里, 那种情况只是回显, 不是注入。
_SPLIT_RE = re.compile(r"\r?\n\r?\nHTTP/1\.[01]\s+\d{3}")

#: 载荷模板: ``{crlf}`` 会被替换成换行编码
PAYLOAD_TEMPLATES: tuple[str, ...] = (
    "/{crlf}" + INJECT_HEADER + ": " + INJECT_VALUE,
    "/x{crlf}" + INJECT_HEADER + ": " + INJECT_VALUE,
    "/x{crlf}{crlf}<html>" + INJECT_VALUE,
    "/x{crlf}Set-Cookie: sentinel_crlf=" + INJECT_VALUE,
)

ENCODINGS: tuple[str, ...] = ("%0d%0a", "%0a", "%0d%0a%20", "%23%0d%0a")


@register
class Crlf(Plugin):
    """CRLF 注入 / HTTP 响应头注入."""

    name = "crlf"
    title = "CRLF 响应头注入"
    category = "crlf"
    severity = Severity.MEDIUM
    cwe = "CWE-93"
    owasp = A03
    description = "注入 %0d%0a 变体尝试伪造响应头, 依据响应中出现注入头判定"
    param_hints = ("url", "uri", "next", "redirect", "return", "goto", "target",
                   "to", "dest", "link", "page", "path", "file", "name", "lang",
                   "callback", "ref", "from", "host", "domain", "q", "search")
    references = ("https://owasp.org/www-community/attacks/HTTP_Response_Splitting",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        for encoding in ENCODINGS:
            for template in PAYLOAD_TEMPLATES:
                payload = template.format(crlf=encoding)
                # safe="%": 载荷本身就是**已编码**的换行, 必须原样送到服务端由它解码成
                # 真正的 CRLF; 再编码一次会变成字面量 "%0d%0a", 检测随之失效。
                result = ctx.inject(payload, safe="%")
                if not result.status:
                    continue
                injected = result.header(INJECT_HEADER)
                cookie = result.header("Set-Cookie")
                if injected:
                    return [self._finding(ctx, result, payload,
                                          f"{INJECT_HEADER}: {injected}",
                                          "注入的响应头被服务端接受")]
                if "sentinel_crlf" in cookie:
                    return [self._finding(ctx, result, payload,
                                          f"Set-Cookie: {cookie}",
                                          "注入的 Set-Cookie 被服务端接受")]
                # 响应体里出现完整的第二个响应起始行 => 响应拆分成功
                if _SPLIT_RE.search(result.text):
                    return [self._finding(ctx, result, payload,
                                          snippet(result.text, "HTTP/1.", 60),
                                          "注入内容落到了响应体并开启新响应, "
                                          "确认为响应拆分", 0.85)]
        return []

    def _finding(self, ctx: PluginContext, result, payload: str, evidence: str,
                 proof: str, confidence: float = 0.9) -> Finding:
        return ctx.add(
            vuln_type="crlf", url=result.url, method=result.method,
            param=ctx.param, payload=payload, evidence=evidence,
            severity=self.severity, confidence=confidence,
            proof=proof + ", 可伪造响应头 / 拆分响应体 (XSS、会话固定)")


__all__ = ["ENCODINGS", "INJECT_HEADER", "INJECT_VALUE", "PAYLOAD_TEMPLATES", "Crlf"]
