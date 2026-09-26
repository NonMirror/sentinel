"""HTTP 请求走私检测 (w13scan ``http_smuggling``).

**诚实说明**: 这是全库中最不可靠的一个插件, w13scan 上游自己也在 2020 年把它改成了
``return`` (issue #457 / #459: "bug太多了 后面再修吧")。真正判定请求走私需要在前端与
后端之间制造连接复用与去同步 (socket 层面 pipeline 两个请求), 本实现**没有**做到那
一步, 只做了一个保守的启发式:

    同一个请求体 (``0\\r\\n\\r\\nX``), 分别带上 "CL+TE 冲突" 与 "只有 CL" 两种头。
    合规的前端会直接拒绝含糊报文 (400/411/501); 如果服务端**接受**了含糊报文, 且
    解析结果与明文请求明显不同, 说明它对报文边界的理解与声明的头不一致。

因此本插件只在 ``deep`` 模式下运行, 置信度固定为 0.5, 并在证据里写明"需人工复验"。
它不会把"服务端忽略了 TE 头、按 CL 读完整个 body"这种正常行为判成漏洞 —— 那种情况
下两种请求的响应完全一致。
"""
from __future__ import annotations

from ...core.models import Finding, Severity
from .base import A03, SCOPE_ENDPOINT, Plugin, PluginContext, register, similarity

#: 请求体: 一个已终止的 chunk + 一个会被后端当成下一个请求前缀的残留字节
PROBE_BODY = b"0\r\n\r\nX"
#: 冲突头的声明长度 (等于 PROBE_BODY 长度, 让 CL 侧语法合法)
PROBE_LENGTH = str(len(PROBE_BODY))
#: 明确拒绝含糊报文的状态码
REJECT_CODES = frozenset({400, 411, 413, 501, 505})


@register
class HttpSmuggling(Plugin):
    """HTTP 请求走私 (启发式, 见模块 docstring)."""

    name = "http_smuggling"
    title = "HTTP 请求走私 (CL.TE 启发式)"
    category = "smuggling"
    severity = Severity.MEDIUM
    cwe = "CWE-444"
    owasp = A03
    description = "提交 CL 与 TE 冲突的含糊报文, 依据服务端是否接受及其解析差异做启发式判定"
    scope = SCOPE_ENDPOINT
    deep_only = True
    references = ("https://portswigger.net/web-security/request-smuggling",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        insecure = ctx.request("POST", ctx.endpoint.url, PROBE_BODY,
                               {"Content-Length": PROBE_LENGTH,
                                "Transfer-Encoding": "chunked"})
        reference = ctx.request("POST", ctx.endpoint.url, PROBE_BODY,
                                {"Content-Length": PROBE_LENGTH})
        if not insecure.status or not reference.status:
            return []
        if insecure.status in REJECT_CODES:
            return []          # 前端明确拒绝含糊报文 -> 无走私面
        if insecure.status == reference.status and \
                similarity(insecure.text, reference.text) > 0.98:
            return []          # 忽略 TE、按 CL 解析 -> 正常行为, 不报
        evidence = (f"含糊报文 HTTP {insecure.status} (正文 {len(insecure.body)}B) "
                    f"vs 明文请求 HTTP {reference.status} "
                    f"(正文 {len(reference.body)}B), 相似度 "
                    f"{similarity(insecure.text, reference.text):.2f}")
        return [ctx.add(
            vuln_type="smuggling", url=insecure.url, method="POST", param="",
            payload=f"Content-Length: {PROBE_LENGTH} + Transfer-Encoding: chunked",
            evidence=evidence,
            severity=self.severity, confidence=0.5,
            proof="服务端接受了 CL/TE 冲突的含糊报文, 且其解析结果与明文请求不一致; "
                  "启发式判定, 需用 socket 层连接复用复验")]


__all__ = ["PROBE_BODY", "PROBE_LENGTH", "REJECT_CODES", "HttpSmuggling"]
