"""文件上传插件 (w13scan 无独立插件).

爬虫只记录表单字段**名字**, 不记录 ``<input type="file">``; 因此插件先用两个信号定位
上传点: (1) 字段名命中 ``file``/``upload``/``avatar`` 一类提示, (2) 拉一次页面 HTML 找
``type="file"``。

确认上传点后提交两个探针文件: 一个无害的 ``.txt`` (只证明"能传") 一个 ``.php``
(证明"危险扩展名未被拦")。判定依据是响应里回出现探针文件名或文件内容标记 ——
「上传成功但静默丢弃」的服务端不会被误报成漏洞。

**深度扫描专用**: 该插件会向目标写入文件, 属于侵入性动作。
"""
from __future__ import annotations

import re

from ...core.models import Finding, Severity
from .base import A05, SCOPE_ENDPOINT, Plugin, PluginContext, register, snippet

#: 文件字段名提示
UPLOAD_FIELD_HINTS: tuple[str, ...] = (
    "file", "upload", "image", "img", "avatar", "photo", "picture", "attachment",
    "document", "doc", "media", "filename", "filedata", "blob", "content",
)

#: 探针文件内容标记
UPLOAD_MARKER = "sentinelUPLOAD9137"
PROBE_BASE = "sentinel_probe"

#: (扩展名, Content-Type, 内容) —— 第二个探针用于验证危险扩展名是否被拦截
PROBES: tuple[tuple[str, str, bytes], ...] = (
    ("txt", "text/plain", f"{UPLOAD_MARKER}\n".encode()),
    ("php", "application/x-php", f"<?php echo '{UPLOAD_MARKER}'; ?>\n".encode()),
)

#: 可直接获得代码执行的服务端扩展名
DANGEROUS_EXTENSIONS: tuple[str, ...] = ("php", "php5", "phtml", "jsp", "jspx",
                                         "asp", "aspx", "war", "ashx")

_FILE_INPUT_RE = re.compile(r"""<input[^>]*type=["']file["'][^>]*>""", re.I)
_NAME_IN_INPUT_RE = re.compile(r"""name=["']([^"']+)["']""", re.I)
BOUNDARY = "----SentinelBoundary9137"


@register
class Upload(Plugin):
    """任意文件上传 (深度扫描)."""

    name = "upload"
    title = "任意文件上传"
    category = "upload"
    severity = Severity.CRITICAL
    cwe = "CWE-434"
    owasp = A05
    description = "向上传点提交 txt/php 探针文件, 依据响应是否回显文件名/内容判定"
    scope = SCOPE_ENDPOINT
    deep_only = True
    references = ("https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        field = self._locate_field(ctx)
        if not field:
            return []
        for extension, content_type, content in PROBES:
            filename = f"{PROBE_BASE}.{extension}"
            body, ctype = _multipart(field, filename, content_type, content,
                                     ctx.endpoint.form_fields)
            result = ctx.request(ctx.endpoint.method or "POST", ctx.endpoint.url,
                                 body, {"Content-Type": ctype})
            if not result.status or result.status >= 400:
                continue
            text = result.text
            marker_hit = UPLOAD_MARKER in text
            name_hit = filename in text
            if not (marker_hit or name_hit):
                continue
            dangerous = extension in DANGEROUS_EXTENSIONS
            return [ctx.add(
                vuln_type="upload", url=result.url, method=result.method,
                param=field, payload=f"{filename} ({content_type})",
                evidence=snippet(text, UPLOAD_MARKER if marker_hit else filename, 60),
                severity=self.severity, confidence=0.85 if dangerous else 0.7,
                proof=f"上传 {filename!r} 成功且服务端回显了"
                      + ("文件内容" if marker_hit else "文件名")
                      + ("; 可执行扩展名未被拦截, 可直接获得代码执行"
                         if dangerous else "; 需进一步确认扩展名白名单与落地路径"))]
        return []

    # 定位文件字段: 字段名提示 -> 页面 type="file" -> 放弃
    def _locate_field(self, ctx: PluginContext) -> str:
        for name in ctx.endpoint.form_fields:
            low = name.lower()
            if any(hint in low for hint in UPLOAD_FIELD_HINTS):
                return name
        page = ctx.raw(ctx.endpoint.url)
        if not page.status:
            return ""
        for tag in _FILE_INPUT_RE.findall(page.text):
            match = _NAME_IN_INPUT_RE.search(tag)
            if match:
                return match.group(1)
        return ""


def _multipart(field: str, filename: str, content_type: str, content: bytes,
               other_fields: list[str]) -> tuple[bytes, str]:
    """构造 multipart/form-data 请求体 (其他表单字段填占位值)."""
    parts: list[bytes] = []
    for name in other_fields:
        if name == field:
            continue
        parts.append(
            f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
            f"sentinel9137\r\n".encode())
    parts.append(
        f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{field}\"; "
        f"filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n".encode()
        + content + b"\r\n")
    parts.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={BOUNDARY}"


__all__ = ["BOUNDARY", "DANGEROUS_EXTENSIONS", "PROBES", "PROBE_BASE",
           "UPLOAD_FIELD_HINTS", "UPLOAD_MARKER", "Upload"]
