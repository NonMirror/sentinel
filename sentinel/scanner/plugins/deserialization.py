"""反序列化参数分析插件 (移植 w13scan ``analyze_parameter.py`` / ``VulType.BASELINE``).

w13scan 把这类检测归为 "baseline" —— 它**不证明**漏洞存在, 只回答一个对渗透很有用的
问题: "这个参数里跑的是序列化对象吗?"。一旦确认, 后续就可以直接对参数做反序列化
利用链测试 (ysoserial / phpggc / pickle), 因此报告里按中危登记。

识别依据是各语言序列化流的固定头部 (与 w13scan ``api.is*ObjectDeserialization`` 同源):

======== ==========================================================
Java     ``rO0AB`` (base64) / ``\\xac\\xed\\x00\\x05`` (原始)
PHP      ``O:8:"stdClass":1:{}`` / ``a:2:{...}``
Python   ``gASV`` ``gAJ`` (base64 pickle) / ``\\x80\\x04`` (原始)
.NET     ``AAEAAAD/////`` (BinaryFormatter)
Ruby     ``\\x04\\x08`` (Marshal)
======== ==========================================================

插件按**接口**执行: 爬虫把 URL query 剥离后只保留了参数名, 因此这里直接回源种子 URL
的 query, 那里才有真实的参数值。
"""
from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote, urlsplit

from ...core.models import Finding, Severity
from .base import A08, SCOPE_ENDPOINT, Plugin, PluginContext, register

#: 明文头部 -> 语言
PLAIN_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("\xac\xed\x00\x05", "Java ObjectOutputStream"),
    ("\x80\x04", "Python pickle"),
    ("\x80\x05", "Python pickle"),
    ("\x04\x08", "Ruby Marshal"),
    ("\x00\x01\x00\x00\x00", ".NET BinaryFormatter"),
)

#: base64 头部 -> 语言
BASE64_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("rO0AB", "Java ObjectOutputStream"),
    ("gASV", "Python pickle"),
    ("gAJ", "Python pickle"),
    ("gAN", "Python pickle"),
    ("AAEAAAD/////", ".NET BinaryFormatter"),
)

#: PHP 序列化对象的完整形态 —— ``O:`` / ``a:`` 开头太容易误命中, 必须匹配整体结构
PHP_OBJECT_RE = re.compile(r'^(?:O:\d+:"[^"]+":\d+:\{|a:\d+:\{|s:\d+:"|i:\d+;|b:[01];|'
                           r'd:[-\d.]+;)')


@register
class Deserialization(Plugin):
    """反序列化参数分析 (w13scan ``analyze_parameter``)."""

    name = "deserialization"
    title = "反序列化参数"
    category = "deserialization"
    severity = Severity.MEDIUM
    cwe = "CWE-502"
    owasp = A08
    description = "识别种子 URL 参数值中的 Java/PHP/Python/.NET/Ruby 序列化流"
    scope = SCOPE_ENDPOINT
    references = ("https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        for name, value in seed_values(ctx.target.base_url):
            engine = detect_serialized(unquote(value))
            if not engine:
                continue
            return [ctx.add(
                vuln_type="baseline", url=ctx.endpoint.url, method=ctx.endpoint.method,
                param=name, payload=unquote(value)[:120],
                evidence=f"参数 {name} 的值形如 {engine} 序列化流: "
                         f"{unquote(value)[:80]!r}",
                severity=self.severity, confidence=0.75,
                proof=f"参数携带 {engine} 序列化数据, 存在反序列化攻击面 "
                      f"(需进一步验证利用链)")]
        return []


def seed_values(url: str) -> list[tuple[str, str]]:
    """解析种子 URL 的 query, 返回 (参数名, 原始值) 列表."""
    query = urlsplit(url).query
    out: list[tuple[str, str]] = []
    for pair in query.split("&"):
        if "=" in pair:
            name, _, value = pair.partition("=")
            out.append((name, value))
    return out


def detect_serialized(text: str) -> str:
    """返回序列化语言名; 不是序列化数据则返回空串."""
    value = text.strip()
    if not value:
        return ""
    if PHP_OBJECT_RE.match(value):
        return "PHP serialize"
    for signature, engine in PLAIN_SIGNATURES:
        if value.startswith(signature):
            return engine
    for signature, engine in BASE64_SIGNATURES:
        if value.startswith(signature):
            return engine
    # 有些客户端把序列化流整体再做了一次 base64, 解一层看能否露出明文头部
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except (binascii.Error, ValueError):
        return ""
    for signature, engine in PLAIN_SIGNATURES:
        if decoded.startswith(signature.encode("latin-1", "ignore")):
            return engine
    return ""


__all__ = ["BASE64_SIGNATURES", "PLAIN_SIGNATURES", "PHP_OBJECT_RE", "Deserialization",
           "detect_serialized", "seed_values"]
