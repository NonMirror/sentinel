"""IIS 短文件名 (8.3 shortname) 枚举检测 (w13scan ``iis_parse.py`` 的同类面).

IIS 为兼容 16 位程序保留了 ``PROGRA~1`` 形式的短文件名; 若站点开启了 8.3 名称生成,
攻击者可以用 ``~1`` 通配符逐字符猜出目录/文件名 (包括本不该被列出的备份与配置)。

**启发式说明**: 真正的枚举要按字符逐步收敛 (数十到上百次请求)。这里只做"是否存在
差异"的探测 —— 比较 ``*~1*`` 形式路径与普通不存在路径的状态码, IIS 对畸形短名会返回
``400 Bad Request`` 而普通不存在路径返回 ``404``。命中即提示"可能开启短名", 置信度
0.6, 需要在报告里人工复验。
"""
from __future__ import annotations

import secrets
import string

from ...core.models import Finding, Severity
from .base import A05, SCOPE_SERVER, Plugin, PluginContext, register

#: 短名探测路径模板 (``{n}`` 为 ``~1`` 形式)
SHORTNAME_PROBES: tuple[str, ...] = (
    "/{token}~1.aspx", "/{token}~1.txt", "/{token}~1", "/*~1*/a.aspx",
    "/a~1{b}/b.aspx", "/{token}~1.{ext}",
)

#: 扩展名 (IIS 短名只对已注册的扩展名生成)
EXTENSIONS: tuple[str, ...] = ("aspx", "asp", "ashx", "config", "txt", "zip")


@register
class IisShortname(Plugin):
    """IIS 短文件名枚举 (启发式)."""

    name = "iis_shortname"
    title = "IIS 短文件名 (8.3) 枚举"
    category = "dirlist"
    severity = Severity.MEDIUM
    cwe = "CWE-548"
    owasp = A05
    description = "用 ~1 通配路径触发 IIS 差异响应, 启发式判断是否启用 8.3 短文件名"
    scope = SCOPE_SERVER
    references = ("https://owasp.org/www-community/attacks/",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        # 对照组: 一个必然不存在的普通路径, 拿到"本站 404 长什么样"
        missing = ctx.raw(ctx.base_url + "/sentinel_" + _token() + ".txt")
        if not missing.status:
            return []
        for template in SHORTNAME_PROBES:
            for extension in EXTENSIONS:
                path = template.format(token=_token(), ext=extension, b=_token())
                result = ctx.raw(ctx.base_url + path)
                if not result.status or result.status == missing.status:
                    continue
                if result.status not in (400, 404, 500):
                    continue
                return [ctx.add(
                    vuln_type="iis_shortname", url=ctx.base_url + path,
                    method="GET", param="", payload=path,
                    evidence=f"短名路径 HTTP {result.status}, 普通不存在路径 "
                             f"HTTP {missing.status}",
                    severity=self.severity, confidence=0.6,
                    proof="IIS 对含 ~1 的路径返回了与普通 404 不同的状态码, "
                          "疑似启用 8.3 短文件名 (启发式, 需人工枚举复验)")]
        return []


def _token() -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))


__all__ = ["EXTENSIONS", "SHORTNAME_PROBES", "IisShortname"]
