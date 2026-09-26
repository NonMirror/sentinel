"""命令/代码/模板注入插件族 (移植 w13scan ``command_system.py`` /
``command_php_code.py`` / ``ssti.py``).

三条检测路径的共同点是"注入的内容会被服务端**执行**", 因此判定必须以"执行结果"为
证据, 而不能以"参数被回显"为证据 —— 否则任何一个会回显参数的接口都会被误报。这里
统一采用 w13scan 的两个反回显技巧:

  * 命令注入: 打 ``echo <token>|base64``, 期望出现 token 的 base64 摘要 (回显只会
    出现 token 明文, 不可能出现它的 base64);
  * 代码/模板注入: 载荷里写的是**算式** ``{{9137*9139}}``, 期望出现的是**乘积**, 回显
    永远只会回显算式本身。
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import string

from ...core.models import Finding, Severity
from .base import A03, Plugin, PluginContext, register, snippet

#: 命令注入标记 (与 base64 摘要配合, 规避参数回显造成的假阳性)
CMD_MARKER = "sentinelCMD9137"

#: 命令注入分隔符 (对应 w13scan ``['', ';', "&&", "|"]``, 另加换行与后台执行)
CMD_SEPARATORS: tuple[str, ...] = ("", ";", "|", "&&", "\n", "&")

#: 命令执行结果的判定特征
CMD_EVIDENCE: tuple[tuple[str, str], ...] = (
    (r"uid=\d+\([\w.-]+\)\s+gid=\d+", "id 命令回显 Unix 账户信息"),
    (r"Microsoft Windows \[Version", "ver 命令回显 Windows 版本"),
    (r"root:x:0:0:", "读取到 /etc/passwd"),
    (r"PATH=|Path=[\s\S]{0,40}PWD=", "set/env 命令回显环境变量"),
)


def command_payloads() -> list[tuple[str, str]]:
    """构造 (payload, 期望证据) 列表.

    期望证据若以 ``re:`` 开头按正则匹配, 否则按子串匹配 —— 命令输出里的具体
    用户名/UUID 无法预知, 只能靠正则概括。
    """
    digest = base64.b64encode((CMD_MARKER + "\n").encode()).decode()
    out: list[tuple[str, str]] = []
    for sep in CMD_SEPARATORS:
        out.append((f"{sep}echo {CMD_MARKER}|base64", digest))
    out.append((f"`echo {CMD_MARKER}|base64`", digest))
    out.append((f"$(echo {CMD_MARKER}|base64)", digest))
    for sep in (";", "|", "&&", "\n"):
        out.append((f"{sep}id", r"re:uid=\d+\([\w.-]+\)\s+gid=\d+"))
        out.append((f"{sep}ver", "Microsoft Windows [Version"))
        out.append((f"{sep}cat /etc/passwd", "root:x:0:0:"))
    return out


def evidence_hit(body: str, expected: str) -> bool:
    """按 ``re:`` 前缀区分正则 / 子串匹配."""
    if expected.startswith("re:"):
        return re.search(expected[3:], body) is not None
    return expected in body


def _needle(expected: str) -> str:
    """把期望证据折算成可在响应里定位的关键词 (用于截取证据片段)."""
    if not expected.startswith("re:"):
        return expected
    for token in ("uid=", "gid="):
        if token in expected:
            return token
    return expected[3:].split("\\")[0][:32]


@register
class CmdInject(Plugin):
    """系统命令注入 (w13scan ``command_system``)."""

    name = "cmd_inject"
    title = "系统命令注入"
    category = "rce"
    severity = Severity.CRITICAL
    cwe = "CWE-78"
    owasp = A03
    description = "拼接 shell 元字符执行 echo/id/ver 等命令, 依据命令输出判定注入"
    param_hints = ("cmd", "exec", "command", "ping", "host", "ip", "domain", "url",
                   "addr", "address", "target", "hostname", "query", "name", "file",
                   "path", "dir", "shell", "run", "do", "action", "func", "system")
    references = ("https://owasp.org/www-community/attacks/Command_Injection",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        for payload, expected in command_payloads():
            result = ctx.inject(payload)
            if not result.status or not result.body:
                continue
            body = result.text
            if evidence_hit(body, expected):
                return [ctx.add(
                    vuln_type="cmd_injection", url=result.url, method=result.method,
                    param=ctx.param, payload=payload,
                    evidence=snippet(body, _needle(expected), 80),
                    severity=self.severity, confidence=0.95,
                    proof=f"载荷 {payload!r} 被服务端执行, 响应出现命令输出特征 "
                          f"{expected!r}")]
            for pattern, desc in CMD_EVIDENCE:
                match = re.search(pattern, body)
                if match:
                    return [ctx.add(
                        vuln_type="cmd_injection", url=result.url, method=result.method,
                        param=ctx.param, payload=payload,
                        evidence=snippet(body, match.group(0), 60),
                        severity=self.severity, confidence=0.9,
                        proof=f"载荷 {payload!r} 被服务端执行 ({desc})")]
        return []


#: PHP 代码注入载荷模板 (``{}`` 为随机整数, 期望回显其 md5)
PHP_CODE_TEMPLATES: tuple[str, ...] = (
    "print(md5({n}));",
    ";print(md5({n}));",
    "';print(md5({n}));$a='",
    "\";print(md5({n}));$a=\"",
    "${{@print(md5({n}))}}",
    "${{@print(md5({n}))}}\\",
    "'.print(md5({n})).'",
)

#: PHP 语法错误特征 (载荷未闭合语句时也会暴露代码执行面)
PHP_ERROR_RE = re.compile(r"(Parse error: syntax error|Fatal error: Uncaught|"
                          r"Warning: print\(\)|Undefined variable)", re.I)


@register
class PhpCode(Plugin):
    """PHP 代码注入 (w13scan ``command_php_code``)."""

    name = "php_code"
    title = "PHP 代码注入"
    category = "rce"
    severity = Severity.CRITICAL
    cwe = "CWE-94"
    owasp = A03
    description = "注入 print(md5(n)) 系列载荷, 依据 md5 回显判定任意 PHP 代码执行"
    param_hints = ("cmd", "code", "exec", "eval", "function", "func", "do", "action",
                   "call", "method", "module", "template", "page", "file", "path",
                   "name", "id", "content")
    references = ("https://owasp.org/www-community/attacks/Code_Injection",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        number = _rand_int()
        digest = hashlib.md5(str(number).encode()).hexdigest()
        for template in PHP_CODE_TEMPLATES:
            payload = template.format(n=number)
            result = ctx.inject(payload)
            if not result.status or not result.body:
                continue
            body = result.text
            if digest in body:
                return [ctx.add(
                    vuln_type="code_injection", url=result.url, method=result.method,
                    param=ctx.param, payload=payload,
                    evidence=snippet(body, digest, 40),
                    severity=self.severity, confidence=0.97,
                    proof=f"md5({number}) 出现在响应中, 说明服务端执行了注入的 PHP 代码")]
            match = PHP_ERROR_RE.search(body)
            if match and ("print" in payload or "md5" in payload):
                return [ctx.add(
                    vuln_type="code_injection", url=result.url, method=result.method,
                    param=ctx.param, payload=payload,
                    evidence=snippet(body, match.group(0), 60),
                    severity=Severity.HIGH, confidence=0.7,
                    proof=f"载荷 {payload!r} 触发 PHP 解析/运行时错误, 存在代码注入面")]
        return []


#: SSTI 载荷模板 (``%d`` 为随机整数, 期望回显乘积) — 覆盖 w13scan 的模板集合
SSTI_TEMPLATES: tuple[str, ...] = (
    "{{%d*%d}}",          # Jinja2 / Twig / Nunjucks
    "${%d*%d}",           # JSP EL / FreeMarker / Thymeleaf
    "${{%d*%d}}",         # Thymeleaf / Spring
    "#{%d*%d}",           # Ruby ERB / Pug
    "{%%= %d*%d %%}",     # ASP / EJS
    "{{= %d*%d}}",        # DoT / Handlebars 变体
    "<# %d*%d>",          # FreeMarker 指令
    "{@%d*%d}",           # Razor (Umbraco)
    "@(%d*%d)",           # Razor
    "[[%d*%d]]",          # Angular 风格模板
    "*{%d*%d}*",          # 通用花括号求值
)


@register
class Ssti(Plugin):
    """服务端模板注入 (w13scan ``ssti``)."""

    name = "ssti"
    title = "服务端模板注入 (SSTI)"
    category = "ssti"
    severity = Severity.HIGH
    cwe = "CWE-1336"
    owasp = A03
    description = "按常见模板语法注入算式, 依据服务端是否回显计算结果判定模板注入"
    param_hints = ("name", "q", "search", "query", "page", "template", "tpl", "view",
                   "content", "title", "message", "text", "subject", "email", "lang",
                   "theme", "file", "url", "id", "user", "input")
    references = ("https://owasp.org/www-project-web-security-testing-guide/"
                  "latest/4-Web_Application_Security_Testing/"
                  "07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        left, right = _rand_int(), _rand_int()
        product = str(left * right)
        if left == 1 or right == 1:
            left, right = left + 3, right + 7
            product = str(left * right)
        for template in SSTI_TEMPLATES:
            payload = template % (left, right)
            result = ctx.inject(payload)
            if not result.status or not result.body:
                continue
            if product in result.text:
                return [ctx.add(
                    vuln_type="ssti", url=result.url, method=result.method,
                    param=ctx.param, payload=payload,
                    evidence=snippet(result.text, product, 60),
                    severity=self.severity, confidence=0.95,
                    proof=f"载荷 {payload!r} 被服务端求值并回显 {product}")]
        return []


def _rand_int() -> int:
    """4 位随机整数 (>1, 避免乘积与操作数混淆)."""
    value = int("".join(secrets.choice(string.digits) for _ in range(4)))
    return value if value > 1 else 9137


__all__ = ["CMD_EVIDENCE", "CMD_MARKER", "CMD_SEPARATORS", "PHP_CODE_TEMPLATES",
           "PHP_ERROR_RE", "SSTI_TEMPLATES", "CmdInject", "PhpCode", "Ssti",
           "command_payloads", "evidence_hit"]
