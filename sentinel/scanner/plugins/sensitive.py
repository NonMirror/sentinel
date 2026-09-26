"""敏感信息泄漏插件族 (移植 w13scan ``js_sensitive_content.py`` /
``errorpage.py`` / ``phpinfo_craw.py`` / ``analyze_parameter`` 的敏感信息部分).

三个插件都只做"响应内容分析", 不发攻击载荷, 因此不会对目标造成副作用:

  * ``sensitive_info``  —— 逐接口扫描响应体, 匹配堆栈/密钥/云凭据/JS 敏感变量;
  * ``errorpage``       —— 访问不存在的页面, 从错误页里提取技术栈与路径;
  * ``phpinfo``         —— 探测常见 phpinfo 文件名。

匹配规则直接复用 :mod:`sentinel.scanner.vulndb` 的 ``TRACEBACK_RE`` / ``SECRET_RE``,
保证与内置检测器对"什么算敏感信息"的口径一致 (否则多引擎融合会出现同一响应一个引擎
报一个引擎不报的矛盾)。
"""
from __future__ import annotations

import re
import secrets
import string

from ...core.models import Finding, Severity
from ..vulndb import SECRET_RE, TRACEBACK_RE
from .base import (A01, A05, SCOPE_ENDPOINT, SCOPE_SERVER, Plugin, PluginContext,
                   register, snippet)

#: 敏感信息规则: (名称, 正则, 严重级别)
SENSITIVE_RULES: tuple[tuple[str, str, Severity], ...] = (
    ("数据库口令", r"(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD)"
                   r"\s*[=:]\s*[^\s<\"']{3,}", Severity.HIGH),
    ("云访问密钥", r"AKIA[0-9A-Z]{12,}", Severity.HIGH),
    ("私钥文件", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY", Severity.HIGH),
    ("数据库连接串", r"(jdbc|mysql|postgres(?:ql)?|mongodb|redis)://[^\s\"'<>]{6,}",
     Severity.HIGH),
    ("口令或密钥赋值", SECRET_RE.pattern, Severity.MEDIUM),
    ("框架调试信息", TRACEBACK_RE.pattern, Severity.MEDIUM),
    ("SQL 报错信息", r"(You have an error in your SQL syntax|"
                     r"System\.Data\.SqlClient\.SqlException|ORA-[0-9]{4,5}|"
                     r"SQLSTATE\[\w+\])", Severity.MEDIUM),
    ("靶场标记", r"FLAG\{[^}]{4,}\}", Severity.MEDIUM),
)

#: 仅对 ``.js`` 响应生效的规则 (w13scan ``js_sensitive_content.regx`` 的精选子集)
JS_RULES: tuple[tuple[str, str, Severity], ...] = (
    ("AWS AccessKey", r"AKIA[0-9A-Z]{16}", Severity.HIGH),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH),
    ("JWT 令牌", r"ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*",
     Severity.MEDIUM),
    ("云存储地址", r"[\w\-.]+\.(?:s3[^.]*\.amazonaws\.com|cloudfront\.net|"
                   r"appspot\.com|digitaloceanspaces\.com|storage\.googleapis\.com)",
     Severity.LOW),
    ("token/口令赋值",
     r"(?:secret|token|auth_token|access_token|api_key|apikey|password|passwd|"
     r"client_secret|private_key|consumer_secret)[\"'\s]*(?::|=|=>)[\"'\s]*"
     r"[A-Za-z0-9_\-]{8,64}", Severity.MEDIUM),
    ("邮箱地址", r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,}", Severity.LOW),
)


@register
class SensitiveInfo(Plugin):
    """响应体敏感信息泄漏 (w13scan ``js_sensitive_content`` 的泛化)."""

    name = "sensitive_info"
    title = "敏感信息泄漏"
    category = "info"
    severity = Severity.MEDIUM
    cwe = "CWE-200"
    owasp = A01
    description = "分析响应体中的堆栈、密钥、云凭据、数据库连接串等敏感信息"
    scope = SCOPE_ENDPOINT
    references = ("https://owasp.org/www-community/vulnerabilities/Information_exposure",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        result = ctx.raw(ctx.endpoint.url)
        if not result.status or not result.body:
            return []
        body = result.text
        is_script = result.url.split("?")[0].lower().endswith(".js") or \
            "javascript" in result.content_type.lower()
        rules = SENSITIVE_RULES + (JS_RULES if is_script else ())
        findings: list[Finding] = []
        seen: set[str] = set()
        for name, pattern, severity in rules:
            match = re.search(pattern, body, re.I | re.M)
            if not match:
                continue
            if name in seen:
                continue
            seen.add(name)
            findings.append(ctx.add(
                vuln_type="sensitive", url=result.url, method="GET", param="",
                payload="",
                evidence=snippet(body, match.group(0)[:40], 60),
                severity=severity, confidence=0.8,
                proof=f"响应体中匹配到「{name}」, 匹配内容 {match.group(0)[:60]!r}"))
        return findings


#: 报错页特征 (w13scan ``sensitive_page_error_message_check`` 的精选子集)
ERROR_PAGE_RULES: tuple[tuple[str, str], ...] = (
    ("ASP.NET 异常", r"(System\.[A-Za-z.]*Exception|Exception of type|"
                      r"End of inner exception stack trace|Microsoft OLE DB Provider)"),
    ("Java 异常", r"(java\.lang\.[A-Za-z]+Exception|\.java:[0-9]+|"
                  r"nested exception is|javax\.servlet)"),
    ("PHP 异常", r"(Fatal error:|Warning: [a-z_]+\(\)|Parse error: syntax error)"),
    ("Python 异常", r"(Traceback \(most recent call last\)|werkzeug\.debug|"
                    r"django\.core\.exceptions)"),
    ("SQL 报错", r"(You have an error in your SQL syntax|SQLSTATE|ORA-[0-9]{4,5})"),
    ("路径泄漏", r"([A-Za-z]:\\\\?(?:www|inetpub|xampp|apache|tomcat)[^\s\"'<>]*|"
                 r"/(?:var/www|usr/local|home/[a-z]+)/(?:[\w.-]+/)+)"),
    ("服务器版本", r"(Apache/\d|nginx/\d|Microsoft-IIS/\d|Tomcat/\d)"),
)


@register
class ErrorPage(Plugin):
    """错误页信息泄漏 (w13scan ``errorpage``).

    访问一个必然不存在的页面, 从错误页里读技术栈 / 路径 / 堆栈 —— 这是最"零成本"
    的信息收集手段, 也是 w13scan 的 PerServer 插件之一。
    """

    name = "errorpage"
    title = "错误页信息泄漏"
    category = "info"
    severity = Severity.LOW
    cwe = "CWE-209"
    owasp = A05
    description = "访问不存在的页面, 从错误响应中提取堆栈、绝对路径与技术栈信息"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        findings: list[Finding] = []
        for suffix in (".jsp", ".php", ".aspx", ".do"):
            url = f"{ctx.base_url}/sentinel_{_tag()}{suffix}"
            result = ctx.raw(url)
            if not result.status or not result.body:
                continue
            for name, pattern in ERROR_PAGE_RULES:
                match = re.search(pattern, result.text, re.I | re.M)
                if not match:
                    continue
                findings.append(ctx.add(
                    vuln_type="errorpage", url=url, method="GET", param="",
                    payload=url,
                    evidence=snippet(result.text, match.group(0)[:40], 60),
                    severity=self.severity, confidence=0.7,
                    proof=f"HTTP {result.status} 错误页泄漏「{name}」"
                          f"({match.group(0)[:60]!r})"))
                break
            if findings:
                break
        return findings


#: phpinfo 常见文件名 (w13scan ``phpinfo_craw.variants``)
PHPINFO_PATHS: tuple[str, ...] = (
    "phpinfo.php", "info.php", "test.php", "pi.php", "php.php", "i.php",
    "temp.php", "phpinfo/", "phpinfo.php.bak",
)

#: phpinfo 页面特征
PHPINFO_SIGNS: tuple[str, ...] = (
    "<title>phpinfo()</title>", "PHP Version =>", "phpinfo()</title>",
    "PHP Credits</a>", "php_version",
)


@register
class PhpInfo(Plugin):
    """phpinfo 泄漏 (w13scan ``phpinfo_craw``)."""

    name = "phpinfo"
    title = "phpinfo 信息泄漏"
    category = "info"
    severity = Severity.MEDIUM
    cwe = "CWE-200"
    owasp = A05
    description = "探测常见 phpinfo 文件名, 依据页面特征字符串判定"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        for path in PHPINFO_PATHS:
            result = ctx.raw(ctx.absolute(path))
            if result.status != 200 or not result.body:
                continue
            sign = next((s for s in PHPINFO_SIGNS if s in result.text), "")
            if not sign:
                continue
            return [ctx.add(
                vuln_type="phpinfo", url=result.url, method="GET", param="",
                payload=path, evidence=snippet(result.text, sign, 60),
                severity=self.severity, confidence=0.9,
                proof=f"{path} 暴露 phpinfo 页面, 泄漏 PHP 配置、环境变量与绝对路径")]
        return []


def _tag() -> str:
    """不可预测的探针后缀 (避免命中真实页面)."""
    return "".join(secrets.choice(string.ascii_lowercase + string.digits)
                   for _ in range(8))


__all__ = ["ERROR_PAGE_RULES", "JS_RULES", "PHPINFO_PATHS", "PHPINFO_SIGNS",
           "SENSITIVE_RULES", "ErrorPage", "PhpInfo", "SensitiveInfo"]
