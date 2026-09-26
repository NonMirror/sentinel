"""漏洞库与规则引擎.

集中定义检测插件 (payload / 匹配规则 / 严重级别 / CWE / OWASP 映射),
是扫描子系统与报告模块的单一事实来源.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from ..core.models import Severity

# 通用标记
SSRF_MARKER = "sentinel-ssrf-ok"
JSONP_MARKER = "sentinelCB9137"
REDIRECT_MARKER = "sentinel-redirect.example"
XSS_MARKER = "sentinelXSS9137"

SQL_ERROR_SIGNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"ora-\d{4,5}",
    r"pg_query\(\)|postgresql.*error",
    r"sqlite3\.(?:operational|programming)error",
    r"system\.data\.sqlclient\.sqlexception",
    r"java\.sql\.sqlsyntaxerrorexception",
    r"jdbc.*syntax",
    r"列名无效|语法错误|数据库错误",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNS), re.I)

FILE_READ_SIGNS = [
    re.compile(r"root:x:0:0:"),
    re.compile(r"\[boot loader\]", re.I),
    re.compile(r"\[fonts\]", re.I),
    re.compile(r"daemon:x:\d+:"),
    re.compile(r"FLAG\{[^}]{4,}\}"),
    re.compile(r"<web-app[\s>]"),
    re.compile(r"DB_PASSWORD\s*=", re.I),
]
TRACEBACK_RE = re.compile(
    r"(traceback \(most recent call last\)|stack\s*trace|"
    r"at\s+[\w.$]+\([\w.]+\.java:\d+\)|"
    r"notice:\s+undefined\s+(?:index|variable)|"
    r"fatal\s+error:\s+uncaught|"
    r"werkzeug\.debug|"
    r"exception\s+in\s+thread)", re.I)
SECRET_RE = re.compile(
    r"(password\s*[=:]\s*[^\s<\"']{4,}|api[_-]?key\s*[=:]\s*\w{8,}|"
    r"secret\s*[=:]\s*\w{6,}|AKIA[0-9A-Z]{12,}|FLAG\{[^}]+\})", re.I)

SQLI_PAYLOADS = {
    "error": ["'", "\"", "')", "\"\",", "'--", "1'", "1\""],
    "boolean": ["' OR '1'='1", "1 OR 1=1", "1' OR '1'='1'--", "1) OR (1=1"],
    "union": ["1 UNION SELECT NULL--", "' UNION SELECT NULL,NULL--"],
    "time": ["1' AND SLEEP({n})--", "1 AND SLEEP({n})", "1';SELECT PG_SLEEP({n})--",
             "1;WAITFOR DELAY '0:0:{n}'--"],
}
XSS_PAYLOADS = [
    f"<script>alert('{XSS_MARKER}')</script>",
    f"\"><script>alert('{XSS_MARKER}')</script>",
    f"<img src=x onerror=alert('{XSS_MARKER}')>",
    f"javascript:alert('{XSS_MARKER}')",
    f"<svg/onload=alert('{XSS_MARKER}')>",
]
SSRF_PAYLOADS = [
    "http://127.0.0.1:80/",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:{oob}/ssrf-probe",
    "file:///etc/passwd",
]
FILE_READ_PAYLOADS = [
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd%00",
    "../../../../../../../../../../windows/win.ini",
    "/WEB-INF/web.xml",
]
REDIRECT_PAYLOADS = [
    "http://sentinel-redirect.example/",
    "//sentinel-redirect.example/",
    "https://sentinel-redirect.example/evil",
]
JSONP_PARAMS = ["callback", "cb", "jsonp", "jsonpcallback", "jsonp_callback", "jsonCallback"]
UNAUTH_PATHS = ["/admin", "/api/orders", "/debug", "/manager/html", "/console",
                "/actuator/env", "/api/v1/users"]


@dataclass(frozen=True)
class DetectorSpec:
    """单个检测插件的元数据与参数语义."""

    name: str
    title: str
    severity: Severity
    cwe: str
    owasp: str
    description: str
    param_hints: tuple[str, ...] = ()
    method: str = "GET"
    active: bool = True
    references: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return self.name


def _spec(name, title, severity, cwe, owasp, description, hints=(), method="GET",
          active=True, refs=()):
    return DetectorSpec(name=name, title=title, severity=Severity(severity), cwe=cwe,
                        owasp=owasp, description=description, param_hints=tuple(hints),
                        method=method, active=active, references=tuple(refs))


DEFAULT_SPECS: list[DetectorSpec] = [
    _spec("sqli_error", "SQL 注入 (报错型)", "critical", "CWE-89", "A03:2021",
          "注入单引号/布尔载荷, 依据数据库报错特征判定",
          ("id", "q", "search", "query", "name", "page", "user", "product"),
          refs=("https://owasp.org/Top10/A03_2021-Injection/",)),
    _spec("sqli_time", "SQL 注入 (时间盲注)", "critical", "CWE-89", "A03:2021",
          "注入 SLEEP/WAITFOR 载荷, 依据响应时延差判定",
          ("id", "q", "search", "query", "name", "page", "product")),
    _spec("xss", "跨站脚本 (反射型)", "high", "CWE-79", "A03:2021",
          "注入 script/事件处理器载荷, 判定是否原样反射",
          ("q", "name", "search", "query", "message", "content", "page", "keyword")),
    _spec("ssrf", "服务端请求伪造", "high", "CWE-918", "A10:2021",
          "注入内网/回连 URL, 依据响应标记与带外回调判定",
          ("url", "uri", "link", "image", "img", "src", "target", "callback",
           "webhook", "proxy", "fetch", "domain", "host")),
    _spec("cors", "跨域资源共享配置错误", "medium", "CWE-942", "A05:2021",
          "发送恶意 Origin, 判定是否反射且允许携带凭据",
          ("*",)),
    _spec("jsonp", "JSONP 劫持", "medium", "CWE-346", "A01:2021",
          "篡改 callback 参数, 判定是否未校验直接反射"),
    _spec("file_read", "任意文件读取 (路径穿越)", "high", "CWE-22", "A01:2021",
          "注入路径穿越载荷, 依据敏感文件内容特征判定",
          ("file", "path", "filename", "filepath", "download", "template", "page",
           "include", "doc", "read")),
    _spec("url_redirect", "开放重定向", "medium", "CWE-601", "A01:2021",
          "注入外部地址, 判定 3xx Location 是否指向外部域",
          ("next", "url", "redirect", "return", "returnurl", "goto", "target",
           "to", "dest", "continue", "jump", "link")),
    _spec("unauth", "未授权访问", "high", "CWE-306", "A01:2021",
          "访问敏感路径, 判定是否在无鉴权下返回业务数据", ("*",)),
    _spec("html_res_information_disclosure", "信息泄露", "medium", "CWE-200", "A01:2021",
          "分析响应中的堆栈、密钥、配置文件等敏感信息", ("*",)),
]


class VulnDB:
    """漏洞库与规则引擎."""

    def __init__(self, specs: list[DetectorSpec] | None = None) -> None:
        self.specs = {s.name: s for s in (specs or DEFAULT_SPECS)}
        self.payloads = {
            "sqli": SQLI_PAYLOADS,
            "xss": XSS_PAYLOADS,
            "ssrf": SSRF_PAYLOADS,
            "file_read": FILE_READ_PAYLOADS,
            "url_redirect": REDIRECT_PAYLOADS,
            "jsonp_params": JSONP_PARAMS,
            "unauth_paths": UNAUTH_PATHS,
        }
        self.matchers: dict[str, Callable[[str, str], bool]] = {
            "sql_error": lambda body, _h: bool(SQL_ERROR_RE.search(body)),
            "traceback": lambda body, _h: bool(TRACEBACK_RE.search(body)),
            "secret": lambda body, _h: bool(SECRET_RE.search(body)),
            "file_read": lambda body, _h: any(p.search(body) for p in FILE_READ_SIGNS),
        }

    def spec(self, name: str) -> DetectorSpec:
        return self.specs[name]

    def select(self, param: str) -> list[DetectorSpec]:
        """按参数名推荐检测插件 (参数提示匹配 + 通用插件)."""
        selected: list[DetectorSpec] = []
        low = (param or "").lower()
        for spec in self.specs.values():
            if not spec.active:
                continue
            if "*" in spec.param_hints or not spec.param_hints:
                selected.append(spec)
            elif low in spec.param_hints or any(h in low for h in spec.param_hints):
                selected.append(spec)
        return selected

    def severity_of(self, name: str) -> Severity:
        return self.specs[name].severity if name in self.specs else Severity.MEDIUM

    def summary(self) -> dict:
        by_sev: dict[str, int] = {}
        for spec in self.specs.values():
            by_sev[spec.severity.value] = by_sev.get(spec.severity.value, 0) + 1
        return {"plugins": len(self.specs), "by_severity": by_sev,
                "payload_sets": len(self.payloads)}


def default_db() -> VulnDB:
    return VulnDB()
