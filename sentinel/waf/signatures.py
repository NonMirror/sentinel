"""规则防御模块 — 攻击特征检测 (libinjection 风格 + 正则特征库).

包含: SQL 注入、XSS、命令注入、路径穿越、SSRF、扫描器指纹、协议异常.
所有函数返回命中标签集合, 便于规则引擎与 IDS 复用.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SQLI_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sqli.union", re.compile(r"\bunion\b[\s\S]{0,12}?\bselect\b", re.I)),
    ("sqli.boolean", re.compile(
        r"\b(?:or|and)\b\s*\(?\s*(?:'?\d{1,8}'?\s*(?:=|<>|!=|like|<|>)|'[^']{0,32}'\s*=)", re.I)),
    ("sqli.tautology", re.compile(
        r"\b(?:or|and)\b\s*\(?\s*['\"]?(\w{1,16})['\"]?\s*=\s*['\"]?\1\b", re.I)),
    ("sqli.paren_bool", re.compile(r"\)\s*(?:or|and)\s*\(?\s*\d{1,6}\s*=\s*\d{1,6}", re.I)),
    ("sqli.quote_comment", re.compile(r"['\"`]\s*(?:--|#|/\*)", re.I)),
    ("sqli.comment", re.compile(r"(?:--\s|#\s*$|/\*.*?\*/)", re.I | re.S)),
    ("sqli.stacked", re.compile(r";\s*(?:drop|alter|create|insert|update|delete|truncate|exec|shutdown)\b", re.I)),
    ("sqli.time", re.compile(r"\b(?:sleep|pg_sleep|benchmark|waitfor\s+delay|dbms_pipe\.receive_message)\b\s*\(?", re.I)),
    ("sqli.metadata", re.compile(r"\b(?:information_schema|sysobjects|syscolumns|pg_catalog|all_tables|dual)\b", re.I)),
    ("sqli.file", re.compile(r"\b(?:load_file|into\s+outfile|into\s+dumpfile|utl_file|xp_cmdshell|sp_executesql)\b", re.I)),
    ("sqli.error", re.compile(r"\b(?:extractvalue|updatexml|exp|geometrycollection|polygon|multipoint)\s*\(", re.I)),
    ("sqli.quote", re.compile(r"(?:'|\")\s*(?:or|and|union|;)\b", re.I)),
    ("sqli.hex", re.compile(r"0x[0-9a-f]{6,}", re.I)),
    ("sqli.char", re.compile(r"\bchar\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\)", re.I)),
    ("sqli.version", re.compile(r"\b(?:version|database|user|current_user|@@version)\s*\(\s*\)|\b@@version\b", re.I)),
    ("sqli.orderby", re.compile(r"\border\s+by\s+\d{1,4}\b", re.I)),
    ("sqli.having", re.compile(r"\bhaving\s+\d+=\d+", re.I)),
]

XSS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("xss.script_tag", re.compile(r"<\s*script[\s/>]", re.I)),
    ("xss.js_proto", re.compile(r"javascript\s*:", re.I)),
    ("xss.event_handler", re.compile(r"\bon(?:error|load|click|mouseover|focus|submit|input|animationstart|toggle|begin)\s*=", re.I)),
    ("xss.html_tag", re.compile(r"<\s*(?:img|svg|iframe|body|video|audio|object|embed|marquee|details|form|math|input|link|meta)\b", re.I)),
    ("xss.js_func", re.compile(r"\b(?:alert|confirm|prompt|eval|setTimeout|setInterval|Function)\s*\(", re.I)),
    ("xss.dom_sink", re.compile(r"(?:document\.(?:cookie|domain|write|location)|window\.location|innerHTML|outerHTML|String\.fromCharCode)", re.I)),
    ("xss.encoded", re.compile(r"&#x?[0-9a-f]{2,4};|%3c\s*script|\\x3c|\\u003c", re.I)),
    ("xss.data_uri", re.compile(r"data\s*:\s*text/html", re.I)),
    ("xss.attribute_break", re.compile(r"[\"']\s*(?:on\w+\s*=|>\s*<\s*script)", re.I)),
    ("xss.angular", re.compile(r"\{\{[\s\S]{1,80}\}\}|ng-app", re.I)),
]

RCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("rce.shell_meta", re.compile(r"[;|&`]\s*(?:cat|ls|id|whoami|uname|curl|wget|nc|bash|sh|powershell|cmd)\b", re.I)),
    ("rce.subshell", re.compile(r"\$\([^)]{1,120}\)|\$\{[^}]{1,120}\}")),
    ("rce.php_func", re.compile(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|assert)\s*\(", re.I)),
    ("rce.java", re.compile(r"\$\{jndi:|java\.lang\.(?:Runtime|ProcessBuilder)|ProcessBuilder\s*\(", re.I)),
    ("rce.log4shell", re.compile(r"\$\{jndi:(?:ldap|rmi|dns|http)s?://", re.I)),
    ("rce.python", re.compile(r"__import__\s*\(|os\.system\s*\(|subprocess\.(?:Popen|call|run)", re.I)),
    ("rce.win", re.compile(r"%(?:COMSPEC|PATH)%=|cmd\.exe\s*/\s*c|powershell\s+-enc", re.I)),
]

TRAVERSAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("lfi.dotdot", re.compile(r"(?:\.\./|\.\.\\|%2e%2e[/\\%]|\.\.%2f|%c0%ae)", re.I)),
    ("lfi.abs_path", re.compile(r"(?:^|[/\\\s\"'=])(?:etc|proc|boot|windows|winnt|system32)[/\\]", re.I)),
    ("lfi.file", re.compile(r"(?:^|[\s\"'=])(?:/etc/passwd|/etc/shadow|boot\.ini|win\.ini|/proc/self/environ)", re.I)),
    ("lfi.wrapper", re.compile(
        r"(?:php|data|expect|zip|phar|glob|file|gopher|dict|input)\s*:\s*/{1,2}", re.I)),
    ("lfi.webinf", re.compile(r"(?:WEB-INF|META-INF)/\w+\.xml", re.I)),
]

SSRF_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssrf.localhost", re.compile(r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])", re.I)),
    ("ssrf.internal", re.compile(r"https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)", re.I)),
    ("ssrf.metadata", re.compile(r"169\.254\.169\.254|metadata\.(?:google|azure)|100\.100\.100\.200", re.I)),
    ("ssrf.proto", re.compile(r"\b(?:gopher|dict|tftp|ldap|jar|netdoc|ftp)://", re.I)),
    ("ssrf.file", re.compile(r"file://(?:/etc/|/proc/|/c:/)", re.I)),
]

SCANNER_FINGERPRINTS: list[tuple[str, re.Pattern[str]]] = [
    ("scanner.sqlmap", re.compile(r"sqlmap", re.I)),
    ("scanner.nikto", re.compile(r"nikto", re.I)),
    ("scanner.nmap", re.compile(r"\bnmap\b|nmap\s+scripting", re.I)),
    ("scanner.masscan", re.compile(r"masscan", re.I)),
    ("scanner.nuclei", re.compile(r"nuclei", re.I)),
    ("scanner.acunetix", re.compile(r"acunetix", re.I)),
    ("scanner.w3af", re.compile(r"w3af", re.I)),
    ("scanner.w13scan", re.compile(r"w13scan", re.I)),
    ("scanner.gobuster", re.compile(r"gobuster|dirbuster|dirb\b|feroxbuster|ffuf", re.I)),
    ("scanner.zgrab", re.compile(r"zgrab|zmap", re.I)),
    ("scanner.metasploit", re.compile(r"metasploit|msfconsole", re.I)),
    ("scanner.hydra", re.compile(r"hydra\b|patator|wfuzz", re.I)),
]

PROTOCOL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("proto.null_byte", re.compile(r"\x00")),
    ("proto.overlong", re.compile(r"%(?:c0|e0|f0)%(?:80|a0|af)")),
    ("proto.utf7", re.compile(r"\+ADw-", re.I)),
    ("proto.crlf", re.compile(r"%0d%0a|%0a%0d", re.I)),
]

CATEGORIES: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "sqli": SQLI_PATTERNS,
    "xss": XSS_PATTERNS,
    "rce": RCE_PATTERNS,
    "lfi": TRAVERSAL_PATTERNS,
    "ssrf": SSRF_PATTERNS,
    "scanner": SCANNER_FINGERPRINTS,
    "protocol": PROTOCOL_PATTERNS,
}

_SQL_KEYWORDS = frozenset(
    {"select", "union", "insert", "update", "delete", "drop", "from", "where", "and",
     "or", "having", "order", "by", "group", "exec", "sleep", "waitfor", "delay",
     "information_schema", "load_file", "outfile", "benchmark", "cast", "convert"}
)
_SQL_METACHARS = frozenset("'\"`;#-/*()<>=%")
_SQL_STRONG_META = frozenset("'\"`=;()#*")


@dataclass(slots=True)
class SigHit:
    tag: str
    category: str
    snippet: str


def _scan(value: str, patterns: list[tuple[str, re.Pattern[str]]], category: str,
          limit: int = 2) -> list[SigHit]:
    hits: list[SigHit] = []
    for tag, pattern in patterns:
        match = pattern.search(value)
        if match:
            start = max(0, match.start() - 8)
            hits.append(SigHit(tag, category, value[start:match.end() + 8][:96]))
            if len(hits) >= limit:
                break
    return hits


def looks_like_sqli(value: str) -> bool:
    """libinjection 风格启发式: SQL 关键字 + 强特征元字符 + 数量阈值.

    仅统计 SQL 专有元字符 (引号 / 等号 / 分号 / 括号 / 注释符), 排除路径分隔符,
    以免把 ``/search?q=order+by+popularity`` 这类正常请求误判为注入。
    """
    if len(value) > 4096:
        value = value[:4096]
    low = value.lower()
    tokens = re.findall(r"[a-z_]+|[^\sa-z_]", low)
    if len(tokens) < 3:
        return False
    keywords = sum(1 for t in tokens if t in _SQL_KEYWORDS)
    strong = sum(1 for t in tokens if t in _SQL_STRONG_META)
    quotes = low.count("'") + low.count('"')
    if keywords == 0 or strong == 0:
        return False
    if keywords >= 2 and strong >= 2:
        return True
    if quotes >= 1 and keywords >= 1 and strong >= 2:
        return True
    return keywords >= 3 and strong >= 3


def looks_like_xss(value: str) -> bool:
    if re.search(r"<\s*[a-z]+[\s/>]|&#x?[0-9a-f]{2,4};", value, re.I):
        if re.search(r"script|on\w+\s*=|javascript:|<svg|<img|<iframe|alert\(", value, re.I):
            return True
    return False


def looks_like_shell(value: str) -> bool:
    return bool(re.search(r"[;|&`]\s*\w|(?:\$\()|\bexec\b", value))


def detect(value: str, categories: list[str] | None = None) -> list[SigHit]:
    """对单值执行特征检测."""
    hits: list[SigHit] = []
    for name in (categories or list(CATEGORIES)):
        hits.extend(_scan(value, CATEGORIES[name], name))
    return hits


def scan_request_parts(parts: dict[str, str]) -> dict[str, list[SigHit]]:
    """对整个请求的各组成部分批量检测."""
    return {name: detect(value) for name, value in parts.items() if value}
