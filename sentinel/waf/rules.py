"""规则防御模块 — ModSecurity 风格规则引擎.

规则模型与语义对齐 OWASP ModSecurity (SecRule) 规则子集:
``SecRule VARIABLES "@operator arg" "id:...,phase:...,severity:...,action"``.

支持从以下位置载入:
  * JSON 规则文件 (原生, 功能最全)
  * ModSecurity 风格 ``.conf`` 文本 (子集)
  * 内置默认规则集 (无外部依赖)
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

from ..core.models import HttpRequest, Severity, Verdict
from . import signatures
from .parser import collect_arguments, iter_variable_values
from .transforms import apply_transforms

SEVERITY_SCORE = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

ACTION_VERDICT = {
    "block": Verdict.BLOCK,
    "deny": Verdict.BLOCK,
    "drop": Verdict.DROP,
    "pass": Verdict.PASS,
    "allow": Verdict.PASS,
    "log": Verdict.LOG,
    "redirect": Verdict.REDIRECT,
    "ratelimit": Verdict.RATE_LIMIT,
}


@dataclass(slots=True)
class Match:
    rule: "Rule"
    variable: str
    value: str
    evidence: str

    @property
    def score(self) -> int:
        return self.rule.effective_score


class Operator:
    """算子实现集合."""

    NAMES = (
        "rx", "contains", "containsAny", "containsWord", "pm", "eq", "startsWith",
        "endsWith", "detectSQLi", "detectXSS", "detectRCE", "detectTraversal",
        "detectSSRF", "ipMatch", "gt", "ge", "lt", "le", "noMatch", "alwaysMatch",
        "validateByteRange", "within", "unconditionalMatch", "beginsWith",
    )

    _CANON = {
        "rx": "rx", "contains": "contains", "containsany": "containsAny",
        "containsword": "containsWord", "pm": "pm", "eq": "eq",
        "startswith": "startsWith", "beginswith": "startsWith", "endswith": "endsWith",
        "detectsqli": "detectSQLi", "detectxss": "detectXSS", "detectrce": "detectRCE",
        "detecttraversal": "detectTraversal", "detectssrf": "detectSSRF",
        "ipmatch": "ipMatch", "gt": "gt", "ge": "ge", "lt": "lt", "le": "le",
        "nomatch": "noMatch", "alwaysmatch": "alwaysMatch",
        "unconditionalmatch": "alwaysMatch", "validatebyterange": "validateByteRange",
        "within": "within",
    }

    @classmethod
    def compile(cls, name: str, arg: str):
        name = cls._CANON.get(name.strip().lower(), name.strip().lower())
        if name in ("rx",):
            try:
                flags = re.I | re.S
                return ("rx", re.compile(arg, flags))
            except re.error:
                return ("rx", re.compile(re.escape(arg), re.I))
        if name == "pm":
            phrases = [p.strip().lower() for p in arg.split("|") if p.strip()]
            return ("pm", phrases)
        if name == "containsAny":
            items = [p for p in arg.split("|") if p]
            return ("containsAny", items)
        if name == "contains":
            return ("contains", arg)
        if name == "containsWord":
            return ("containsWord", arg)
        if name == "ipMatch":
            from ipaddress import ip_address, ip_network

            nets = []
            for token in arg.split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    nets.append(ip_network(token, strict=False))
                except ValueError:
                    continue
            return ("ipMatch", nets)
        if name in ("gt", "ge", "lt", "le"):
            try:
                return (name, float(arg))
            except ValueError:
                return (name, 0.0)
        if name == "within":
            return ("within", arg)
        if name == "validateByteRange":
            return ("validateByteRange", [int(x) for x in arg.split(",") if x.strip()])
        return (name, arg)

    @staticmethod
    def apply(op, value: str) -> tuple[bool, str]:  # noqa: C901
        name, arg = op
        if name == "rx":
            match = arg.search(value)
            return (bool(match), match.group(0)[:120] if match else "")
        if name == "pm":
            low = value.lower()
            for phrase in arg:
                if phrase and phrase in low:
                    return True, phrase
            return False, ""
        if name == "contains":
            return (arg in value), (arg if arg in value else "")
        if name == "containsAny":
            for item in arg:
                if item in value:
                    return True, item
            return False, ""
        if name == "containsWord":
            found = re.search(rf"\b{re.escape(arg)}\b", value, re.I)
            return (bool(found), arg if found else "")
        if name == "eq":
            return (value == arg), value
        if name == "startsWith":
            return (value.startswith(arg), arg)
        if name == "endsWith":
            return (value.endswith(arg), arg)
        if name == "gt" or name == "ge" or name == "lt" or name == "le":
            try:
                number = float(value)
            except ValueError:
                return False, ""
            ok = {"gt": number > arg, "ge": number >= arg,
                  "lt": number < arg, "le": number <= arg}[name]
            return ok, str(number)
        if name == "ipMatch":
            from ipaddress import ip_address

            try:
                addr = ip_address(value)
            except ValueError:
                return False, ""
            for net in arg:
                if addr in net:
                    return True, str(addr)
            return False, ""
        if name == "within":
            return (value in arg), value
        if name == "validateByteRange":
            # 参数为允许范围白名单, 命中表示存在越界字节
            allowed = set()
            for item in arg:
                allowed.add(item)
            for ch in value:
                if ord(ch) not in allowed and ord(ch) not in (9, 10, 13):
                    return True, f"0x{ord(ch):02x}"
            return False, ""
        if name == "detectSQLi":
            hits = signatures._scan(value, signatures.SQLI_PATTERNS, "sqli", 1)
            if hits:
                return True, hits[0].snippet
            if signatures.looks_like_sqli(value):
                return True, value[:80]
            return False, ""
        if name == "detectXSS":
            hits = signatures._scan(value, signatures.XSS_PATTERNS, "xss", 1)
            if hits:
                return True, hits[0].snippet
            if signatures.looks_like_xss(value):
                return True, value[:80]
            return False, ""
        if name == "detectRCE":
            hits = signatures._scan(value, signatures.RCE_PATTERNS, "rce", 1)
            return (bool(hits), hits[0].snippet if hits else "")
        if name == "detectTraversal":
            hits = signatures._scan(value, signatures.TRAVERSAL_PATTERNS, "lfi", 1)
            return (bool(hits), hits[0].snippet if hits else "")
        if name == "detectSSRF":
            hits = signatures._scan(value, signatures.SSRF_PATTERNS, "ssrf", 1)
            return (bool(hits), hits[0].snippet if hits else "")
        if name == "noMatch":
            return (not value), ""
        if name == "alwaysMatch":
            return True, value[:60]
        return False, ""


@dataclass(slots=True)
class Rule:
    id: int
    description: str
    variables: list[str] = field(default_factory=lambda: ["ARGS"])
    operator: str = "detectSQLi"
    operator_arg: str = ""
    severity: Severity = Severity.HIGH
    action: str = "block"
    phase: int = 2
    transforms: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    score: int = 0
    paranoia_level: int = 1
    enabled: bool = True
    category: str = "generic"
    _compiled: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        self._compiled = Operator.compile(self.operator, self.operator_arg)

    @property
    def effective_score(self) -> int:
        return self.score or SEVERITY_SCORE[self.severity]

    @property
    def verdict(self) -> Verdict:
        return ACTION_VERDICT.get(self.action.lower(), Verdict.LOG)

    def matches(self, req: HttpRequest) -> list[Match]:
        if not self.enabled:
            return []
        found: list[Match] = []
        seen: set[str] = set()
        for selector in self.variables:
            for raw in iter_variable_values(req, selector):
                if raw is None:
                    continue
                value = apply_transforms(raw, self.transforms) if self.transforms else raw
                key = f"{selector}\u0000{value}"
                if key in seen:
                    continue
                seen.add(key)
                hit, evidence = Operator.apply(self._compiled, value)
                if hit:
                    found.append(Match(self, selector, value[:256], evidence[:160]))
        return found

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "variables": self.variables,
            "operator": self.operator,
            "operator_arg": self.operator_arg,
            "severity": self.severity.value,
            "action": self.action,
            "phase": self.phase,
            "transforms": self.transforms,
            "tags": self.tags,
            "score": self.score,
            "paranoia_level": self.paranoia_level,
            "enabled": self.enabled,
            "category": self.category,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        data = dict(data)
        if "id" not in data or "description" not in data:
            raise ValueError("规则缺少 id/description")
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_modsecurity(self) -> str:
        """导出为 ModSecurity (SecRule) 指令, 可被 ModSecurity/CRS 引擎加载."""
        arg = self.operator_arg.replace('"', '\\"')
        actions = [
            f"id:{self.id}",
            f"phase:{self.phase}",
            f"severity:{self.severity.value.upper()}",
            *[f"t:{name}" for name in self.transforms],
            f"setvar:'tx.anomaly_score_pl1=+{self.effective_score}'",
            f"msg:'{self.description}'",
            f"tag:'{','.join(self.tags)}'" if self.tags else "",
            f"block" if self.action in ("block", "deny") else self.action,
        ]
        action_str = ",".join(a for a in actions if a)
        return f'SecRule {",".join(self.variables)} "@{self.operator} {arg}" "{action_str}"'


class RuleSet:
    """规则集合 + 载入器."""

    def __init__(self, rules: Iterable[Rule] | None = None,
                 paranoia_level: int = 1) -> None:
        self.rules: list[Rule] = list(rules or [])
        self._by_id: dict[int, Rule] = {r.id: r for r in self.rules}
        self.paranoia_level = paranoia_level

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def add(self, rule: Rule) -> None:
        if rule.id in self._by_id:
            self.rules[self.rules.index(self._by_id[rule.id])] = rule
        else:
            self.rules.append(rule)
        self._by_id[rule.id] = rule

    def get(self, rule_id: int) -> Rule | None:
        return self._by_id.get(rule_id)

    def enable(self, rule_id: int, enabled: bool) -> bool:
        rule = self._by_id.get(rule_id)
        if not rule:
            return False
        rule.enabled = enabled
        return True

    def active(self) -> list[Rule]:
        return [r for r in self.rules if r.enabled and r.paranoia_level <= self.paranoia_level]

    def evaluate(self, req: HttpRequest) -> list[Match]:
        matches: list[Match] = []
        for rule in self.active():
            matches.extend(rule.matches(req))
        return matches

    # ---------- 载入 ----------
    @classmethod
    def load_json(cls, path: str, paranoia_level: int = 1) -> "RuleSet":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        items = data.get("rules", data) if isinstance(data, dict) else data
        return cls((Rule.from_dict(item) for item in items), paranoia_level)

    @classmethod
    def load_conf(cls, path: str, paranoia_level: int = 1) -> "RuleSet":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(_parse_modsecurity(fh.read()), paranoia_level)

    @classmethod
    def load_dir(cls, directory: str, paranoia_level: int = 1) -> "RuleSet":
        """载入目录内所有规则文件 (不做内置回退)."""
        rules: list[Rule] = []
        if os.path.isdir(directory):
            for name in sorted(os.listdir(directory)):
                full = os.path.join(directory, name)
                if name.endswith(".json"):
                    rules.extend(cls.load_json(full).rules)
                elif name.endswith((".conf", ".rules")):
                    rules.extend(cls.load_conf(full).rules)
        return cls(rules, paranoia_level)

    def save_json(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"rules": [r.to_dict() for r in self.rules]}, fh,
                      ensure_ascii=False, indent=2)

    def export_modsecurity(self, path: str) -> int:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# 由 Sentinel 规则引擎导出, 兼容 OWASP ModSecurity SecRule 语法\n")
            for rule in self.rules:
                if rule.enabled:
                    fh.write(rule.to_modsecurity() + "\n")
        return sum(1 for r in self.rules if r.enabled)

    def summary(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for rule in self.rules:
            by_sev[rule.severity.value] = by_sev.get(rule.severity.value, 0) + 1
            by_cat[rule.category] = by_cat.get(rule.category, 0) + 1
        return {
            "total": len(self.rules),
            "enabled": sum(1 for r in self.rules if r.enabled),
            "by_severity": by_sev,
            "by_category": by_cat,
        }


_SECRULE_RE = re.compile(
    r'^\s*SecRule\s+(?P<vars>[^\s"]+)\s+"(?P<op>@?\w+)\s*(?P<arg>(?:[^"\\]|\\.)*)"\s*"'
    r'(?P<actions>(?:[^"\\]|\\.)*)"',
    re.I,
)


def _parse_modsecurity(text: str) -> list[Rule]:
    rules: list[Rule] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _SECRULE_RE.match(line)
        if not match:
            continue
        variables = [v.strip().upper() for v in match.group("vars").split("|") if v.strip()]
        op_name = match.group("op").lstrip("@")
        op_arg = match.group("arg").replace('\\"', '"')
        actions = match.group("actions")
        rule = Rule(
            id=int(_action(actions, "id") or len(rules) + 900000),
            description=_action(actions, "msg") or line[:60],
            variables=variables or ["ARGS"],
            operator=op_name,
            operator_arg=op_arg,
            severity=(_action(actions, "severity") or "high").lower(),
            action=("drop" if "drop" in actions.lower() else
                    "block" if re.search(r"\b(block|deny)\b", actions, re.I) else "log"),
            phase=int(_action(actions, "phase") or 2),
            transforms=_transforms(actions),
            tags=[t for t in (_action(actions, "tag") or "").split(",") if t],
            category="imported",
        )
        rules.append(rule)
    return rules


def _transforms(actions: str) -> list[str]:
    """收集全部 t: 变换 (同时兼容 t:a,t:b 与 t:a,t:b 两种写法)."""
    found: list[str] = []
    for chunk in re.findall(r"(?:^|,)\s*t\s*:\s*([^,]+)", actions, re.I):
        found.extend(part.strip() for part in chunk.split(",") if part.strip())
    return found


def _action(actions: str, key: str) -> str:
    match = re.search(rf"(?:^|,)\s*{key}\s*:\s*([^,]+)", actions, re.I)
    if not match:
        return ""
    return match.group(1).strip().strip("'\"")


def default_rules() -> list[Rule]:
    """内置默认规则集 (对齐 OWASP CRS 的核心检测点)."""
    r: list[Rule] = []

    def add(rid, desc, variables, op, arg, severity, action="block", score=0,
            transforms=(), tags=(), phase=2, pl=1, category="generic") -> None:
        r.append(Rule(id=rid, description=desc, variables=list(variables), operator=op,
                      operator_arg=arg, severity=Severity(severity), action=action,
                      transforms=list(transforms), tags=list(tags), score=score,
                      phase=phase, paranoia_level=pl, category=category))

    # --- 协议层 (phase 1) ---
    add(910000, "请求方法不在白名单内", ["REQUEST_METHOD"], "rx",
        "^(?!(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)$).+$", "medium", score=3,
        phase=1, tags=("protocol",), category="protocol")
    add(910001, "URI 过长 (疑似缓冲区探测)", ["REQUEST_URI"], "gt", "8192", "medium",
        score=3, transforms=("length",), phase=1, tags=("protocol",),
        category="protocol")
    add(910002, "请求头注入 CRLF", ["REQUEST_HEADERS"], "rx", "(?:%0d%0a|\\r\\n)", "high",
        score=5, phase=1, tags=("protocol", "crlf"), category="protocol")
    add(910003, "空字节注入", ["REQUEST_URI", "REQUEST_BODY"], "rx", "\\x00", "high",
        score=5, phase=1, tags=("protocol",), category="protocol")
    add(910004, "请求头过长 (疑似缓冲区探测)", ["REQUEST_HEADERS"], "gt", "8192",
        "medium", score=3, transforms=("length",), phase=1,
        tags=("protocol",), category="protocol")

    # --- SQL 注入 ---
    sqli_vars = ["ARGS", "REQUEST_URI", "REQUEST_HEADERS:User-Agent",
                 "REQUEST_HEADERS:Referer", "REQUEST_COOKIES"]
    add(942100, "SQL 注入: libinjection 检测", sqli_vars, "detectSQLi", "", "critical",
        score=5, transforms=("urlDecodeUni", "removeNulls", "compressWhitespace"),
        tags=("sqli", "owasp-a03"), category="sqli")
    add(942110, "SQL 注入: union select", sqli_vars, "rx",
        "(?i)\\bunion\\b[\\s\\S]{0,12}?\\bselect\\b", "critical", score=5,
        transforms=("urlDecodeUni",), tags=("sqli",), category="sqli")
    add(942120, "SQL 注入: 布尔/恒真表达式", sqli_vars, "rx",
        "(?i)(?:\\bor\\b|\\band\\b)\\s*\\(?\\s*(?:['\"`]\\w{1,16}['\"`]|\\d{1,8})\\s*"
        "(?:=|<>|!=|<|>|like)\\s*(?:['\"`]\\w{1,16}['\"`]|\\d{1,8})", "high", score=4,
        transforms=("urlDecodeUni", "lowercase"), tags=("sqli",), category="sqli")
    add(942130, "SQL 注入: 时间盲注函数", sqli_vars, "rx",
        "(?i)\\b(?:sleep|benchmark|pg_sleep|waitfor\\s+delay)\\s*\\(", "critical", score=5,
        transforms=("urlDecodeUni",), tags=("sqli", "time-based"), category="sqli")
    add(942140, "SQL 注入: 堆叠查询", sqli_vars, "rx",
        "(?i);\\s*(?:drop|alter|create|insert|update|delete|truncate|exec)\\b", "critical",
        score=5, transforms=("urlDecodeUni",), tags=("sqli",), category="sqli")
    add(942150, "SQL 注入: 元数据/文件读写", sqli_vars, "rx",
        "(?i)\\b(?:information_schema|load_file|into\\s+outfile|xp_cmdshell|sysobjects)\\b",
        "high", score=4, transforms=("urlDecodeUni",), tags=("sqli",), category="sqli")
    add(942160, "SQL 注入: 报错注入函数", sqli_vars, "rx",
        "(?i)\\b(?:extractvalue|updatexml|exp|geometrycollection|polygon)\\s*\\(", "high",
        score=4, transforms=("urlDecodeUni",), tags=("sqli",), category="sqli")
    add(942170, "SQL 注入: order by 探测", sqli_vars, "rx",
        "(?i)\\border\\s+by\\s+\\d{1,4}\\b", "medium", score=3,
        transforms=("urlDecodeUni",), tags=("sqli",), category="sqli", pl=2)

    # --- XSS ---
    xss_vars = ["ARGS", "REQUEST_HEADERS:Referer", "REQUEST_HEADERS:User-Agent",
                "REQUEST_COOKIES"]
    add(941100, "XSS: libinjection 检测", xss_vars, "detectXSS", "", "high", score=4,
        transforms=("urlDecodeUni", "htmlEntityDecode", "jsDecode"),
        tags=("xss", "owasp-a03"), category="xss")
    add(941110, "XSS: script 标签", xss_vars, "rx", "(?i)<\\s*script[\\s/>]", "high",
        score=4, transforms=("urlDecodeUni", "htmlEntityDecode"), tags=("xss",), category="xss")
    add(941120, "XSS: 事件处理器", xss_vars, "rx",
        "(?i)\\bon(?:error|load|click|mouseover|focus|submit|animationstart|toggle)\\s*=",
        "high", score=4, transforms=("urlDecodeUni", "htmlEntityDecode"),
        tags=("xss",), category="xss")
    add(941130, "XSS: javascript 伪协议", xss_vars, "rx", "(?i)javascript\\s*:", "high",
        score=4, transforms=("urlDecodeUni", "htmlEntityDecode"), tags=("xss",), category="xss")
    add(941140, "XSS: 危险 HTML 标签", xss_vars, "rx",
        "(?i)<\\s*(?:svg|iframe|object|embed|img|video|math|details)\\b", "medium", score=3,
        transforms=("urlDecodeUni", "htmlEntityDecode"), tags=("xss",), category="xss")
    add(941150, "XSS: DOM 危险汇聚点", xss_vars, "rx",
        "(?i)(?:document\\.(?:cookie|write|location)|innerHTML|String\\.fromCharCode)", "medium",
        score=3, transforms=("urlDecodeUni",), tags=("xss",), category="xss")
    add(941160, "XSS: 编码绕过载荷", xss_vars, "rx",
        "(?i)(?:&#x?[0-9a-f]{2,4};|%3c\\s*script|\\\\x3c|\\\\u003c)", "high", score=4,
        transforms=("urlDecodeUni",), tags=("xss", "evasion"), category="xss", pl=2)

    # --- 命令注入 ---
    rce_vars = ["ARGS", "REQUEST_URI", "REQUEST_HEADERS:User-Agent", "REQUEST_COOKIES"]
    add(932100, "命令注入: 特征检测", rce_vars, "detectRCE", "", "critical", score=5,
        transforms=("urlDecodeUni", "removeNulls"), tags=("rce", "owasp-a03"), category="rce")
    add(932110, "命令注入: shell 元字符", rce_vars, "rx",
        "[;|&`]\\s*(?:cat|ls|id|whoami|uname|curl|wget|nc|bash|sh|powershell|cmd)\\b",
        "critical", score=5, transforms=("urlDecodeUni", "lowercase"),
        tags=("rce",), category="rce")
    add(932120, "命令注入: Log4Shell", rce_vars + ["REQUEST_HEADERS"], "rx",
        "(?i)\\$\\{jndi:(?:ldap|rmi|dns|http)s?://", "critical", score=5,
        tags=("rce", "log4shell", "cve-2021-44228"), category="rce")

    # --- 路径穿越 / 文件包含 ---
    add(930100, "路径穿越: 特征检测", ["ARGS", "REQUEST_URI"], "detectTraversal", "",
        "high", score=4, transforms=("urlDecodeUni", "removeNulls"),
        tags=("lfi", "owasp-a01"), category="lfi")
    add(930110, "路径穿越: 点目录序列", ["ARGS", "REQUEST_URI"], "rx",
        "(?:\\.\\./|\\.\\.\\\\|%2e%2e[/\\\\%])", "high", score=4,
        transforms=("urlDecodeUni", "normalizePath"), tags=("lfi",), category="lfi")
    add(930120, "敏感文件访问", ["ARGS", "REQUEST_URI"], "rx",
        "(?i)(?:/etc/passwd|/etc/shadow|boot\\.ini|win\\.ini|/proc/self/environ|WEB-INF/\\w+\\.xml)",
        "high", score=4, transforms=("urlDecodeUni",), tags=("lfi",), category="lfi")

    # --- SSRF ---
    add(934100, "SSRF: 内网地址探测", ["ARGS", "REQUEST_URI"], "detectSSRF", "", "high",
        score=4, transforms=("urlDecodeUni",), tags=("ssrf", "owasp-a10"), category="ssrf")
    add(934110, "SSRF: 云元数据端点", ["ARGS"], "rx",
        "(?i)(?:169\\.254\\.169\\.254|metadata\\.(?:google|azure)|100\\.100\\.100\\.200)",
        "critical", score=5, transforms=("urlDecodeUni",), tags=("ssrf",), category="ssrf")

    # --- 扫描器/自动化工具 ---
    add(913100, "自动化扫描器 User-Agent", ["REQUEST_HEADERS:User-Agent"], "rx",
        "(?i)(?:sqlmap|nikto|nmap|masscan|nuclei|acunetix|w3af|w13scan|gobuster|dirbuster|dirb|feroxbuster|ffuf|zgrab|zmap|metasploit|hydra|wfuzz|patator)",
        "medium", score=3, tags=("scanner", "recon"), category="scanner")
    add(913110, "空/异常 User-Agent", ["REQUEST_HEADERS:User-Agent"], "noMatch", "",
        "low", score=2, tags=("scanner",), category="scanner", pl=3)
    add(913120, "敏感文件/目录探测", ["REQUEST_URI"], "rx",
        "(?i)/\\.(?:git|svn|env|ssh|aws|htaccess|DS_Store)|/(?:phpinfo|phpmyadmin|wp-admin|wp-login|adminer|actuator|swagger-ui|druid|console|manager/html|debug|config|admin)|/[\\w.-]*\\.(?:bak|sql|zip|tar\\.gz|old|swp)(?:$|[?\\s])",
        "medium", score=3, tags=("recon",), category="scanner")

    # --- 信息泄露 ---
    add(950100, "请求体包含错误堆栈特征", ["REQUEST_BODY"], "rx",
        "(?i)(?:stack\\s*trace|exception|traceback|\\.java:\\d+|at\\s+[\\w.$]+\\([\\w.]+\\.java)",
        "low", score=2, tags=("info-leak",), category="info-leak", pl=2)

    return r


def load_ruleset(rule_dir: str | None = None, paranoia_level: int = 1,
                 with_builtin: bool = True) -> RuleSet:
    """构建规则集: 内置规则 + 规则目录扩展 (同 ID 时以目录内规则覆盖).

    这是 WAF 引擎与 TUI 的统一入口, 保证 "基础检测能力开箱即用, 同时支持
    通过 rules/ 目录扩展或覆盖规则".
    """
    rules: list[Rule] = default_rules() if with_builtin else []
    index = {rule.id: position for position, rule in enumerate(rules)}
    if rule_dir and os.path.isdir(rule_dir):
        for name in sorted(os.listdir(rule_dir)):
            full = os.path.join(rule_dir, name)
            try:
                if name.endswith(".json"):
                    loaded = RuleSet.load_json(full).rules
                elif name.endswith((".conf", ".rules")):
                    loaded = RuleSet.load_conf(full).rules
                else:
                    continue
            except (ValueError, OSError):
                continue
            for rule in loaded:
                if rule.id in index:
                    rules[index[rule.id]] = rule
                else:
                    index[rule.id] = len(rules)
                    rules.append(rule)
    return RuleSet(rules, paranoia_level)
