"""Naxsi 规则语法 (``MainRule`` / ``CheckRule`` / ``BasicRule``).

语法极简, 但有几个必须照做的细节:

* 参数是**空格分隔的带前缀引号串** (``"rx:..."`` / ``"msg:..."``), 且
  ``msg`` 内部可以含空格 —— 不能简单按空白切分。
* ``mz:`` 里的 ``$HEADERS_VAR:Cookie`` 带冒号, 与 ``ARGS`` 这类裸 zone 混写。
* ``s:$SQL:4`` 可以逗号连接多个计分项 (``"s:$SQL:8,$XSS:8"``)。
* ``CheckRule "$SQL >= 8" BLOCK;`` 的阈值是**字符串表达式**, 需要解析出来。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_ARG_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_ID_RE = re.compile(r"\bid:(\d+)")
_SCORE_RE = re.compile(r"\$([A-Za-z_]+)\s*:\s*(\d+)")
_THRESHOLD_RE = re.compile(r'\$([A-Za-z_]+)\s*(>=|>|==|=)\s*(\d+)')

#: Naxsi 官方示例 nginx 配置的默认判定阈值 (规则文件中不存在 CheckRule)
DEFAULT_THRESHOLDS = {
    "SQL": 8, "XSS": 8, "RFI": 8, "TRAVERSAL": 4, "EVADE": 4, "UPLOAD": 8,
}


@dataclass(slots=True)
class MainRule:
    """一条 ``MainRule`` (匹配面 + 计分)."""

    id: int
    kind: str = "str"          # str | rx
    pattern: str = ""
    message: str = ""
    zones: tuple[str, ...] = ()
    scores: dict[str, int] = field(default_factory=dict)
    raw: str = ""
    #: 预编译的正则 (仅 kind == "rx")
    compiled: re.Pattern[str] | None = None
    #: ``d:`` 指令 (内部规则, 不作为检测信号)
    internal: bool = False

    @property
    def points(self) -> int:
        return max(self.scores.values(), default=0)


@dataclass(slots=True)
class CheckRule:
    """一条 ``CheckRule`` (分区阈值 + 处置)."""

    variable: str = "SQL"
    operator: str = ">="
    threshold: int = 0
    action: str = "BLOCK"
    raw: str = ""


@dataclass(slots=True)
class NaxsiRuleSet:
    """Naxsi 规则集."""

    rules: list[MainRule] = field(default_factory=list)
    checks: list[CheckRule] = field(default_factory=list)
    whitelists: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def thresholds(self, tightening: int = 0) -> dict[str, int]:
        """按 ``tightening`` (paranoia level - 1) 收紧各分区阈值.

        ``naxsi_core.rules`` **只有 MainRule**: ``CheckRule`` 历来写在 nginx
        配置里, 不在规则文件中。因此没有显式 CheckRule 时回落到 Naxsi 官方
        示例配置的默认阈值, 否则所有请求都会因为「阈值为 0」而被拦截。
        """
        base: dict[str, int] = {} if self.checks else dict(DEFAULT_THRESHOLDS)
        for check in self.checks:
            current = base.get(check.variable)
            # 同名变量取最严格的一条
            base[check.variable] = (check.threshold if current is None
                                    else min(current, check.threshold))
        delta = max(0, tightening)
        return {name: max(1, value - delta) for name, value in base.items()}

    def summary(self) -> dict[str, object]:
        zones: dict[str, int] = {}
        for rule in self.rules:
            for zone in rule.zones:
                zones[zone] = zones.get(zone, 0) + 1
        return {
            "total": len(self.rules),
            "checks": len(self.checks),
            "whitelists": len(self.whitelists),
            "by_zone": zones,
            "by_score": self._score_histogram(),
            "warnings": len(self.warnings),
        }

    def _score_histogram(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for rule in self.rules:
            for name in rule.scores:
                out[name] = out.get(name, 0) + 1
        return out


# --------------------------------------------------------------------------
# 解析
# --------------------------------------------------------------------------
def parse_main_rule(statement: str) -> MainRule | None:
    """解析一条 ``MainRule``."""
    args = _ARG_RE.findall(statement)
    if len(args) < 2:
        return None
    rule_id_match = _ID_RE.search(statement)
    rule = MainRule(id=int(rule_id_match.group(1)) if rule_id_match else 0,
                    raw=statement[:400])
    internal = False
    for argument in args:
        prefix, _, body = argument.partition(":")
        prefix = prefix.lower()
        if prefix == "rx":
            rule.kind = "rx"
            rule.pattern = _unescape(body)
        elif prefix == "str":
            rule.kind = "str"
            # Naxsi 的 str: 是**大小写不敏感**的子串匹配
            # (naxsi_utils.c 用 strncasechr/strncasecmp), 因此预先把模式小写化,
            # 检测时只需要小写化待检值一次。
            rule.pattern = _unescape(body)
        elif prefix == "msg":
            rule.message = body
        elif prefix == "mz":
            rule.zones = tuple(part.strip() for part in body.split("|") if part.strip())
        elif prefix == "s":
            rule.scores.update(
                {name: int(value) for name, value in _SCORE_RE.findall(body)})
        elif prefix in ("d", "c", "f"):
            internal = True
    rule.internal = internal
    if rule.kind == "rx" and rule.pattern:
        try:
            # Naxsi 编译 rx: 时固定带 PCRE_CASELESS | PCRE_MULTILINE
            # (naxsi_config.c: `rgc->options = PCRE_CASELESS | PCRE_MULTILINE`)。
            # 少了 IGNORECASE, 核心规则里的 `rx:select|union|...` 会漏掉
            # 所有大写形式的攻击。
            rule.compiled = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as exc:
            rule.compiled = None
            rule.message = f"{rule.message} (正则无效: {exc})"
    if rule.kind == "str":
        rule.pattern = rule.pattern.lower()
    if not rule.zones:
        rule.zones = ("ARGS", "BODY", "URL", "HEADERS")
    rule.zones = tuple(_normalise_zone(z) for z in rule.zones)
    return rule


def _unescape(text: str) -> str:
    """去掉 ModSecurity/Naxsi 参数里的反斜杠转义 (``\\"`` -> ``"``)."""
    if "\\" not in text:
        return text
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            out.append(text[index + 1])
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _normalise_zone(zone: str) -> str:
    """``$HEADERS_VAR:Cookie`` 与 ``HEADERS_VAR:Cookie`` 是同一个检测面."""
    return zone.lstrip("$").strip()


def parse_check_rule(statement: str) -> CheckRule | None:
    """解析一条 ``CheckRule``."""
    match = _THRESHOLD_RE.search(statement)
    if match is None:
        return None
    # 阈值表达式通常被引号包着: CheckRule "$SQL >= 8" BLOCK;
    # 匹配结束后要先跳过收尾引号, 否则动作会被解析成 `"`。
    action = "BLOCK"
    tail = statement[match.end():].lstrip().lstrip("\"'").strip().rstrip(";").strip()
    if tail:
        action = tail.split()[0].upper()
    return CheckRule(variable=match.group(1).upper(), operator=match.group(2),
                     threshold=int(match.group(3)), action=action,
                     raw=statement[:200])


def load_naxsi_rules(paths) -> NaxsiRuleSet:
    """加载 ``naxsi_core.rules`` 或目录."""
    ruleset = NaxsiRuleSet()
    for path in _expand(paths):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:                        # pragma: no cover
            ruleset.warnings.append(f"{path}: {exc}")
            continue
        ruleset.sources.append(str(path))
        for line in text.splitlines():
            statement = line.strip()
            if not statement or statement.startswith("#"):
                continue
            if statement.startswith("MainRule"):
                rule = parse_main_rule(statement)
                if rule is not None:
                    ruleset.rules.append(rule)
                else:
                    ruleset.warnings.append(f"无法解析: {statement[:80]}")
            elif statement.startswith("CheckRule"):
                check = parse_check_rule(statement)
                if check is not None:
                    ruleset.checks.append(check)
            elif statement.startswith("BasicRule"):
                ruleset.whitelists.append(statement)
            elif statement.startswith(("Include", "SecRulesEnabled",
                                       "SecRulesDisabled", "LearningMode",
                                       "DeniedUrl")):
                continue
            else:
                ruleset.warnings.append(f"未处理的指令: {statement[:60]}")
    return ruleset


def _expand(paths) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            out.extend(sorted(path.rglob("*.rules")))
        elif path.exists():
            out.append(path)
    return out
