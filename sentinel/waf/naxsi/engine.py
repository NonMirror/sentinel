"""Naxsi 评分引擎 (原生实现).

执行模型:

1. 把请求摊平成 Naxsi 的**检测面** (URL / ARGS / BODY / HEADERS / FILE_EXT);
2. 每条 ``MainRule`` 在它声明的 ``mz:`` 面上匹配, 命中就按 ``s:$KEY:n`` 加分;
3. 与 ``CheckRule`` 的阈值比较, 任一计分项越线即判定拦截。

与 ModSecurity 侧最大的差别在于「没有规则命中 = 没有信号」: 单条规则命中只
意味着加分, 是否拦截由**累计分数**决定 —— 这也是 Naxsi 误报低、漏报相对高的
根本原因 (README 的实测数据同样呈现这个特征)。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ...core.models import HttpRequest, Severity
from .syntax import MainRule, NaxsiRuleSet

#: Naxsi 的检测面 -> 中文说明 (供 TUI 展示)
ZONE_LABELS = {
    "URL": "请求 URL", "ARGS": "参数值", "BODY": "请求体",
    "HEADERS": "请求头", "RAW": "原始报文", "FILE_EXT": "文件扩展名",
}


@dataclass(slots=True)
class NaxsiHit:
    """一条 MainRule 的命中记录."""

    rule_id: int
    message: str
    zone: str
    points: int
    keyword: str
    value: str


@dataclass
class NaxsiVerdict:
    """一次请求的判定结果."""

    blocked: bool = False
    scores: dict[str, int] = field(default_factory=dict)
    thresholds: dict[str, int] = field(default_factory=dict)
    hits: list[NaxsiHit] = field(default_factory=list)
    status: int = 403
    elapsed_ms: float = 0.0
    evaluated: int = 0

    @property
    def total(self) -> int:
        return sum(self.scores.values())

    @property
    def breached(self) -> dict[str, int]:
        return {name: score for name, score in self.scores.items()
                if score >= self.thresholds.get(name, 1 << 30)}

    def messages(self) -> list[str]:
        return [hit.message for hit in self.hits]

    def matched_rules(self) -> list[int]:
        out: list[int] = []
        for hit in self.hits:
            if hit.rule_id and hit.rule_id not in out:
                out.append(hit.rule_id)
        return out

    @property
    def severity(self) -> Severity:
        if not self.blocked:
            return Severity.INFO
        score = max(self.scores.values(), default=0)
        return Severity.CRITICAL if score >= 16 else (
            Severity.HIGH if score >= 8 else Severity.MEDIUM)

    def as_dict(self) -> dict:
        return {
            "blocked": self.blocked, "scores": dict(self.scores),
            "thresholds": dict(self.thresholds), "total": self.total,
            "breached": self.breached,
            "hits": [{"rule_id": h.rule_id, "message": h.message,
                      "zone": h.zone, "points": h.points,
                      "keyword": h.keyword} for h in self.hits[:32]],
            "elapsed_ms": round(self.elapsed_ms, 4),
            "evaluated": self.evaluated,
        }


class NativeNaxsiEngine:
    """在进程内执行 Naxsi 规则的评分引擎."""

    def __init__(self, ruleset: NaxsiRuleSet, *, paranoia_level: int = 1,
                 enabled: bool = True, mode: str = "block") -> None:
        self.ruleset = ruleset
        self.paranoia_level = max(1, min(4, int(paranoia_level)))
        self.enabled = enabled
        self.mode = mode
        self.thresholds = ruleset.thresholds(self.paranoia_level - 1)
        self.warnings = list(ruleset.warnings)
        self.stats = {"inspected": 0, "scored": 0, "blocked": 0}
        #: 只保留非内部规则 (d:/c:/f: 是 Naxsi 的内部信号, 不是检测规则)
        self._rules: list[MainRule] = [r for r in ruleset.rules if not r.internal]
        self._string_rules = [r for r in self._rules if r.kind == "str"]
        self._regex_rules = [r for r in self._rules if r.kind == "rx"]

    # ------------------------------------------------------------------
    @classmethod
    def from_paths(cls, paths, **kwargs) -> "NativeNaxsiEngine":
        from .syntax import load_naxsi_rules
        return cls(load_naxsi_rules(paths), **kwargs)

    @property
    def active_rules(self) -> list[MainRule]:
        """参与检测的规则 (已剔除 ``d:`` 等内部信号规则)."""
        return self._rules

    def summary(self) -> dict[str, object]:
        return {**self.ruleset.summary(), "active": len(self._rules),
                "thresholds": dict(self.thresholds)}

    # ------------------------------------------------------------------
    def inspect(self, request: HttpRequest) -> NaxsiVerdict:
        started = time.perf_counter()
        verdict = NaxsiVerdict(thresholds=dict(self.thresholds))
        self.stats["inspected"] += 1
        if not self.enabled or self.mode == "off":
            verdict.elapsed_ms = (time.perf_counter() - started) * 1000.0
            return verdict

        surfaces = self._surfaces(request)
        # 大小写不敏感匹配是 Naxsi 的语义 (见 syntax.py 的注释)。待检值只小写
        # 一次, 而不是每条规则各转一遍 —— 46 条规则 x 每个参数, 差别很实在。
        lowered = {zone: [value.lower() for value in values]
                   for zone, values in surfaces.items()}
        for rule in self._string_rules:
            self._score_string_rule(rule, lowered, verdict)
        for rule in self._regex_rules:
            self._score_regex_rule(rule, surfaces, verdict)

        if verdict.scores:
            self.stats["scored"] += 1
        breached = verdict.breached
        if breached and self.mode == "block":
            verdict.blocked = True
            self.stats["blocked"] += 1
        verdict.elapsed_ms = (time.perf_counter() - started) * 1000.0
        return verdict

    # ------------------------------------------------------------------
    # 检测面
    # ------------------------------------------------------------------
    @staticmethod
    def _surfaces(request: HttpRequest) -> dict[str, list[str]]:
        """把请求摊平成 zone -> 待检测字符串列表."""
        out: dict[str, list[str]] = {"URL": [], "ARGS": [], "BODY": [],
                                     "HEADERS": [], "HEADERS_VAR:Cookie": [],
                                     "FILE_EXT": [], "RAW": []}
        if request.target:
            out["URL"].append(request.target)
        if request.query:
            out["ARGS"].extend(
                value for _key, value in _query_pairs(request.query))
        body = request.body.decode("latin-1", "replace")
        if body:
            out["BODY"].append(body)
            if "application/x-www-form-urlencoded" in request.content_type.lower():
                out["ARGS"].extend(
                    value for _key, value in _query_pairs(body))
        for name, value in request.headers.items():
            out["HEADERS"].append(value)
            if name.lower() == "cookie":
                out["HEADERS_VAR:Cookie"].append(value)
        basename = (request.path or "/").rsplit("/", 1)[-1]
        if "." in basename:
            out["FILE_EXT"].append(basename.rsplit(".", 1)[-1])
        out["RAW"].append(f"{request.method} {request.target} {request.version}")
        return out

    # ------------------------------------------------------------------
    # 计分
    # ------------------------------------------------------------------
    def _score_string_rule(self, rule: MainRule, surfaces: dict[str, list[str]],
                           verdict: NaxsiVerdict) -> None:
        if not rule.pattern:
            return
        needle = rule.pattern
        for zone in rule.zones:
            for value in surfaces.get(zone, ()):
                verdict.evaluated += 1
                if needle in value:
                    self._add(rule, zone, needle, value, verdict)

    def _score_regex_rule(self, rule: MainRule, surfaces: dict[str, list[str]],
                          verdict: NaxsiVerdict) -> None:
        pattern = rule.compiled
        if pattern is None:
            return
        for zone in rule.zones:
            for value in surfaces.get(zone, ()):
                verdict.evaluated += 1
                if pattern.search(value):
                    self._add(rule, zone, rule.pattern, value, verdict)

    @staticmethod
    def _add(rule: MainRule, zone: str, keyword: str, value: str,
             verdict: NaxsiVerdict) -> None:
        for name, points in rule.scores.items():
            verdict.scores[name] = verdict.scores.get(name, 0) + points
        verdict.hits.append(NaxsiHit(
            rule_id=rule.id,
            message=rule.message or f"命中 MainRule {rule.id}",
            zone=zone, points=rule.points, keyword=keyword[:60],
            value=value[:120],
        ))

    # ------------------------------------------------------------------
    def rule_views(self) -> list[dict]:
        """规则清单 (供 TUI 的规则防御面板)."""
        out = [{
            "id": rule.id,
            "description": rule.message or f"Naxsi MainRule {rule.id}",
            "zones": list(rule.zones),
            "points": rule.points,
            "scores": dict(rule.scores),
            "kind": rule.kind,
            "pattern": rule.pattern[:120],
            "internal": rule.internal,
        } for rule in self.ruleset.rules]
        return out


def _query_pairs(query: str) -> list[tuple[str, str]]:
    from urllib.parse import parse_qsl
    try:
        return parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return []
