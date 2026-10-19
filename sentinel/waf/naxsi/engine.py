"""Naxsi 评分引擎 (原生实现).

执行模型:

1. 把请求摊平成 Naxsi 的**检测面** (URL / ARGS / BODY / HEADERS / FILE_EXT);
2. 每条 ``MainRule`` 在它声明的 ``mz:`` 面上匹配, 命中就按 ``s:$KEY:n`` 加分;
3. 每次命中后执行显式 ``CheckRule``；没有显式配置时使用默认分区阈值。

重复匹配会累计分数；规则也可直接 BLOCK/DROP。实际误报取决于规则和业务输入。
"""
from __future__ import annotations

import time
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from ...core.models import HttpRequest, Severity
from ..parser import parse_json_arguments, parse_multipart, parse_xml_values
from .syntax import CheckRule, MainRule, NaxsiRuleSet

#: Naxsi 的检测面 -> 中文说明 (供 TUI 展示)
ZONE_LABELS = {
    "URL": "请求 URL", "ARGS": "参数值", "BODY": "请求体",
    "HEADERS": "请求头", "RAW": "原始报文", "FILE_EXT": "文件扩展名",
}
_INVALID_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")


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
    checks: tuple[CheckRule, ...] = ()
    policy_blocked: bool = False
    check_breaches: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.scores.values())

    @property
    def breached(self) -> dict[str, int]:
        if self.checks:
            return dict(self.check_breaches)
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
        # Explicit CheckRule expressions are policy: PL tightening applies only
        # to the fallback thresholds, not to arbitrary < / == / ALLOW checks.
        verdict = NaxsiVerdict(thresholds=dict(self.thresholds), checks=tuple(self.ruleset.checks))
        self.stats["inspected"] += 1
        if not self.enabled or self.mode == "off":
            verdict.elapsed_ms = (time.perf_counter() - started) * 1000.0
            return verdict

        self._encoding_signals(request, verdict)
        fields = self._fields(request)
        lowered: dict[str, str] = {}
        # Core rules share a handful of match zones. Resolve each selection
        # once per request instead of rebuilding it for every pattern.
        selections: dict[tuple[tuple[str, ...], bool], list[tuple[str, str]]] = {}
        for rule in self._rules:
            key = (rule.zones, rule.negative)
            if key not in selections:
                selections[key] = list(self._rule_values(rule, fields))
            for zone, value in selections[key]:
                verdict.evaluated += 1
                if rule.kind == "str":
                    if value not in lowered:
                        lowered[value] = value.lower()
                    count = self._string_count(rule.pattern, lowered[value])
                elif rule.compiled is not None:
                    count = self._regex_count(rule, value)
                else:
                    continue
                if rule.negative:
                    count = int(count == 0)
                if count:
                    self._add(rule, zone, rule.pattern, value, verdict, count)

        if verdict.scores:
            self.stats["scored"] += 1
        breached = verdict.breached
        if (breached or verdict.policy_blocked) and self.mode == "block":
            verdict.blocked = True
            self.stats["blocked"] += 1
        verdict.elapsed_ms = (time.perf_counter() - started) * 1000.0
        return verdict

    # ------------------------------------------------------------------
    # 检测面
    # ------------------------------------------------------------------
    @staticmethod
    def _encoding_signals(request: HttpRequest, verdict: NaxsiVerdict) -> None:
        # Validate only transport surfaces that are actually URL-decoded.
        # A literal percent in a JSON value, text body or Cookie is not an
        # invalid URL escape. Encoded literal percents are not decoded twice.
        uri = urlsplit(request.target)
        encoded = [("URL", uri.path), ("ARGS", request.query)]
        media_type = request.content_type.partition(";")[0].strip().lower()
        if media_type == "application/x-www-form-urlencoded":
            encoded.append(("BODY", request.body.decode("latin-1")))
        for zone, value in encoded:
            if "\x00" in value or "%00" in value or _INVALID_PERCENT.search(value):
                verdict.policy_blocked = True
                verdict.hits.append(NaxsiHit(10, "无效 URL 编码或空字节", zone, 0,
                                             "encoding", value[:120]))
        for name, value in request.headers.items():
            if "\x00" in name or "\x00" in value:
                verdict.policy_blocked = True
                verdict.hits.append(NaxsiHit(10, "请求头包含空字节", "HEADERS", 0,
                                             "null-byte", value[:120]))

    @staticmethod
    def _surfaces(request: HttpRequest) -> dict[str, list[str]]:
        """Compatibility view; inspection retains the field names separately."""
        fields = NativeNaxsiEngine._fields(request)
        out = {zone: [part for name, value in pairs
                      for part in ((value,) if name is None or zone == "HEADERS" else (name, value))]
               for zone, pairs in fields.items()}
        out["HEADERS_VAR:Cookie"] = [value for name, value in fields["HEADERS"]
                                     if name is not None and name.lower() == "cookie"]
        return out

    @staticmethod
    def _fields(request: HttpRequest) -> dict[str, list[tuple[str | None, str]]]:
        out: dict[str, list[tuple[str | None, str]]] = {
            zone: [] for zone in ("URL", "ARGS", "BODY", "HEADERS", "FILE_EXT", "RAW")}
        if request.target:
            out["URL"].append((None, unquote(urlsplit(request.target).path or "/")))
        if request.query:
            out["ARGS"].extend(_query_pairs(request.query))
        body = request.body.decode("latin-1", "replace")
        if body:
            media_type = request.content_type.lower().partition(";")[0].strip()
            # 表单属于 BODY；只检查解码后的字段，避免分隔符和传输编码重复计分。
            if "application/x-www-form-urlencoded" in request.content_type.lower():
                out["BODY"].extend(_query_pairs(body))
            elif media_type == "application/json" or media_type.endswith("+json"):
                # Array indexes are our metadata, not bytes supplied in key names.
                fields = parse_json_arguments(request.body, indexed_arrays=False)
                if fields is None:
                    out["BODY"].append((None, body))
                else:
                    out["BODY"].extend(fields)
            elif media_type == "multipart/form-data":
                parsed = parse_multipart(request.body, request.content_type)
                for part in parsed.parts:
                    if part.filename is None:
                        out["BODY"].append((part.name, part.value.decode("latin-1")))
                    else:
                        # Naxsi FILE_EXT inspects the upload field and filename, not file bytes.
                        out["FILE_EXT"].append((part.name, part.filename))
                if parsed.errors:
                    out["BODY"].append((None, body))
            elif media_type in ("application/xml", "text/xml") or media_type.endswith("+xml"):
                parsed = parse_xml_values(request.body)
                if parsed is None:
                    out["BODY"].append((None, body))
                else:
                    text, attributes = parsed
                    out["BODY"].append((None, text))
                    out["BODY"].extend(attributes)
            else:
                out["BODY"].append((None, body))
        for name, value in request.headers.items():
            out["HEADERS"].append((name, value))
        basename = (request.path or "/").rsplit("/", 1)[-1]
        if "." in basename:
            out["FILE_EXT"].append((None, basename.rsplit(".", 1)[-1]))
        out["RAW"].append((None, f"{request.method} {request.target} {request.version}"))
        return out

    # ------------------------------------------------------------------
    # 计分
    # ------------------------------------------------------------------
    @staticmethod
    def _rule_values(rule: MainRule, fields: dict[str, list[tuple[str | None, str]]]):
        path = fields["URL"][0][1] if fields["URL"] else "/"
        for selector in rule.zones:
            kind, separator, target = selector.partition(":")
            if separator and kind in {"URL", "URL_X"}:
                if kind == "URL" and path.lower() != target.lower():
                    return
                if kind == "URL_X" and (selector not in rule.zone_patterns
                                         or not rule.zone_patterns[selector].search(path)):
                    return
                break  # upstream uses the first URL constraint

        seen = set()
        for selector in rule.zones:
            kind, separator, target = selector.partition(":")
            custom = separator and kind in {"ARGS_VAR", "BODY_VAR", "HEADERS_VAR",
                                           "ARGS_VAR_X", "BODY_VAR_X", "HEADERS_VAR_X"}
            zone = kind.split("_VAR", 1)[0] if custom else kind
            if separator and not custom:
                continue
            for index, (name, value) in enumerate(fields.get(zone, ())):
                if custom:
                    if name is None:
                        continue
                    if kind.endswith("_X"):
                        if selector not in rule.zone_patterns or not rule.zone_patterns[selector].search(name):
                            continue
                    elif name.lower() != target.lower():
                        continue
                # Custom locations inspect values and (unless negative) names.
                # NAME limits only zone-wide rules, as in naxsi_runtime.c.
                candidates = []
                if custom or "NAME" not in rule.zones:
                    candidates.append((False, value))
                if name is not None and not rule.negative:
                    candidates.append((True, name))
                for is_name, candidate in candidates:
                    identity = (zone, index, is_name, bool(custom))
                    if identity not in seen:
                        seen.add(identity)
                        yield zone, candidate

    @staticmethod
    def _regex_count(rule: MainRule, value: str) -> int:
        if not value:
            return 0
        count = 0
        # finditer guarantees progress for zero-width matches. Upstream's
        # offset loop stops at the buffer end, even if another empty match
        # could follow a nonempty match there.
        for match in rule.compiled.finditer(value):
            count += 1
            if rule.compiled.groups:
                # PCRE includes slots through the highest participating group.
                count += max((i for i, span in enumerate(match.regs[1:], 1)
                              if span != (-1, -1)), default=0)
            if match.end() == len(value):
                break
        return count

    @staticmethod
    def _string_count(needle: str, value: str) -> int:
        if not needle:
            return 0
        if len(needle) == 1:
            return value.count(needle)
        count, offset = 0, 0
        while (offset := value.find(needle, offset)) != -1:
            count += 1
            offset += 1  # Naxsi includes overlapping string occurrences.
        return count

    @staticmethod
    def _add(rule: MainRule, zone: str, keyword: str, value: str,
             verdict: NaxsiVerdict, count: int) -> None:
        for name, points in rule.scores.items():
            verdict.scores[name] = verdict.scores.get(name, 0) + points * count
        blocked, dropped = rule.action == "BLOCK", rule.action == "DROP"
        breaches: dict[str, int] = {}
        # Check after every field match: a <= boundary may trigger before
        # later fields increase the score beyond it. Preserve that decision.
        # Within one update, upstream checks run in score/tag order; ALLOW/LOG
        # clear BLOCK, while DROP remains terminal.
        for name, score in verdict.scores.items():
            for check in verdict.checks:
                if check.variable == name and check.matches(score):
                    blocked = check.action == "BLOCK"
                    dropped = dropped or check.action == "DROP"
                    if check.action in {"BLOCK", "DROP"}:
                        breaches[name] = score
                    elif not dropped:
                        breaches.clear()
        if blocked or dropped:
            verdict.policy_blocked = True
            verdict.check_breaches.update(breaches)
        verdict.hits.append(NaxsiHit(
            rule_id=rule.id,
            message=rule.message or f"命中 MainRule {rule.id}",
            zone=zone, points=rule.points * count, keyword=keyword[:60],
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
            "negative": rule.negative,
            "action": rule.action,
        } for rule in self.ruleset.rules]
        return out


def _query_pairs(query: str) -> list[tuple[str, str]]:
    from urllib.parse import parse_qsl
    try:
        return parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return []
