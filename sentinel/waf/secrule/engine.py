"""原生 SecRule 执行引擎.

按 ModSecurity 的语义逐条求值 CRS 规则:

1. **phase 顺序**: phase 1 (请求行/头部) -> phase 2 (参数/请求体);
   同一 phase 内严格按**规则定义顺序**执行 —— CRS 的异常评分聚合
   (``REQUEST-949``) 依赖这一点, 它排在文件序末尾才能汇总到前面的得分。
2. **链式规则**: 父规则命中后依次求值每一环, 任一环失败则整条链失败。
3. **跳转**: ``skipAfter:MARKER`` 跳转到同 phase 内的 ``SecMarker``,
   ``skip:N`` 跳过后续 N 条规则。
4. **处置**: CRS 规则普遍写 ``block``, 而 ``SecDefaultAction`` 是 ``pass``,
   所以它们只计分不拦截; 真正的拦截来自 ``REQUEST-949`` 的 ``deny``。
5. **异常评分**: 由规则通过 ``setvar:tx.blocking_inbound_anomaly_score``
   自行累计, 引擎只负责读出结果 —— 不自作主张地另算一套分数。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from ...core.models import HttpRequest, Severity
from . import operators
from .syntax import Action, Marker, Operator, Rule, RuleSet, Variable
from .transforms import apply_chain
from .variables import Match, Transaction

#: ModSecurity 内建默认处置 (SecDefaultAction 未覆盖时)
_BUILTIN_DEFAULT_DISRUPTIVE = "pass"
_DEFAULT_DENY_STATUS = 403


@dataclass(slots=True)
class RuleHit:
    """一条规则的命中记录 (供 TUI / 审计 / 报告)."""

    rule_id: int
    phase: int
    message: str = ""
    severity: str = "medium"
    targets: tuple[str, ...] = ()
    values: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    source: str = ""
    disruptive: str = ""

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "phase": self.phase, "message": self.message,
            "severity": self.severity, "targets": list(self.targets),
            "values": [v[:200] for v in self.values], "tags": list(self.tags),
            "source": self.source, "disruptive": self.disruptive,
        }


@dataclass
class EngineVerdict:
    """一次请求的引擎判定结果."""

    blocked: bool = False
    disruptive: str = "pass"
    status: int = 200
    phase: int = 2
    anomaly_score: int = 0
    severity: Severity = Severity.INFO
    messages: list[str] = field(default_factory=list)
    matched_rules: list[int] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    hits: list[RuleHit] = field(default_factory=list)
    elapsed_ms: float = 0.0
    evaluated: int = 0
    inspected: int = 0

    @property
    def detected(self) -> bool:
        return bool(self.hits)

    def as_dict(self) -> dict:
        return {
            "blocked": self.blocked, "disruptive": self.disruptive,
            "status": self.status, "phase": self.phase,
            "anomaly_score": self.anomaly_score, "severity": self.severity.value,
            "messages": self.messages[:8], "matched_rules": self.matched_rules[:32],
            "tags": sorted(self.tags), "elapsed_ms": round(self.elapsed_ms, 4),
            "evaluated": self.evaluated, "inspected": self.inspected,
            "hits": [h.as_dict() for h in self.hits[:32]],
        }


class SecRuleEngine:
    """执行 :class:`RuleSet` 的请求处理引擎."""

    #: 支持的请求侧阶段
    PHASES = (1, 2)

    def __init__(self, ruleset: RuleSet, *, paranoia_level: int = 1,
                 anomaly_threshold: int = 5, blocking_paranoia_level: int | None = None,
                 enabled: bool = True, mode: str = "block",
                 max_body_bytes: int = 131072) -> None:
        self.ruleset = ruleset
        self.paranoia_level = max(1, min(4, int(paranoia_level)))
        self.blocking_paranoia_level = max(
            1, min(4, int(blocking_paranoia_level or self.paranoia_level)))
        self.anomaly_threshold = max(1, int(anomaly_threshold))
        self.enabled = enabled
        self.mode = mode
        #: DetectionOnly (``mode == "detect"``) 语义: 规则照跑、告警照记,
        #: 但**不执行中断动作**。ModSecurity 的 DetectionOnly 就是这么定义的,
        #: 若在引擎层提前 return, 反而会漏掉后续阶段的命中。
        self.detect_only = mode == "detect"
        self.max_body_bytes = int(max_body_bytes)
        self.warnings = list(ruleset.warnings)
        self._defaults = self._resolve_defaults(ruleset)
        self._phases, self._markers = self._index(ruleset)
        self.stats = {"inspected": 0, "evaluated": 0, "hits": 0, "blocked": 0,
                      "errors": 0}
        self._transform_cache: dict[tuple, str] = {}
        self._dynamic_cache: dict[tuple, Operator] = {}

    # ------------------------------------------------------------------
    # 构造
    # ------------------------------------------------------------------
    @classmethod
    def from_paths(cls, paths: Iterable, **kwargs) -> "SecRuleEngine":
        """从 ``.conf`` 文件/目录直接构造引擎."""
        from .syntax import load_ruleset
        return cls(load_ruleset(paths), **kwargs)

    def _resolve_defaults(self, ruleset: RuleSet) -> dict[int, str]:
        """每个 phase 的默认处置动作 (SecDefaultAction, 缺省 = pass)."""
        out: dict[int, str] = {}
        for phase, actions in ruleset.default_actions.items():
            for action in actions:
                if action.name in ("pass", "allow", "block", "deny", "drop"):
                    out[phase] = action.name
                    break
        return out

    def default_disruptive(self, phase: int) -> str:
        return self._defaults.get(phase, _BUILTIN_DEFAULT_DISRUPTIVE)

    def _index(self, ruleset: RuleSet):
        """按 phase 建立有序执行序列与标记索引."""
        phases: dict[int, list[Rule | Marker]] = {1: [], 2: []}
        markers: dict[int, dict[str, int]] = {1: {}, 2: {}}
        for item in ruleset.items:
            if isinstance(item, Marker):
                # 标记同时进入两个 phase 的序列 (ModSecurity 的跳转是 phase 内可见)
                for phase in self.PHASES:
                    markers[phase][item.name] = len(phases[phase])
                    phases[phase].append(item)
                continue
            if item.phase in self.PHASES:
                phases[item.phase].append(item)
        return phases, markers

    # ------------------------------------------------------------------
    # 规则视图
    # ------------------------------------------------------------------
    @property
    def rules(self) -> list[Rule]:
        return self.ruleset.rules

    def summary(self) -> dict[str, int]:
        return self.ruleset.summary()

    def health(self) -> dict[str, object]:
        return {
            **operators.health(),
            "warnings": len(self.warnings),
            "warning_samples": self.warnings[:5],
        }

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    def inspect(self, request: HttpRequest) -> EngineVerdict:
        started = time.perf_counter()
        verdict = EngineVerdict()
        self.stats["inspected"] += 1
        if not self.enabled or self.mode == "off":
            verdict.elapsed_ms = (time.perf_counter() - started) * 1000.0
            return verdict

        tx = Transaction(request=request)
        self._seed_transaction(tx)
        self._transform_cache.clear()
        self._dynamic_cache.clear()

        if request.truncated and self.max_body_bytes:
            tx.set_tx("crs_skip_body", "1")

        try:
            for phase in self.PHASES:
                self._run_phase(phase, tx, verdict)
                if verdict.disruptive == "allow":
                    break
                # detect 模式下 blocked 只是「本应拦截」的记录, 不能据此提前
                # 结束 —— 那样会漏掉 phase 2 的命中, DetectionOnly 就失去意义。
                if verdict.blocked and not self.detect_only:
                    verdict.phase = phase
                    break
        except Exception as exc:                          # noqa: BLE001 - 单请求失败不拖垮代理
            self.stats["errors"] += 1
            self.warnings.append(f"规则执行异常: {type(exc).__name__}: {exc}")
            verdict.messages.append(f"规则执行异常: {exc}")

        verdict.anomaly_score = self._anomaly_score(tx)
        if self.detect_only:
            # 判定结果只作观测: 把「本应拦截」降级为「已记录」
            verdict.blocked = False
            verdict.disruptive = "pass"
            verdict.status = 200
        verdict.elapsed_ms = (time.perf_counter() - started) * 1000.0
        if verdict.blocked:
            self.stats["blocked"] += 1
        return verdict

    # ------------------------------------------------------------------
    # 事务初始化
    # ------------------------------------------------------------------
    def _seed_transaction(self, tx: Transaction) -> None:
        """把 Sentinel 的运行参数写进 TX, 优先于 CRS 的内建默认值.

        CRS 的默认值规则全部带 ``&TX:x "@eq 0"`` 守卫, 因此这里先写就先赢 ——
        这正是官方 ``crs-setup.conf`` 覆盖 PL 与阈值的方式。
        """
        tx.set_tx("paranoia_level", str(self.paranoia_level))
        tx.set_tx("blocking_paranoia_level", str(self.blocking_paranoia_level))
        tx.set_tx("detection_paranoia_level", str(self.paranoia_level))
        tx.set_tx("inbound_anomaly_score_threshold", str(self.anomaly_threshold))
        tx.set_tx("outbound_anomaly_score_threshold",
                  str(max(1, self.anomaly_threshold - 1)))
        tx.set_tx("early_blocking", "0")
        tx.set_tx("reporting_level", "2")
        tx.set_tx("sampling_percentage", "100")

    def _anomaly_score(self, tx: Transaction) -> int:
        """优先级: CRS 的 blocking 总分 > 旧版 anomaly_score > 规则权重和."""
        for key in ("blocking_inbound_anomaly_score", "anomaly_score"):
            value = tx.get_tx(key)
            if value:
                try:
                    return int(float(value))
                except ValueError:
                    continue
        return 0

    # ------------------------------------------------------------------
    # phase 执行
    # ------------------------------------------------------------------
    def _run_phase(self, phase: int, tx: Transaction, verdict: EngineVerdict) -> None:
        items = self._phases.get(phase) or []
        markers = self._markers.get(phase) or {}
        index = 0
        total = len(items)
        while index < total:
            item = items[index]
            if isinstance(item, Marker):
                index += 1
                continue
            rule = item
            if rule.id and rule.id in tx.disabled_rules:
                index += 1
                continue
            self.stats["evaluated"] += 1
            if self._match(rule, tx, verdict):
                if rule.skip_after and rule.skip_after in markers:
                    index = markers[rule.skip_after]
                    continue
                if rule.skip:
                    index += rule.skip + 1
                    continue
                # detect 模式不中断 —— 要把所有阶段的命中都收集齐
                if (verdict.blocked and not self.detect_only) \
                        or verdict.disruptive == "allow":
                    return
            index += 1

    # ------------------------------------------------------------------
    # 单条规则求值
    # ------------------------------------------------------------------
    def _match(self, rule: Rule, tx: Transaction, verdict: EngineVerdict) -> bool:
        """规则 (含链) 是否命中; 命中则立即执行动作."""
        hit = self._match_one(rule, tx)
        if hit is None:
            return False
        if rule.chain:
            matched_links = [hit]
            for link in rule.chain:
                link_hit = self._match_one(link, tx)
                if link_hit is None:
                    return False
                matched_links.append(link_hit)
        self._apply_actions(rule, tx, verdict, hit)
        return True

    def _match_one(self, rule: Rule, tx: Transaction) -> Match | None:
        """求值单个规则 (不含链) 的变量 x 算子, 返回首个命中."""
        if not rule.variables:
            # SecAction: 无条件执行
            tx.matched_var = ""
            tx.matched_var_name = ""
            return Match(name="", value="", key="")
        multi = rule.multi_match
        found: Match | None = None
        pairs = self._collect(rule, tx)
        for variable, match in pairs:
            if self._excluded(rule, variable, match, tx):
                continue
            value = self._transform(rule.transforms, match.value)
            if self._operate(rule.operator, value, tx):
                tx.matched_var = value
                tx.matched_var_name = self._matched_name(variable, match)
                if rule.capture:
                    self._capture(rule, value, tx)
                if not multi:
                    return match
                found = found or match
        return found

    def _collect(self, rule: Rule, tx: Transaction) -> list[tuple[Variable, Match]]:
        """按声明顺序收集目标命中, 处理 ``A|!A:x`` 的「并集减去排除项」语义.

        ModSecurity 里 ``!VAR`` 目标不是「取反」而是**从已累积的集合中剔除**:
        ``REQUEST_HEADERS|!REQUEST_HEADERS:User-Agent`` = 除 User-Agent 外的
        所有请求头。漏掉这条会让几乎每条排除型规则都误报。
        """
        out: list[tuple[Variable, Match]] = []
        for variable in rule.variables:
            if variable.negated:
                out = [(v, m) for (v, m) in out
                       if not _target_covers(variable, v, m)]
                continue
            out.extend((variable, match) for match in tx.resolve(variable))
        for variable in rule.additions:
            out.extend((variable, match) for match in tx.resolve(variable))
        return out

    @staticmethod
    def _matched_name(variable: Variable, match: Match) -> str:
        if match.key:
            return f"{variable.name}:{match.key}"
        return variable.name

    def _excluded(self, rule: Rule, variable: Variable, match: Match,
                  tx: Transaction) -> bool:
        """规则自身的与运行时的目标排除 (``!VAR`` / ``ctl:ruleRemoveTargetById``)."""
        for exclusion in rule.exclusions:
            if exclusion.name != variable.name:
                continue
            if _selector_hits(exclusion, match.key):
                return True
        if tx.removed_targets:
            name = self._matched_name(variable, match)
            for rule_id, pattern in tx.removed_targets:
                if rule_id not in (0, rule.id):
                    continue
                if pattern == name or name.startswith(f"{pattern}:"):
                    return True
        return False

    def _operate(self, operator: Operator, value: str, tx: Transaction) -> bool:
        """算子求值 (含 ``%{...}`` 宏参数展开)."""
        if operator.dynamic:
            operator = self._expand_operator(operator, tx)
        return operators.evaluate(operator, value)

    def _expand_operator(self, operator: Operator, tx: Transaction) -> Operator:
        """把 ``@rx %{tx.foo}`` 之类展开成具体算子, 按展开结果缓存."""
        expanded = tx.expand(operator.argument)
        if expanded == operator.argument:
            return operator
        key = (operator.name, expanded, operator.negated)
        cached = self._dynamic_cache.get(key)
        if cached is not None:
            return cached
        clone = Operator(name=operator.name, argument=expanded,
                         negated=operator.negated, dynamic=False)
        if operator.name == "rx":
            clone.compiled = operators.compile_pattern(expanded)
        elif operator.name in ("pm", "within"):
            clone.words = tuple(expanded.split())
        elif operator.name in ("pmfromfile", "ipmatchfromfile"):
            clone.words = operator.words
        self._dynamic_cache[key] = clone
        return clone

    def _capture(self, rule: Rule, value: str, tx: Transaction) -> None:
        pattern = rule.operator.compiled
        if pattern is None or rule.operator.dynamic:
            pattern = operators.compile_pattern(rule.operator.argument)
        if pattern is None:
            return
        match = pattern.search(value)
        if match is None:
            return
        groups = [match.group(0)]
        groups.extend(g or "" for g in match.groups()[:9])
        tx.capture(groups)

    def _transform(self, transforms: Sequence[str], value: str) -> str:
        if not transforms:
            return value
        key = (transforms, value)
        cached = self._transform_cache.get(key)
        if cached is not None:
            return cached
        result = apply_chain(tuple(transforms), value)
        if len(self._transform_cache) < 20000:
            self._transform_cache[key] = result
        return result

    # ------------------------------------------------------------------
    # 动作
    # ------------------------------------------------------------------
    def _apply_actions(self, rule: Rule, tx: Transaction, verdict: EngineVerdict,
                       match: Match) -> None:
        if rule.setvars or rule.ctl:
            self._execute_side_effects(rule, tx)
        disruptive = self._effective_disruptive(rule, tx)
        # nolog 规则是 CRS 的内部记账 (初始化 / 评分聚合 / PL 跳转守卫),
        # 把它们的命中算进告警会让入侵检测面板被 100+ 条噪声淹没。
        if rule.log:
            message = tx.expand(rule.msg) if rule.msg else self._default_message(rule)
            severity = Severity(rule.severity) if rule.severity else Severity.MEDIUM
            hit = RuleHit(
                rule_id=rule.id, phase=rule.phase, message=message,
                severity=severity.value,
                targets=(tx.matched_var_name,) if tx.matched_var_name else (),
                values=(tx.matched_var,), tags=rule.tags, source=rule.source,
                disruptive=disruptive,
            )
            verdict.hits.append(hit)
            self.stats["hits"] += 1
            if rule.id and rule.id not in verdict.matched_rules:
                verdict.matched_rules.append(rule.id)
            if message and message not in verdict.messages:
                verdict.messages.append(message)
            verdict.tags.update(rule.tags)
            if severity.weight > verdict.severity.weight:
                verdict.severity = severity

        if disruptive == "pass":
            return
        if disruptive == "allow":
            verdict.disruptive = "allow"
            return
        verdict.disruptive = disruptive
        if disruptive == "drop":
            verdict.blocked = True
            verdict.status = rule.status or 0
            return
        verdict.blocked = True
        verdict.status = rule.status or _DEFAULT_DENY_STATUS

    def _effective_disruptive(self, rule: Rule, tx: Transaction) -> str:
        requested = rule.disruptive
        if requested in ("", "block"):
            # block = 执行 SecDefaultAction 的处置动作 (CRS 里是 pass)
            return self.default_disruptive(rule.phase)
        if requested == "pass":
            return "pass"
        return requested

    @staticmethod
    def _default_message(rule: Rule) -> str:
        if rule.source:
            return f"规则 {rule.id} 命中 ({rule.source})"
        return f"规则 {rule.id} 命中"

    # ------------------------------------------------------------------
    # setvar / ctl
    # ------------------------------------------------------------------
    def _execute_side_effects(self, rule: Rule, tx: Transaction) -> None:
        for expression in rule.setvars:
            self._setvar(tx, expression)
        for expression in rule.ctl:
            self._ctl(tx, expression)
        tx.invalidate()

    def _setvar(self, tx: Transaction, expression: str) -> None:
        body = expression.strip().strip("'\"")
        name, sep, raw = body.partition("=")
        if not sep:
            return
        key = name.strip()
        if key.lower().startswith("tx."):
            key = key[3:]
        else:
            return                                   # 仅维护 TX 集合
        key = key.lower()
        operation = "set"
        value = raw.strip()
        if value[:1] in ("+", "-"):
            operation = "add" if value[0] == "+" else "sub"
            value = value[1:]
        value = tx.expand(value)
        if operation == "set":
            tx.set_tx(key, value)
            return
        current = tx.get_tx_int(key, 0)
        delta = self._to_int(value)
        tx.set_tx(key, str(current + delta if operation == "add" else current - delta))

    @staticmethod
    def _to_int(text: str) -> int:
        try:
            return int(float(text))
        except (TypeError, ValueError):
            return 0

    def _ctl(self, tx: Transaction, expression: str) -> None:
        body = tx.expand(expression.strip().strip("'\""))
        name, _, argument = body.partition("=")
        name = name.strip().lower()
        argument = argument.strip()
        if name == "ruleengine":
            if argument.lower() in ("off", "detectiononly"):
                tx.set_tx("__rule_engine__", argument.lower())
        elif name == "ruleremovebyid":
            for token in argument.split(","):
                token = token.strip()
                if token.isdigit():
                    tx.disabled_rules.add(int(token))
        elif name == "ruleremovetargetbyid":
            rule_id, _, target = argument.partition(";")
            target = target.strip()
            if rule_id.strip().isdigit() and target:
                tx.removed_targets.append((int(rule_id), target))
        elif name == "requestbodyprocessor":
            tx.set_tx("reqbody_processor_override", argument.upper())


_SELECTOR_RE_CACHE: dict[str, object] = {}


def _target_covers(exclusion: Variable, source: Variable, match: Match) -> bool:
    """``!VAR:sel`` 是否剔除了来自 ``source`` 的这条命中."""
    if exclusion.name != source.name:
        return False
    return _selector_hits(exclusion, match.key)


def _selector_hits(exclusion: Variable, key: str) -> bool:
    """排除目标的匹配: 无选择器 = 全排除; ``/re/`` = 正则; 否则大小写不敏感等值."""
    if not exclusion.selectors:
        return True
    if not key:
        return False
    for selector in exclusion.selectors:
        if len(selector) > 2 and selector.startswith("/") and selector.endswith("/"):
            compiled = _SELECTOR_RE_CACHE.get(selector)
            if compiled is None:
                compiled = operators.compile_pattern(selector[1:-1])
                _SELECTOR_RE_CACHE[selector] = compiled
            if compiled is not None and compiled.search(key):
                return True
        elif selector.lower() == key.lower():
            return True
    return False


__all__ = ["EngineVerdict", "RuleHit", "SecRuleEngine"]
