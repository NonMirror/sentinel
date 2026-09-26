"""Naxsi 引擎驱动 —— Sentinel 原生评分器.

**不再调用 nginx 的 Naxsi C 模块。** 规则数据取自
``sentinel/vendor/naxsi/naxsi_config/naxsi_core.rules``, 评分与判定由
:mod:`sentinel.waf.naxsi` 在进程内完成。

Naxsi 与 ModSecurity 的模型差异很大, 这也决定了两个引擎在质量指标上的
不同画像 (见 README 的实测表):

* 只有「加分」没有「命中即拦」, 拦截由**累计分数越过 CheckRule 阈值**决定;
* 因此对单点特征不明显的攻击 (例如只有一处可疑关键字) 容易漏报,
  但对正常流量几乎不误报 —— 本项目的基准数据正是这个形态。
"""
from __future__ import annotations

from pathlib import Path

from ...core.models import Decision, HttpRequest, Verdict
from ...vendor import naxsi_core_rules
from ..naxsi import NativeNaxsiEngine, NaxsiVerdict, load_naxsi_rules
from .base import RuleView
from .native import InProcessEngine, rule_summary_from

ENGINE_NAME = "naxsi"


class NaxsiEngine(InProcessEngine):
    """Naxsi 规则的原生评分引擎."""

    name = ENGINE_NAME
    display = "Naxsi 评分模型 (Sentinel 原生评分器)"
    upstream = ("nbs-system/naxsi (规则数据, GPL-3.0) — "
                "评分与判定由 sentinel.waf.naxsi 自研实现")

    def __init__(self, config, *, bus=None, audit=None, metrics=None,
                 rules_path: Path | None = None) -> None:
        super().__init__(config, bus=bus, audit=audit, metrics=metrics)
        self._rules_path = Path(rules_path) if rules_path else naxsi_core_rules()
        self.engine: NativeNaxsiEngine | None = None
        self._load()

    # ------------------------------------------------------------------
    @property
    def rules_path(self) -> Path:
        return self._rules_path

    @classmethod
    def available(cls) -> bool:
        """原生实现: 只要 vendor 里有 Naxsi 核心规则就可用."""
        return naxsi_core_rules().exists()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self.rules_path.exists():
            self.last_error = f"未找到 Naxsi 规则: {self.rules_path}"
            self.engine = None
            return
        ruleset = load_naxsi_rules([self.rules_path])
        self.engine = NativeNaxsiEngine(
            ruleset,
            paranoia_level=self.waf_config.paranoia_level,
            enabled=self.waf_config.enabled,
            mode=self.waf_config.mode,
        )
        self.last_error = ""

    def _sync_config(self) -> None:
        waf = self.waf_config
        engine = self.engine
        if (engine is None
                or engine.paranoia_level != max(1, min(4, waf.paranoia_level))
                or engine.mode != waf.mode
                or engine.enabled != waf.enabled):
            self._load()

    # ------------------------------------------------------------------
    def inspect(self, request: HttpRequest) -> Decision:
        self._sync_config()
        engine = self.engine
        if engine is None:
            return self.publish_decision(request, Decision(verdict=Verdict.PASS))
        verdict = engine.inspect(request)
        return self.publish_decision(request, self.to_decision(verdict),
                                     category="naxsi")

    def to_decision(self, verdict: NaxsiVerdict) -> Decision:
        if verdict.blocked:
            final = Verdict.BLOCK
        elif verdict.hits:
            final = Verdict.LOG
        else:
            final = Verdict.PASS
        tags = {"naxsi"}
        for hit in verdict.hits:
            tags.add(f"zone:{hit.zone}")
        return Decision(
            verdict=final,
            severity=verdict.severity,
            anomaly_score=verdict.total,
            matched_rules=verdict.matched_rules(),
            messages=verdict.messages()[:8],
            tags=tags,
            phase=2,
            elapsed_ms=verdict.elapsed_ms,
        )

    # ------------------------------------------------------------------
    # 观测
    # ------------------------------------------------------------------
    def rule_count(self) -> int:
        return len(self.engine.active_rules) if self.engine else 0

    def version(self) -> str:
        return f"sentinel-naxsi/{self.rule_count()} 条" if self.engine else ""

    def health(self) -> dict:
        if self.engine is None:
            return {"available": False}
        summary = self.engine.summary()
        return {**summary, "warnings": len(self.engine.warnings)}

    def rules_summary(self) -> dict:
        if self.engine is None:
            return {}
        return {
            **self.engine.summary(),
            **rule_summary_from(self.rule_index()),
            "thresholds": dict(self.engine.thresholds),
        }

    def rule_index(self, limit: int | None = None) -> list[RuleView]:
        from ...core.models import Severity
        if self.engine is None:
            return []
        out: list[RuleView] = []
        for view in self.engine.rule_views():
            points = int(view["points"])
            out.append(RuleView(
                id=int(view["id"]),
                description=str(view["description"]),
                severity=Severity.CRITICAL if points >= 16 else (
                    Severity.HIGH if points >= 8 else Severity.MEDIUM),
                category=(next(iter(view["scores"]), "generic").lower()),
                action="score",
                enabled=not view["internal"],
                source="naxsi_core.rules",
                variables=list(view["zones"]),
                operator=str(view["kind"]),
                operator_arg=str(view["pattern"]),
                secrule=f'MainRule "{view["kind"]}:{view["pattern"]}" '
                        f'id:{view["id"]};',
            ))
        return out[:limit] if limit else out

    def export_rules(self, path) -> int:
        """导出 Naxsi 规则文本 (MainRule + 生效的 CheckRule 阈值)."""
        if self.engine is None:
            return 0
        lines = [
            "# Sentinel 导出: Naxsi 规则 (原生评分器执行)",
            f"# paranoia_level: {self.waf_config.paranoia_level}",
            "",
        ]
        count = 0
        for view in self.engine.rule_views():
            if view["internal"]:
                continue
            scores = ",".join(f"${k}:{v}" for k, v in view["scores"].items())
            lines.append(
                f'MainRule "{view["kind"]}:{view["pattern"]}" '
                f'"msg:{view["description"]}" '
                f'"mz:{"|".join(view["zones"])}" "s:{scores}" id:{view["id"]};')
            count += 1
        lines.append("")
        for name, value in sorted(self.engine.thresholds.items()):
            lines.append(f'CheckRule "${name} >= {value}" BLOCK;')
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return count
