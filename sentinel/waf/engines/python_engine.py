"""进程内 Python 引擎驱动 (便携回退 / 单元测试).

真实生产路径由 ModSecurity / Naxsi 承担; 该引擎保留全 Python 实现, 用于:
  * 无 nginx 工具链的环境 (开发机 / CI)
  * 规则语义与解析器的细粒度单元测试
  * 与真实引擎的检测质量对照 (benchmarks)
"""
from __future__ import annotations

from ...core.audit import AuditLog
from ...core.config import Config
from ...core.events import EventBus, Topic
from ...core.metrics import Metrics
from ...core.models import Decision, Verdict
from .base import EngineStatus, RuleView, WafEngineDriver


class PythonEngine(WafEngineDriver):
    """包装 :class:`sentinel.waf.engine.WafEngine` 的驱动."""

    name = "python"
    display = "Python 进程内引擎 (便携回退)"
    upstream = "sentinel builtin (无外部依赖)"
    real_engine = False

    def __init__(self, config: Config, *, bus: EventBus | None = None,
                 audit: AuditLog | None = None, metrics: Metrics | None = None) -> None:
        from ..engine import WafEngine
        from ..rules import load_ruleset

        self.config = config
        self.bus = bus or EventBus()
        self.audit = audit if audit is not None else AuditLog(4096)
        self.metrics = metrics or Metrics()
        self.ruleset = load_ruleset(getattr(config, "rule_dir", None),
                                    config.waf.paranoia_level)
        self.engine = WafEngine(config.waf, self.ruleset, bus=self.bus,
                                audit=self.audit, metrics=self.metrics)
        self.engine.bus = self.bus
        self.engine.metrics = self.metrics
        self.running = False

    @classmethod
    def available(cls) -> bool:
        return True

    def start(self) -> None:
        self.running = True
        self.bus.publish(Topic.LIFECYCLE, {"event": "engine_started", "engine": self.name,
                                           "rules": self.rule_count()})

    def stop(self) -> None:
        self.running = False
        self.bus.publish(Topic.LIFECYCLE, {"event": "engine_stopped", "engine": self.name})

    def decide(self, request) -> Decision:  # noqa: ANN001
        return self.engine.inspect(request)

    def inspect(self, request) -> Decision:  # noqa: ANN001
        """兼容旧接口 (WafProxy 直接调用)."""
        return self.engine.inspect(request)

    def set_paranoia(self, level: int) -> None:
        self.engine.set_paranoia(level)

    def rule_count(self) -> int:
        summary = self.ruleset.summary() if hasattr(self.ruleset, "summary") else {}
        if isinstance(summary, dict):
            for key in ("total", "count", "rules"):
                if key in summary:
                    return int(summary[key])
            return int(sum(int(v) for v in summary.values() if isinstance(v, int)))
        return len(getattr(self.ruleset, "rules", []))

    def status(self) -> EngineStatus:
        return EngineStatus(
            name=self.name,
            display=self.display,
            upstream=self.upstream,
            available=True,
            running=self.running,
            rules=self.rule_count(),
            detail="进程内引擎" if self.running else "未启动",
            extra={"real_engine": False, "in_process": True,
                   "mode": self.config.waf.mode, **self.health()},
        )

    def health(self) -> dict:
        """健康指标 —— 与其它原生引擎保持同一形状.

        TUI 的引擎面板 / 报告统一读 ``driver.health()``; 内置引擎若不提供,
        面板上它的那一栏就会缺项 (而不是显示 0), 看起来像功能缺失。
        """
        return {
            "failed_patterns": 0,
            "translated_patterns": 0,
            "warnings": 0,
            "rule_source": "rules/*.json + 内置规则",
        }

    def snapshot(self) -> dict:
        return {
            "name": self.name, "running": self.running,
            "rules": self.rule_count(), "mode": self.config.waf.mode,
            "paranoia_level": self.config.waf.paranoia_level,
            **self.engine.stats,
        }

    def rule_index(self) -> list[RuleView]:
        rules = getattr(self.ruleset, "rules", []) or []
        return [
            RuleView(
                id=int(rule.id),
                description=rule.description,
                severity=rule.severity,
                category=rule.category,
                action=rule.action,
                enabled=bool(rule.enabled),
                source="builtin+rules/",
                variables=list(rule.variables),
                operator=rule.operator,
                operator_arg=rule.operator_arg,
                transforms=list(rule.transforms),
                tags=list(rule.tags),
                secrule=rule.to_modsecurity()[:400],
            )
            for rule in rules
        ]

    def rules_summary(self) -> dict:
        return self.ruleset.summary() if hasattr(self.ruleset, "summary") else {}

    def export_rules(self, path) -> int:
        if hasattr(self.ruleset, "export_modsecurity"):
            text = self.ruleset.export_modsecurity()
            from pathlib import Path
            Path(path).write_text(text, encoding="utf-8")
            return self.rule_count()
        return 0
