"""进程内原生引擎的公共基类.

Sentinel 现在有两类 WAF 引擎:

* **原生 (in-process)** —— :mod:`sentinel.waf.secrule` 解释 ModSecurity 规则语言,
  :mod:`sentinel.waf.naxsi` 解释 Naxsi 规则。决策在请求线程里同步完成,
  因此 ``real_engine = False``, 由 :class:`~sentinel.waf.proxy.WafProxy` 直接调用。
* **真实 C 数据面 (out-of-process)** —— nginx + libmodsecurity / Naxsi 模块,
  决策发生在进程外, Sentinel 只能回采日志 (见
  :mod:`sentinel.waf.engines.nginx_dataplane`), ``real_engine = True``。

本模块把「原生引擎要实现的公共部分」收拢: 状态快照、规则视图、参数热更新,
以及 :class:`~sentinel.core.models.Decision` 的构造。
"""
from __future__ import annotations

from abc import abstractmethod

from ...core.audit import AuditLog
from ...core.config import Config
from ...core.events import EventBus, Topic
from ...core.metrics import Metrics
from ...core.models import Alert, Decision, HttpRequest, Severity, Verdict
from .base import EngineStatus, WafEngineDriver


class InProcessEngine(WafEngineDriver):
    """在请求线程内完成判定的引擎基类."""

    real_engine = False
    #: 决策用的中断级别 -> Sentinel 处置
    verdict_for_block = Verdict.BLOCK

    def __init__(self, config: Config, *, bus: EventBus | None = None,
                 audit: AuditLog | None = None, metrics: Metrics | None = None) -> None:
        self.config = config
        self.bus = bus or EventBus()
        self.audit = audit if audit is not None else AuditLog(4096)
        self.metrics = metrics or Metrics()
        self.running = False
        self.last_error = ""
        self.blocks = 0
        self.detections = 0
        self.stats = {"inspected": 0, "blocked": 0, "detected": 0}

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.bus.publish(Topic.LIFECYCLE, {
            "event": "engine_started", "engine": self.name,
            "rules": self.rule_count(), "in_process": True})

    def stop(self) -> None:
        self.running = False
        self.bus.publish(Topic.LIFECYCLE, {"event": "engine_stopped",
                                           "engine": self.name})

    def reload(self) -> None:
        """原生引擎重建规则库 (等价于重启, 但不需要动数据面)."""
        self._load()
        self.bus.publish(Topic.LIFECYCLE, {"event": "engine_reloaded",
                                           "engine": self.name})

    # ------------------------------------------------------------------
    # 子类钩子
    # ------------------------------------------------------------------
    @abstractmethod
    def _load(self) -> None:
        """(重新) 装载规则."""

    @abstractmethod
    def inspect(self, request: HttpRequest) -> Decision:
        """对单个请求给出决策 (由 WafProxy 调用)."""

    def decide(self, request: HttpRequest) -> Decision:
        """驱动接口别名 (与 ``inspect`` 等价)."""
        return self.inspect(request)

    def rule_count(self) -> int:
        return 0

    # ------------------------------------------------------------------
    # 观测
    # ------------------------------------------------------------------
    def status(self) -> EngineStatus:
        health = self.health()
        return EngineStatus(
            name=self.name, display=self.display, upstream=self.upstream,
            available=self.available(), running=self.running,
            version=self.version(), rules=self.rule_count(),
            detail=self.last_error or ("进程内运行" if self.running else "未启动"),
            blocks=self.blocks, requests=self.stats["inspected"],
            extra={"real_engine": False, "in_process": True,
                   "mode": self.waf_config.mode, **health},
        )

    def version(self) -> str:
        return ""

    def health(self) -> dict:
        """引擎健康指标 (子类覆盖)."""
        return {}

    def snapshot(self) -> dict:
        return {
            "name": self.name, "running": self.running,
            "rules": self.rule_count(), "mode": self.waf_config.mode,
            "paranoia_level": self.waf_config.paranoia_level,
            **self.stats,
        }

    def traffic(self) -> dict[str, int]:
        return {}

    def backend_stats(self) -> dict[str, int]:
        return {}

    # ------------------------------------------------------------------
    # 参数热更新
    # ------------------------------------------------------------------
    @property
    def waf_config(self):
        """WafConfig —— 驱动通常持有整个 Config, 但也要容忍被直接传 WafConfig."""
        return getattr(self.config, "waf", self.config)

    def set_paranoia(self, level: int) -> None:
        self.waf_config.paranoia_level = max(1, min(4, int(level)))
        self._load()

    def set_mode(self, mode: str) -> None:
        self.waf_config.mode = mode

    # ------------------------------------------------------------------
    # 决策构造
    # ------------------------------------------------------------------
    def publish_decision(self, request: HttpRequest, decision: Decision,
                         *, category: str = "waf") -> Decision:
        """统一的指标 / 事件广播 (原生引擎共用).

        请求数与拦截数由 :class:`~sentinel.waf.proxy.WafProxy` 统计 (它才知道
        最终处置); 这里补三件代理看不到的事:

        * **决策耗时** —— 面板的「WAF 决策延迟分位」直接读 ``waf_latency``,
          不在这里记录就会永远显示 0.000ms;
        * **命中计数** —— 命中但按 ``SecDefaultAction`` 只计分不拦截的规则
          同样要算进来;
        * **事件广播** —— 入侵检测面板、来源 IP 画像、仪表盘事件流都订阅
          ``ids`` / ``block`` / ``decision`` 主题。**原生引擎不发布这些事件,
          那些面板就是空的**: 现象是「告警总数 1185、表格一行没有」。

        事件里的 ``client`` 必须是真实来源 IP —— 少了它, 事件会被
        :meth:`SentinelRuntime._on_ids_event` 记成「无法归属」, 来源排名永远是
        空的。
        """
        self.stats["inspected"] += 1
        if decision.severity is None:
            decision.severity = Severity.INFO
        self.metrics.waf_latency.observe(decision.elapsed_ms)
        if decision.blocked:
            self.blocks += 1
            self.stats["blocked"] += 1

        if decision.matched_rules:
            self.detections += 1
            self.stats["detected"] += 1
            # 一次请求 = 一条告警 (与面板上的「告警总数」口径一致); 命中多条
            # 规则体现在 tags / matched_rules 里, 不把计数乘上去。
            self.metrics.ids_alerts.inc()
            alert = self._alert_for(request, decision, category)
            self.bus.publish(Topic.IDS, alert.as_dict())
            if decision.blocked:
                self.bus.publish(Topic.BLOCK, alert.as_dict())

        self.bus.publish(Topic.DECISION, {
            "engine": self.name,
            "url": request.url,
            "client": request.remote_addr,
            "verdict": decision.verdict.value,
            "score": decision.anomaly_score,
            "rules": list(decision.matched_rules[:8]),
            "elapsed_ms": decision.elapsed_ms,
        })
        return decision

    def _alert_for(self, request: HttpRequest, decision: Decision,
                   category: str) -> Alert:
        """把决策转成一条可读告警.

        ``evidence`` 刻意**不复述 message**: 面板上两列显示同一句话没有信息量。
        这里给的是判定依据 —— 异常评分 + 命中的规则号, 让人一眼看出「为什么拦」,
        以及这条请求在评分管道里走到了哪一步。
        """
        rules = "/".join(str(r) for r in decision.matched_rules[:5])
        extra = f" (+{len(decision.matched_rules) - 5})" if len(
            decision.matched_rules) > 5 else ""
        evidence = f"score={decision.anomaly_score}  rules={rules}{extra}"
        if decision.phase:
            evidence += f"  phase={decision.phase}"
        return Alert(
            rule_id=decision.matched_rules[0] if decision.matched_rules else 0,
            message=(decision.messages[0] if decision.messages
                     else f"{self.display} 命中规则"),
            severity=decision.severity,
            client=request.remote_addr,
            url=request.url,
            method=request.method,
            category=category,
            evidence=evidence[:200],
            tags=tuple(sorted(decision.tags))[:8],
        )


def severity_from_weight(weight: int) -> Severity:
    """把 0-4 的权重映射回严重级别."""
    return Severity.from_weight(max(0, min(4, weight)))


def rule_summary_from(views) -> dict:
    """从规则视图统计出统一的四键概览 (TUI / 报告共用)."""
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for view in views:
        by_category[view.category] = by_category.get(view.category, 0) + 1
        by_severity[view.severity.value] = by_severity.get(view.severity.value, 0) + 1
    return {
        "total": len(views),
        "enabled": sum(1 for view in views if view.enabled),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_severity": by_severity,
    }
