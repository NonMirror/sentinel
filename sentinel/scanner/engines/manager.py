"""扫描引擎管理器: 多引擎编排 / 去重融合 / 执行记录."""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Iterable, Sequence

from ...core.events import EventBus, Topic
from ...core.metrics import Metrics
from ...core.models import Finding
from .base import EngineInfo, EngineRun, ScanOutcome, ScannerEngine, dedupe
from .builtin import BuiltinEngine
from .nuclei import NucleiEngine
from .w13scan import W13ScanEngine

#: 引擎优先级: 模板化 (nuclei) -> 通用主动扫描 (w13scan) -> 内置
DEFAULT_ORDER = ("nuclei", "w13scan", "builtin")


def build_engines(scanner=None) -> dict[str, ScannerEngine]:
    """构造全部引擎实例 (含不可用者, 便于状态展示)."""
    return {
        "nuclei": NucleiEngine(),
        "w13scan": W13ScanEngine(),
        "builtin": BuiltinEngine(scanner),
    }


class ScannerEngineManager:
    """同时编排多个真实扫描引擎并融合结果."""

    def __init__(self, scanner=None, *, bus: EventBus | None = None,
                 metrics: Metrics | None = None) -> None:
        self.bus = bus or EventBus()
        self.metrics = metrics or Metrics()
        self.engines: dict[str, ScannerEngine] = build_engines(scanner)

    # ---------------- 观测 ----------------
    def available(self) -> dict[str, bool]:
        return {name: engine.available() for name, engine in self.engines.items()}

    def infos(self) -> list[EngineInfo]:
        order = {name: i for i, name in enumerate(DEFAULT_ORDER)}
        return sorted((e.info() for e in self.engines.values()),
                      key=lambda i: order.get(i.name, 99))

    def default_selection(self, deep: bool = False) -> list[str]:
        """默认使用全部可用引擎 (深度扫描额外启用官方全量模板)."""
        return [name for name, engine in self.engines.items()
                if engine.available() and (deep or not engine.deep_only)]

    # ---------------- 扫描 ----------------
    def scan(self, targets: Sequence[str], *, engines: Iterable[str] | None = None,
             deep: bool = False, timeout_s: float = 420.0) -> ScanOutcome:
        selected = list(engines) if engines else self.default_selection(deep)
        outcome = ScanOutcome()
        merged: list[Finding] = []
        for name in selected:
            engine = self.engines.get(name)
            if engine is None:
                continue
            if not engine.available():
                outcome.runs.append(EngineRun(engine=name, ok=False,
                                              error="引擎不可用", targets=len(targets)))
                continue
            self.bus.publish(Topic.SCAN_PROGRESS,
                             {"phase": "engine_start", "engine": name,
                              "targets": len(targets)})
            started = time.time()
            try:
                findings = engine.scan(targets, deep=deep, timeout_s=timeout_s)
                ok = True
                # 引擎自报的告警 (如"空报告") 一并记录, 避免静默的 0 发现
                error = "" if findings else getattr(engine, "last_error", "")
            except Exception as exc:  # noqa: BLE001 - 单引擎失败不影响整体
                findings, ok, error = [], False, str(exc)
            seconds = time.time() - started
            outcome.runs.append(EngineRun(engine=name, ok=ok, findings=len(findings),
                                          seconds=seconds, error=error,
                                          targets=len(targets)))
            merged.extend(findings)
            for finding in findings:
                self.bus.publish(Topic.SCAN_FINDING, finding.as_dict())
            self.bus.publish(Topic.SCAN_PROGRESS,
                             {"phase": "engine_done", "engine": name,
                              "findings": len(findings), "seconds": round(seconds, 3)})
        outcome.findings = dedupe(merged)
        outcome.finished_at = time.time()
        self.metrics.findings.inc(len(outcome.findings))
        # 按引擎统计贡献 (融合后仍可追溯来源)
        by_engine: dict[str, int] = defaultdict(int)
        for finding in outcome.findings:
            by_engine[finding.conn_id] += 1
        self.bus.publish(Topic.SCAN_PROGRESS, {
            "phase": "done", "findings": len(outcome.findings),
            "engines": dict(by_engine),
        })
        return outcome
