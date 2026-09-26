"""运行时编排: 漏洞靶场 + 轻量级防火墙 + 扫描器 一体化.

供 TUI 与 CLI 复用. 数据面统一由 asyncio 反向代理承载, 判定交给当前引擎:

  * **原生引擎** (``modsecurity`` / ``naxsi`` / ``python``) —— 在请求线程内直接
    调用驱动的 ``inspect()`` 拿决策, 不依赖任何外部进程;
  * **参考引擎** (``nginx-modsecurity`` / ``nginx-naxsi``, 需预先构建) —— 决策
    发生在 nginx 进程内, 代理改走 nginx 前端, 事件通过日志回采进入总线。

靶场运行在线程中, 扫描器通过线程池执行, 所有组件共享事件总线 / 指标 / 审计日志.
"""
from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from typing import Callable

from .core.audit import AuditLog
from .core.config import BackendConfig, Config
from .core.events import EventBus, Topic
from .core.metrics import Metrics
from .core.models import Severity
from .lab.server import LabServer
from .scanner.scanner import ScanReport, Scanner
from .scanner.engines import ScanOutcome, ScannerEngineManager
from .waf.balancer import LoadBalancer
from .waf.engines import EngineManager
from .waf.engines.base import RuleView
from .waf.proxy import WafProxy


class SentinelRuntime:
    """一体化运行时 (真实引擎优先, 便携引擎回退)."""

    def __init__(self, config: Config | None = None, start_lab: bool = True,
                 engine: str | None = None) -> None:
        self.config = config or Config()
        self.bus = EventBus(history=5000)
        self.metrics = Metrics()
        self.audit = AuditLog(capacity=20000, path=self.config.audit_path)
        self.lab: list[LabServer] = []
        self.engine_manager = EngineManager(
            self.config, bus=self.bus, audit=self.audit, metrics=self.metrics,
            engine=engine,
        )
        self.proxy = WafProxy(self.config, bus=self.bus, audit=self.audit,
                              metrics=self.metrics)
        self.balancer = LoadBalancer(self.config.backends, self.config.waf.strategy)
        self.scanner = Scanner(self.config.scanner, bus=self.bus, metrics=self.metrics)
        self.scanner_manager = ScannerEngineManager(self.scanner, bus=self.bus,
                                                    metrics=self.metrics)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._start_lab = start_lab
        self._proxy_started = False
        self._client_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        self._unattributed_alerts = 0
        self._rule_cache: dict[str, list[RuleView]] = {}
        self.started_at = 0.0
        self.running = False
        self.last_report: ScanReport | None = None
        self.last_outcome: ScanOutcome | None = None
        self.scan_history: list[ScanReport] = []
        self.bus.subscribe(Topic.IDS, self._on_ids_event)

    # ---------------- 生命周期 ----------------
    def start(self) -> "SentinelRuntime":
        if self.running:
            return self
        if self._start_lab:
            base = self.config.lab.base_port
            self.lab = [LabServer(self.config.lab.host,
                                  (base + i - 1) if base else 0, f"app-{i}")
                        for i in range(1, self.config.lab.instances + 1)]
            for server in self.lab:
                try:
                    server.start()
                except OSError:
                    self.lab.remove(server)
            if base == 0 and self.lab:      # 使用随机端口时同步后端地址
                self.config.backends = [
                    BackendConfig(s.name, s.host, s.bound_port or 0) for s in self.lab
                ]
        self.balancer = LoadBalancer(self.config.backends, self.config.waf.strategy)
        driver = self.engine_manager.start()
        if not self.engine_manager.is_real:
            # 进程内引擎 (原生 CRS / Naxsi / 内置): 反向代理直接调用驱动判定
            self.proxy.set_engine(driver)
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._run_loop, name="sentinel-proxy",
                                            daemon=True)
            self._thread.start()
            deadline = time.time() + 10
            while self.proxy.bound_port is None and time.time() < deadline:
                time.sleep(0.02)
            self._proxy_started = True
        self.running = True
        self.started_at = time.time()
        self.bus.publish(Topic.LIFECYCLE, {
            "event": "runtime_started",
            "engine": self.engine_manager.active_name,
            "front_port": self.front_port,
            "lab_ports": [s.bound_port for s in self.lab],
        })
        return self

    def _run_loop(self) -> None:
        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self.proxy.start())
            self._loop.run_forever()
        except Exception as exc:  # pragma: no cover
            self.bus.publish(Topic.LIFECYCLE, {"event": "proxy_fatal", "error": str(exc)})

    def stop(self) -> None:
        if self._proxy_started and self._loop is not None and self.proxy.bound_port is not None:
            future = asyncio.run_coroutine_threadsafe(self.proxy.stop(), self._loop)
            try:
                future.result(timeout=5)
            except Exception:
                pass
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._proxy_started = False
        try:
            self.engine_manager.stop()
        except Exception:  # noqa: BLE001
            pass
        for server in self.lab:
            server.stop()
        self.audit.close()
        self.running = False

    def __enter__(self) -> "SentinelRuntime":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---------------- 端口与组件别名 ----------------
    @property
    def front_port(self) -> int | None:
        """统一入口端口 (真实引擎 = nginx, 便携引擎 = Python 代理)."""
        if self.engine_manager.is_real:
            return self.engine_manager.current.front_port
        return self.proxy.bound_port

    @property
    def proxy_port(self) -> int | None:
        """向后兼容别名."""
        return self.front_port

    @property
    def engine(self):
        """当前生效的引擎驱动 (原生解释器或真实数据面驱动).

        进程内引擎的 ``inspect()`` 直接给出决策; 真实 nginx 引擎在进程外决策,
        只能通过事件流观测, 因此这里返回驱动本身而不是代理。
        """
        return self.engine_manager.current

    @property
    def engine_name(self) -> str:
        return self.engine_manager.active_name

    @property
    def ids(self):
        """IDS 状态 (真实数据面下由事件流聚合, 进程内由代理持有)."""
        if self.engine_manager.is_real:
            return self
        return self.proxy.ids

    # ---- IDS 兼容接口 (真实引擎下由事件流聚合) ----
    def top_clients(self, limit: int = 10) -> list[tuple[str, int, int, int]]:
        rows = [(ip, stat[0], stat[1], stat[1]) for ip, stat in self._client_stats.items()]
        return sorted(rows, key=lambda r: r[1], reverse=True)[:limit]

    def stats(self) -> dict[str, int]:
        return {"tracked_clients": len(self._client_stats),
                "alerts": sum(s[1] for s in self._client_stats.values())
                + self._unattributed_alerts}

    def _on_ids_event(self, event) -> None:
        """聚合 IDS 告警 (兼容 Alert 对象与 dict 两种载荷)."""
        payload = event.payload
        if payload is None:
            return
        if isinstance(payload, dict):
            client = payload.get("client") or ""
            severity = payload.get("severity", "medium")
        else:
            client = getattr(payload, "client", "") or ""
            severity = getattr(payload, "severity", Severity.MEDIUM)
        if isinstance(severity, Severity):
            weight = severity.weight
        else:
            try:
                weight = Severity(str(severity)).weight
            except ValueError:
                weight = Severity.MEDIUM.weight
        if not client or client == "-":
            # 真实引擎的审计日志可能缺少 $remote_addr: 计入告警总数, 但不伪造来源
            self._unattributed_alerts += 1
            return
        entry = self._client_stats[client]
        entry[0] += 1
        entry[1] += weight

    # ---------------- 引擎管理 ----------------
    def switch_engine(self, name: str) -> str:
        """热切换 WAF 引擎并重建数据面."""
        if name == self.engine_manager.active_name and self.running:
            return self.engine_manager.active_name
        was_running = self.running
        if was_running:
            self._teardown_data_plane()
        driver = self.engine_manager.switch(name)
        if was_running:
            self._bring_up_data_plane()
        return driver.name if hasattr(driver, "name") else name

    def _teardown_data_plane(self) -> None:
        if self._proxy_started and self._loop is not None and self.proxy.bound_port is not None:
            future = asyncio.run_coroutine_threadsafe(self.proxy.stop(), self._loop)
            try:
                future.result(timeout=5)
            except Exception:
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=5)
            self._proxy_started = False
            self._loop = None
            self._thread = None

    def _bring_up_data_plane(self) -> None:
        if not self.engine_manager.is_real:
            self.proxy.set_engine(self.engine_manager.current)
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._run_loop, name="sentinel-proxy",
                                            daemon=True)
            self._thread.start()
            deadline = time.time() + 10
            while self.proxy.bound_port is None and time.time() < deadline:
                time.sleep(0.02)
            self._proxy_started = True

    def reload_engine(self) -> None:
        self.engine_manager.reload()
        self._rule_cache.clear()

    # ---------------- 规则库 (统一视图) ----------------
    def rule_index(self, limit: int | None = None) -> list[RuleView]:
        name = self.engine_manager.active_name
        if name not in self._rule_cache:
            try:
                self._rule_cache[name] = list(self.engine_manager.current.rule_index())
            except Exception:  # noqa: BLE001
                self._rule_cache[name] = []
        rules = self._rule_cache[name]
        return rules[:limit] if limit else rules

    def rule_by_id(self, rule_id: int) -> RuleView | None:
        for rule in self.rule_index():
            if rule.id == rule_id:
                return rule
        return None

    def rules_summary(self) -> dict:
        """规则概览 —— 一律以引擎驱动为准 (原生引擎自报其规则库)."""
        driver = self.engine_manager.current
        native = getattr(driver, "rules_summary", None)
        if callable(native):
            summary = dict(native())
            if summary:
                # 统一出 total/enabled/by_category/by_severity 四个键, 面板与
                # 报告都按这组键取值, 引擎各自的额外字段原样保留。
                summary.setdefault("total", driver.rule_count())
                summary.setdefault("enabled", summary["total"])
                return summary
        rules = self.rule_index()
        by_cat: dict[str, int] = defaultdict(int)
        by_sev: dict[str, int] = defaultdict(int)
        for rule in rules:
            by_cat[rule.category] += 1
            by_sev[rule.severity.value] += 1
        return {
            "total": len(rules),
            "enabled": sum(1 for r in rules if r.enabled),
            "by_category": dict(by_cat),
            "by_severity": dict(by_sev),
        }

    def export_rules(self, path: str) -> int:
        return int(self.engine_manager.current.export_rules(path) or 0)

    # ---------------- 扫描 ----------------
    def scan(self, url: str, deep: bool = False) -> ScanReport:
        report = self.scanner.scan(url, deep=deep)
        self.last_report = report
        self.scan_history.append(report)
        return report

    def scan_async(self, url: str, deep: bool = False,
                   on_done: Callable[[ScanReport], None] | None = None) -> threading.Thread:
        def worker() -> None:
            try:
                report = self.scan(url, deep=deep)
            except Exception as exc:
                self.bus.publish(Topic.SCAN_PROGRESS,
                                 {"phase": "error", "error": str(exc), "seed": url})
                return
            if on_done:
                on_done(report)

        thread = threading.Thread(target=worker, name="sentinel-scan", daemon=True)
        thread.start()
        return thread

    # ---------------- 多引擎扫描 (综设 I 融合) ----------------
    def scan_multi(self, targets: list[str] | None = None, *,
                   engines: list[str] | None = None, deep: bool = False,
                   timeout_s: float = 420.0) -> ScanOutcome:
        """并行编排 nuclei / w13scan / builtin 引擎并融合结果."""
        target_list = list(targets or self.lab_urls())
        outcome = self.scanner_manager.scan(target_list, engines=engines, deep=deep,
                                            timeout_s=timeout_s)
        report = ScanReport(seed=target_list[0] if target_list else "n/a",
                            findings=outcome.findings, deep_scan=deep)
        report.stats.findings = len(outcome.findings)
        report.stats.duration_s = outcome.duration_s
        report.stats.urls = len(target_list)
        report.started_at = outcome.started_at
        report.finished_at = outcome.finished_at
        by_sev: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for finding in outcome.findings:
            by_sev[finding.severity.value] = by_sev.get(finding.severity.value, 0) + 1
            by_type[finding.vuln_type] = by_type.get(finding.vuln_type, 0) + 1
        report.stats.by_severity = by_sev
        report.stats.by_type = by_type
        report.engine_runs = list(outcome.runs)
        self.last_outcome = outcome
        self.last_report = report
        self.scan_history.append(report)
        return outcome

    def scan_multi_async(self, targets: list[str] | None = None, *,
                         engines: list[str] | None = None, deep: bool = False,
                         on_done: Callable[[ScanOutcome], None] | None = None
                         ) -> threading.Thread:
        def worker() -> None:
            try:
                outcome = self.scan_multi(targets, engines=engines, deep=deep)
            except Exception as exc:  # noqa: BLE001
                self.bus.publish(Topic.SCAN_PROGRESS,
                                 {"phase": "error", "error": str(exc)})
                return
            if on_done:
                on_done(outcome)

        thread = threading.Thread(target=worker, name="sentinel-scan-multi", daemon=True)
        thread.start()
        return thread

    def scanner_snapshot(self) -> dict:
        return {
            "engines": [info.as_dict() for info in self.scanner_manager.infos()],
            "default": self.scanner_manager.default_selection(),
            "last_runs": [run.as_dict() for run in (self.last_outcome.runs
                                                    if self.last_outcome else [])],
        }

    def lab_urls(self) -> list[str]:
        return [f"http://{s.host}:{s.bound_port}/" for s in self.lab]

    #: 目标识别阶段使用的参数化种子端点 (架构图: 目标识别 -> 漏洞检测)
    PARAM_ENDPOINTS = (
        "/search?q=test", "/product?id=1", "/page?name=test",
        "/fetch?url=http://127.0.0.1/", "/api/jsonp?callback=cb",
        "/download?file=readme.txt", "/go?next=/", "/admin", "/debug",
        "/api/orders", "/api/user",
    )

    def scan_targets(self, seed: str | None = None) -> list[str]:
        """构造多引擎扫描目标: 种子 URL + 参数化端点."""
        base_urls = [seed] if seed else self.lab_urls()
        if not base_urls:
            return []
        base = base_urls[0].rstrip("/")
        extra = [f"{base}{path}" for path in self.PARAM_ENDPOINTS]
        return base_urls + extra

    # ---------------- 快照 ----------------
    def engine_snapshot(self) -> dict:
        manager = self.engine_manager
        status = manager.current.status()
        rules = self.rules_summary()
        real = manager.is_real
        traffic = manager.current.traffic() if real and hasattr(manager.current, "traffic") else {}
        return {
            "name": status.name,
            "display": status.display,
            "upstream": status.upstream,
            "real_engine": real,
            # in_process = 决策发生在请求线程内 (原生解释器); 与 real_engine
            # 互为反面, 但两个名字都保留 —— 面板与报告各自习惯不同的读法。
            "in_process": not real,
            "reference": manager.is_reference,
            "running": status.running,
            "rules_total": rules["total"],
            "rules_active": rules["enabled"],
            "anomaly_threshold": self.config.waf.anomaly_threshold,
            "mode": self.config.waf.mode,
            "paranoia_level": self.config.waf.paranoia_level,
            "front_port": status.front_port,
            "pid": status.pid,
            "rules_loaded": status.rules,
            "blocks": status.blocks,
            "traffic": traffic,
            "ids": self.stats(),
        }

    # ---------------- 平台自检 (TUI 引擎面板 / 报告) ----------------
    def platform_snapshot(self) -> dict:
        """sentinel 自身的构成: 内置资产 + 引擎实现状态.

        「我们不再调用别人」这件事必须**可见**: 面板要能一眼看到规则/模板
        来自 ``sentinel/vendor``, 解释器有几个算子缺失、几条正则走了方言改写,
        以及真实 C 数据面到底有没有构建。
        """
        from .vendor import missing, summary as vendor_summary
        driver = self.engine_manager.current
        health = driver.health() if hasattr(driver, "health") else {}
        return {
            "vendor": vendor_summary(),
            "vendor_missing": missing(),
            "engine": self.engine_name,
            "engine_display": getattr(driver, "display", ""),
            "in_process": not self.engine_manager.is_real,
            "reference": self.engine_manager.is_reference,
            "health": health,
        }

    def snapshot(self) -> dict:
        backends = (self.engine_manager.current.backend_stats()
                    if self.engine_manager.is_real
                    and hasattr(self.engine_manager.current, "backend_stats")
                    else self.balancer.stats())
        return {
            "running": self.running,
            "uptime_s": round(time.time() - self.started_at, 1) if self.started_at else 0.0,
            "engine_name": self.engine_name,
            "real_engine": self.engine_manager.is_real,
            "proxy_port": self.front_port,
            "front_port": self.front_port,
            "lab_ports": [s.bound_port for s in self.lab],
            "metrics": self.metrics.snapshot(),
            "engine": self.engine_snapshot(),
            "engines": self.engine_manager.snapshot(),
            "backends": backends,
            "ids_top_clients": self.top_clients(8),
            "audit_total": self.audit.total,
            "rules": self.rules_summary(),
        }
