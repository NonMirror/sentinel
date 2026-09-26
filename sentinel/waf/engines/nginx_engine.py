"""nginx 数据面 WAF 引擎的公共基类.

负责:
  * 定位已构建的 nginx (含 ModSecurity / Naxsi 模块)
  * 生成配置并托管 nginx 进程
  * 回采 ``error.log`` 中的引擎安全事件 -> Alert / Decision / 审计
  * 回采 ``access.log`` 中的真实流量指标 -> QPS / 延迟直方图 / 字节数

子类只需提供指令片段与事件解析 (:meth:`NginxWafEngine.parse_event`).
"""
from __future__ import annotations

import os
import shutil
import threading
import time
import uuid
from typing import Sequence

from ...core.audit import AuditLog, AuditRecord
from ...core.config import Config
from ...core.events import EventBus, Topic
from ...core.metrics import Metrics
from ...core.models import Alert, Decision, Severity, Verdict
from .base import (EngineStatus, EngineUnavailable, WafEngineDriver,
                   prune_run_dirs, run_dir)
from .nginx_stack import LogTailer, NginxHost, NginxInstall, free_port, render_nginx_conf

_SEVERITY_WORDS = {
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "notice": Severity.LOW,
}


def _severity_of(text: str) -> Severity:
    return _SEVERITY_WORDS.get(text.strip().lower(), Severity.MEDIUM)


class NginxWafEngine(WafEngineDriver):
    """以真实 nginx 进程为数据面的引擎基类."""

    real_engine = True
    upstream = "nginx"
    rules_glob = ""

    def __init__(self, config: Config, *, bus: EventBus | None = None,
                 audit: AuditLog | None = None, metrics: Metrics | None = None,
                 install: NginxInstall | None = None, base=None) -> None:
        self.config = config
        self.bus = bus or EventBus()
        self.audit = audit if audit is not None else AuditLog(4096)
        self.metrics = metrics or Metrics()
        self.install = install or NginxInstall.locate()
        # 运行目录必须**按实例唯一**: 同一进程内可能并存多个同名引擎实例
        # (测试 / TUI + CLI), 若共用目录会互相覆盖 nginx.conf 与 nginx.pid,
        # 导致 ``-s stop`` 误杀另一实例。自动目录在实例停止后清理。
        self._auto_base = base is None
        self.base = base or (run_dir() / f"{self.name}-{os.getpid()}-{uuid.uuid4().hex[:8]}")
        self.host: NginxHost | None = None
        self._tails: list[LogTailer] = []
        self._lock = threading.RLock()
        self.blocks = 0
        self.upstream_hits: dict[str, int] = {}
        self.events = 0
        self.last_error = ""
        self.rules_loaded = 0
        self._http_directives: list[str] = []
        self._location_directives: list[str] = []
        self._location_off_directives: list[str] = []
        self._extra_locations: list[str] = []
        self._users = 0

    # ------------------------------------------------------------------
    # 能力探测
    # ------------------------------------------------------------------
    @classmethod
    def available(cls) -> bool:
        install = NginxInstall.locate()
        if install is None:
            return False
        return cls._module_present(install)

    @staticmethod
    def _module_present(install: NginxInstall) -> bool:  # pragma: no cover - 子类覆盖
        return False

    @property
    def available_now(self) -> bool:
        return self.install is not None and self._module_present(self.install)

    # ------------------------------------------------------------------
    # 子类钩子
    # ------------------------------------------------------------------
    def prepare_rules(self) -> tuple[list[str], list[str], list[str]]:
        """返回 (http 指令, location 指令, 豁免 location 指令)."""
        raise NotImplementedError

    def count_rules(self) -> int:
        return 0

    def parse_event(self, line: str) -> Alert | None:
        """解析一行 error.log, 返回安全告警 (非安全行返回 None)."""
        return None

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.host is not None and self.host.running:
            return
        if self.install is None:
            raise EngineUnavailable(
                f"{self.name}: 未找到已构建的 nginx "
                f"(请运行 tools/build_engines.sh, 产物在 sentinel/build/)")
        if not self._module_present(self.install):
            raise EngineUnavailable(f"{self.name}: 当前 nginx 未编译该模块")
        prune_run_dirs()          # 回收上次被强杀进程遗留的运行目录
        self.base.mkdir(parents=True, exist_ok=True)
        self._extra_locations = []
        self._http_directives, self._location_directives, self._location_off_directives = \
            self.prepare_rules()
        self.rules_loaded = self.count_rules()

        listen = self.config.listener
        port = listen.port or free_port(listen.host)
        status_port = free_port("127.0.0.1")
        host = NginxHost(name=self.name, install=self.install, base=self.base,
                         host=listen.host, front_port=port, status_port=status_port)
        conf = render_nginx_conf(
            host=host,
            backends=self.config.backends,
            waf=self.config.waf,
            http_directives=self._http_directives,
            location_directives=self._location_directives,
            location_off_directives=self._location_off_directives,
            extra_locations=self._extra_locations,
        )
        host.write_conf(conf)
        host.start()
        if not host.wait_ready(timeout=10):
            host.stop()
            raise EngineUnavailable(f"{self.name}: nginx 前端端口 {port} 未就绪")
        self.host = host
        # 安全事件 (error.log) + 真实流量指标 (access.log) 双通道回采
        self._tails = [
            host.tail_errors(self._on_error_line, poll=0.1),
            LogTailer(host.access_log, self._on_access_line, poll=0.1),
        ]
        self._tails[1].start()
        self._users += 1
        self.bus.publish(Topic.LIFECYCLE, {
            "event": "engine_started", "engine": self.name,
            "front_port": port, "status_port": status_port,
            "pid": host.pid(), "rules": self.rules_loaded,
        })

    def stop(self) -> None:
        for tail in self._tails:
            tail.stop()
        self._tails = []
        host = self.host
        if host is not None:
            host.stop()
            self.bus.publish(Topic.LIFECYCLE, {"event": "engine_stopped", "engine": self.name})
        self.host = None
        if self._auto_base and host is not None and not host.running:
            shutil.rmtree(self.base, ignore_errors=True)

    def reload(self) -> None:
        if self.host is None:
            self.start()
            return
        self._extra_locations = []
        self._http_directives, self._location_directives, self._location_off_directives = \
            self.prepare_rules()
        self.rules_loaded = self.count_rules()
        conf = render_nginx_conf(
            host=self.host,
            backends=self.config.backends,
            waf=self.config.waf,
            http_directives=self._http_directives,
            location_directives=self._location_directives,
            location_off_directives=self._location_off_directives,
            extra_locations=self._extra_locations,
        )
        self.host.write_conf(conf)
        ok, out = self.host.test()
        if not ok:  # pragma: no cover - 配置错误
            self.last_error = out
            raise RuntimeError(f"{self.name} 重载失败: {out}")
        self.host.reload()
        self.bus.publish(Topic.LIFECYCLE, {"event": "engine_reloaded", "engine": self.name})

    # ------------------------------------------------------------------
    # 观测
    # ------------------------------------------------------------------
    def status(self) -> EngineStatus:
        host = self.host
        return EngineStatus(
            name=self.name,
            display=self.display,
            upstream=self.upstream,
            available=self.available_now,
            running=bool(host and host.running),
            version=self.install.version if self.install else "",
            rules=self.rules_loaded,
            detail=self.last_error or ("运行中" if host and host.running else "未启动"),
            front_port=host.front_port if host else None,
            status_port=host.status_port if host else None,
            pid=host.pid() if host else None,
            blocks=self.blocks,
            requests=self.events,
            extra={"real_engine": True, "nginx": self.install.version if self.install else ""},
        )

    def traffic(self) -> dict[str, int]:
        return self.host.stub_status() if self.host else {}

    # ------------------------------------------------------------------
    # 日志回采
    # ------------------------------------------------------------------
    def _on_error_line(self, line: str) -> None:
        alert = self.parse_event(line)
        if alert is None:
            return
        self.events += 1
        self.blocks += 1
        decision = Decision(
            verdict=Verdict.BLOCK if self.config.waf.mode == "block" else Verdict.LOG,
            severity=alert.severity,
            matched_rules=[alert.rule_id],
            messages=[alert.message],
            tags=set(alert.tags),
        )
        self.metrics.requests.inc()
        self.metrics.blocked.inc()
        self.metrics.blocked_window.add(1)
        self.metrics.ids_alerts.inc()
        self.audit.append(AuditRecord(
            action="block" if decision.blocked else "alert",
            client=alert.client,
            method=alert.method,
            url=alert.url,
            status=403 if decision.blocked else 200,
            severity=alert.severity.value,
            rules=(alert.rule_id,),
            backend=f"{self.name}:nginx",
            extra={"evidence": alert.evidence[:400], "engine": self.name},
        ))
        self.bus.publish(Topic.BLOCK, alert.as_dict())
        self.bus.publish(Topic.IDS, alert.as_dict())
        self.bus.publish(Topic.DECISION, {
            "engine": self.name,
            "verdict": decision.verdict.value,
            "rules": decision.matched_rules,
            "severity": decision.severity.value,
            "client": alert.client,
            "url": alert.url,
        })

    def _on_access_line(self, line: str) -> None:
        parts = line.split("|", 8)
        if len(parts) < 6:
            return
        client, method, uri, status, size, req_time = parts[:6]
        upstream = parts[7] if len(parts) > 7 else ""
        try:
            status_code = int(status)
            elapsed_ms = float(req_time) * 1000.0
            nbytes = int(size)
        except ValueError:
            return
        self.metrics.requests.inc()
        if status_code == 403:
            self.metrics.blocked.inc()
            self.metrics.blocked_window.add(1)
        elif status_code == 429:
            self.metrics.rate_limited.inc()
        else:
            self.metrics.passed.inc()
        self.metrics.bytes_out.inc(nbytes)
        self.metrics.latency.observe(elapsed_ms)
        self.metrics.qps.add(1.0)
        if upstream and upstream != "-":
            with self._lock:
                self.upstream_hits[upstream] = self.upstream_hits.get(upstream, 0) + 1

    def backend_stats(self) -> dict[str, int]:
        """按 nginx ``$upstream_addr`` 统计真实负载均衡分布."""
        with self._lock:
            return dict(self.upstream_hits)

    # ------------------------------------------------------------------
    # 便捷方法
    # ------------------------------------------------------------------
    def export_rules(self, path) -> int:
        """导出当前生效的规则文本 (供受测/审计)."""
        count = 0
        return count

    def rules_summary(self) -> dict[str, int]:
        return {self.name: self.rules_loaded}

    @staticmethod
    def _read_lines(path) -> Sequence[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
