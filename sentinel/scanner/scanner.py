"""漏洞扫描子系统 — 编排器 (目标识别 -> 漏洞检测 -> 报告).

支持 w13scan 风格的三种范围: PerFile / PerFolder / PerServer, 通过并发
线程池执行, 并对发现结果去重、分级、统计.
"""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..core.config import ScannerConfig
from ..core.events import EventBus, Topic
from ..core.metrics import Metrics
from ..core.models import Finding, Severity
from .client import HttpClient
from .crawler import Endpoint, Target, TargetRecognizer
from .detectors import (DETECTORS, ENDPOINT_LEVEL, DetectorContext, OobRegistry,
                        run_detectors)
from .vulndb import VulnDB, default_db


@dataclass
class ScanStats:
    requests: int = 0
    urls: int = 0
    params: int = 0
    plugins_run: int = 0
    findings: int = 0
    duration_s: float = 0.0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)
    errors: int = 0

    def as_dict(self) -> dict:
        return {
            "requests": self.requests, "urls": self.urls, "params": self.params,
            "plugins_run": self.plugins_run, "findings": self.findings,
            "duration_s": round(self.duration_s, 3),
            "by_severity": dict(self.by_severity), "by_type": dict(self.by_type),
            "errors": self.errors,
        }


@dataclass
class ScanReport:
    seed: str
    target: Target | None = None
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    scope: str = "server"
    deep_scan: bool = False
    #: 多引擎融合扫描时每个引擎的执行记录 (EngineRun 对象; 避免循环导入故为 list)
    engine_runs: list = field(default_factory=list)

    @property
    def risk_score(self) -> float:
        weights = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "info": 0.2}
        return round(sum(weights.get(f.severity.value, 1.0) for f in self.findings), 2)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 40:
            return "严重"
        if score >= 20:
            return "高"
        if score >= 8:
            return "中"
        if score > 0:
            return "低"
        return "无"

    def by_severity(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for finding in self.findings:
            out.setdefault(finding.severity.value, []).append(finding)
        return out

    def as_dict(self) -> dict:
        return {
            "seed": self.seed,
            "scope": self.scope,
            "deep_scan": self.deep_scan,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "target": None if not self.target else {
                "base_url": self.target.base_url,
                "server": self.target.server,
                "technologies": self.target.technologies,
                "urls": self.target.url_count,
                "params": self.target.param_count,
                "title": self.target.title,
            },
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "stats": self.stats.as_dict(),
            "findings": [f.as_dict() for f in self.findings],
            "engine_runs": [run.as_dict() if hasattr(run, "as_dict") else run
                            for run in self.engine_runs],
        }


class OobHttpServer:
    """带外回调服务器, 用于 SSRF 主动验证 (默认监听 9999)."""

    def __init__(self, registry: OobRegistry, host: str = "127.0.0.1",
                 port: int = 9999) -> None:
        self.registry = registry
        self.host = host
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.bound_port: int | None = None

    def start(self) -> int:
        registry = self.registry

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                return

            def do_GET(self):  # noqa: N802
                token = self.path.strip("/") or "callback"
                registry.record(token)
                payload = f"{SSRF_OK}\n".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self._httpd.daemon_threads = True
        self.bound_port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name="sentinel-oob", daemon=True)
        self._thread.start()
        return self.bound_port

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None


SSRF_OK = "sentinel-ssrf-ok"


class Scanner:
    """漏洞扫描子系统编排器."""

    def __init__(self, config: ScannerConfig | None = None, db: VulnDB | None = None,
                 bus: EventBus | None = None, metrics: Metrics | None = None,
                 oob: OobRegistry | None = None) -> None:
        self.config = config or ScannerConfig()
        self.db = db or default_db()
        self.bus = bus or EventBus()
        self.metrics = metrics or Metrics()
        self.oob = oob or OobRegistry()
        self.client = HttpClient(timeout=self.config.timeout_s,
                                 user_agent=self.config.user_agent,
                                 cookie=self.config.cookie,
                                 headers=self.config.headers)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def scan(self, seed_url: str, deep: bool = False) -> ScanReport:
        started = time.time()
        report = ScanReport(seed=seed_url, scope=self.config.scan_scope,
                            deep_scan=deep)
        recognizer = TargetRecognizer(self.client, max_urls=self.config.max_urls,
                                      max_depth=self.config.max_depth)
        target = recognizer.recognize(seed_url)
        report.target = target
        self.bus.publish(Topic.SCAN_PROGRESS,
                         {"phase": "recognized", "urls": target.url_count,
                          "params": target.param_count, "seed": seed_url})

        findings: list[Finding] = []
        tasks: list[tuple[Endpoint, str, str, list[str]]] = []
        endpoint_level: list[Endpoint] = []
        for endpoint in target.endpoints.values():
            endpoint_level.append(endpoint)
            for param, position in [(p, "query") for p in endpoint.params] + \
                    [(f, "form") for f in endpoint.form_fields]:
                names = [s.name for s in self.db.select(param)
                         if s.name not in ENDPOINT_LEVEL]
                if names:
                    tasks.append((endpoint, param, position, names))
        for endpoint in endpoint_level:
            tasks.append((endpoint, "", "endpoint", sorted(ENDPOINT_LEVEL)))

        plugins_run = 0
        with ThreadPoolExecutor(max_workers=max(1, self.config.concurrency)) as pool:
            futures = {}
            for endpoint, param, position, names in tasks:
                for name in names:
                    if position == "endpoint" and name == "unauth":
                        continue  # unauth 为整站级, 只跑一次
                    futures[pool.submit(self._run_one, target, endpoint, param,
                                        position, name, deep)] = (endpoint, param,
                                                                  position, name)

            for future in as_completed(futures):
                endpoint, param, position, name = futures[future]
                try:
                    result = future.result()
                except Exception:
                    with self._lock:
                        report.stats.errors += 1
                    continue
                plugins_run += 1
                with self._lock:
                    findings.extend(result)
                    for finding in result:
                        self.metrics.findings.inc()
                        self.bus.publish(Topic.SCAN_FINDING, finding.as_dict())

        # 整站级: 未授权访问
        if any(s.name == "unauth" for s in self.db.specs.values()):
            ctx = self._ctx(target, next(iter(target.endpoints.values())), "", "endpoint")
            for finding in run_detectors(ctx, ["unauth"]):
                findings.append(finding)
                self.metrics.findings.inc()
                self.bus.publish(Topic.SCAN_FINDING, finding.as_dict())
            plugins_run += 1

        deduped = _dedupe(findings)
        report.findings = deduped
        report.finished_at = time.time()
        stats = report.stats
        stats.requests = self.client.request_count
        stats.urls = target.url_count
        stats.params = target.param_count
        stats.plugins_run = plugins_run
        stats.findings = len(deduped)
        stats.duration_s = report.finished_at - started
        for finding in deduped:
            stats.by_severity[finding.severity.value] = \
                stats.by_severity.get(finding.severity.value, 0) + 1
            stats.by_type[finding.vuln_type] = stats.by_type.get(finding.vuln_type, 0) + 1
        self.bus.publish(Topic.SCAN_PROGRESS,
                         {"phase": "finished", "findings": len(deduped),
                          "requests": stats.requests,
                          "duration_s": round(stats.duration_s, 3)})
        return report

    # ------------------------------------------------------------------
    def _ctx(self, target: Target, endpoint: Endpoint, param: str,
             position: str) -> DetectorContext:
        baseline = 0.0
        return DetectorContext(
            client=self.client, db=self.db, target=target, endpoint=endpoint,
            param=param, position=position, baseline_ms=baseline,
            time_delay=max(1, int(self.config.time_based_threshold_s) or 3),
            time_threshold_s=self.config.time_based_threshold_s,
            oob=self.oob, oob_host=self.config.oob_host,
            oob_port=self.config.oob_port)

    def _run_one(self, target: Target, endpoint: Endpoint, param: str,
                 position: str, name: str, deep: bool) -> list[Finding]:
        ctx = self._ctx(target, endpoint, param, position)
        if name == "sqli_time" and not deep:
            # 时间盲注较慢, 仅在 deep 模式或参数疑似 id 时启用
            if param.lower() not in ("id", "q", "search", "query", "product"):
                return []
        if name in ("xss",) and position == "form":
            return []
        return run_detectors(ctx, [name])


def _dedupe(findings: list[Finding]) -> list[Finding]:
    best: dict[str, Finding] = {}
    order: list[str] = []
    for finding in findings:
        key = finding.fingerprint
        if key not in best:
            best[key] = finding
            order.append(key)
        elif finding.confidence > best[key].confidence:
            best[key] = finding
    order.sort(key=lambda k: (-best[k].severity.weight, -best[k].confidence))
    return [best[k] for k in order]


def scan_url(seed_url: str, config: ScannerConfig | None = None,
             deep: bool = False) -> ScanReport:
    """便捷函数: 一次性扫描."""
    return Scanner(config).scan(seed_url, deep=deep)
