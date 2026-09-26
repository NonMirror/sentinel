"""W13Scan 引擎驱动 — Sentinel **原生**主动扫描插件引擎.

上游 ``w-digital-scanner/w13scan`` (1,943★) 的插件体系是本引擎的**设计参考**: 插件
按 PerFile / PerFolder / PerServer 三档作用域组织, 每个插件只负责一类检测并自报结果。
Sentinel 把这套设计**原生重写**为 :mod:`sentinel.scanner.plugins` 包, 因此本文件里:

  * 没有 ``subprocess``, 没有独立 venv, 也不再指向任何兄弟项目的源码 checkout ——
    引擎是纯 Python, 与 Sentinel 同环境同进程运行, ``available()`` 恒为真;
  * 检测能力来自 :data:`sentinel.scanner.plugins.registry` 里注册的插件, 与内置检测器
    引擎 (``builtin``) 各自独立, 融合扫描时才有多引擎交叉验证的意义;
  * 只保留对上游 **JSONL 报告格式**的解析能力 (:meth:`W13ScanEngine.parse_report`),
    用于把历史报告与外部 w13scan 输出统一规范化成 :class:`~sentinel.core.models.Finding`。

执行模型: 每个目标先用既有爬虫 :class:`~sentinel.scanner.crawler.TargetRecognizer`
做资产/参数发现, 再把插件按作用域分派 —— ``param`` 逐参数并发执行, ``endpoint`` 逐
接口执行, ``server`` 每目标执行一次。单个插件抛异常只计入 :attr:`last_error`, 不会
中断整轮扫描。
"""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Sequence
from urllib.parse import unquote_plus, urlsplit

from ...core.config import ScannerConfig
from ...core.events import EventBus, Topic
from ...core.models import Finding
from ..client import HttpClient
from ..crawler import Endpoint, Target, TargetRecognizer
from ..detectors import OobRegistry
from ..plugins import (SCOPE_ENDPOINT, SCOPE_PARAM, SCOPE_SERVER, Plugin,
                       PluginContext, registry)
from .base import EngineInfo, ScannerEngine, engine_run_dir, severity_by_type

#: 单个目标内并发执行的插件数上限 (再高收益递减, 且会压垮小站点)
MAX_WORKERS = 8
#: 插件 crash 时保留的最近错误条数
MAX_ERRORS = 12


class W13ScanEngine(ScannerEngine):
    """Sentinel 原生插件引擎 (w13scan 血统)."""

    name = "w13scan"
    display = "W13Scan 原生插件引擎 (Sentinel 自研)"
    upstream = "w-digital-scanner/w13scan (设计参考, 已原生重写)"

    def __init__(self, root: Path | None = None, *,
                 config: ScannerConfig | None = None,
                 plugins: Sequence[Plugin] | None = None,
                 bus: EventBus | None = None) -> None:
        self.root = root or engine_run_dir(self.name)
        self.work = self.root
        self.config = config or ScannerConfig()
        self.bus = bus or EventBus()
        self._plugins = list(plugins) if plugins is not None else None
        self.oob = OobRegistry()
        # 最近一次执行的统计 (报告观测用)
        self.stats: dict[str, object] = {}
        self._lock = threading.Lock()

    # ---------------- 探测 ----------------
    @classmethod
    def available(cls) -> bool:
        """纯 Python 实现, 无外部依赖 —— 恒可用."""
        return True

    def version(self) -> str:
        from ... import __version__

        return f"{__version__}-native"

    def plugins(self, deep: bool = False) -> list[Plugin]:
        if self._plugins is not None:
            return [p for p in self._plugins if deep or not p.deep_only]
        return registry.select(deep=deep)

    def info(self) -> EngineInfo:
        info = super().info()
        categories = registry.categories()
        info.detail = (f"{len(registry)} 个原生插件 / {len(categories)} 个分类 "
                       f"(纯 Python, 无外部依赖)")
        info.tools = {
            "plugins": len(registry),
            "categories": categories,
            "deep_only": registry.summary()["deep_only"],
            "work_dir": str(self.work),
        }
        return info

    # ---------------- 扫描 ----------------
    def scan(self, targets: Sequence[str], *, deep: bool = False,
             timeout_s: float = 240.0) -> list[Finding]:
        self.last_error = ""
        self.stats = {}
        if not targets:
            return []
        self.work.mkdir(parents=True, exist_ok=True)
        started = time.time()
        deadline = started + timeout_s
        client = HttpClient(timeout=self.config.timeout_s,
                            user_agent=self.config.user_agent,
                            cookie=self.config.cookie, headers=self.config.headers)
        crawler = TargetRecognizer(client, max_urls=self.config.max_urls,
                                   max_depth=self.config.max_depth)
        findings: list[Finding] = []
        errors: list[str] = []
        plugins_run = 0
        endpoints_seen = 0

        for index, seed in enumerate(targets, 1):
            if time.time() > deadline:
                errors.append(f"扫描超时 (>{timeout_s:.0f}s), 已完成 "
                              f"{index - 1}/{len(targets)} 个目标")
                break
            target = crawler.recognize(seed)
            endpoints_seen += target.url_count
            self.bus.publish(Topic.SCAN_PROGRESS, {
                "phase": "recognized", "engine": self.name, "seed": seed,
                "urls": target.url_count, "params": target.param_count})
            found, ran = self._scan_target(target, deep=deep, errors=errors,
                                           client=client)
            findings.extend(found)
            plugins_run += ran

        # 引擎内去重 (同一证据链只留置信度最高者, 不同技术路径各自保留)
        deduped = _dedupe(findings)
        self.stats = {
            "targets": len(targets), "endpoints": endpoints_seen,
            "plugins_run": plugins_run, "findings": len(deduped),
            "requests": client.request_count, "errors": len(errors),
            "seconds": round(time.time() - started, 3),
            "deep": deep,
        }
        if errors:
            self.last_error = "; ".join(errors[:MAX_ERRORS])
        self._write_report(deduped)
        # 阶段名用 engine_finished 而非 finished: 内置检测器引擎在同一条总线上也会发
        # "finished", 两者同用会让订阅者无法区分是哪个引擎收官。
        self.bus.publish(Topic.SCAN_PROGRESS, {
            "phase": "engine_finished", "engine": self.name,
            "findings": len(deduped), **self.stats})
        return deduped

    def _scan_target(self, target: Target, *, deep: bool,
                     errors: list[str], client: HttpClient) -> tuple[list[Finding], int]:
        """对一个目标分派全部插件, 返回 (发现, 执行次数)."""
        active = self.plugins(deep=deep)
        param_plugins = [p for p in active if p.scope == SCOPE_PARAM]
        endpoint_plugins = [p for p in active if p.scope == SCOPE_ENDPOINT]
        server_plugins = [p for p in active if p.scope == SCOPE_SERVER]

        jobs: list[tuple[Plugin, Endpoint, str, str]] = []
        # param 档: 参数名提示不匹配的直接不派发, 省掉大量无谓请求
        for endpoint, param, position in target.injectable():
            for plugin in param_plugins:
                if plugin.matches(param, position):
                    jobs.append((plugin, endpoint, param, position))
        # endpoint 档: 每个接口一次
        for endpoint in target.endpoints.values():
            for plugin in endpoint_plugins:
                jobs.append((plugin, endpoint, "", SCOPE_ENDPOINT))
        # server 档: 每目标一次 (无接口时退化到目标根地址)
        anchor = next(iter(target.endpoints.values()), None) or \
            Endpoint(url=target.base_url, method="GET", source="synthetic")
        for plugin in server_plugins:
            jobs.append((plugin, anchor, "", SCOPE_SERVER))

        results: list[list[Finding]] = [[] for _ in jobs]
        workers = max(1, min(MAX_WORKERS, int(self.config.concurrency) or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for index, (plugin, endpoint, param, position) in enumerate(jobs):
                futures[pool.submit(self._run_plugin, plugin, client, target,
                                    endpoint, param, position, deep)] = (index, plugin)
            for future, (index, plugin) in futures.items():
                try:
                    results[index] = future.result()
                except Exception as exc:                       # noqa: BLE001
                    message = f"{plugin.name}: {type(exc).__name__}: {exc}"
                    with self._lock:
                        if message not in errors:
                            errors.append(message)
                    self.bus.publish(Topic.SCAN_PROGRESS, {
                        "phase": "plugin_error", "engine": self.name,
                        "plugin": plugin.name, "error": str(exc)[:200]})

        findings: list[Finding] = []
        for (plugin, _endpoint, param, _position), batch in zip(jobs, results):
            if not batch:
                continue
            findings.extend(batch)
            self.bus.publish(Topic.SCAN_PROGRESS, {
                "phase": "plugin_done", "engine": self.name, "plugin": plugin.name,
                "param": param, "findings": len(batch)})
        return findings, len(jobs)

    def _run_plugin(self, plugin: Plugin, client: HttpClient, target: Target,
                    endpoint: Endpoint, param: str, position: str,
                    deep: bool) -> list[Finding]:
        """执行单个插件 —— 这里不吞异常, 由调用方统一记账."""
        ctx = PluginContext(
            client=client, target=target, endpoint=endpoint, param=param,
            position=position, deep=deep,
            time_delay=max(1, int(round(self.config.time_based_threshold_s))),
            time_threshold_s=max(1.2, self.config.time_based_threshold_s * 0.6),
            oob=self.oob, oob_host=self.config.oob_host,
            oob_port=self.config.oob_port)
        produced = plugin.run(ctx) or []
        return list(ctx.findings) + [f for f in produced if f not in ctx.findings]

    # ---------------- 报告 ----------------
    def _write_report(self, findings: Sequence[Finding]) -> None:
        """落盘一份与上游 w13scan 兼容的 JSONL 报告, 便于统一解析与复现.

        无发现时不落盘: 空报告没有信息量, 高频扫描下只会把工作目录堆满 0 字节文件。
        """
        if not findings:
            return
        try:
            self.work.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            report = self.work / f"w13scan-native-{stamp}.jsonl"
            lines = [
                json.dumps({
                    "type": finding.vuln_type, "name": finding.vuln_type,
                    "url": finding.url, "conn_id": finding.conn_id,
                    "createtime": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": finding.severity.value,
                    "detail": {"payload": [finding.payload]},
                }, ensure_ascii=False)
                for finding in findings]
            report.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as exc:                                  # 报告写失败不影响扫描
            self.last_error = (self.last_error + "; " if self.last_error else "") + \
                f"报告写入失败: {exc}"

    # ---------------- 结果解析 ----------------
    @staticmethod
    def _injected_request(detail) -> str:
        """从 ``detail`` 中取出 w13scan 实际发送并命中的请求报文."""
        if not isinstance(detail, dict):
            return ""
        for value in detail.values():
            if isinstance(value, list) and value:
                first = value[0]
                if isinstance(first, dict):
                    return str(first.get("request", ""))
                return str(first)
        return ""

    @classmethod
    def _locate_injection(cls, url: str, injected: str) -> tuple[str, str, str]:
        """从命中请求中定位 方法 / 注入参数 / payload.

        w13scan 的 ``url`` 是原始地址, ``detail.*[0].request`` 是携带 payload 的
        实际请求报文; 两者对比即可还原真正的注入点 (而非插件文件路径).
        """
        method, param, payload = "GET", "", ""
        base_query = urlsplit(url).query
        base_keys = [kv.split("=", 1)[0] for kv in base_query.split("&") if "=" in kv]
        if injected:
            line = injected.splitlines()[0].strip()
            parts = line.split()
            has_method = len(parts) > 1 and parts[0].isalpha()
            if has_method:
                method = parts[0].upper()
            target = parts[1] if has_method else line
            if "?" in target:
                for pair in target.split("?", 1)[1].split("&"):
                    key, sep, value = pair.partition("=")
                    if sep and key in base_keys:
                        param = key
                        payload = unquote_plus(value)[:200]
                        break
            if not payload:
                payload = injected[:200]
        if not param and base_keys:
            param = base_keys[0]
        return method, param, payload

    @classmethod
    def parse_report(cls, path: Path) -> list[Finding]:
        """解析 w13scan JSONL 报告 (历史报告 / 上游输出的兼容入口)."""
        out: list[Finding] = []
        if not path.exists():
            return out
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            vuln_type = row.get("type") or row.get("result") or "unknown"
            name = row.get("name", "")
            url = str(row.get("url", ""))
            injected = cls._injected_request(row.get("detail") or {})
            method, param, payload = cls._locate_injection(url, injected)
            out.append(Finding(
                vuln_type=str(vuln_type),
                url=url,
                severity=severity_by_type(str(vuln_type)),
                method=method,
                param=param,
                payload=payload,
                evidence=f"{name} ({row.get('createtime', '')})",
                confidence=0.85,
                conn_id="w13scan",
            ))
        return out


def _dedupe(findings: Sequence[Finding]) -> list[Finding]:
    """去重并稳定排序.

    去重键在 :attr:`Finding.fingerprint` (类型|路径|参数) 之外**额外带上 payload**:
    同一注入点上 "报错型 / 布尔型 / 时间型" 三条独立证据链的 payload 天然不同, 只按
    指纹去重会把后两条静默丢掉 —— 而它们恰恰是不依赖报错回显的更强证据。携带 payload
    后, 同一插件的重复命中仍会被合并, 不同技术路径则各自保留。
    """
    best: dict[str, Finding] = {}
    for finding in findings:
        key = f"{finding.fingerprint}|{finding.method}|{finding.payload[:60]}"
        current = best.get(key)
        if current is None or finding.confidence > current.confidence:
            best[key] = finding
    return sorted(best.values(),
                  key=lambda f: (-f.severity.weight, f.vuln_type, f.url, f.param))
