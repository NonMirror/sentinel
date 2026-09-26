"""Sentinel 综合基准 / 质量评测 (综设 I·II·III 统一证据链).

产出 (写入 ``reports/``):

* ``bench-<stamp>.json`` — 机器可读全量结果 (供报告生成器消费)
* ``bench-<stamp>.md``   — 中文基准报告

评测维度:

============  =================================================================
维度          说明
============  =================================================================
corpus        标注语料库规模 (攻击 / 正常 / 类型分布)
quality       各 WAF 引擎对语料的 TP/FP/TN/FN, 精确率/召回率/F1/误报率, 逐类检出
parser        HTTP/1.1 解析吞吐与微秒级延迟 (P50/P90/P99)
throughput    引擎判定吞吐 (进程内 python 引擎) 与延迟分布
qps           原生引擎 (CRS 解释器 / Naxsi 评分器) 经反向代理的并发 QPS
scanner       漏洞扫描吞吐 (内置检测器 + nuclei/w13scan 多引擎融合)
proxy         反向代理端到端延迟 (顺序 / 并发) 与状态码分布
balance       负载均衡分发均匀度 (变异系数 / 最大偏差)
rules         各引擎规则库规模与索引构建耗时
============  =================================================================
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:               # 允许 ``python benchmarks/run_all.py``
    sys.path.insert(0, str(ROOT))

from benchmarks.corpus import build_corpus, corpus_stats            # noqa: E402
from sentinel.core.config import Config, ScannerConfig, WafConfig    # noqa: E402
from sentinel.core.metrics import LatencyHistogram                   # noqa: E402
from sentinel.waf.parser import parse_request                        # noqa: E402
from sentinel.waf.rules import load_ruleset                          # noqa: E402

UA = "Sentinel-Bench/1.0"


# --------------------------------------------------------------------------
# 通用工具
# --------------------------------------------------------------------------
def percentile(values: list[float], p: float) -> float:
    """最近秩 (nearest-rank) 百分位: ``ceil(p/100 * n)``."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(p / 100.0 * len(ordered)) - 1))
    return ordered[index]


def latency_stats(samples_ms: list[float], unit: str = "ms") -> dict:
    if not samples_ms:
        return {}
    return {
        "count": len(samples_ms),
        "mean": round(statistics.fmean(samples_ms), 4),
        "min": round(min(samples_ms), 4),
        "max": round(max(samples_ms), 4),
        "p50": round(percentile(samples_ms, 50), 4),
        "p90": round(percentile(samples_ms, 90), 4),
        "p99": round(percentile(samples_ms, 99), 4),
        "unit": unit,
    }


def http_get(url: str, timeout: float = 15.0) -> tuple[int, dict[str, str], bytes]:
    """发起 GET, 不跟随重定向, 返回 (status, headers, body)."""
    req = urlrequest.Request(url, headers={"User-Agent": UA})
    try:
        with urlrequest.urlopen(req, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urlerror.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()
    except Exception:  # noqa: BLE001 - 连接失败视为 -1
        return -1, {}, b""


def raw_status(base: str, raw: bytes, timeout: float = 15.0) -> int:
    """以原始报文形式回放请求 (保留原始方法/头部/请求体), 返回状态码.

    真实引擎的质量评测必须回放原始头部, 否则 User-Agent / 自定义头 类的攻击样本
    在测量中会被"人为"漏掉, 结论不可信.
    """
    parts = urlsplit(base)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 80
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(raw)
            sock.settimeout(timeout)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            if not data:
                return -1
            try:
                return int(data.split(b" ", 2)[1])
            except (IndexError, ValueError):
                return -1
    except OSError:
        return -1


def run_capture(argv: list[str], timeout: float = 15.0) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or proc.stderr or "").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


# --------------------------------------------------------------------------
# 1. 环境
# --------------------------------------------------------------------------
def bench_environment() -> dict:
    from sentinel import __version__
    from sentinel.waf.engines import available_engines, ENGINE_CLASSES
    from sentinel.waf.engines.nginx_stack import NginxInstall
    from sentinel.scanner.engines import ScannerEngineManager

    versions = {"uv": "", "mise": ""}
    for tool in ("uv", "mise"):
        text = run_capture([tool, "--version"])
        if text:
            parts = text.split()
            versions[tool] = parts[1] if tool == "uv" and len(parts) > 1 else parts[0]

    install = NginxInstall.locate()
    engines = {}
    for name, cls in ENGINE_CLASSES.items():
        try:
            engines[name] = {
                "display": cls.display,
                "upstream": cls.upstream,
                "available": bool(cls.available()),
                "real_engine": bool(getattr(cls, "real_engine", False)),
            }
        except Exception:  # noqa: BLE001
            engines[name] = {"display": cls.display, "available": False}

    scanners = {}
    for info in ScannerEngineManager().infos():
        scanners[info.name] = {"display": info.display, "available": info.available,
                               "version": info.version, "upstream": info.upstream}
    return {
        "sentinel_version": __version__,
        "python": platform.python_version(),
        "uv": versions["uv"],
        "mise": versions["mise"],
        "platform": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "cpu_count": os.cpu_count() or 0,
        "nginx": {
            "version": install.version if install else "",
            "modules": list(install.modules) if install else [],
            "prefix": str(install.prefix) if install else "",
        },
        "waf_engines": engines,
        "available_engines": available_engines(),
        "scanner_engines": scanners,
    }


# --------------------------------------------------------------------------
# 2. 解析器吞吐
# --------------------------------------------------------------------------
def bench_parser(corpus, rounds: int = 8, min_seconds: float = 0.5) -> dict:
    """HTTP/1.1 解析吞吐 (微秒级延迟分布).

    ``rounds`` 是**最少**轮数: 若总耗时不足 ``min_seconds`` 会继续循环. 桌面环境下
    5ms 量级的测量窗口受调度/降频影响误差可达 2 倍, 因此这里先把窗口做厚,
    并预热一次以触发解析器的惰性初始化.
    """
    for sample in corpus[:64]:                      # 预热
        parse_request(sample.raw, "127.0.0.1", 12345)
    histogram = LatencyHistogram()
    ops = 0
    passes = 0
    started = time.perf_counter()
    while passes < rounds or (time.perf_counter() - started) < min_seconds:
        for sample in corpus:
            t0 = time.perf_counter()
            parse_request(sample.raw, "127.0.0.1", 12345)
            histogram.observe((time.perf_counter() - t0) * 1000.0)
            ops += 1
        passes += 1
    elapsed = time.perf_counter() - started
    return {
        "samples": len(corpus),
        "rounds": passes,
        "ops": ops,
        "seconds": round(elapsed, 4),
        "ops_per_s": round(ops / elapsed, 1),
        "latency_us": {
            "mean": round(histogram.mean_ms * 1000, 2),
            "p50": round(histogram.percentile(50) * 1000, 2),
            "p90": round(histogram.percentile(90) * 1000, 2),
            "p99": round(histogram.percentile(99) * 1000, 2),
        },
    }


# --------------------------------------------------------------------------
# 3. 语料质量 (检出率 / 误报率)
# --------------------------------------------------------------------------
def _quality_from_flags(records: list[tuple[bool, bool, str]]) -> dict:
    """records: (expect_block, got_block, category)."""
    tp = fp = tn = fn = 0
    by_category: dict[str, dict[str, int]] = {}
    false_positives: list[str] = []
    false_negatives: list[str] = []
    for expect, got, label in records:
        bucket = by_category.setdefault(label, {"total": 0, "detected": 0})
        bucket["total"] += 1
        if expect and got:
            tp += 1
            bucket["detected"] += 1
        elif expect and not got:
            fn += 1
            false_negatives.append(label)
        elif not expect and got:
            fp += 1
            false_positives.append(label)
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    total = tp + fp + tn + fn
    for bucket in by_category.values():
        bucket["rate"] = round(bucket["detected"] / bucket["total"], 4) if bucket["total"] else 0.0
    return {
        "total": total, "attacks": tp + fn, "benign": tn + fp,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if (fn + tp) else 0.0,
        "by_category": by_category,
        "false_positive_samples": false_positives[:12],
        "false_negative_samples": false_negatives[:12],
    }


def quality_inprocess(corpus, engine_name: str = "python",
                      paranoia_level: int = 1,
                      anomaly_threshold: int | None = None) -> dict:
    from sentinel.waf.engine import WafEngine

    kwargs = {"mode": "block", "paranoia_level": paranoia_level}
    if anomaly_threshold is not None:
        kwargs["anomaly_threshold"] = anomaly_threshold
    config = WafConfig(**kwargs)
    engine = WafEngine(config, load_ruleset(str(ROOT / "rules"), paranoia_level))
    records: list[tuple[bool, bool, str]] = []
    started = time.perf_counter()
    for sample in corpus:
        req = parse_request(sample.raw, "203.0.113.7", 40000)
        decision = engine.inspect(req)
        records.append((sample.expect_block, bool(decision.blocked), sample.category))
    quality = _quality_from_flags(records)
    quality.update({"engine": engine_name, "mode": "in-process",
                    "elapsed_s": round(time.perf_counter() - started, 4),
                    "rules": len(engine.ruleset)})
    return quality


def quality_over_http(corpus, base: str, engine_name: str, timeout: float = 15.0) -> dict:
    """回放原始报文评测 (方法 / 头部 / 请求体全部保留)."""
    records: list[tuple[bool, bool, str]] = []
    started = time.perf_counter()
    for sample in corpus:
        status = raw_status(base, sample.raw, timeout=timeout)
        records.append((sample.expect_block, status in (403, 429), sample.category))
    quality = _quality_from_flags(records)
    quality.update({"engine": engine_name, "mode": "http-raw",
                    "elapsed_s": round(time.perf_counter() - started, 4)})
    return quality


# --------------------------------------------------------------------------
# 4. 引擎吞吐 / QPS
# --------------------------------------------------------------------------
def bench_engine_inprocess(corpus, rounds: int = 6, min_seconds: float = 0.5) -> dict:
    """进程内引擎判定吞吐 (最少 ``rounds`` 轮, 不足 ``min_seconds`` 则继续)."""
    from sentinel.waf.engine import WafEngine

    engine = WafEngine(WafConfig(mode="block"), load_ruleset(str(ROOT / "rules"), 1))
    requests = [parse_request(sample.raw, "203.0.113.9", 40000) for sample in corpus]
    for req in requests[:64]:                       # 预热
        engine.inspect(req)
    histogram = LatencyHistogram()
    ops = 0
    passes = 0
    started = time.perf_counter()
    while passes < rounds or (time.perf_counter() - started) < min_seconds:
        for req in requests:
            t0 = time.perf_counter()
            engine.inspect(req)
            histogram.observe((time.perf_counter() - t0) * 1000.0)
            ops += 1
        passes += 1
    elapsed = time.perf_counter() - started
    return {
        "engine": "python", "ops": ops, "seconds": round(elapsed, 4),
        "ops_per_s": round(ops / elapsed, 1),
        "latency_detail": histogram.summary(),
    }


def bench_http_qps(base: str, engine_name: str, requests: int = 600,
                   concurrency: int = 8) -> dict:
    """真实 nginx 数据面并发 QPS (含 403 / 200 混合流量)."""
    targets = ["/?q=hello&page=2", "/api/orders?page=1", "/product?id=1",
               "/?id=1%20union%20select%201,2,3--", "/?q=%3Cscript%3Ealert(1)%3C/script%3E"]
    latencies: list[float] = []
    statuses: dict[str, int] = {}
    lock = threading.Lock()

    def one(index: int) -> None:
        target = targets[index % len(targets)]
        t0 = time.perf_counter()
        status, _h, _b = http_get(base + target)
        elapsed = (time.perf_counter() - t0) * 1000.0
        with lock:
            latencies.append(elapsed)
            statuses[str(status)] = statuses.get(str(status), 0) + 1

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(one, range(requests)))
    wall = time.perf_counter() - started
    return {
        "engine": engine_name, "requests": requests, "concurrency": concurrency,
        "seconds": round(wall, 4), "qps": round(requests / wall, 1),
        "statuses": statuses, "latency_ms": latency_stats(latencies),
    }


# --------------------------------------------------------------------------
# 5. 扫描器吞吐
# --------------------------------------------------------------------------
def bench_scanner_builtin(base: str, max_urls: int = 60) -> dict:
    from sentinel.scanner.scanner import Scanner

    config = ScannerConfig(max_urls=max_urls, concurrency=8, time_based_threshold_s=1.0)
    scanner = Scanner(config)
    started = time.perf_counter()
    report = scanner.scan(base + "/")
    elapsed = time.perf_counter() - started
    stats = report.stats
    return {
        "engine": "builtin", "seconds": round(elapsed, 4),
        "requests": stats.requests, "urls": stats.urls, "params": stats.params,
        "plugins_run": stats.plugins_run, "findings": stats.findings,
        "requests_per_s": round(stats.requests / elapsed, 1) if elapsed else 0.0,
        "findings_per_s": round(stats.findings / elapsed, 2) if elapsed else 0.0,
        "by_severity": dict(stats.by_severity), "by_type": dict(stats.by_type),
        "risk_score": report.risk_score, "risk_level": report.risk_level,
    }


def bench_scanner_multi(targets: list[str], deep: bool = False,
                        engines: list[str] | None = None) -> dict:
    from sentinel.scanner.engines import ScannerEngineManager

    manager = ScannerEngineManager()
    started = time.perf_counter()
    # 靶场 backlog 放大后 nuclei 会跑完全部模板/端点, 耗时随之上升
    # (实测 ~290 s), 因此给足超时余量, 避免把完整结果截断成"少发现".
    outcome = manager.scan(targets, engines=engines, deep=deep, timeout_s=420.0)
    elapsed = time.perf_counter() - started
    by_engine: dict[str, int] = {}
    for run in outcome.runs:
        by_engine[run.engine] = run.findings
    return {
        "seconds": round(elapsed, 4), "targets": len(targets),
        "findings": len(outcome.findings),
        "findings_per_s": round(len(outcome.findings) / elapsed, 2) if elapsed else 0.0,
        "runs": [run.as_dict() for run in outcome.runs],
        "by_engine": by_engine,
        "by_severity": _severity_counts(outcome.findings),
        "sample": [f.as_dict() for f in outcome.findings[:15]],
    }


def _severity_counts(findings) -> dict[str, int]:
    out: dict[str, int] = {}
    for finding in findings:
        out[finding.severity.value] = out.get(finding.severity.value, 0) + 1
    return out


# --------------------------------------------------------------------------
# 6. 反向代理端到端
# --------------------------------------------------------------------------
def bench_proxy(base: str, requests: int = 400, concurrency: int = 8) -> dict:
    sequential: list[float] = []
    for index in range(min(requests, 150)):
        t0 = time.perf_counter()
        http_get(f"{base}/api/orders?page=1&i={index}")
        sequential.append((time.perf_counter() - t0) * 1000.0)

    latencies: list[float] = []
    statuses: dict[str, int] = {}
    lock = threading.Lock()

    def one(index: int) -> None:
        t0 = time.perf_counter()
        status, _h, _b = http_get(f"{base}/api/orders?page=1&i={index}")
        elapsed = (time.perf_counter() - t0) * 1000.0
        with lock:
            latencies.append(elapsed)
            statuses[str(status)] = statuses.get(str(status), 0) + 1

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(one, range(requests)))
    wall = time.perf_counter() - started
    return {
        "sequential": latency_stats(sequential),
        "concurrent": {
            "requests": requests, "concurrency": concurrency,
            "seconds": round(wall, 4), "qps": round(requests / wall, 1),
            "statuses": statuses, "latency_ms": latency_stats(latencies),
        },
    }


def bench_load_balancer(base: str, requests: int = 300) -> dict:
    counts: dict[str, int] = {}
    for index in range(requests):
        status, headers, _body = http_get(f"{base}/health?i={index}")
        if status != 200:
            continue
        backend = headers.get("X-Sentinel-Backend", "unknown")
        counts[backend] = counts.get(backend, 0) + 1
    if not counts:
        return {"distribution": {}, "requests": requests}
    values = list(counts.values())
    mean = statistics.fmean(values)
    stdev = statistics.pstdev(values) if len(values) > 1 else 0.0
    return {
        "requests": requests,
        "backends": len(counts),
        "distribution": counts,
        "mean": round(mean, 2),
        "stdev": round(stdev, 3),
        "coefficient_of_variation": round(stdev / mean, 4) if mean else 0.0,
        "max_deviation": round(max(values) - min(values), 1),
    }


# --------------------------------------------------------------------------
# 6.5 paranoia level 权衡 (检出率 vs 误报率)
# --------------------------------------------------------------------------
def bench_paranoia_sweep(corpus, levels=(1, 2, 3, 4), real_engines: bool = True,
                         log=lambda _m: None) -> dict:
    """逐 PL 评测检出率: 展示 "更严格 -> 召回更高, 误报可能上升" 的权衡."""
    from sentinel.waf.engines import available_engines

    out: dict[str, dict] = {"python": {}}
    for level in levels:
        out["python"][str(level)] = quality_inprocess(corpus, f"python@PL{level}", level)

    if not real_engines:
        return out
    from sentinel.runtime import SentinelRuntime

    for name in ("modsecurity", "naxsi"):
        if not available_engines().get(name):
            continue
        out[name] = {}
        for level in levels:
            config = Config()
            config.listener.host, config.listener.port = "127.0.0.1", 0
            config.lab.base_port, config.lab.instances = 0, 2
            config.waf.paranoia_level = level
            config.audit_path = f"reports/bench-audit-{name}-pl{level}.jsonl"
            runtime = SentinelRuntime(config, engine=name).start()
            try:
                base = f"http://127.0.0.1:{runtime.front_port}"
                log(f"  {name} PL{level} 语料评测 ...")
                quality = quality_over_http(corpus, base, f"{name}@PL{level}")
                driver = runtime.engine_manager.current
                if hasattr(driver, "check_thresholds"):
                    quality["thresholds"] = driver.check_thresholds()
                out[name][str(level)] = quality
            finally:
                runtime.stop()
            out[name][str(level)]["mode"] = "http"
    return out


def bench_threshold_sweep(corpus, thresholds=(1, 3, 5, 8), real_engines: bool = True,
                          log=lambda _m: None) -> dict:
    """逐异常阈值评测: 揭示 CRS/Naxsi "更严格 -> 召回更高, 误报上升" 的调优曲线."""
    from sentinel.waf.engines import available_engines

    out: dict[str, dict] = {"python": {}}
    for threshold in thresholds:
        out["python"][str(threshold)] = quality_inprocess(
            corpus, f"python@threshold{threshold}", 1, threshold)

    if real_engines and available_engines().get("modsecurity"):
        from sentinel.runtime import SentinelRuntime

        out["modsecurity"] = {}
        for threshold in thresholds:
            config = Config()
            config.listener.host, config.listener.port = "127.0.0.1", 0
            config.lab.base_port, config.lab.instances = 0, 2
            config.waf.paranoia_level = 1
            config.waf.anomaly_threshold = threshold
            config.audit_path = f"reports/bench-audit-modsec-th{threshold}.jsonl"
            runtime = SentinelRuntime(config, engine="modsecurity").start()
            try:
                base = f"http://127.0.0.1:{runtime.front_port}"
                log(f"  modsecurity 阈值 {threshold} 语料评测 ...")
                out["modsecurity"][str(threshold)] = quality_over_http(
                    corpus, base, f"modsecurity@threshold{threshold}")
            finally:
                runtime.stop()
            out["modsecurity"][str(threshold)]["mode"] = "http"
    return out


# --------------------------------------------------------------------------
# 7. 规则库
# --------------------------------------------------------------------------
def bench_rules() -> dict:
    from sentinel.waf.engines import ENGINE_CLASSES

    out: dict[str, dict] = {}
    started = time.perf_counter()
    ruleset = load_ruleset(str(ROOT / "rules"), 1)
    out["python"] = {
        "total": len(ruleset), "enabled": len(ruleset.active()),
        "load_ms": round((time.perf_counter() - started) * 1000, 2),
        "source": "rules/ (JSON, 可导出 ModSecurity 语法)",
    }
    for name in ("modsecurity", "naxsi"):
        cls = ENGINE_CLASSES.get(name)
        if cls is None or not cls.available():
            out[name] = {"available": False}
            continue
        driver = cls(Config())                   # 仅构建规则索引, 不启动数据面
        t0 = time.perf_counter()
        index = list(driver.rule_index())
        elapsed = (time.perf_counter() - t0) * 1000
        out[name] = {
            "available": True, "total": len(index),
            "index_ms": round(elapsed, 2), "upstream": cls.upstream,
            "by_severity": _count_attr(index, "severity"),
            "by_category": _count_attr(index, "category"),
        }
    return out


def _count_attr(rules, attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for rule in rules:
        value = getattr(rule, attr)
        key = value.value if hasattr(value, "value") else str(value)
        out[key] = out.get(key, 0) + 1
    return out


# --------------------------------------------------------------------------
# 编排
# --------------------------------------------------------------------------
def run_benchmarks(*, real_engines: bool = True, scanner_multi: bool = True,
                   verbose: bool = True) -> dict:
    def log(message: str) -> None:
        if verbose:
            print(f"[bench] {message}", flush=True)

    started = time.perf_counter()
    corpus = build_corpus()
    report: dict = {
        "meta": {"generated_at": datetime.now().isoformat(timespec="seconds"),
                 "corpus_size": len(corpus)},
        "environment": bench_environment(),
        "corpus": {"stats": corpus_stats(corpus), "total": len(corpus)},
    }

    log("解析器吞吐 ...")
    report["parser"] = bench_parser(corpus)

    log("进程内引擎质量/吞吐 (python) ...")
    report["quality"] = {"python": quality_inprocess(corpus)}
    report["engine_throughput"] = {"python": bench_engine_inprocess(corpus)}

    log("规则库规模 ...")
    report["rules"] = bench_rules()

    log("启动靶场 + 原生引擎 (入口: asyncio 反向代理) ...")
    from sentinel.runtime import SentinelRuntime

    runtimes: list[SentinelRuntime] = []
    if real_engines:
        # 原生引擎 (默认数据面) + 已构建的参考数据面 (若存在), 两者跑同一套规则
        from sentinel.waf.engines import REFERENCE_ENGINES, available_engines

        engine_names = ["modsecurity", "naxsi"]
        engine_names += [name for name in REFERENCE_ENGINES
                         if available_engines().get(name)]
        for engine_name in engine_names:
            from sentinel.waf.engines import available_engines

            if not available_engines().get(engine_name):
                report.setdefault("real_engines", {})[engine_name] = {"available": False}
                continue
            config = Config()
            config.listener.host, config.listener.port = "127.0.0.1", 0
            config.lab.base_port, config.lab.instances = 0, 3
            config.audit_path = f"reports/bench-audit-{engine_name}.jsonl"
            runtime = SentinelRuntime(config, engine=engine_name).start()
            runtimes.append(runtime)
            base = f"http://127.0.0.1:{runtime.front_port}"
            log(f"  {engine_name}: 前端端口 {runtime.front_port}, 语料质量评测 ...")
            entry = report.setdefault("real_engines", {}).setdefault(engine_name, {})
            entry["available"] = True
            entry["console"] = _runtime_console(runtime)
            entry["quality"] = quality_over_http(corpus, base, engine_name)
            entry["qps"] = bench_http_qps(base, engine_name)
            entry["load_balancer"] = _engine_lb(runtime)
            entry["uptime_s"] = round(time.time() - runtime.started_at, 1)

    log("内置引擎反向代理延迟 ...")
    config = Config()
    config.listener.host, config.listener.port = "127.0.0.1", 0
    config.lab.base_port, config.lab.instances = 0, 3
    config.audit_path = "reports/bench-audit-python.jsonl"
    proxy_runtime = SentinelRuntime(config, engine="python").start()
    runtimes.append(proxy_runtime)
    proxy_base = f"http://127.0.0.1:{proxy_runtime.front_port}"
    report["proxy"] = bench_proxy(proxy_base)
    report["load_balancer"] = bench_load_balancer(proxy_base)

    lab_base = proxy_runtime.lab_urls()[0]
    log("paranoia level 权衡评测 ...")
    report["paranoia"] = bench_paranoia_sweep(
        corpus, real_engines=real_engines, log=log if verbose else (lambda _m: None))
    report["threshold_sweep"] = bench_threshold_sweep(
        corpus, real_engines=real_engines, log=log if verbose else (lambda _m: None))

    log(f"扫描器吞吐 (内置, 直连靶场 {lab_base}) ...")
    report["scanner"] = {"builtin": bench_scanner_builtin(lab_base)}
    if scanner_multi:
        log("扫描器吞吐 (nuclei + w13scan + 内置, 多引擎融合) ...")
        targets = proxy_runtime.scan_targets(lab_base)
        report["scanner"]["multi"] = bench_scanner_multi(targets)

    for runtime in runtimes:
        try:
            runtime.stop()
        except Exception:  # noqa: BLE001
            pass

    report["meta"]["duration_s"] = round(time.perf_counter() - started, 2)
    return report


def _runtime_console(runtime: SentinelRuntime) -> dict:
    snapshot = runtime.snapshot()
    return {
        "engine": snapshot["engine_name"],
        "rules_total": snapshot["engine"]["rules_total"],
        "front_port": snapshot["front_port"],
        "backend_stats": snapshot.get("backends"),
    }


def _engine_lb(runtime: SentinelRuntime) -> dict:
    driver = runtime.engine_manager.current
    stats = {}
    if hasattr(driver, "backend_stats"):
        stats = dict(driver.backend_stats())
    values = list(stats.values())
    if not values:
        return {"distribution": {}}
    mean = statistics.fmean(values)
    return {
        "distribution": stats,
        "backends": len(stats),
        "mean": round(mean, 2),
        "max_deviation": round(max(values) - min(values), 1),
    }


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------
def render_markdown(report: dict) -> str:
    env = report["environment"]
    lines = [
        "# Sentinel 综合性能与质量基准报告",
        "",
        f"- 生成时间: {report['meta']['generated_at']}",
        f"- 采集耗时: {report['meta']['duration_s']} 秒",
        f"- 运行环境: Python {env['python']} · uv {env['uv']} · mise {env['mise']} · "
        f"{env['platform']} / {env['machine']} / {env['cpu_count']} vCPU",
        f"- nginx 数据面: {env['nginx']['version']} (模块: "
        f"{', '.join(env['nginx']['modules']) or 'core'})",
        "",
        "## 一、语料库",
        "",
        "| 类别 | 数量 |",
        "| --- | --- |",
    ]
    for key, value in sorted(report["corpus"]["stats"].items(), key=lambda kv: -kv[1]):
        lines.append(f"| {key} | {value} |")

    parser = report["parser"]
    lines += [
        "", "## 二、HTTP 解析吞吐", "",
        f"- 样本数: {parser['samples']} × {parser['rounds']} 轮 = {parser['ops']} 次解析",
        f"- 吞吐: **{parser['ops_per_s']:,.0f} 次/秒**",
        f"- 延迟: P50 {parser['latency_us']['p50']} µs · "
        f"P90 {parser['latency_us']['p90']} µs · P99 {parser['latency_us']['p99']} µs",
    ]

    lines += ["", "## 三、检测质量 (语料库)", "",
              "> 原生引擎与参考数据面跑的是**同一套规则数据** (sentinel/vendor),",
              "> 因此这一栏同时是「解释器实现是否忠实」的对照。", "",
              "| 引擎 | 模式 | TP | FP | TN | FN | 精确率 | 召回率 | F1 | 误报率 |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    quality_rows = [("python", report["quality"]["python"])]
    for name, entry in (report.get("real_engines") or {}).items():
        if entry.get("quality"):
            quality_rows.append((name, entry["quality"]))
    for name, quality in quality_rows:
        lines.append(
            f"| `{name}` | {quality.get('mode', '-')} | {quality['tp']} | {quality['fp']} | "
            f"{quality['tn']} | {quality['fn']} | {quality['precision']:.3f} | "
            f"{quality['recall']:.3f} | {quality['f1']:.3f} | "
            f"{quality['false_positive_rate']:.3f} |")

    for name, quality in quality_rows:
        lines += ["", f"### {name} 逐类检出率", "", "| 类别 | 检出/总数 | 检出率 |",
                  "| --- | --- | --- |"]
        for category, bucket in sorted(quality["by_category"].items()):
            lines.append(f"| {category} | {bucket['detected']}/{bucket['total']} | "
                         f"{bucket['rate'] * 100:.1f}% |")
        if quality["false_negative_samples"]:
            lines.append("")
            lines.append(f"漏报样例: `{'`; `'.join(quality['false_negative_samples'][:5])}`")
        if quality["false_positive_samples"]:
            lines.append("")
            lines.append(f"误报样例: `{'`; `'.join(quality['false_positive_samples'][:5])}`")

    lines += ["", "## 四、引擎吞吐", "",
              "| 引擎 | 请求数 | 并发 | 耗时(s) | QPS | P50(ms) | P90(ms) | P99(ms) | 状态码分布 |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    py = report["engine_throughput"]["python"]
    detail = py.get("latency_detail", {})
    lines.append(
        f"| `python` (进程内) | {py['ops']} | 1 | {py['seconds']} | {py['ops_per_s']:,.0f} | "
        f"{detail.get('p50_ms', 0)} | {detail.get('p90_ms', 0)} | {detail.get('p99_ms', 0)} | - |")
    for name, entry in (report.get("real_engines") or {}).items():
        qps = entry.get("qps")
        if not qps:
            continue
        lat = qps["latency_ms"]
        kind = "真实 C 数据面" if name.startswith("nginx-") else "原生解释器"
        lines.append(
            f"| `{name}` ({kind}) | {qps['requests']} | {qps['concurrency']} | "
            f"{qps['seconds']} | {qps['qps']:,.1f} | {lat['p50']} | {lat['p90']} | "
            f"{lat['p99']} | {qps['statuses']} |")

    lines += ["", "## 五、反向代理端到端延迟 (便携引擎)", ""]
    seq = report["proxy"]["sequential"]
    con = report["proxy"]["concurrent"]
    lines += [
        f"- 顺序请求: P50 {seq['p50']} ms · P90 {seq['p90']} ms · P99 {seq['p99']} ms "
        f"({seq['count']} 次)",
        f"- 并发请求: {con['requests']} 次 / {con['concurrency']} 并发 → "
        f"**{con['qps']:,.1f} QPS**, P50 {con['latency_ms']['p50']} ms · "
        f"P99 {con['latency_ms']['p99']} ms",
        f"- 状态码分布: {con['statuses']}",
        "",
        "### 负载均衡分发",
        "",
        f"- 后端数: {report['load_balancer'].get('backends', 0)}",
        f"- 分发分布: {report['load_balancer'].get('distribution', {})}",
        f"- 变异系数: {report['load_balancer'].get('coefficient_of_variation', 0)} "
        f"(越小越均匀)",
    ]

    lines += ["", "## 六、漏洞扫描吞吐", ""]
    builtin = report["scanner"]["builtin"]
    lines += [
        f"- 内置检测器: {builtin['requests']} 次请求 / {builtin['seconds']} 秒 → "
        f"**{builtin['requests_per_s']:,.1f} req/s**, 发现 {builtin['findings']} 个漏洞, "
        f"风险评分 {builtin['risk_score']} ({builtin['risk_level']})",
    ]
    multi = report["scanner"].get("multi")
    if multi:
        lines += [
            f"- 多引擎融合: {multi['targets']} 个目标 / {multi['seconds']} 秒 → "
            f"**{multi['findings']} 个唯一漏洞** ({multi['findings_per_s']} 个/秒)",
            "",
            "| 引擎 | 执行 | 发现 | 耗时(s) |",
            "| --- | --- | --- | --- |",
        ]
        for run in multi["runs"]:
            lines.append(f"| `{run['engine']}` | {'成功' if run['ok'] else '失败'} | "
                         f"{run['findings']} | {run['seconds']} |")

    paranoia = report.get("paranoia") or {}
    if paranoia:
        lines += ["", "## 七、paranoia level 权衡 (检出率 vs 误报率)", "",
                  "| 引擎 | PL | 召回率 | 精确率 | F1 | 误报率 | 漏报 | 误报 |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for name, levels in paranoia.items():
            for level, quality in sorted(levels.items()):
                lines.append(
                    f"| `{name}` | PL{level} | {quality['recall']:.3f} | "
                    f"{quality['precision']:.3f} | {quality['f1']:.3f} | "
                    f"{quality['false_positive_rate']:.3f} | {quality['fn']} | "
                    f"{quality['fp']} |")

    sweep = report.get("threshold_sweep") or {}
    if sweep:
        lines += ["", "## 八、异常阈值调优曲线", "",
                  "| 引擎 | 异常阈值 | 召回率 | 精确率 | F1 | 误报率 | 漏报 | 误报 |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for name, entries in sweep.items():
            for threshold, quality in sorted(entries.items(), key=lambda kv: int(kv[0])):
                lines.append(
                    f"| `{name}` | {threshold} | {quality['recall']:.3f} | "
                    f"{quality['precision']:.3f} | {quality['f1']:.3f} | "
                    f"{quality['false_positive_rate']:.3f} | {quality['fn']} | "
                    f"{quality['fp']} |")

    lines += ["", "## 九、规则库规模", "", "| 引擎 | 规则数 | 索引耗时(ms) | 上游 |",
              "| --- | --- | --- | --- |"]
    for name, entry in report["rules"].items():
        if not entry.get("available", True):
            lines.append(f"| `{name}` | - | - | 未构建 |")
            continue
        lines.append(f"| `{name}` | {entry['total']} | "
                     f"{entry.get('index_ms', entry.get('load_ms', '-'))} | "
                     f"{entry.get('source') or entry.get('upstream', '-')} |")

    lines += ["", "---", "",
              "_本基准由 `mise run bench` (benchmarks/run_all.py) 生成, 全部数据来自真实引擎进程。_"]
    return "\n".join(lines) + "\n"


def save(report: dict, outdir: str = "reports", stamp: str | None = None) -> dict[str, str]:
    stamp = stamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    base = Path(outdir)
    base.mkdir(parents=True, exist_ok=True)
    json_path = base / f"bench-{stamp}.json"
    md_path = base / f"bench-{stamp}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return {"json": str(json_path), "md": str(md_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel 综合基准")
    parser.add_argument("--out", default="reports")
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--no-real-engines", action="store_true",
                        help="跳过 ModSecurity / Naxsi 真实引擎评测")
    parser.add_argument("--no-multi-scanner", action="store_true",
                        help="跳过多引擎融合扫描")
    parser.add_argument("--report", action="store_true",
                        help="基准完成后生成中文综合测试报告 (MD/HTML/DOCX)")
    parser.add_argument("--tests", action="store_true",
                        help="生成报告前重新运行完整 pytest 以刷新 JUnit 结果")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    report = run_benchmarks(real_engines=not args.no_real_engines,
                            scanner_multi=not args.no_multi_scanner,
                            verbose=not args.quiet)
    paths = save(report, args.out, args.stamp)
    print(f"[bench] JSON -> {paths['json']}")
    print(f"[bench] Markdown -> {paths['md']}")

    if args.report:
        from sentinel.reporting import generate_test_report
        generated = generate_test_report(bench=report, outdir=args.out, run_tests=args.tests)
        for kind, path in generated.items():
            print(f"[report] {kind.upper()} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
