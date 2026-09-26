"""指标采集: 计数器、滚动窗口、延迟直方图 (供 TUI 可视化与性能报告使用)."""
from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field


class Counter:
    __slots__ = ("name", "_value", "_lock")

    def __init__(self, name: str = "") -> None:
        self.name = name
        self._value = 0
        self._lock = threading.Lock()

    def inc(self, n: int = 1) -> int:
        with self._lock:
            self._value += n
            return self._value

    @property
    def value(self) -> int:
        with self._lock:
            return self._value


class RollingWindow:
    """按时间分桶的滚动计数, 用于 sparkline 与 QPS 曲线."""

    def __init__(self, seconds: int = 60, buckets: int = 60) -> None:
        self.seconds = seconds
        self.buckets = buckets
        self._width = max(0.001, seconds / buckets)
        self._data: deque[tuple[float, float]] = deque(maxlen=buckets * 4)
        self._lock = threading.Lock()

    def add(self, value: float = 1.0, now: float | None = None) -> None:
        with self._lock:
            self._data.append((now or time.time(), float(value)))

    def series(self, now: float | None = None) -> list[float]:
        now = now or time.time()
        start = now - self.seconds
        out = [0.0] * self.buckets
        with self._lock:
            data = list(self._data)
        for ts, value in data:
            if ts < start:
                continue
            idx = min(self.buckets - 1, int((ts - start) / self._width))
            out[idx] += value
        return out

    @property
    def total(self) -> float:
        with self._lock:
            return sum(v for _, v in self._data)

    def rate_per_second(self, now: float | None = None) -> float:
        now = now or time.time()
        start = now - self.seconds
        with self._lock:
            recent = [v for ts, v in self._data if ts >= start]
        window = min(self.seconds, max(1.0, now - (now - self.seconds)))
        return sum(recent) / window


@dataclass
class LatencyHistogram:
    """精确百分位延迟统计 (样本有界, 保证内存可控)."""

    capacity: int = 200000
    _samples: list[float] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    count: int = 0
    total_ms: float = 0.0
    _max_ms: float = 0.0
    _min_ms: float = float("inf")

    def observe(self, ms: float) -> None:
        with self._lock:
            self.count += 1
            self.total_ms += ms
            self._max_ms = max(self._max_ms, ms)
            self._min_ms = min(self._min_ms, ms)
            if len(self._samples) < self.capacity:
                self._samples.append(ms)

    def percentile(self, p: float) -> float:
        with self._lock:
            if not self._samples:
                return 0.0
            data = sorted(self._samples)
        k = max(0, min(len(data) - 1, math.ceil((p / 100.0) * len(data)) - 1))
        return data[k]

    @property
    def mean_ms(self) -> float:
        return self.total_ms / self.count if self.count else 0.0

    @property
    def max_ms(self) -> float:
        return self._max_ms if self.count else 0.0

    @property
    def min_ms(self) -> float:
        return self._min_ms if self.count else 0.0

    def summary(self) -> dict[str, float]:
        return {
            "count": self.count,
            "mean_ms": round(self.mean_ms, 4),
            "min_ms": round(self.min_ms, 4),
            "max_ms": round(self.max_ms, 4),
            "p50_ms": round(self.percentile(50), 4),
            "p90_ms": round(self.percentile(90), 4),
            "p95_ms": round(self.percentile(95), 4),
            "p99_ms": round(self.percentile(99), 4),
        }

    def reset(self) -> None:
        with self._lock:
            self._samples.clear()
            self.count = 0
            self.total_ms = 0.0
            self._max_ms = 0.0
            self._min_ms = float("inf")


class Metrics:
    """平台统一指标注册表."""

    def __init__(self) -> None:
        self.requests = Counter("requests")
        self.blocked = Counter("blocked")
        self.passed = Counter("passed")
        self.rate_limited = Counter("rate_limited")
        self.ids_alerts = Counter("ids_alerts")
        self.findings = Counter("findings")
        self.errors = Counter("errors")
        self.bytes_in = Counter("bytes_in")
        self.bytes_out = Counter("bytes_out")
        self.latency = LatencyHistogram()
        self.waf_latency = LatencyHistogram()
        self.qps = RollingWindow(seconds=60, buckets=60)
        self.blocked_window = RollingWindow(seconds=60, buckets=60)
        self.started_at = time.time()

    def uptime(self) -> float:
        return time.time() - self.started_at

    def snapshot(self) -> dict[str, float | int]:
        return {
            "uptime_s": round(self.uptime(), 2),
            "requests": self.requests.value,
            "passed": self.passed.value,
            "blocked": self.blocked.value,
            "rate_limited": self.rate_limited.value,
            "ids_alerts": self.ids_alerts.value,
            "findings": self.findings.value,
            "errors": self.errors.value,
            "bytes_in": self.bytes_in.value,
            "bytes_out": self.bytes_out.value,
            "qps": round(self.qps.rate_per_second(), 3),
            **{f"latency_{k}": v for k, v in self.latency.summary().items()},
            **{f"waf_{k}": v for k, v in self.waf_latency.summary().items()},
        }
