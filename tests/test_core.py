"""核心组件测试: 事件总线 / 指标 / 审计日志.

对应架构图中的 "事件驱动" 与 "日志审计" 组件。
"""
from __future__ import annotations

import json
import threading
import time

import pytest

from sentinel.core.audit import AuditLog, AuditRecord
from sentinel.core.events import EventBus, Topic
from sentinel.core.metrics import Counter, LatencyHistogram, Metrics, RollingWindow


# --------------------------------------------------------------------------
# 事件总线
# --------------------------------------------------------------------------
def test_event_bus_publish_subscribe_and_wildcard():
    bus = EventBus(history=10)
    seen: list[tuple[str, object]] = []
    bus.subscribe(Topic.BLOCK, lambda e: seen.append(("block", e.payload)))
    bus.subscribe("*", lambda e: seen.append(("any", e.topic)))

    bus.publish(Topic.BLOCK, {"rule": 1})
    bus.publish(Topic.IDS, "payload")

    assert ("block", {"rule": 1}) in seen
    assert ("any", Topic.IDS) in seen
    assert bus.published == 2


def test_event_bus_history_and_sequence():
    bus = EventBus(history=10)
    bus.publish(Topic.REQUEST, {"i": 1})
    bus.publish(Topic.REQUEST, {"i": 2})
    bus.publish(Topic.DECISION, {"i": 3})

    assert [e.seq for e in bus.history()] == [1, 2, 3]
    assert len(bus.history(Topic.REQUEST)) == 2
    assert len(bus.history(limit=2)) == 2
    assert bus.history(Topic.REQUEST)[-1].payload == {"i": 2}

    bus.clear()
    assert bus.history() == []


def test_event_bus_isolates_failing_subscribers():
    bus = EventBus()
    good: list[int] = []

    def boom(_event):
        raise RuntimeError("subscriber exploded")

    bus.subscribe(Topic.BLOCK, boom)
    bus.subscribe(Topic.BLOCK, lambda e: good.append(1))
    bus.publish(Topic.BLOCK, None)          # 不得抛出
    assert good == [1]
    assert bus.published == 1


def test_event_bus_unsubscribe():
    bus = EventBus()
    received: list[int] = []
    handle = bus.subscribe(Topic.METRIC, lambda e: received.append(e.seq))
    bus.publish(Topic.METRIC)
    handle()
    bus.publish(Topic.METRIC)
    assert received == [1]


def test_event_bus_is_thread_safe():
    bus = EventBus(history=5000)
    counter = Counter("events")
    bus.subscribe("*", lambda _e: counter.inc())

    def worker() -> None:
        for _ in range(200):
            bus.publish(Topic.METRIC)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert counter.value == 1200
    assert len(bus.history(limit=5000)) == 1200


# --------------------------------------------------------------------------
# 指标
# --------------------------------------------------------------------------
def test_counter_increments():
    counter = Counter("requests")
    assert counter.inc() == 1
    assert counter.inc(4) == 5
    assert counter.value == 5


def test_rolling_window_series_and_rate():
    window = RollingWindow(seconds=10, buckets=10)
    now = time.time()
    for _ in range(5):
        window.add(1.0, now=now)

    series = window.series(now=now)
    assert len(series) == 10
    assert sum(series) == 5
    assert window.total == 5
    assert window.rate_per_second(now=now) == pytest.approx(0.5)

    stream = window.series(now=now + 1.0)          # 样本仍在窗口内
    assert sum(stream) == 5


def test_latency_histogram_percentiles():
    histogram = LatencyHistogram()
    for value in range(1, 101):
        histogram.observe(float(value))

    assert histogram.count == 100
    assert histogram.mean_ms == pytest.approx(50.5)
    assert histogram.min_ms == 1.0
    assert histogram.max_ms == 100.0
    assert histogram.percentile(50) == 50.0
    assert histogram.percentile(90) == 90.0
    assert 99.0 <= histogram.percentile(99) <= 100.0

    summary = histogram.summary()
    assert summary["count"] == 100
    assert summary["p50_ms"] == 50.0
    assert set(summary) == {"count", "mean_ms", "min_ms", "max_ms",
                            "p50_ms", "p90_ms", "p95_ms", "p99_ms"}

    histogram.reset()
    assert histogram.count == 0
    assert histogram.percentile(50) == 0.0
    assert histogram.mean_ms == 0.0


def test_latency_histogram_bounded_samples():
    histogram = LatencyHistogram(capacity=64)
    for value in range(600):
        histogram.observe(float(value))
    assert histogram.count == 600            # 计数完整
    assert len(histogram._samples) == 64     # 样本有界, 内存可控


def test_metrics_snapshot_exposes_all_panels():
    metrics = Metrics()
    metrics.requests.inc(3)
    metrics.passed.inc(2)
    metrics.blocked.inc()
    metrics.rate_limited.inc()
    metrics.ids_alerts.inc(2)
    metrics.findings.inc(4)
    metrics.errors.inc()
    metrics.bytes_in.inc(100)
    metrics.bytes_out.inc(200)
    metrics.latency.observe(12.5)
    metrics.waf_latency.observe(0.5)
    metrics.qps.add(1.0)

    snapshot = metrics.snapshot()
    for key in ("uptime_s", "requests", "passed", "blocked", "rate_limited",
                "ids_alerts", "findings", "errors", "bytes_in", "bytes_out", "qps"):
        assert key in snapshot, f"缺少指标键: {key}"
    assert snapshot["requests"] == 3
    assert snapshot["passed"] == 2
    assert snapshot["blocked"] == 1
    assert snapshot["findings"] == 4
    assert snapshot["bytes_out"] == 200
    assert snapshot["latency_count"] == 1
    assert snapshot["latency_mean_ms"] == pytest.approx(12.5)
    assert snapshot["waf_p50_ms"] == pytest.approx(0.5)
    assert metrics.uptime() >= 0.0


# --------------------------------------------------------------------------
# 审计日志
# --------------------------------------------------------------------------
def _record(**overrides) -> AuditRecord:
    payload = dict(action="block", client="1.2.3.4", method="GET", url="/?id=1",
                   status=403, severity="high", rules=(942100,), backend="nginx")
    payload.update(overrides)
    return AuditRecord(**payload)


def test_audit_log_append_search_counts(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(capacity=10, path=str(path))
    log.append(_record())
    log.append(_record(action="pass", client="5.6.7.8", url="/", status=200,
                       severity="info", rules=()))

    assert len(log) == 2
    assert log.total == 2
    assert log.counts_by_action() == {"block": 1, "pass": 1}
    assert log.search(severity="high")[0].rules == (942100,)
    assert [r.action for r in log.search(action="pass")] == ["pass"]
    assert log.search("1.2.3.4")[0].client == "1.2.3.4"
    assert log.search("", limit=1)[0].action == "pass"      # 最近优先
    assert len(log.recent(1)) == 1

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    row = json.loads(lines[0])
    assert row["action"] == "block"
    assert row["rules"] == [942100]
    assert row["client"] == "1.2.3.4"

    log.close()


def test_audit_log_capacity_ring_and_iteration(tmp_path):
    log = AuditLog(capacity=3)
    for index in range(5):
        log.append(_record(url=f"/p{index}", rules=(index,)))
    assert log.total == 5
    assert len(log) == 3
    assert [record.url for record in log] == ["/p2", "/p3", "/p4"]
    assert log.counts_by_action()["block"] == 3


def test_audit_record_serialisation_includes_extra():
    record = _record(extra={"engine": "modsecurity"}, latency_ms=1.2345, bytes_out=512)
    row = json.loads(record.to_line())
    assert row["extra"] == {"engine": "modsecurity"}
    assert row["latency_ms"] == pytest.approx(1.234)
    assert row["bytes_out"] == 512
    assert row["ts"] > 0
