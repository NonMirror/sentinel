"""入侵检测模块 (行为分析 / 速率限制) 测试."""
from __future__ import annotations

import time

from sentinel.core.config import WafConfig
from sentinel.waf.engine import WafEngine
from sentinel.waf.ids import IdsTracker
from sentinel.waf.parser import parse_request
from sentinel.waf.rules import load_ruleset
from tests.conftest import raw_request


def make_request(target: str, client: str = "203.0.113.5", method: str = "GET"):
    return parse_request(raw_request(method, target), client, 1234)


def test_sensitive_path_sweep_alert():
    tracker = IdsTracker(window_s=60)
    alerts = []
    for path in ["/.env", "/.git/config", "/admin", "/phpmyadmin/index.php",
                 "/wp-login.php", "/actuator/env", "/config", "/debug"]:
        alerts += tracker.observe(make_request(path))
    assert any(a.rule_id == 980003 for a in alerts)
    assert tracker.stats()["total_alerts"] >= 1


def test_brute_force_alert_on_auth_endpoint():
    tracker = IdsTracker(window_s=60)
    alerts = []
    for _ in range(12):
        alerts += tracker.observe(make_request("/login", method="POST"))
    assert any(a.rule_id == 980004 for a in alerts)


def test_high_frequency_alert():
    tracker = IdsTracker(window_s=60)
    alerts = []
    for i in range(90):
        alerts += tracker.observe(make_request(f"/page?n={i}"))
    assert any(a.rule_id == 980002 for a in alerts)


def test_alert_cooldown_deduplicates():
    tracker = IdsTracker(window_s=60)
    alerts = []
    for _ in range(12):           # 触发敏感路径扫描告警
        alerts += tracker.observe(make_request("/.env"))
    sweep = [a for a in alerts if a.rule_id == 980003]
    assert len(sweep) == 1, "冷却窗口内同类告警只应产生一次"


def test_rate_limiter_token_bucket():
    tracker = IdsTracker(window_s=60, rate_limit_rps=5, rate_limit_burst=5)
    alerts = [a for i in range(30) for a in tracker.observe(make_request(f"/p{i}"))]
    assert any(a.rule_id == 980001 for a in alerts), "超过突发额度应触发限速"


def test_no_rate_limit_when_disabled():
    tracker = IdsTracker(window_s=60, rate_limit_rps=0)
    alerts = [a for i in range(50) for a in tracker.observe(make_request(f"/p{i}"))]
    assert not any(a.rule_id == 980001 for a in alerts)


def test_four_xx_sweep_detection():
    tracker = IdsTracker(window_s=60)
    tracker.observe(make_request("/x"))
    alerts = []
    for _ in range(40):
        alerts += tracker.record_response("203.0.113.5", 404)
    assert any(a.rule_id == 980006 for a in alerts)


def test_windows_are_evicted_over_time():
    tracker = IdsTracker(window_s=0.2)
    tracker.observe(make_request("/a"))
    time.sleep(0.3)
    tracker.observe(make_request("/b"))
    rows = tracker.top_clients()
    assert rows and rows[0][1] <= 2


def test_top_clients_sorted_by_score():
    tracker = IdsTracker(window_s=60)
    tracker.observe(make_request("/x", "10.0.0.1"), decision_score=30)
    tracker.observe(make_request("/y", "10.0.0.2"), decision_score=1)
    top = tracker.top_clients()
    assert top[0][0] == "10.0.0.1"


def test_engine_wires_ids_into_pipeline():
    engine = WafEngine(WafConfig(), load_ruleset("rules", 1))
    seen = []
    engine.bus.subscribe("ids", lambda event: seen.append(event.payload))
    for path in ["/.env", "/.git/config", "/admin", "/phpmyadmin/x.php",
                 "/wp-login.php", "/actuator/env", "/druid", "/console"]:
        decision = engine.inspect(make_request(path, "198.18.0.1"))
        assert decision.matched_rules
    assert seen, "IDS 告警应通过事件总线广播"
    assert engine.snapshot()["ids"]["total_alerts"] >= 1


def test_accumulated_anomaly_escalates():
    engine = WafEngine(WafConfig(), load_ruleset("rules", 1))
    blocked_late = False
    for i in range(6):
        decision = engine.inspect(make_request(f"/?q={i}+OR+1%3D1", "198.18.0.2"))
        if i >= 4 and decision.blocked:
            blocked_late = True
    assert blocked_late
