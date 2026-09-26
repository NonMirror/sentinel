"""WAF 决策引擎测试 (处置动作 / 异常评分 / 模式)."""
from __future__ import annotations

import pytest

from sentinel.core.models import Verdict
from sentinel.waf.parser import parse_request
from tests.conftest import raw_request


def classify(raw: bytes):
    """辅助: 返回 (verdict, score, rules, messages)."""
    from sentinel.core import EventBus, Metrics
    from sentinel.core.config import WafConfig
    from sentinel.waf.engine import WafEngine
    from sentinel.waf.rules import load_ruleset

    engine = WafEngine(WafConfig(), load_ruleset("rules", 1), EventBus(), None, Metrics())
    decision = engine.inspect(parse_request(raw, "198.51.100.9", 4444))
    return decision


@pytest.mark.parametrize("target,expect", [
    ("/search?q=1+OR+1%3D1", Verdict.BLOCK),
    ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", Verdict.BLOCK),
    ("/download?file=../../../../etc/passwd", Verdict.BLOCK),
    ("/fetch?url=http://169.254.169.254/", Verdict.BLOCK),
    ("/ping?ip=127.0.0.1%3Bid", Verdict.BLOCK),
    ("/products?page=2&sort=price", Verdict.PASS),
])
def test_verdict_matrix(target, expect):
    decision = classify(raw_request("GET", target))
    assert decision.verdict is expect, decision.messages
    assert decision.anomaly_score >= 0


def test_anomaly_score_accumulates_and_threshold_blocks():
    decision = classify(raw_request("GET", "/download?file=../../../../etc/passwd"))
    assert decision.anomaly_score >= 4
    assert decision.severity.weight >= 3
    assert decision.matched_rules


def test_detect_mode_logs_instead_of_blocking():
    from sentinel.core import EventBus, Metrics
    from sentinel.core.config import WafConfig
    from sentinel.waf.engine import WafEngine
    from sentinel.waf.rules import load_ruleset

    engine = WafEngine(WafConfig(mode="detect"), load_ruleset("rules", 1),
                       EventBus(), None, Metrics())
    decision = engine.inspect(parse_request(
        raw_request("GET", "/search?q=1+OR+1%3D1"), "1.1.1.1", 1))
    assert decision.verdict is Verdict.LOG
    assert decision.blocked is False
    assert decision.matched_rules


def test_off_mode_passes_everything():
    from sentinel.core import EventBus, Metrics
    from sentinel.core.config import WafConfig
    from sentinel.waf.engine import WafEngine
    from sentinel.waf.rules import load_ruleset

    engine = WafEngine(WafConfig(mode="off"), load_ruleset("rules", 1),
                       EventBus(), None, Metrics())
    decision = engine.inspect(parse_request(
        raw_request("GET", "/search?q=1+OR+1%3D1"), "1.1.1.1", 1))
    assert decision.verdict is Verdict.PASS


def test_body_inspection_can_be_disabled():
    from sentinel.core import EventBus, Metrics
    from sentinel.core.config import WafConfig
    from sentinel.waf.engine import WafEngine
    from sentinel.waf.rules import load_ruleset

    body = b"q=1+OR+1%3D1"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    on = WafEngine(WafConfig(inspect_body=True), load_ruleset("rules", 1),
                   EventBus(), None, Metrics())
    off = WafEngine(WafConfig(inspect_body=False), load_ruleset("rules", 1),
                    EventBus(), None, Metrics())
    assert on.inspect(parse_request(raw_request("POST", "/s", headers, body),
                                    "1.1.1.1", 1)).blocked
    assert not off.inspect(parse_request(raw_request("POST", "/s", headers, body),
                                         "1.1.1.1", 1)).blocked


def test_uri_length_limit_rule():
    decision = classify(raw_request("GET", "/" + "a" * 9000))
    assert decision.blocked
    assert 910001 in decision.matched_rules


def test_oversized_header_rule():
    decision = classify(raw_request("GET", "/", {"Referer": "https://x/" + "a" * 9000}))
    assert decision.blocked and 910004 in decision.matched_rules


def test_critical_rule_blocks_even_below_threshold():
    from sentinel.core import EventBus, Metrics
    from sentinel.core.config import WafConfig
    from sentinel.waf.engine import WafEngine
    from sentinel.waf.rules import load_ruleset

    engine = WafEngine(WafConfig(anomaly_threshold=100), load_ruleset("rules", 1),
                       EventBus(), None, Metrics())
    decision = engine.inspect(parse_request(
        raw_request("GET", "/?a=1;DROP+TABLE+users--"), "1.1.1.1", 1))
    assert decision.blocked


def test_events_published_and_stats_counted():
    from sentinel.core import EventBus, Metrics
    from sentinel.core.config import WafConfig
    from sentinel.waf.engine import WafEngine
    from sentinel.waf.rules import load_ruleset

    bus, metrics = EventBus(), Metrics()
    seen: list[str] = []
    bus.subscribe("*", lambda e: seen.append(e.topic))
    engine = WafEngine(WafConfig(), load_ruleset("rules", 1), bus, None, metrics)
    engine.inspect(parse_request(raw_request("GET", "/x"), "1.1.1.1", 1))
    engine.inspect(parse_request(raw_request("GET", "/?q=1+OR+1%3D1"), "1.1.1.1", 2))
    assert "decision" in seen and "block" in seen
    snapshot = engine.snapshot()
    assert snapshot["inspected"] == 2 and snapshot["blocked"] == 1
    assert metrics.waf_latency.count == 2


def test_paranoia_level_switch():
    from sentinel.core import EventBus, Metrics
    from sentinel.core.config import WafConfig
    from sentinel.waf.engine import WafEngine
    from sentinel.waf.rules import load_ruleset

    engine = WafEngine(WafConfig(paranoia_level=1), load_ruleset("rules", 1),
                       EventBus(), None, Metrics())
    low = engine.snapshot()["rules_active"]
    engine.set_paranoia(4)
    assert engine.snapshot()["rules_active"] > low
    assert engine.config.paranoia_level == 4


def test_duplicate_rule_scoring_counted_once():
    decision = classify(raw_request("GET", "/search?q=1+OR+1%3D1&x=1+OR+1%3D1"))
    assert len(decision.matched_rules) == len(set(decision.matched_rules))


def test_large_body_truncated_still_inspected():
    body = b"a" * 200 + b"&q=1+OR+1%3D1"
    raw = raw_request("POST", "/s",
                      {"Content-Type": "application/x-www-form-urlencoded"}, body)
    decision = classify(raw)
    assert decision.blocked
