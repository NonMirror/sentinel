"""原生 Naxsi 规则引擎测试.

Naxsi 的模型是「负向白名单 + 分区计分」: 单条规则命中只加分, 是否拦截由
累计分数与 ``CheckRule`` 阈值决定。这里守住三件事:

* ``MainRule`` / ``CheckRule`` 的解析 (含 ``mz:`` 与 ``s:$KEY:n``);
* 计分与阈值判定 (PL1–PL4 逐级收紧);
* **规则文件里没有 CheckRule** —— 必须回落到 Naxsi 官方示例配置的默认阈值,
  否则阈值为 0 会让每个请求都被拦截。
"""
from __future__ import annotations

import pytest

from sentinel.core.models import HttpRequest
from sentinel.vendor import naxsi_core_rules
from sentinel.waf.naxsi import NativeNaxsiEngine, load_naxsi_rules
from sentinel.waf.naxsi.syntax import (DEFAULT_THRESHOLDS, CheckRule, MainRule,
                                       parse_check_rule, parse_main_rule)


def request(target: str = "/", *, method: str = "GET", body: bytes = b"",
            ctype: str = "", headers: dict | None = None) -> HttpRequest:
    merged = {"Host": "lab.local", "User-Agent": "Mozilla/5.0"}
    merged.update(headers or {})
    if ctype:
        merged["Content-Type"] = ctype
    path, _, query = target.partition("?")
    return HttpRequest(method=method, target=target, path=path or "/", query=query,
                       headers=merged, body=body, remote_addr="127.0.0.1")


@pytest.fixture(scope="module")
def ruleset():
    return load_naxsi_rules([naxsi_core_rules()])


@pytest.fixture(scope="module")
def engine(ruleset):
    return NativeNaxsiEngine(ruleset, paranoia_level=1)


# --------------------------------------------------------------------------
# 语法解析
# --------------------------------------------------------------------------
class TestSyntax:
    def test_parse_main_rule_with_scores_and_zones(self):
        rule = parse_main_rule(
            'MainRule "str:\\"" "msg:double quote" '
            '"mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;')
        assert isinstance(rule, MainRule)
        assert rule.id == 1001 and rule.kind == "str" and rule.pattern == '"'
        assert rule.message == "double quote"
        # 检测面里的 ``$`` 前缀被归一化掉, 与引擎的 zone 键保持一致
        # (否则 ``$HEADERS_VAR:Cookie`` 这类规则永远不会命中)
        assert set(rule.zones) == {"BODY", "URL", "ARGS", "HEADERS_VAR:Cookie"}
        assert rule.scores == {"SQL": 8, "XSS": 8}
        assert rule.points == 8

    def test_str_patterns_are_unescaped_and_lowercased(self):
        """``str:\\"`` 就是字面双引号; Naxsi 的 str: 匹配不分大小写."""
        rule = parse_main_rule(
            'MainRule "str:SELECT" "msg:m" "mz:ARGS" "s:$SQL:4" id:2;')
        assert rule.pattern == "select"

    def test_rx_patterns_are_case_insensitive(self):
        rule = parse_main_rule(
            'MainRule "rx:union" "msg:m" "mz:ARGS" "s:$SQL:4" id:3;')
        assert rule.compiled.search("UNION SELECT")

    def test_parse_main_rule_regex(self):
        rule = parse_main_rule(
            'MainRule "rx:select|union" "msg:sql keywords" '
            '"mz:ARGS" "s:$SQL:4" id:1000;')
        assert rule.kind == "rx" and rule.compiled is not None
        assert rule.compiled.search("SELECT")

    def test_parse_check_rule(self):
        check = parse_check_rule('CheckRule "$SQL >= 8" BLOCK;')
        assert isinstance(check, CheckRule)
        assert check.variable == "SQL" and check.operator == ">="
        assert check.threshold == 8 and check.action == "BLOCK"

    def test_internal_rules_are_flagged(self):
        """``d:`` 等是 Naxsi 的内部信号, 不是检测规则."""
        rule = parse_main_rule(
            'MainRule "msg:weird request" "mz:ARGS" "s:$SQL:4" "d:1" id:1;')
        assert rule.internal is True

    def test_vendored_rules_parse_cleanly(self, ruleset):
        assert len(ruleset.rules) >= 40
        assert ruleset.warnings == [], ruleset.warnings[:5]
        assert all(rule.id for rule in ruleset.rules)

    def test_score_histogram_covers_expected_keys(self, ruleset):
        keys = set(ruleset.summary()["by_score"])
        assert {"SQL", "XSS", "RFI", "TRAVERSAL"} <= keys


# --------------------------------------------------------------------------
# 阈值
# --------------------------------------------------------------------------
class TestThresholds:
    def test_falls_back_to_defaults_without_check_rules(self, ruleset):
        """naxsi_core.rules 只有 MainRule —— 没有回落就会全员拦截."""
        assert ruleset.checks == []
        assert ruleset.thresholds(0) == DEFAULT_THRESHOLDS

    def test_explicit_check_rules_override_defaults(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.rules"
            path.write_text(
                'MainRule "str:a" "msg:m" "mz:ARGS" "s:$SQL:4" id:1;\n'
                'CheckRule "$SQL >= 12" BLOCK;\n', encoding="utf-8")
            loaded = load_naxsi_rules([path])
        assert loaded.thresholds(0) == {"SQL": 12}

    def test_paranoia_level_tightens_thresholds(self, ruleset):
        base = ruleset.thresholds(0)
        tight = ruleset.thresholds(3)
        assert base["SQL"] == 8 and tight["SQL"] == 5
        assert tight["TRAVERSAL"] == 1
        assert all(tight[k] <= base[k] for k in base)
        assert all(v >= 1 for v in tight.values())


# --------------------------------------------------------------------------
# 判定
# --------------------------------------------------------------------------
class TestScoring:
    @pytest.mark.parametrize("target", [
        "/search?q=1'%20or%20'1'%3D'1",
        "/product?id=1%20union%20select%201,2%20from%20users",
        "/page?name=%3Cscript%3Ealert(1)%3C/script%3E",
        "/download?file=../../etc/passwd",
    ])
    def test_attacks_are_blocked(self, engine, target):
        verdict = engine.inspect(request(target))
        assert verdict.blocked, f"未拦截: {target} 分数={verdict.scores}"

    @pytest.mark.parametrize("target", [
        "/", "/search?q=hello+world", "/product?id=42&sort=name",
        "/api/v1/orders?page=2&limit=20",
    ])
    def test_benign_traffic_scores_zero(self, engine, target):
        verdict = engine.inspect(request(target))
        assert not verdict.blocked
        assert verdict.scores == {}, verdict.scores

    def test_scores_accumulate_per_key(self, engine):
        verdict = engine.inspect(request("/?q=<script>alert(1)</script>"))
        assert verdict.scores["XSS"] >= 8
        assert verdict.breached["XSS"] >= verdict.thresholds["XSS"]

    def test_matched_rules_are_reported(self, engine):
        verdict = engine.inspect(request("/?id=1 union select 1"))
        assert verdict.matched_rules()
        assert all(hit.zone for hit in verdict.hits)

    def test_body_is_inspected(self, engine):
        verdict = engine.inspect(request(
            "/comment", method="POST", ctype="application/x-www-form-urlencoded",
            body=b"message=<script>alert(1)</script>"))
        assert verdict.blocked

    def test_cookie_header_zone(self, engine):
        verdict = engine.inspect(request("/", headers={"Cookie": "a=1' or '1'='1"}))
        assert verdict.scores, "Cookie 头未被纳入检测面"

    def test_mode_detect_records_without_blocking(self, ruleset):
        detect = NativeNaxsiEngine(ruleset, mode="detect")
        verdict = detect.inspect(request("/?q=1 union select 1"))
        assert not verdict.blocked
        assert verdict.scores, "detect 模式仍应计分"

    def test_mode_off_short_circuits(self, ruleset):
        off = NativeNaxsiEngine(ruleset, mode="off")
        assert off.inspect(request("/?q=1 union select 1")).scores == {}

    def test_paranoia_level_tightens_decisions(self, ruleset):
        """同一请求在 PL4 的分数不低于 PL1 (阈值更严 -> 更容易越线)."""
        low = NativeNaxsiEngine(ruleset, paranoia_level=1)
        high = NativeNaxsiEngine(ruleset, paranoia_level=4)
        target = "/?id=1' or '1'='1"
        assert high.inspect(request(target)).total == low.inspect(request(target)).total
        assert high.thresholds["TRAVERSAL"] < low.thresholds["TRAVERSAL"]

    def test_engine_summary_and_views(self, engine):
        summary = engine.summary()
        assert summary["total"] >= 40 and "thresholds" in summary
        views = engine.rule_views()
        assert len(views) == summary["total"]
        assert {"id", "zones", "points", "scores"} <= set(views[0])
