"""规则引擎与规则库测试."""
from __future__ import annotations

import json

import pytest

from sentinel.core.models import Severity, Verdict
from sentinel.waf.parser import parse_request
from sentinel.waf.rules import (Operator, Rule, RuleSet, default_rules,
                                load_ruleset)
from tests.conftest import raw_request


@pytest.fixture()
def ruleset():
    return load_ruleset("rules", 1)


def test_default_ruleset_shape():
    rules = default_rules()
    assert len(rules) >= 30
    categories = {r.category for r in rules}
    assert {"protocol", "sqli", "xss", "rce", "lfi", "ssrf", "scanner"} <= categories
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "规则 ID 必须唯一"


def test_rule_directory_extends_and_overrides(tmp_path):
    (tmp_path / "extra.json").write_text(json.dumps({"rules": [
        {"id": 910000, "description": "覆盖内置协议规则", "variables": ["REQUEST_METHOD"],
         "operator": "eq", "operator_arg": "GET", "severity": "low", "action": "log",
         "category": "custom"},
        {"id": 999999, "description": "自定义规则", "variables": ["REQUEST_URI"],
         "operator": "contains", "operator_arg": "/secret", "severity": "high",
         "action": "block", "category": "custom"},
    ]}), encoding="utf-8")
    ruleset = load_ruleset(str(tmp_path), 1)
    assert len(ruleset) == len(default_rules()) + 1
    assert ruleset.get(910000).description == "覆盖内置协议规则"
    assert ruleset.get(999999).operator == "contains"


def test_shipped_custom_rules_present(ruleset):
    assert ruleset.get(999001) is not None
    assert ruleset.get(999002) is not None


def test_paranoia_level_filters_rules(ruleset):
    total = len(ruleset)
    pl1 = len(RuleSet(ruleset.rules, 1).active())
    pl4 = len(RuleSet(ruleset.rules, 4).active())
    assert pl1 < pl4 <= total


def test_enable_disable_rule(ruleset):
    rule = ruleset.get(942100)
    ruleset.enable(942100, False)
    assert rule.enabled is False and all(r.id != 942100 for r in ruleset.active())
    ruleset.enable(942100, True)
    assert 942100 in [r.id for r in ruleset.active()]
    assert ruleset.enable(123456789, True) is False


@pytest.mark.parametrize("name,arg,value,hit", [
    ("rx", "^/admin", "/admin/x", True),
    ("rx", "^/admin", "/public", False),
    ("contains", "abc", "xxabcxx", True),
    ("containsAny", "a|b|c", "zzb", True),
    ("containsWord", "cat", "the cat sat", True),
    ("containsWord", "cat", "concatenate", False),
    ("eq", "GET", "GET", True),
    ("startsWith", "/api", "/api/v1", True),
    ("endsWith", ".php", "/index.php", True),
    ("gt", "10", "11", True),
    ("gt", "10", "9", False),
    ("le", "10", "10", True),
    ("pm", "union|select", "xx union yy", True),
    ("detectSQLi", "", "1' OR '1'='1", True),
    ("detectSQLi", "", "hello world", False),
    ("detectXSS", "", "<svg/onload=alert(1)>", True),
    ("detectRCE", "", "127.0.0.1;id", True),
    ("detectTraversal", "", "../../etc/passwd", True),
    ("detectSSRF", "", "http://169.254.169.254/", True),
    ("ipMatch", "10.0.0.0/8", "10.1.2.3", True),
    ("ipMatch", "10.0.0.0/8", "192.168.1.1", False),
    ("within", "abcdef", "bcd", True),
    ("noMatch", "", "", True),
    ("alwaysMatch", "", "x", True),
])
def test_operators(name, arg, value, hit):
    op = Operator.compile(name, arg)
    matched, evidence = Operator.apply(op, value)
    assert matched is hit
    if hit:
        assert isinstance(evidence, str)


def test_rule_matching_against_request(ruleset):
    req = parse_request(raw_request("GET", "/search?q=1+UNION+SELECT+1--"), "1.1.1.1", 1)
    matches = ruleset.evaluate(req)
    rules_hit = {m.rule.id for m in matches}
    assert 942110 in rules_hit
    assert all(m.evidence for m in matches)


def test_rule_severity_and_verdict_mapping():
    rule = Rule(id=1, description="x", severity="critical", action="block",
                operator="alwaysMatch")
    assert rule.severity is Severity.CRITICAL
    assert rule.verdict is Verdict.BLOCK
    assert rule.effective_score == 5
    drop = Rule(id=2, description="y", action="drop", score=9, operator="alwaysMatch")
    assert drop.verdict is Verdict.DROP and drop.effective_score == 9


def test_json_roundtrip(tmp_path, ruleset):
    path = tmp_path / "rules.json"
    ruleset.save_json(str(path))
    reloaded = RuleSet.load_json(str(path))
    assert len(reloaded) == len(ruleset)
    assert {r.id for r in reloaded} == {r.id for r in ruleset}


def test_modsecurity_parse_and_export(tmp_path):
    conf = tmp_path / "crs.conf"
    conf.write_text(
        "# 注释行\n"
        'SecRule ARGS "@rx union\\s+select" "id:1001,phase:2,severity:CRITICAL,'
        't:urlDecodeUni,t:lowercase,msg:\'SQLi union\',tag:\'sqli\',block"\n'
        'SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" '
        '"id:1002,severity:MEDIUM,msg:\'scanner\',log"\n',
        encoding="utf-8")
    ruleset = RuleSet.load_conf(str(conf))
    assert len(ruleset) == 2
    rule = ruleset.get(1001)
    assert rule.severity is Severity.CRITICAL
    assert rule.transforms == ["urlDecodeUni", "lowercase"]
    assert rule.tags == ["sqli"]

    out = tmp_path / "export.conf"
    count = ruleset.export_modsecurity(str(out))
    text = out.read_text(encoding="utf-8")
    secrule_lines = [line for line in text.splitlines() if line.startswith("SecRule")]
    assert count == 2 and len(secrule_lines) == 2
    assert "id:1001" in text and "@rx" in text

    # 导出的规则可被再次解析 (闭环)
    reparsed = RuleSet.load_conf(str(out))
    assert {r.id for r in reparsed} == {1001, 1002}


def test_load_dir_ignores_unknown_formats(tmp_path):
    (tmp_path / "note.txt").write_text("not a rule", encoding="utf-8")
    (tmp_path / "ok.rules").write_text(
        'SecRule ARGS "@contains abc" "id:5,msg:\'x\'"\n', encoding="utf-8")
    assert len(RuleSet.load_dir(str(tmp_path))) == 1


def test_summary_counts(ruleset):
    summary = ruleset.summary()
    assert summary["total"] == len(ruleset)
    assert summary["enabled"] == len(ruleset)
    assert sum(summary["by_category"].values()) == len(ruleset)
