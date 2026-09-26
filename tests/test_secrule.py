"""原生 SecRule 解释器测试.

这里的用例**基本上是开发期踩过的坑的固化**. ModSecurity 的规则语言有一批
反直觉的语义, 写错时不会报错、只会静默失效 (漏报或全量误报), 因此每条都
值得一个回归测试:

* ``(?i)`` 出现在模式中部 —— Python 拒绝, PCRE 接受;
* 校验类算子命中于**失败**;
* ``&TX:x`` 取命中**个数**;
* ``!VAR`` 目标是**从集合中剔除**而非取反;
* 注释里的撇号会污染整个文件的引号配对;
* 动作名大小写 (``skipAfter`` / ``multiMatch``) 决定 PL 分级跳转是否生效。
"""
from __future__ import annotations

import pytest

from sentinel.core.models import HttpRequest, Severity
from sentinel.waf.secrule import SecRuleEngine, operators
from sentinel.waf.secrule.syntax import (load_ruleset, logical_statements,
                                         parse_actions, parse_variables)


# --------------------------------------------------------------------------
# 辅助
# --------------------------------------------------------------------------
def make_request(method: str = "GET", target: str = "/", headers=None,
                 body: bytes = b"", ctype: str = "") -> HttpRequest:
    merged = {"Host": "lab.local", "User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    merged.update(headers or {})
    if ctype:
        merged["Content-Type"] = ctype
    path, _, query = target.partition("?")
    return HttpRequest(method=method, target=target, path=path, query=query,
                       headers=merged, body=body, remote_addr="127.0.0.1")


def build_engine(conf: str, **kwargs) -> SecRuleEngine:
    """从一段规则文本构造引擎 (不落盘)."""
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "test.conf"
        path.write_text(conf, encoding="utf-8")
        ruleset = load_ruleset([str(path)])
    return SecRuleEngine(ruleset, **kwargs)


def fired(engine: SecRuleEngine, request: HttpRequest) -> list[int]:
    return engine.inspect(request).matched_rules


# --------------------------------------------------------------------------
# 词法: 续行 / 注释 / 引号
# --------------------------------------------------------------------------
class TestLexing:
    def test_continuation_removed_inside_quotes(self):
        """引号内的续行必须整体删除, 否则会插进正则里."""
        text = 'SecRule ARGS "@rx a\\\nb" "id:1"\n'
        statements = [s for s in logical_statements(text) if s.strip()]
        assert len(statements) == 1
        assert "@rx ab" in statements[0]

    def test_continuation_becomes_space_outside_quotes(self):
        text = 'SecRule ARGS \\\n"@rx a" "id:1"\n'
        statements = [s for s in logical_statements(text) if s.strip()]
        assert statements[0].startswith("SecRule ARGS ")

    def test_apostrophe_in_comment_does_not_leak(self):
        """注释里的不成对撇号曾经把整个文件的引号状态带偏."""
        text = (
            "# don't do this\n"
            "# isn't it odd\n"
            'SecRule ARGS "@rx x" "id:7"\n'
        )
        statements = [s for s in logical_statements(text) if s.strip()]
        assert len(statements) == 1
        assert statements[0].startswith("SecRule ARGS")

    def test_escaped_quote_inside_operator(self):
        r"""算子里的转义引号不能当成算子串的收尾."""
        text = "SecRule ARGS \"@rx [\\\"]{2}\" \"id:9,msg:'x'\"\n"
        statements = [s for s in logical_statements(text) if s.strip()]
        assert len(statements) == 1
        assert "id:9" in statements[0]

    def test_action_arguments_lose_syntactic_quotes(self):
        actions = {a.name: a.argument for a in parse_actions("id:1,tag:'OWASP_CRS'")}
        assert actions["tag"] == "OWASP_CRS"


# --------------------------------------------------------------------------
# 目标解析
# --------------------------------------------------------------------------
class TestVariables:
    def test_pipe_and_exclusion_parsing(self):
        variables = parse_variables("REQUEST_HEADERS|!REQUEST_HEADERS:Cookie|&TX:x")
        assert [v.name for v in variables] == ["REQUEST_HEADERS",
                                               "REQUEST_HEADERS", "TX"]
        assert variables[1].negated and variables[1].selectors == ("Cookie",)
        assert variables[2].count

    def test_count_selector_counts_instead_of_value(self):
        engine = build_engine(
            'SecRule &ARGS "@eq 2" "id:1,phase:2,deny,status:403"\n')
        hit = engine.inspect(make_request(target="/x?a=1&b=2"))
        assert hit.matched_rules == [1]
        miss = engine.inspect(make_request(target="/x?a=1"))
        assert miss.matched_rules == []

    def test_count_selector_on_unset_tx_is_zero(self):
        engine = build_engine(
            'SecRule &TX:missing "@eq 0" "id:2,phase:1,pass,nolog,'
            "setvar:'tx.missing=set'\"\n"
            'SecRule TX:missing "@streq set" "id:3,phase:1,deny,status:403"\n')
        assert engine.inspect(make_request()).matched_rules == [3]

    def test_exclusion_target_removes_from_union(self):
        """``A|!A:x`` 应把 x 从集合里剔掉, 而不是参与取反."""
        engine = build_engine(
            'SecRule REQUEST_HEADERS|!REQUEST_HEADERS:Cookie '
            '"@rx secret" "id:1,phase:1,deny,status:403"\n')
        conn = make_request(headers={"Cookie": "secret"})
        assert engine.inspect(conn).matched_rules == []
        other = make_request(headers={"X-Trace": "secret"})
        assert engine.inspect(other).matched_rules == [1]

    def test_tx_keys_are_case_insensitive(self):
        engine = build_engine(
            'SecAction "id:1,phase:1,pass,nolog,setvar:\'tx.foo=bar\'"\n'
            'SecRule TX:FOO "@streq bar" "id:2,phase:1,deny,status:403"\n')
        assert engine.inspect(make_request()).matched_rules == [2]


# --------------------------------------------------------------------------
# 算子
# --------------------------------------------------------------------------
class TestOperators:
    def test_validation_operators_match_on_failure(self):
        """ModSecurity 里 @validateByteRange 命中于**越界**, 不是命中于合法."""
        valid = build_engine(
            'SecRule ARGS "@validateByteRange 97-122" '
            '"id:1,phase:2,deny,status:403"\n')
        assert valid.inspect(make_request(target="/x?a=abc")).matched_rules == []
        assert valid.inspect(make_request(target="/x?a=a1c")).matched_rules == [1]

    def test_validate_utf8_matches_on_invalid(self):
        engine = build_engine(
            'SecRule ARGS "@validateUtf8Encoding" "id:1,phase:2,deny,status:403"\n')
        assert engine.inspect(make_request(target="/x?a=hello")).matched_rules == []

    def test_pmfromfile_actually_loads_words(self, tmp_path):
        words = tmp_path / "words.data"
        words.write_text("# comment\nsqlmap\nnikto\n", encoding="utf-8")
        conf = (
            f'SecRule REQUEST_HEADERS:User-Agent '
            f'"@pmFromFile {words}" "id:1,phase:1,deny,status:403"\n')
        engine = build_engine(conf)
        hit = engine.inspect(make_request(headers={"User-Agent": "sqlmap/1.7"}))
        assert hit.matched_rules == [1]
        clean = engine.inspect(make_request(headers={"User-Agent": "Mozilla"}))
        assert clean.matched_rules == []

    def test_numeric_and_string_comparison(self):
        engine = build_engine(
            'SecAction "id:1,phase:1,pass,nolog,setvar:\'tx.n=10\'"\n'
            'SecRule TX:n "@ge 5" "id:2,phase:1,deny,status:403"\n')
        assert engine.inspect(make_request()).matched_rules == [2]

    def test_negated_operator(self):
        engine = build_engine(
            'SecRule REQUEST_METHOD "!@streq GET" "id:1,phase:1,deny,status:403"\n')
        assert engine.inspect(make_request(method="GET")).matched_rules == []
        assert engine.inspect(make_request(method="POST")).matched_rules == [1]


# --------------------------------------------------------------------------
# PCRE 方言
# --------------------------------------------------------------------------
class TestPcreDialect:
    @pytest.mark.parametrize("pattern", [
        r"\x{62}",           # 花括号十六进制转义
        r"(?|a|b)",          # 分支重置
        r"[\--9A-Z_a-z]+",   # 转义连字符作区间起点
        r"^(?i)up",          # 中部全局标志 (Python 拒绝, PCRE 接受)
    ])
    def test_dialect_patterns_compile(self, pattern):
        operators.reset_health()
        assert operators.compile_pattern(pattern) is not None

    def test_dialect_translation_preserves_semantics(self):
        assert operators.compile_pattern(r"^(?i)up").search("UPLOAD")
        assert operators.compile_pattern(r"\x{62}").search("b")
        assert operators.compile_pattern(r"[\--9]+").search("-42")

    def test_broken_regex_is_reported_not_raised(self):
        operators.reset_health()
        assert operators.compile_pattern("(?P<bad") is None
        assert operators.health()["failed_patterns"] >= 1


# --------------------------------------------------------------------------
# 控制流
# --------------------------------------------------------------------------
class TestControlFlow:
    def test_skipafter_jumps_to_marker(self):
        engine = build_engine(
            'SecRule ARGS "@streq skip" "id:1,phase:2,pass,nolog,'
            'skipAfter:END"\n'
            'SecRule ARGS "@rx ." "id:2,phase:2,deny,status:403"\n'
            'SecMarker "END"\n')
        assert engine.inspect(make_request(target="/x?a=skip")).matched_rules == []
        assert engine.inspect(make_request(target="/x?a=go")).matched_rules == [2]

    def test_chain_requires_every_link(self):
        engine = build_engine(
            'SecRule REQUEST_METHOD "@streq POST" '
            '"id:1,phase:2,deny,status:403,chain"\n'
            '    SecRule ARGS "@streq evil"\n')
        assert engine.inspect(make_request(method="GET",
                                           target="/x?a=evil")).matched_rules == []
        assert engine.inspect(make_request(method="POST",
                                           target="/x?a=ok")).matched_rules == []
        assert engine.inspect(make_request(method="POST",
                                           target="/x?a=evil")).matched_rules == [1]

    def test_capture_feeds_tx_groups(self):
        engine = build_engine(
            'SecRule ARGS "@rx (\\d+)-(\\d+)" "id:1,phase:2,pass,nolog,capture,'
            'setvar:\'tx.lo=%{tx.1}\'"\n'
            'SecRule TX:lo "@streq 42" "id:2,phase:2,deny,status:403"\n')
        assert engine.inspect(make_request(target="/x?r=42-99")).matched_rules == [2]

    def test_default_action_downgrades_block(self):
        """SecDefaultAction pass 时, 规则里的 block 只计分不拦截."""
        engine = build_engine(
            'SecDefaultAction "phase:2,log,auditlog,pass"\n'
            'SecRule ARGS "@streq evil" "id:1,phase:2,block,'
            "setvar:'tx.score=+5'\"\n"
            'SecRule TX:score "@ge 5" "id:2,phase:2,deny,status:403"\n')
        verdict = engine.inspect(make_request(target="/x?a=evil"))
        assert verdict.blocked and 2 in verdict.matched_rules

    def test_nolog_rules_do_not_pollute_hits(self):
        engine = build_engine(
            'SecAction "id:1,phase:1,pass,nolog,setvar:\'tx.a=1\'"\n'
            'SecRule ARGS "@streq evil" "id:2,phase:2,deny,status:403"\n')
        verdict = engine.inspect(make_request(target="/x?a=evil"))
        assert verdict.matched_rules == [2]
        assert [hit.rule_id for hit in verdict.hits] == [2]

    def test_unknown_action_is_recorded(self):
        ruleset = build_engine(
            'SecRule ARGS "@rx x" "id:1,phase:2,pass,totallyMadeUp:1"\n').ruleset
        assert any("totallymadeup" in rule.unknown_actions for rule in ruleset.rules)


# --------------------------------------------------------------------------
# 端到端 (真实 CRS)
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def engine() -> SecRuleEngine:
    """装载真实 CRS 的解释器 (整个模块复用一份, 装载约 0.2s)."""
    from sentinel.core.config import Config
    from sentinel.waf.engines.modsecurity import ModSecurityEngine
    driver = ModSecurityEngine(Config())
    assert driver.engine is not None, "CRS 规则未装载"
    return driver.engine


@pytest.mark.integration
class TestCrsEngine:
    @pytest.mark.parametrize("target", [
        "/search?q=1%27+OR+%271%27%3D%271",
        "/product?id=1+UNION+SELECT+user,pass+FROM+users",
        "/page?name=<script>alert(1)</script>",
        "/download?file=../../../../etc/passwd",
        "/run?cmd=;cat+/etc/passwd",
    ])
    def test_attacks_are_blocked(self, engine, target):
        verdict = engine.inspect(make_request(target=target))
        assert verdict.blocked, f"未拦截: {target}"

    @pytest.mark.parametrize("target", [
        "/", "/search?q=hello+world", "/product?id=42&sort=name",
        "/api/v1/orders?page=2&limit=20",
        "/search?q=select+the+best+laptop",     # 良性近似攻击
        "/search?q=union+station+hours",
        "/search?q=order+by+popularity",
    ])
    def test_benign_traffic_passes(self, engine, target):
        verdict = engine.inspect(make_request(target=target))
        assert not verdict.blocked, f"误报: {target} -> {verdict.matched_rules}"

    def test_scanner_user_agent_detected(self, engine):
        verdict = engine.inspect(make_request(
            headers={"User-Agent": "sqlmap/1.7.2#stable"}))
        assert verdict.blocked and 913100 in verdict.matched_rules

    def test_paranoia_level_tightens_rules(self):
        """PL4 下运行的规则更多, 同一请求的异常评分应当不低于 PL1.

        PL 分级不是靠筛选规则集实现的, 而是 CRS 自己的 ``skipAfter`` +
        ``SecMarker`` 跳转; 一旦该机制失效, 两个 PL 的得分会完全相同 ——
        这正是这条用例要盯住的回归。
        """
        from sentinel.core.config import Config
        from sentinel.waf.engines.modsecurity import ModSecurityEngine
        target = "/search?q=1%20or%201%3D1%20--"
        low = ModSecurityEngine(Config()).engine
        config = Config()
        config.waf.paranoia_level = 4
        high = ModSecurityEngine(config).engine
        low_verdict = low.inspect(make_request(target=target))
        high_verdict = high.inspect(make_request(target=target))
        assert high_verdict.anomaly_score >= low_verdict.anomaly_score
        assert high_verdict.blocked

    def test_severity_and_score_reported(self, engine):
        verdict = engine.inspect(make_request(
            target="/page?name=<script>alert(1)</script>"))
        assert verdict.anomaly_score >= 5
        assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)


# --------------------------------------------------------------------------
# 缓存一致性
# --------------------------------------------------------------------------
class TestCacheCoherence:
    def test_capture_invalidates_resolution_cache(self):
        """先查过 TX:1 (哪怕为空) 也必须能读到之后的 capture 结果.

        解析缓存会把「未命中」也缓存成空列表, 若 capture 不让缓存失效,
        后续所有 ``TX:n`` 都会被那个空结果挡住。
        """
        engine = build_engine(
            # 先"摸"一次 TX:1, 让空结果进入缓存
            'SecRule ARGS "@rx ." "id:1,phase:2,pass,nolog,capture,'
            'setvar:\'tx.warm=%{tx.1}\'"\n'
            'SecRule ARGS "@rx (\\d+)-(\\d+)" "id:2,phase:2,pass,nolog,capture"\n'
            'SecRule TX:2 "@streq 99" "id:3,phase:2,deny,status:403"\n')
        assert engine.inspect(make_request(target="/x?r=42-99")).matched_rules == [3]

    def test_setvar_invalidates_resolution_cache(self):
        engine = build_engine(
            'SecRule &TX:counter "@eq 0" "id:1,phase:1,pass,nolog,'
            "setvar:'tx.counter=1'\"\n"
            'SecRule TX:counter "@eq 1" "id:2,phase:1,deny,status:403"\n')
        assert engine.inspect(make_request()).matched_rules == [2]


# --------------------------------------------------------------------------
# 请求体解析
# --------------------------------------------------------------------------
class TestBodyParsing:
    """缺少 Content-Type 的 POST 也必须被解析成 ARGS.

    ModSecurity 在请求未声明 Content-Type 时按 ``application/x-www-form-urlencoded``
    处理请求体; 若严格要求显式声明, 大量真实 POST 的注入会**整条规则都看不见**。
    """

    def test_body_without_content_type_is_parsed(self):
        engine = build_engine(
            'SecRule ARGS "@streq evil" "id:1,phase:2,deny,status:403"\n')
        request = HttpRequest(method="POST", target="/login", path="/login",
                              headers={"Host": "lab.local"}, body=b"user=evil",
                              remote_addr="127.0.0.1")
        assert engine.inspect(request).matched_rules == [1]

    def test_json_body_is_not_parsed_as_form(self):
        engine = build_engine(
            'SecRule ARGS "@rx ." "id:1,phase:2,deny,status:403"\n')
        request = HttpRequest(method="POST", target="/api", path="/api",
                              headers={"Host": "lab.local",
                                       "Content-Type": "application/json"},
                              body=b'{"user":"evil"}', remote_addr="127.0.0.1")
        assert engine.inspect(request).matched_rules == []

    def test_urlencoded_body_is_parsed(self):
        engine = build_engine(
            'SecRule ARGS:user "@streq evil" "id:1,phase:2,deny,status:403"\n')
        request = HttpRequest(
            method="POST", target="/login", path="/login",
            headers={"Host": "lab.local",
                     "Content-Type": "application/x-www-form-urlencoded"},
            body=b"user=evil&pass=x", remote_addr="127.0.0.1")
        assert engine.inspect(request).matched_rules == [1]
