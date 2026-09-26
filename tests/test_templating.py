"""原生 nuclei 模板引擎测试.

覆盖四层: 模板加载/索引 → 表达式语言 → DSL 求值 → 端到端执行。
重点是那些**静默失效**的路径 —— 模板没加载到、matcher 类型写错、DSL 函数
少一个, 都不会报错, 只会少报漏洞。
"""
from __future__ import annotations

import textwrap

import pytest

from sentinel.core.models import Severity
from sentinel.lab.server import LabServer
from sentinel.scanner.client import HttpClient
from sentinel.scanner.templating import (TemplateEngine, TemplateLoader,
                                         TemplateRunner, TargetVars)
from sentinel.scanner.templating.expression import (DslError, ResponseContext,
                                                    evaluate_dsl, render)
from sentinel.scanner.templating.matchers import extract, match_one
from sentinel.scanner.templating.model import Extractor, Matcher
from sentinel.scanner.templating.runner import expand_payloads


# --------------------------------------------------------------------------
# 夹具
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def lab():
    server = LabServer("127.0.0.1", 0, "tpl-test")
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="module")
def lab_url(lab) -> str:
    return f"http://127.0.0.1:{lab.bound_port}/"


def write_template(tmp_path, name: str, body: str):
    path = tmp_path / f"{name}.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def context(url: str = "http://h/p", status: int = 200, body: str = "",
            headers: dict | None = None) -> ResponseContext:
    return ResponseContext(url=url, status_code=status, body=body,
                           body_bytes=body.encode(), headers=headers or {})


# --------------------------------------------------------------------------
# 加载与索引
# --------------------------------------------------------------------------
class TestLoading:
    def test_index_and_parse(self, tmp_path):
        write_template(tmp_path, "t1", """
            id: t1
            info:
              name: 测试模板
              severity: high
              tags: sqli,test
            http:
              - method: GET
                path: ["{{BaseURL}}/x"]
                matchers:
                  - type: status
                    status: [200]
        """)
        loader = TemplateLoader([tmp_path])
        assert list(loader.entries) == ["t1"]
        template = loader.load("t1")
        assert template.name == "测试模板"
        assert template.severity is Severity.HIGH
        assert template.tags == ("sqli", "test")
        assert len(template.blocks) == 1

    def test_non_http_protocols_are_skipped(self, tmp_path):
        write_template(tmp_path, "dns1", """
            id: dns1
            info: {name: DNS, severity: info}
            dns:
              - name: "{{FQDN}}"
        """)
        assert TemplateLoader([tmp_path]).entries == {}

    def test_broken_yaml_is_isolated(self, tmp_path):
        write_template(tmp_path, "bad", "id: bad\ninfo: {name: x\n")
        write_template(tmp_path, "good", """
            id: good
            info: {name: ok, severity: low}
            http: [{method: GET, path: ["{{BaseURL}}/"], matchers: [{type: status, status: [200]}]}]
        """)
        loader = TemplateLoader([tmp_path])
        assert list(loader.entries) == ["good"]
        assert loader.load("good") is not None

    def test_disk_cache_round_trip(self, tmp_path):
        write_template(tmp_path, "c1", """
            id: c1
            info: {name: cached, severity: info}
            http: [{method: GET, path: ["{{BaseURL}}/"], matchers: [{type: status, status: [200]}]}]
        """)
        cache = tmp_path / "cache"
        first = TemplateLoader([tmp_path], cache_dir=cache)
        assert list(first.entries) == ["c1"]
        assert (cache / "index.json").exists()
        second = TemplateLoader([tmp_path], cache_dir=cache)
        assert list(second.entries) == ["c1"]

    def test_binary_matcher_is_always_hex_decoded(self, tmp_path):
        """nuclei 的 binary 值一律是十六进制串, 不写 encoding: hex 也是."""
        write_template(tmp_path, "b1", """
            id: b1
            info: {name: bin, severity: info}
            http:
              - method: GET
                path: ["{{BaseURL}}/"]
                matchers:
                  - type: binary
                    binary: ["53514c697465"]
        """)
        matcher = TemplateLoader([tmp_path]).load("b1").blocks[0].matchers[0]
        assert matcher.binary == (b"SQLite",)

    def test_vendored_templates_are_indexed(self):
        from sentinel.vendor import nuclei_templates_dir
        loader = TemplateLoader([nuclei_templates_dir()])
        assert len(loader.entries) > 1000


# --------------------------------------------------------------------------
# 表达式 ({{...}})
# --------------------------------------------------------------------------
class TestExpressions:
    def test_target_variables(self):
        variables = TargetVars.of("https://example.com:8443/a/b").variables()
        assert variables["BaseURL"] == "https://example.com:8443"
        assert variables["Hostname"] == "example.com"
        assert variables["Port"] == "8443"
        assert variables["Scheme"] == "https"

    def test_simple_substitution(self):
        assert render("{{BaseURL}}/x", {"BaseURL": "http://h"}) == "http://h/x"

    def test_nested_helpers(self):
        assert render('{{concat({{Host}}, ":443")}}',
                      {"Host": "h"}) == "h:443"

    def test_helpers(self):
        assert render('{{base64("abc")}}', {}) == "YWJj"
        assert render('{{to_upper("ab")}}', {}) == "AB"
        assert render('{{hex_encode("A")}}', {}) == "41"

    def test_undefined_variable_becomes_empty(self):
        assert render("[{{nope}}]", {}) == "[]"

    def test_self_reference_terminates(self):
        assert render("{{a}}", {"a": "{{a}}"}) is not None


# --------------------------------------------------------------------------
# DSL
# --------------------------------------------------------------------------
class TestDsl:
    def test_boolean_operators(self):
        ctx = context(status=200, body="admin panel")
        assert evaluate_dsl('status_code == 200 && contains(body, "admin")', ctx)
        assert evaluate_dsl('status_code == 404 || contains(body, "panel")', ctx)
        assert evaluate_dsl('!contains(body, "login")', ctx)
        assert not evaluate_dsl('status_code != 200', ctx)

    def test_string_functions(self):
        ctx = context(body="Hello World")
        assert evaluate_dsl('tolower(body) == "hello world"', ctx)
        assert evaluate_dsl('len(body) == 11', ctx)
        assert evaluate_dsl('contains(toupper(body), "WORLD")', ctx)
        assert evaluate_dsl('regex("^Hello", body)', ctx)
        assert evaluate_dsl('startswith(body, "Hell")', ctx)

    def test_header_function(self):
        ctx = context(headers={"Content-Type": "text/html"})
        assert evaluate_dsl('contains(header("content-type"), "html")', ctx)

    def test_content_length_and_duration(self):
        ctx = context(body="12345")
        assert evaluate_dsl("content_length == 5", ctx)

    def test_compare_versions(self):
        assert evaluate_dsl('compare_versions("1.2.3", ">=1.2.0")', context())
        assert not evaluate_dsl('compare_versions("1.2.3", "<1.0.0")', context())

    def test_arbitrary_code_is_rejected(self):
        """模板来自外部仓库, DSL 绝不能让它们执行任意代码."""
        for expr in ('__import__("os").system("true")',
                     'open("/etc/passwd").read()',
                     'body.__class__',
                     '().__class__.__bases__'):
            with pytest.raises(DslError):
                evaluate_dsl(expr, context())

    def test_syntax_error_raises_dsl_error(self):
        with pytest.raises(DslError):
            evaluate_dsl("contains(", context())


# --------------------------------------------------------------------------
# 匹配器 / 提取器
# --------------------------------------------------------------------------
class TestMatchers:
    def test_status_size_word_regex(self):
        ctx = context(status=200, body="hello admin", headers={"X-A": "1"})
        assert match_one(Matcher(type="status", status=(200,)), ctx)
        assert match_one(Matcher(type="size", size=(11,)), ctx)
        assert match_one(Matcher(type="word", words=("admin",)), ctx)
        assert not match_one(Matcher(type="word", words=("nope",)), ctx)
        assert match_one(Matcher(type="regex", regex=(r"adm\w+",)), ctx)
        assert match_one(Matcher(type="word", part="header", words=("X-A",)), ctx)

    def test_condition_and_or(self):
        ctx = context(body="alpha")
        both = Matcher(type="word", words=("alpha", "beta"), condition="and")
        either = Matcher(type="word", words=("alpha", "beta"), condition="or")
        assert not match_one(both, ctx)
        assert match_one(either, ctx)

    def test_negative(self):
        ctx = context(body="alpha")
        assert match_one(Matcher(type="word", words=("beta",), negative=True), ctx)
        assert not match_one(Matcher(type="word", words=("alpha",), negative=True), ctx)

    def test_case_insensitive_words(self):
        ctx = context(body="ADMIN")
        assert match_one(Matcher(type="word", words=("admin",),
                                 case_insensitive=True), ctx)

    def test_binary(self):
        ctx = ResponseContext(body_bytes=b"\x00SQLite format 3\x00")
        assert match_one(Matcher(type="binary", binary=(b"SQLite",)), ctx)

    def test_unsupported_type_is_false_not_crash(self):
        assert not match_one(Matcher(type="xpath", words=("x",)), context())

    def test_extractors(self):
        ctx = context(body="user: admin\nversion: 1.2.3")
        assert extract(Extractor(type="regex", regex=(r"version: ([\d.]+)",),
                                 group=1), ctx) == ["1.2.3"]
        assert extract(Extractor(type="kval", kval=("user",)), ctx) == ["admin"]
        assert extract(Extractor(type="dsl", dsl=("status_code",)), ctx) == ["200"]

    def test_json_extractor(self):
        ctx = context(body='{"a": {"b": [10, 20]}}')
        assert extract(Extractor(type="json", json=("a.b.1",)), ctx) == ["20"]


# --------------------------------------------------------------------------
# 载荷展开
# --------------------------------------------------------------------------
class TestPayloads:
    def test_sniper_single_variable(self):
        from sentinel.scanner.templating.model import HttpBlock
        block = HttpBlock(payloads={"p": ("a", "b")}, attack="sniper")
        combos = expand_payloads(block, {})
        assert [c["p"] for c in combos] == ["a", "b"]

    def test_clusterbomb_is_cartesian(self):
        from sentinel.scanner.templating.model import HttpBlock
        block = HttpBlock(payloads={"a": ("1", "2"), "b": ("x", "y")},
                          attack="clusterbomb")
        assert len(expand_payloads(block, {})) == 4

    def test_pitchfork_pairs_in_lockstep(self):
        from sentinel.scanner.templating.model import HttpBlock
        block = HttpBlock(payloads={"a": ("1", "2"), "b": ("x", "y")},
                          attack="pitchfork")
        combos = expand_payloads(block, {})
        assert len(combos) == 2
        assert [(c["a"], c["b"]) for c in combos] == [("1", "x"), ("2", "y")]

    def test_default_attack_for_single_variable_is_sniper(self):
        from sentinel.scanner.templating.model import HttpBlock
        assert HttpBlock(payloads={"p": ("a",)}).effective_attack == "sniper"


# --------------------------------------------------------------------------
# 端到端
# --------------------------------------------------------------------------
@pytest.mark.integration
class TestEndToEnd:
    def test_lab_templates_find_planted_vulnerabilities(self, lab_url):
        from pathlib import Path
        from sentinel.scanner.engines.base import sentinel_root
        engine = TemplateEngine([sentinel_root() / "templates" / "nuclei"])
        findings = engine.scan([lab_url])
        kinds = {f.vuln_type for f in findings}
        # 靶场预置的十类漏洞里, 模板覆盖的那些都必须被发现
        assert {"sqli-error", "xss-reflected", "admin-panel"} <= kinds, kinds
        assert all(f.conn_id == "nuclei" for f in findings)

    def test_response_cache_collapses_duplicate_requests(self, lab_url):
        """同一 GET 被多条模板重复请求时只应真正发一次."""
        client = HttpClient(timeout=5.0)
        runner = TemplateRunner(client)
        url = lab_url + "robots.txt"
        headers: dict[str, str] = {}
        for _ in range(5):
            runner._send("GET", url, headers, "", block=None)
        assert runner.cache_hits == 4
        assert runner.stats.requests == 1

    def test_engine_reports_stats(self, lab_url):
        from pathlib import Path
        from sentinel.scanner.engines.base import sentinel_root
        engine = TemplateEngine([sentinel_root() / "templates" / "nuclei"])
        engine.scan([lab_url])
        stats = engine.stats.as_dict()
        assert stats["templates"] > 0 and stats["requests"] > 0
        assert stats["matched"] > 0

    def test_custom_template_round_trip(self, tmp_path, lab_url):
        write_template(tmp_path, "custom", """
            id: custom-check
            info: {name: 自定义检查, severity: medium, tags: test}
            http:
              - method: GET
                path: ["{{BaseURL}}/robots.txt"]
                matchers-condition: and
                matchers:
                  - type: status
                    status: [200]
                  - type: word
                    part: body
                    words: ["Disallow"]
        """)
        engine = TemplateEngine([tmp_path])
        findings = engine.scan([lab_url])
        assert len(findings) == 1
        assert findings[0].vuln_type == "custom-check"


# --------------------------------------------------------------------------
# 外部主机隔离
# --------------------------------------------------------------------------
class TestHostIsolation:
    def test_requests_to_other_hosts_are_skipped(self, tmp_path):
        """模板写死外部主机时不得真的发出去 (SSRF/OAST 探测模板很常见)."""
        write_template(tmp_path, "ext", """
            id: external-target
            info: {name: 外部主机, severity: info}
            http:
              - method: GET
                path: ["http://169.254.169.254/latest/meta-data/"]
                matchers: [{type: status, status: [200]}]
        """)
        engine = TemplateEngine([tmp_path])
        assert engine.scan(["http://127.0.0.1:9/"]) == []
        assert engine.stats.blocked_external == 1
        assert engine.stats.requests == 0

    def test_target_host_is_allowed(self, tmp_path, lab_url):
        write_template(tmp_path, "own", """
            id: own-host
            info: {name: 本机, severity: info}
            http:
              - method: GET
                path: ["{{BaseURL}}/robots.txt"]
                matchers: [{type: status, status: [200]}]
        """)
        engine = TemplateEngine([tmp_path])
        assert len(engine.scan([lab_url])) == 1
        assert engine.stats.blocked_external == 0

    def test_allow_external_opt_in(self, tmp_path):
        """显式放行时不再拦截 (库的通用性保留)."""
        engine = TemplateEngine([tmp_path], allow_external=True)
        assert engine.allow_external is True

    def test_runner_host_filter_is_pure(self):
        runner = TemplateRunner(HttpClient(), allowed_hosts={"a.example"})
        assert runner._host_allowed("http://a.example/x")
        assert not runner._host_allowed("http://b.example/x")
        # 空集合 = 不限制
        assert TemplateRunner(HttpClient())._host_allowed("http://any/x")
