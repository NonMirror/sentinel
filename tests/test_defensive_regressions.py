"""Defensive semantics and reporting regressions; no vulnerability scans."""
import pytest

from benchmarks.scripts.bench_regressions import request, semantic_checks
from sentinel.core.models import HttpRequest
from sentinel.scanner.crawler import TargetRecognizer
from sentinel.waf.parser import iter_variable_values
from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.variables import Transaction
from tests.test_crawler_safety import MemoryClient
from tests.test_secrule import build_engine


def test_benchmark_semantics():
    result = semantic_checks()
    assert result["passed"] == result["total"], [
        name for name, passed in result["checks"].items() if not passed]


def test_benchmark_missing_external_fixtures_does_not_fall_back(monkeypatch):
    from benchmarks.scripts import bench_regressions
    monkeypatch.setattr(bench_regressions, "build_attacks", lambda *args: ([], {}))
    monkeypatch.setattr(bench_regressions, "load_benign", lambda: ([], 0))
    with pytest.raises(ValueError, match="fixtures are missing"):
        bench_regressions.run(repeats=1, external=True)


@pytest.mark.parametrize("query,body,blocked", [
    ("id=allow&id=sentinel-deny-marker", b"", True),
    ("id=allow", b"id=sentinel-deny-marker", True),
    ("other=sentinel-deny-marker", b"id=allow", False),
    ("id=allow", b"other=sentinel-deny-marker", False),
])
def test_rule_checks_every_value_of_only_the_selected_field(query, body, blocked):
    engine = build_engine(
        'SecRule ARGS:id "@streq sentinel-deny-marker" "id:1,phase:2,deny"')
    assert engine.inspect(request("/?" + query, body)).blocked is blocked


@pytest.mark.parametrize("header", ["CONTENT-TYPE", "Content-type", "cOnTeNt-TyPe"])
def test_content_type_is_case_insensitive(header):
    req = HttpRequest(headers={header: "application/json"}, body=b'{"name":"ordinary"}')
    assert req.content_type == "application/json"
    fields = Transaction(req).resolve(Variable(name="ARGS"))
    assert [(m.key, m.value) for m in fields] == [("json.name", "ordinary")]


@pytest.mark.parametrize("body", [b"", "你好".encode(), b"a=1"])
def test_body_length_counts_bytes(body):
    tx = Transaction(request(body=body))
    assert tx.resolve(Variable(name="REQUEST_BODY_LENGTH"))[0].value == str(len(body))


def test_invalid_regex_selector_does_not_select_all_fields():
    tx = Transaction(request("/?id=ordinary"))
    assert tx.resolve(Variable(name="ARGS", selectors=("/[/",))) == []


def test_capture_replaces_cached_values():
    tx = Transaction(request())
    tx.capture(["one", "old"])
    assert tx.resolve(Variable(name="TX", selectors=("1",)))[0].value == "old"
    tx.capture(["two"])
    assert tx.resolve(Variable(name="TX", selectors=("1",))) == []


def test_python_selector_retains_repeated_blank_values():
    assert iter_variable_values(request("/?id=&id=ordinary&id="), "ARGS:id") == ["", "ordinary", ""]


def test_sitemap_and_forms_respect_endpoint_budget():
    root = "https://example.test"
    client = MemoryClient({
        root + "/": "".join(f'<form action="/form/{i}"><input name="q"></form>' for i in range(50)),
        root + "/sitemap.xml": "".join(f"<loc>{root}/map/{i}</loc>" for i in range(50)),
    })
    target = TargetRecognizer(client, max_urls=4).recognize(root + "/")
    assert target.url_count == 4
    assert len(client.requests) <= 6


def test_crawler_request_budget_is_not_multiplied_by_repeated_links():
    root = "https://example.test/"
    client = MemoryClient({root: '<a href="/page?q=1">x</a>' * 500})
    TargetRecognizer(client, max_urls=8).recognize(root)
    assert client.requests.count(root + "page?q=1") == 1
