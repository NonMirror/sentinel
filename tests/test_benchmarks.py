"""基准与报告工具链测试 (综设 III 证据链).

覆盖 ``benchmarks.run_all`` 的统计原语与 ``sentinel.reporting`` 的文档生成流水线。
全部为快速测试: 不启动真实引擎、不运行多引擎扫描。
"""
from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from benchmarks import run_all
from benchmarks.corpus import build_corpus
from sentinel import reporting


# ---------------------------------------------------------------------------
# 统计原语
# ---------------------------------------------------------------------------
def test_percentile_handles_edges() -> None:
    assert run_all.percentile([], 50) == 0.0
    assert run_all.percentile([5.0], 99) == 5.0
    values = [float(i) for i in range(1, 101)]
    assert run_all.percentile(values, 50) == 50.0
    assert run_all.percentile(values, 90) == 90.0
    assert run_all.percentile(values, 99) == 99.0
    assert run_all.percentile(values, 0) == 1.0


def test_latency_stats_shape() -> None:
    stats = run_all.latency_stats([1.0, 2.0, 3.0, 4.0])
    assert stats["count"] == 4
    assert stats["mean"] == 2.5
    assert stats["min"] == 1.0 and stats["max"] == 4.0
    assert stats["p50"] <= stats["p90"] <= stats["p99"]
    assert stats["unit"] == "ms"
    assert run_all.latency_stats([]) == {}


# ---------------------------------------------------------------------------
# 质量指标
# ---------------------------------------------------------------------------
def test_quality_from_flags_confusion_matrix() -> None:
    records = [
        (True, True, "sqli"), (True, False, "sqli"),
        (False, False, "benign"), (False, True, "benign"),
    ]
    quality = run_all._quality_from_flags(records)
    assert (quality["tp"], quality["fn"], quality["tn"], quality["fp"]) == (1, 1, 1, 1)
    assert quality["precision"] == 0.5 and quality["recall"] == 0.5
    assert quality["f1"] == 0.5
    assert quality["accuracy"] == 0.5
    assert quality["false_positive_rate"] == 0.5
    assert quality["false_negative_rate"] == 0.5
    assert quality["by_category"]["sqli"]["rate"] == 0.5
    # detected 只统计 TP, 因此正常流量分类恒为 0.0
    assert quality["by_category"]["benign"]["rate"] == 0.0


def test_quality_perfect_and_empty() -> None:
    perfect = run_all._quality_from_flags([(True, True, "xss"), (False, False, "benign")])
    assert (perfect["precision"], perfect["recall"], perfect["f1"]) == (1.0, 1.0, 1.0)
    empty = run_all._quality_from_flags([])
    assert empty["total"] == 0 and empty["precision"] == 1.0


def test_quality_inprocess_on_corpus_subset(corpus) -> None:
    category = next(c for c in ("xss", "sqli", "lfi") if c in
                    {s.category for s in corpus})
    subset = [s for s in corpus if s.category == category][:6]
    quality = run_all.quality_inprocess(subset)
    assert quality["engine"] == "python"
    assert quality["mode"] == "in-process"
    assert quality["total"] == len(subset)
    assert quality["recall"] == 1.0
    assert quality["false_positive_rate"] == 0.0
    assert quality["by_category"][category]["detected"] == len(subset)


# ---------------------------------------------------------------------------
# 基准函数
# ---------------------------------------------------------------------------
def test_bench_parser_is_fast_and_consistent() -> None:
    corpus = build_corpus()
    result = run_all.bench_parser(corpus, rounds=1, min_seconds=0.0)
    assert result["ops"] == len(corpus)
    assert result["ops_per_s"] > 1000
    assert result["latency_us"]["p50"] > 0
    assert result["latency_us"]["p99"] >= result["latency_us"]["p50"]


def test_bench_engine_inprocess_reports_percentiles(corpus) -> None:
    subset = corpus[:12]
    result = run_all.bench_engine_inprocess(subset, rounds=2, min_seconds=0.0)
    assert result["ops"] == 24
    assert result["ops_per_s"] > 100
    detail = result["latency_detail"]
    assert detail["p50_ms"] <= detail["p90_ms"] <= detail["p99_ms"]


def test_corpus_is_balanced_and_labelled() -> None:
    corpus = build_corpus()
    stats = run_all.build_corpus() and None  # noqa: F841 - 保持函数可导入
    from benchmarks.corpus import corpus_stats
    counts = corpus_stats(corpus)
    assert counts["total"] == len(corpus) >= 150
    assert counts["benign"] >= 50
    assert counts["total"] - counts["benign"] >= 80
    assert all(s.raw.startswith((b"GET", b"POST", b"PUT", b"HEAD", b"DELETE"))
               for s in corpus)
    assert any(s.expect_block for s in corpus) and any(not s.expect_block for s in corpus)


# ---------------------------------------------------------------------------
# benchmarks.render_markdown
# ---------------------------------------------------------------------------
def _tiny_report() -> dict:
    return {
        "meta": {"generated_at": "2026-01-01T00:00:00", "duration_s": 1.0,
                 "corpus_size": 2},
        "environment": {"python": "3.14.0", "uv": "0.12.0", "mise": "2026.1.0",
                        "platform": "Linux", "machine": "x86_64", "cpu_count": 8,
                        "nginx": {"version": "1.22.1", "modules": ["modsecurity"],
                                  "prefix": "/tmp"},
                        "waf_engines": {"python": {"display": "Python", "upstream": "builtin",
                                                   "available": True, "real_engine": False}},
                        "available_engines": {"python": True},
                        "scanner_engines": {}},
        "corpus": {"stats": {"benign": 1, "sqli": 1, "total": 2}, "total": 2},
        "parser": {"samples": 2, "rounds": 1, "ops": 2, "seconds": 0.1,
                   "ops_per_s": 20.0,
                   "latency_us": {"mean": 1.0, "p50": 1.0, "p90": 1.0, "p99": 1.0}},
        "quality": {"python": {"total": 2, "attacks": 1, "benign": 1, "tp": 1, "fp": 0,
                               "tn": 1, "fn": 0, "precision": 1.0, "recall": 1.0,
                               "f1": 1.0, "accuracy": 1.0, "false_positive_rate": 0.0,
                               "false_negative_rate": 0.0, "by_category": {},
                               "false_positive_samples": [], "false_negative_samples": [],
                               "engine": "python", "mode": "in-process"}},
        "engine_throughput": {"python": {"engine": "python", "ops": 2, "seconds": 0.1,
                                         "ops_per_s": 20.0,
                                         "latency_detail": {"p50_ms": 1.0, "p90_ms": 1.0,
                                                            "p99_ms": 1.0}}},
        "rules": {"python": {"total": 3, "enabled": 3, "load_ms": 0.1, "source": "rules/"}},
        "real_engines": {},
        "proxy": {"sequential": {"count": 1, "p50": 1.0, "p90": 1.0, "p99": 1.0,
                                 "statuses": {"200": 1}},
                  "concurrent": {"requests": 1, "concurrency": 1, "qps": 1.0,
                                 "statuses": {"200": 1},
                                 "latency_ms": {"p50": 1.0, "p90": 1.0, "p99": 1.0}}},
        "load_balancer": {"backends": 1, "distribution": {"a": 1}, "mean": 1.0,
                          "coefficient_of_variation": 0.0, "max_deviation": 0},
        "scanner": {"builtin": {"seconds": 1.0, "requests": 1, "urls": 1, "params": 1,
                                "plugins_run": 1, "findings": 1, "requests_per_s": 1.0,
                                "risk_score": 10.0, "risk_level": "低危",
                                "by_type": {"xss": 1}}},
    }


def test_render_markdown_has_all_sections() -> None:
    markdown = run_all.render_markdown(_tiny_report())
    assert "# Sentinel 综合性能与质量基准报告" in markdown
    for heading in ("语料库", "解析", "质量", "代理", "负载均衡", "扫描"):
        assert heading in markdown
    assert "python" in markdown


# ---------------------------------------------------------------------------
# sentinel.reporting
# ---------------------------------------------------------------------------
def test_discover_tests_finds_the_suite() -> None:
    discovered = reporting.discover_tests()
    assert discovered["source"] == "static"
    # 静态清单按函数计, 少于 pytest 参数化后的用例实例数
    assert discovered["total"] >= 200
    assert "test_parser" in discovered["modules"]
    assert any(c["name"].startswith("test_") for c in
               discovered["modules"]["test_parser"]["cases"])


def test_parse_junit_reads_statuses(tmp_path: Path) -> None:
    xml = tmp_path / "junit.xml"
    xml.write_text(
        '<?xml version="1.0"?><testsuites><testsuite name="tests.test_demo">'
        '<testcase classname="tests.test_demo" name="test_ok" time="0.01"/>'
        '<testcase classname="tests.test_demo" name="test_bad" time="0.02">'
        '<failure message="boom">trace</failure></testcase>'
        '<testcase classname="tests.test_demo" name="test_skip" time="0.0">'
        '<skipped message="missing"/></testcase>'
        '</testsuite></testsuites>', encoding="utf-8")
    result = reporting.parse_junit(xml)
    assert (result["passed"], result["failed"], result["skipped"]) == (1, 1, 1)
    assert result["total"] == 3
    cases = result["modules"]["test_demo"]["cases"]
    assert {c["status"] for c in cases} == {"passed", "failed", "skipped"}
    assert any("boom" in c["doc"] for c in cases)


def test_junit_roundtrip_through_elementtree() -> None:
    root = ElementTree.Element("testsuites")
    assert root.tag == "testsuites"


def test_test_matrix_groups_by_arch() -> None:
    tests = {"source": "static", "total": 2, "modules": {
        "test_parser": {"cases": [{"name": "test_a", "status": "collected",
                                   "seconds": 0.0}], "seconds": 0.0},
        "test_scanner_report": {"cases": [{"name": "test_b", "status": "collected",
                                           "seconds": 0.0}], "seconds": 0.0},
    }}
    matrix = reporting.test_matrix(tests)
    groups = matrix["groups"]
    assert groups["综设 II"]["total"] == 1
    assert groups["综设 I"]["total"] == 1
    assert {r["module"] for r in matrix["rows"]} == {"test_parser", "test_scanner_report"}


def test_vuln_meta_normalises_names() -> None:
    assert reporting.vuln_meta("sqli")[2] == "CWE-89"
    assert reporting.vuln_meta("sqli_error")[0].startswith("SQL 注入")
    assert reporting.vuln_meta("ssrf-internal")[1].startswith("A10")
    assert reporting.vuln_meta("path_traversal")[2] == "CWE-22"
    assert reporting.vuln_meta("不存在的类型")[0] == "不存在的类型"


def test_svg_charts_are_wellformed() -> None:
    bars = reporting.svg_grouped_bars(
        "t", ["A", "B"], [{"name": "x", "color": "#fff", "values": [0.5, 1.0]}])
    assert bars.startswith("<svg") and bars.endswith("</svg>")
    assert bars.count("<rect") >= 2
    lines = reporting.svg_lines("t", ["PL1", "PL2"],
                               [{"name": "r", "color": "#fff", "values": [0.1, 0.9]}])
    assert "<polyline" in lines
    hbars = reporting.svg_hbars("t", ["很长的标签名字"], [0.5])
    assert "<rect" in hbars
    assert reporting.svg_grouped_bars("t", [], []) == ""


def test_build_document_and_markdown() -> None:
    blocks = reporting.build_document(_tiny_report(),
                                      {"source": "static", "modules": {},
                                       "total": 0}, stamp="X")
    kinds = [b["type"] for b in blocks]
    assert kinds[0] == "h1"
    assert "table" in kinds and "chart" in kinds
    markdown = reporting.render_markdown_doc(blocks, "X")
    assert "# Sentinel 综合测试与评测报告" in markdown
    assert "架构映射" in markdown and "综合测试与评测报告" in markdown


def test_render_html_is_self_contained() -> None:
    blocks = reporting.build_document(_tiny_report(),
                                      {"source": "static", "modules": {},
                                       "total": 0}, stamp="X")
    html = reporting.render_html_doc(blocks, "X", "标题")
    assert html.startswith("<!DOCTYPE html>")
    assert "data:image/png;base64," in html or "<svg" in html
    assert "<h1>标题</h1>" in html
    assert html.count("<h1>") == 1  # 标题不重复
    assert "#303446" in html  # Catppuccin Frappé base 色


def test_generate_test_report_writes_all_formats(tmp_path: Path) -> None:
    bench = _tiny_report()
    (tmp_path / "bench-x.json").write_text(json.dumps(bench), encoding="utf-8")
    generated = reporting.generate_test_report(bench=bench, outdir=tmp_path,
                                               stamp="unit")
    for kind in ("markdown", "html", "docx"):
        assert kind in generated
    markdown = Path(generated["markdown"])
    html = Path(generated["html"])
    assert markdown.exists() and markdown.stat().st_size > 1000
    assert html.exists() and html.stat().st_size > 1000
    assert Path(generated["docx"]).exists()


def test_latest_bench_picks_newest_and_errors_when_empty(tmp_path: Path) -> None:
    (tmp_path / "bench-20260101-000000.json").write_text('{"meta": {}}', encoding="utf-8")
    (tmp_path / "bench-20260202-000000.json").write_text('{"meta": {"n": 2}}',
                                                         encoding="utf-8")
    bench, path = reporting.latest_bench(tmp_path)
    assert bench["meta"]["n"] == 2
    assert path.name == "bench-20260202-000000.json"
    with pytest.raises(FileNotFoundError):
        reporting.latest_bench(tmp_path / "missing")


def test_plain_strips_markdown_tokens() -> None:
    assert reporting._plain("**加粗** 与 `代码`") == "加粗 与 代码"
    assert reporting._pct(0.1234) == "12.3%"
    assert reporting._pct(None) == "-"
    assert reporting._fnum(1234.5678, 1) == "1,234.6"


@pytest.mark.slow
def test_full_benchmark_smoke_is_opt_in() -> None:
    """完整基准耗时较长 (约 2 分钟), 仅在 ``-m slow`` 时运行."""
    report = run_all.run_benchmarks(real_engines=False, scanner_multi=False,
                                    verbose=False)
    assert report["corpus"]["total"] == report["meta"]["corpus_size"]
    assert report["parser"]["ops_per_s"] > 0
    assert "python" in report["quality"]
